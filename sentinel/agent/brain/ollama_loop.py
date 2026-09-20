"""Brain-grow tool-use loop, running on Ollama instead of claude-agent-sdk.

Why this exists: the SDK path spawns the `claude` binary which loads any
configured `SessionStart:startup` hooks (claude-mem on the operator's box). Those
hooks inject ~60KB of irrelevant context into every brain session,
balloon prompts to 41k cache-creation tokens, and reliably trip a
parallel-tool-dispatch edge case in `claude` — `Command failed with exit
code 1`. Brain-grow doesn't need Sonnet-class reasoning anyway: it's a
mechanical search → fetch → extract → ingest loop. A local model on
Ollama handles it for $0 with no claude binary involved.

This module reuses every existing brain tool handler from
`sentinel/agent/brain/tools.py` — we just bypass the @tool decorator's
MCP wrapper and call the raw async functions directly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any, Callable, Optional

from sentinel.agent.brain import tools as brain_tools
from sentinel.agent.ollama_provider import OllamaClient


log = logging.getLogger(__name__)


# Map Python types in @tool's input_schema to JSON-Schema primitive types.
_PYTYPE_TO_JSON: dict[type, str] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
}


def _tool_to_json_schema(tool) -> dict:
    """Convert a claude-agent-sdk SdkMcpTool to Ollama's OpenAI-compatible
    function format."""
    properties: dict[str, dict] = {}
    required: list[str] = []
    for arg_name, py_type in (tool.input_schema or {}).items():
        json_type = _PYTYPE_TO_JSON.get(py_type, "string")
        properties[arg_name] = {"type": json_type}
        # Treat all declared args as required — Ollama models behave better
        # when the schema is explicit; the handlers themselves tolerate
        # missing keys via .get().
        required.append(arg_name)
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


def build_tools_payload(tools: list) -> list[dict]:
    """Build the `tools=[...]` parameter for OllamaClient.chat()."""
    return [_tool_to_json_schema(t) for t in tools]


def _handlers_by_name(tools: list) -> dict[str, Callable]:
    return {t.name: t.handler for t in tools}


def _result_text(result: dict) -> str:
    """Pull the text content out of a brain-tool's return value.

    Tools return the MCP shape: {content: [{type: 'text', text: '...'}], ...}
    """
    content = result.get("content") or []
    parts: list[str] = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(item.get("text") or "")
    txt = "\n".join(parts)
    if result.get("is_error"):
        txt = f"ERROR: {txt}" if not txt.startswith("ERROR") else txt
    return txt


# Chat-template tokens some Ollama models (qwen2.5-coder:7b especially)
# leak into content when their tokenizer's special tokens aren't stripped
# on egress. Observed in runs/brain-cmp-qwen-postfix.log:turn 4 as
# "<|im_start|>\n{...JSON...}". Strip these before any wrapper-unwrap or
# JSON-parse attempt so the inline tool call is recognizable.
_CHAT_TEMPLATE_RE = re.compile(
    r"<\|(?:im_start|im_end|im_sep|endoftext|start|end|user|assistant|system)\|>",
    re.IGNORECASE,
)
_TOOL_RESPONSE_RE = re.compile(
    r"<tool_(?:response|call)>\s*(.*?)\s*</tool_(?:response|call)>",
    re.DOTALL | re.IGNORECASE,
)
# Heuristic last-resort: model narrates URL selection in prose. Match
# patterns like "Selected URL for fetching: https://...", "URL: https://...",
# "I will fetch https://...". First captured URL wins.
_NARRATION_URL_RE = re.compile(
    r"(?:selected\s+url(?:\s+for\s+fetching)?|will\s+fetch|fetch(?:ing)?(?:\s+url)?|URL)\s*:?\s*"
    r"(https?://\S+)",
    re.IGNORECASE,
)


def _parse_inline_tool_call(content: str, allowed_names: set[str]) -> Optional[list[dict]]:
    """Some Ollama models (qwen2.5-coder:7b among them) emit tool calls as
    JSON in the `content` field instead of via structured `tool_calls`.
    This fallback recognizes:
      • bare JSON: {"name": "...", "arguments": {...}}
      • bare JSON with synonyms: tool/args, name/parameters
      • markdown-fenced JSON: ```{"name": ...}```
      • <tool_response>{"name": ...}</tool_response> / <tool_call>...</tool_call>
        wrappers (qwen sometimes mimics this from training data)
      • prose-narrated URL pick ("Selected URL for fetching: https://...") —
        synthesized as a fetch_url call so the loop doesn't stall at turn 2

    Returns a tool_calls-shaped list if it parsed, else None."""
    if not content:
        return None
    s = content.strip()
    # Strip chat-template special tokens (qwen2.5-coder:7b leaks
    # <|im_start|> / <|im_end|>; mistral-instruct leaks <|user|>, etc.).
    # Run before wrapper-unwrap so layered cases also resolve.
    s = _CHAT_TEMPLATE_RE.sub("", s).strip()
    # Unwrap <tool_response>...</tool_response> / <tool_call>...</tool_call>.
    m = _TOOL_RESPONSE_RE.search(s)
    if m:
        s = m.group(1).strip()
    # Strip common markdown fences models emit around JSON.
    if s.startswith("```"):
        s = s.split("\n", 1)[-1] if "\n" in s else s[3:]
        if s.endswith("```"):
            s = s[:-3]
    s = s.strip()

    if s.startswith("{") and s.endswith("}"):
        try:
            obj = json.loads(s)
        except (json.JSONDecodeError, ValueError):
            obj = None
        if isinstance(obj, dict):
            name = obj.get("name") or obj.get("tool") or obj.get("function")
            args = (
                obj.get("arguments")
                or obj.get("args")
                or obj.get("parameters")
                or {}
            )
            if name in allowed_names and isinstance(args, dict):
                return [{
                    "id": "inline_call_1",
                    "type": "function",
                    "function": {"name": name, "arguments": args},
                }]

    # Heuristic last-resort: prose URL selection. Synthesize a fetch_url
    # call from the first URL the model named, so qwen-style narration
    # ("Selected URL for fetching: https://...") doesn't dead-end the loop.
    if "fetch_url" in allowed_names:
        url_match = _NARRATION_URL_RE.search(content)
        if url_match:
            url = url_match.group(1).rstrip(".,;:)\"'")
            return [{
                "id": "inline_call_synth_fetch",
                "type": "function",
                "function": {"name": "fetch_url", "arguments": {"url": url}},
            }]
    return None


def _trim_messages(messages: list[dict], max_chars: int = 30_000) -> list[dict]:
    """When the conversation grows past max_chars, drop the oldest tool
    results (keeping system + user + recent context). Never drops the
    system message or the original user prompt."""
    total = sum(len(json.dumps(m)) for m in messages)
    if total <= max_chars:
        return messages
    head = messages[:2]  # system + initial user
    tail = list(messages[2:])
    while sum(len(json.dumps(m)) for m in head + tail) > max_chars and tail:
        # Drop the oldest tool message in the tail.
        for i, m in enumerate(tail):
            if m.get("role") == "tool":
                tail.pop(i)
                break
        else:
            break  # no more tool messages to drop
    return head + tail


async def run_brain_loop(
    *,
    topic: str,
    ollama_host: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    tools: Optional[list] = None,
    max_turns: int = 30,
    early_exit_no_progress_turns: int = 5,
    per_call_timeout_sec: float = 180.0,
) -> dict:
    """Drive a tool-use loop on Ollama. Returns a summary dict matching
    the existing BrainAgent.run() shape so BrainQueue can consume it
    without modification.

    Caller MUST have already set up brain_tools.set_context(BrainContext)
    so the handlers have a valid corpus + http client.
    """
    if tools is None:
        tools = brain_tools.ALL_TOOLS
    handlers = _handlers_by_name(tools)
    tools_payload = build_tools_payload(tools)
    allowed_tool_names = sorted(handlers.keys())
    client = OllamaClient(host=ollama_host)

    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    print(f"\n=== BrainAgent (ollama backend) ===")
    print(f"  topic:   {topic}")
    print(f"  model:   {model}")
    print(f"  tools:   {', '.join(allowed_tool_names)}")
    print(f"  max_turns: {max_turns}")
    print()

    t0 = time.time()
    turn = 0
    last_progress_turn = 0
    pages_at_last_progress = 0
    final_text = ""
    # Default to a failure state. Each exit path below sets these
    # explicitly; if the loop falls through to max_turns exhaustion
    # without setting them, that's a stall and is_error stays True.
    result_status = "incomplete"
    is_error_flag = True

    ctx = brain_tools._ctx  # the BrainContext set by the caller
    if ctx is None:
        raise RuntimeError(
            "BrainContext not initialized — call brain_tools.set_context() "
            "before run_brain_loop()."
        )

    while turn < max_turns:
        turn += 1
        try:
            resp = await asyncio.wait_for(
                client.chat(
                    model=model,
                    messages=_trim_messages(messages),
                    tools=tools_payload,
                    temperature=0.2,
                ),
                timeout=per_call_timeout_sec,
            )
        except asyncio.TimeoutError:
            log.warning("brain-loop: turn %d timed out after %ss", turn, per_call_timeout_sec)
            print(f"[turn {turn}] ⚠ chat call timed out, breaking loop")
            result_status = "chat_timeout"
            break
        except Exception as e:
            log.warning("brain-loop: turn %d chat failed: %s", turn, e)
            print(f"[turn {turn}] ✗ chat call failed: {e}")
            result_status = "chat_error"
            break

        msg = (resp.get("message") or {})
        content = msg.get("content") or ""
        tool_calls = msg.get("tool_calls") or []

        # Fallback: some local models (qwen2.5-coder, certain llama
        # tunes) emit tool calls as JSON in `content` instead of via the
        # structured `tool_calls` field. Recognize the standard shapes
        # and treat them as if they were native.
        if not tool_calls:
            inline = _parse_inline_tool_call(content, set(handlers.keys()))
            if inline:
                tool_calls = inline
                content = ""

        # Log assistant text (often empty when tool_use, sometimes a plan).
        if content.strip():
            print(f"[turn {turn}] 💬 {content.strip()[:400]}")

        # No tool calls AND no further plan → model is done.
        if not tool_calls:
            final_text = content.strip()
            if ctx.docs_added == 0:
                # Model claims completion but zero docs ingested. Either it
                # hallucinated success (llama3.1:8b's "You have ingested 8
                # new documents." mode) or it gave up after dedup-skips.
                # Either way: tell the caller this was not a successful run.
                result_status = "no_progress"
                is_error_flag = True
                print(f"[turn {turn}] ⚠ stalled — 0 docs ingested, marking is_error=True")
            else:
                result_status = "completed"
                is_error_flag = False
                print(f"[turn {turn}] ✓ no more tool calls — model done")
            break

        # Append assistant message verbatim so the next turn sees its tool_calls.
        messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})

        # Execute each tool call sequentially (parallel exec is unsafe with
        # the shared BrainContext rate limiter).
        for call in tool_calls:
            fn = call.get("function") or {}
            tool_name = fn.get("name") or ""
            args_raw = fn.get("arguments")
            # Ollama can return arguments as either a JSON string or a dict.
            if isinstance(args_raw, str):
                try:
                    args = json.loads(args_raw) if args_raw.strip() else {}
                except json.JSONDecodeError as e:
                    err = f"ERROR: invalid JSON args for {tool_name}: {e}. Got: {args_raw[:200]}"
                    print(f"[turn {turn}] ✗ {err}")
                    messages.append({"role": "tool", "content": err})
                    continue
            elif isinstance(args_raw, dict):
                args = args_raw
            else:
                args = {}

            handler = handlers.get(tool_name)
            if handler is None:
                err = (f"ERROR: unknown tool {tool_name!r}. "
                       f"Allowed: {', '.join(allowed_tool_names)}")
                print(f"[turn {turn}] ✗ {err}")
                messages.append({"role": "tool", "content": err})
                continue

            args_summary = ", ".join(f"{k}={str(v)[:60]!r}" for k, v in args.items())
            print(f"[turn {turn}] → {tool_name}({args_summary})")
            try:
                result = await asyncio.wait_for(handler(args), timeout=per_call_timeout_sec)
            except asyncio.TimeoutError:
                err = f"ERROR: tool {tool_name} timed out after {per_call_timeout_sec}s"
                print(f"[turn {turn}] ⚠ {err}")
                messages.append({"role": "tool", "content": err})
                continue
            except Exception as e:
                err = f"ERROR: tool {tool_name} raised {type(e).__name__}: {e}"
                log.exception("brain-loop: tool %s raised", tool_name)
                print(f"[turn {turn}] ✗ {err}")
                messages.append({"role": "tool", "content": err[:1000]})
                continue

            text = _result_text(result)
            print(f"[turn {turn}] ← {(text or '').splitlines()[0][:200] if text else '(no text)'}")
            messages.append({"role": "tool", "content": text[:8000]})

        # Early-exit if no fetch/ingest progress for N turns.
        if ctx.pages_fetched > pages_at_last_progress or ctx.docs_added > 0:
            pages_at_last_progress = ctx.pages_fetched
            last_progress_turn = turn
        elif turn - last_progress_turn >= early_exit_no_progress_turns:
            print(f"[turn {turn}] ✓ no progress in {early_exit_no_progress_turns} turns — exiting")
            # Some pages may have been fetched, but if nothing was actually
            # ingested the run is a stall, not a success.
            if ctx.docs_added == 0:
                result_status = "no_progress"
                is_error_flag = True
            else:
                result_status = "completed"
                is_error_flag = False
            break

    elapsed = time.time() - t0
    summary = {
        "topic": topic,
        "elapsed_sec": int(elapsed),
        "pages_fetched": ctx.pages_fetched,
        "docs_added": ctx.docs_added,
        "chunks_added": ctx.chunks_added,
        "docs_skipped_dedup": ctx.docs_skipped_dedup,
        "log_path": str(getattr(ctx, "log_path", "")),
        "result": {
            "duration_ms": int(elapsed * 1000),
            "num_turns": turn,
            "total_cost_usd": 0.0,            # Ollama is free
            "is_error": is_error_flag,
            "result_status": result_status,
            "result": final_text or None,
            "backend": "ollama",
            "model": model,
        },
    }
    print(f"\n=== BrainAgent (ollama) done ===")
    print(f"  result_status:{result_status}  is_error={is_error_flag}")
    print(f"  turns:        {turn}")
    print(f"  pages:        {ctx.pages_fetched}")
    print(f"  docs added:   {ctx.docs_added}")
    print(f"  chunks added: {ctx.chunks_added}")
    print(f"  docs deduped: {ctx.docs_skipped_dedup}")
    print(f"  elapsed:      {int(elapsed)}s")
    return summary
