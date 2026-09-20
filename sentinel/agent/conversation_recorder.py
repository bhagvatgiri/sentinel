"""Forward-capture multi-turn Claude conversations during Sentinel phases.

Tier 3a of the qwen training plan (2026-XX-XX). The past-workspace
trace extractor (`tools/training/extract-traces.py`) is lossy — it relies
on `agent_text` + `tool_called` events that drop Claude's exact message
formatting. This recorder hooks the SDK's `query()` message stream
directly, producing high-fidelity ChatML JSONL ready for SFT training.

Usage from inside a phase agent's `async for msg in query(...)` loop:

    from sentinel.agent.conversation_recorder import ConversationRecorder

    recorder = ConversationRecorder.maybe(
        phase="vuln:idor",
        engagement_id=scope.engagement_id,
        system_prompt=options.system_prompt,
        user_prompt=user_prompt,
    )
    async for msg in query(prompt=user_prompt, options=options):
        if recorder is not None:
            recorder.record(msg)
        # ... existing handling ...
    if recorder is not None:
        recorder.finalize()

The `maybe()` constructor returns None when SENTINEL_RECORD_CONVERSATIONS
env var isn't truthy — so this stays opt-in and zero-overhead by default.

Output: `runs/conversations-<engagement_id>-<phase>.jsonl`. Each LINE is one
completed phase's full conversation, ChatML schema:

    {
      "phase": "vuln:idor",
      "engagement_id": "2026-XX-XX-ExampleHotel-world",
      "ts_start": 1778600000.0,
      "ts_end":   1778601234.5,
      "messages": [
        {"role": "system", "content": "..."},
        {"role": "user",   "content": "..."},
        {"role": "assistant", "content": "...", "tool_calls": [...]},
        {"role": "tool", "tool_use_id": "...", "content": "..."},
        ...
      ],
      "_meta": {"source": "conversation_recorder.py", "lossy": false}
    }

Quality note: this is the **non-lossy** version. The system prompt is
captured verbatim. ToolUseBlock + ToolResultBlock are reconstructed
1:1 from the SDK stream.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


log = logging.getLogger(__name__)


_ENV_FLAG = "SENTINEL_RECORD_CONVERSATIONS"


def _is_enabled() -> bool:
    return os.getenv(_ENV_FLAG, "").lower() in ("1", "true", "yes", "on")


def _runs_dir() -> Path:
    """Where conversations land. Mirrors event_log convention."""
    p = Path(os.getenv("SENTINEL_RUNS_DIR", "runs")).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _normalize_content_block(block: Any) -> Optional[dict]:
    """Convert a claude_agent_sdk content block to a ChatML-friendly dict.

    The SDK class names we care about: TextBlock, ThinkingBlock, ToolUseBlock,
    ToolResultBlock. We don't import the classes (would create a hard SDK
    dependency at module import time) — we inspect attributes instead."""
    if block is None:
        return None
    cls = type(block).__name__

    if cls in ("TextBlock", "ThinkingBlock"):
        text = getattr(block, "text", None)
        if text is None:
            return None
        return {"type": "text", "text": text}

    if cls == "ToolUseBlock":
        return {
            "type": "tool_use",
            "id": getattr(block, "id", ""),
            "name": getattr(block, "name", ""),
            "input": getattr(block, "input", {}),
        }

    if cls == "ToolResultBlock":
        content = getattr(block, "content", "")
        # SDK sometimes hands us a list of blocks for content; flatten to text.
        if isinstance(content, list):
            parts = []
            for c in content:
                if isinstance(c, dict):
                    parts.append(c.get("text") or json.dumps(c))
                elif hasattr(c, "text"):
                    parts.append(c.text)
                else:
                    parts.append(str(c))
            content = "\n".join(parts)
        elif not isinstance(content, str):
            content = str(content)
        return {
            "type": "tool_result",
            "tool_use_id": getattr(block, "tool_use_id", ""),
            "content": content,
            "is_error": bool(getattr(block, "is_error", False)),
        }

    # Unknown block type — preserve a stub for debugging.
    return {"type": "unknown", "cls": cls, "repr": repr(block)[:200]}


def _assistant_to_chatml(blocks: list[dict]) -> dict:
    """Convert assistant content blocks to a single ChatML assistant message
    (content text + optional tool_calls list)."""
    text_parts: list[str] = []
    tool_calls: list[dict] = []
    for b in blocks:
        if b is None:
            continue
        if b.get("type") == "text":
            text_parts.append(b.get("text", ""))
        elif b.get("type") == "tool_use":
            tool_calls.append({
                "id": b.get("id", ""),
                "type": "function",
                "function": {
                    "name": b.get("name", ""),
                    "arguments": json.dumps(b.get("input", {}),
                                              ensure_ascii=False)
                                  if not isinstance(b.get("input"), str)
                                  else b.get("input", ""),
                },
            })
    out: dict = {
        "role": "assistant",
        "content": "\n".join(t for t in text_parts if t).strip(),
    }
    if tool_calls:
        out["tool_calls"] = tool_calls
    return out


def _user_blocks_to_chatml(blocks: list[dict]) -> list[dict]:
    """A SDK UserMessage carries tool_result blocks (the harness handing
    tool output back to Claude). Each tool_result block becomes one ChatML
    `tool` message. Plain text in a UserMessage is rare (we always start
    with a user_prompt at construction time) but handled."""
    msgs: list[dict] = []
    text_parts: list[str] = []
    for b in blocks:
        if b is None:
            continue
        if b.get("type") == "tool_result":
            msgs.append({
                "role": "tool",
                "tool_use_id": b.get("tool_use_id", ""),
                "content": b.get("content", ""),
                "is_error": b.get("is_error", False),
            })
        elif b.get("type") == "text":
            text_parts.append(b.get("text", ""))
    if text_parts:
        msgs.append({
            "role": "user",
            "content": "\n".join(text_parts).strip(),
        })
    return msgs


@dataclass
class ConversationRecorder:
    phase: str
    engagement_id: str
    system_prompt: str
    user_prompt: str
    output_path: Path
    messages: list[dict] = field(default_factory=list)
    ts_start: float = field(default_factory=time.time)
    _finalized: bool = False

    @classmethod
    def maybe(cls, *,
               phase: str,
               engagement_id: str,
               system_prompt: str,
               user_prompt: str,
               output_dir: Optional[Path] = None,
               ) -> Optional["ConversationRecorder"]:
        """Return a recorder if SENTINEL_RECORD_CONVERSATIONS is set, else None."""
        if not _is_enabled():
            return None
        out_dir = output_dir or _runs_dir()
        safe_phase = phase.replace(":", "_").replace("/", "_")
        out_path = out_dir / f"conversations-{engagement_id}-{safe_phase}.jsonl"
        rec = cls(
            phase=phase,
            engagement_id=engagement_id,
            system_prompt=system_prompt or "",
            user_prompt=user_prompt or "",
            output_path=out_path,
        )
        rec.messages.append({"role": "system", "content": rec.system_prompt})
        rec.messages.append({"role": "user", "content": rec.user_prompt})
        return rec

    def record(self, msg: Any) -> None:
        """Convert one SDK message into ChatML message(s) and append.

        Tolerates unknown message subclasses — never throws."""
        if self._finalized:
            return
        cls = type(msg).__name__
        try:
            if cls == "AssistantMessage":
                blocks = [
                    _normalize_content_block(b)
                    for b in getattr(msg, "content", []) or []
                ]
                blocks = [b for b in blocks if b is not None]
                self.messages.append(_assistant_to_chatml(blocks))
            elif cls == "UserMessage":
                blocks = [
                    _normalize_content_block(b)
                    for b in getattr(msg, "content", []) or []
                ]
                blocks = [b for b in blocks if b is not None]
                for m in _user_blocks_to_chatml(blocks):
                    self.messages.append(m)
            elif cls in ("ResultMessage", "SystemMessage",
                          "TaskNotificationMessage", "TaskProgressMessage",
                          "TaskStartedMessage", "MirrorErrorMessage"):
                # Envelope/diagnostic messages — not part of the conversation.
                return
            else:
                # Unknown — log once for visibility, don't break.
                log.debug("conversation_recorder: ignoring unknown msg class %r", cls)
        except Exception:
            log.exception("conversation_recorder.record failed (cls=%s)", cls)

    def finalize(self) -> None:
        """Write the conversation to disk. Idempotent."""
        if self._finalized:
            return
        self._finalized = True
        payload = {
            "phase": self.phase,
            "engagement_id": self.engagement_id,
            "ts_start": self.ts_start,
            "ts_end": time.time(),
            "messages": self.messages,
            "_meta": {
                "source": "conversation_recorder.py:2026-XX-XX",
                "lossy": False,
            },
        }
        try:
            with self.output_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except OSError as e:
            log.warning("conversation_recorder: failed to write %s: %s",
                          self.output_path, e)
