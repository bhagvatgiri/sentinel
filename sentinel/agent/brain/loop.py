"""BrainAgent — autonomous loop that grows Sentinel's corpus on a topic.

Wires the tools in `tools.py` into a `claude-agent-sdk` MCP server, calls
`query()` with the research prompt, streams events to stdout + an
ingestion JSONL log.

Usage from Python:
    cfg = BrainConfig(topic="SSRF bypass techniques 2025",
                      corpus_dir="~/sentinel-corpus")
    agent = BrainAgent(cfg)
    asyncio.run(agent.run())

Usage from CLI:
    sentinel brain-grow --topic "..." --corpus-dir ~/sentinel-corpus
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ThinkingBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    create_sdk_mcp_server,
    query,
)

from sentinel.agent.brain import tools as brain_tools
from sentinel.agent.brain.prompt import OLLAMA_SYSTEM_PROMPT, SYSTEM_PROMPT, select_ollama_prompt
from sentinel.corpus.embedder import OllamaEmbedder
from sentinel.corpus.store import CorpusStore


log = logging.getLogger(__name__)


@dataclass
class BrainConfig:
    topic: str
    corpus_dir: str
    ollama_host: str = "http://localhost:11434"
    embed_model: str = "nomic-embed-text"
    chunk_size: int = 1500
    chunk_overlap: int = 200
    depth: int = 2
    max_pages: int = 25
    max_turns: int = 80                          # SDK turn limit (claude backend)
    max_budget_usd: Optional[float] = 5.0        # SDK enforces this (claude backend)
    model: Optional[str] = None                  # None → SDK default (Sonnet) for claude backend
    rate_limit_per_host_sec: float = 1.0
    runs_dir: str = "./runs"
    # Backend selection — "ollama" runs locally for $0 with no claude binary
    # involved; "claude" uses claude-agent-sdk + Anthropic API. Default
    # ollama because that path doesn't crash on the operator's claude-mem hook
    # bloat (see memory: feedback_authorization_grants for context).
    backend: str = "ollama"
    ollama_brain_model: str = "llama3.1:8b"
    ollama_max_turns: int = 30                   # tighter than claude — local models plan less efficiently
    # Topic pre-check — refuse runs on topics the corpus already covers
    # densely so we don't burn ~10 min producing 0 docs. Distance is
    # cosine; lower = more similar. Set force_topic=True to override.
    topic_dense_threshold: float = 0.20
    force_topic: bool = False


class BrainAgent:
    def __init__(self, cfg: BrainConfig):
        self.cfg = cfg

    async def run(self) -> dict:
        """Run the agent. Returns a summary dict (stats + final result).
        Routes to either the Ollama tool-use loop or the claude-agent-sdk
        loop based on `cfg.backend`."""
        store = self._build_store()
        log_path = self._make_log_path()
        async with httpx.AsyncClient(
            headers={"User-Agent": "sentinel-brain/0.2 (+https://github.com/sentinel-sec)"},
            follow_redirects=True,
        ) as http:
            # Saturation threshold (task #73): stop the brain-grow loop
            # early when N consecutive ingest_skip_dedup events fire with
            # no successful ingest in between. Default 5 (env override).
            import os as _os
            sat_threshold = int(_os.environ.get(
                "SENTINEL_BRAIN_SATURATION_THRESHOLD", "5",
            ))
            ctx = brain_tools.BrainContext(
                store=store,
                http=http,
                chunk_size=self.cfg.chunk_size,
                chunk_overlap=self.cfg.chunk_overlap,
                rate_limit_per_host_sec=self.cfg.rate_limit_per_host_sec,
                log_path=log_path,
                saturation_threshold=sat_threshold,
            )
            brain_tools.set_context(ctx)

            # ---- Ollama backend (default) ----
            if self.cfg.backend == "ollama":
                # Topic pre-check: skip the run entirely if the corpus
                # already covers the topic densely (closest-chunk distance
                # below the threshold). Saves ~10 min of zero-doc churn.
                if not self.cfg.force_topic:
                    skip_summary = self._topic_pre_check(ctx, log_path)
                    if skip_summary is not None:
                        return skip_summary

                from sentinel.agent.brain.ollama_loop import run_brain_loop
                # Imperative user prompt — first action MUST be a tool call,
                # not narration. Local models otherwise echo the topic and stop.
                user_prompt = (
                    f"Topic: {self.cfg.topic}\n\n"
                    f"Call web_search NOW with a specific query about this topic. "
                    f"Do not write a plan. Do not greet me. Your next output is a "
                    f"web_search tool call."
                )
                summary = await run_brain_loop(
                    topic=self.cfg.topic,
                    ollama_host=self.cfg.ollama_host,
                    model=self.cfg.ollama_brain_model,
                    # Imperative prompt — local models stop after planning
                    # if you give them the Claude-shaped reflective version.
                    # select_ollama_prompt() returns mistral-nemo's tighter
                    # variant for that model (closes Task #61); other Ollama
                    # models get the standard imperative prompt.
                    system_prompt=select_ollama_prompt(self.cfg.ollama_brain_model).format(
                        topic=self.cfg.topic,
                        depth=self.cfg.depth,
                        max_pages=self.cfg.max_pages,
                    ),
                    user_prompt=user_prompt,
                    max_turns=self.cfg.ollama_max_turns,
                )
                # Stamp the log path the BrainContext was using.
                summary["log_path"] = str(log_path)
                return summary

            # ---- Claude backend (legacy fallback) ----
            mcp_server = create_sdk_mcp_server(
                name="brain",
                version="0.1.0",
                tools=brain_tools.ALL_TOOLS,
            )
            allowed = [f"mcp__brain__{t.name}" for t in brain_tools.ALL_TOOLS]
            options = ClaudeAgentOptions(
                mcp_servers={"brain": mcp_server},
                allowed_tools=allowed,
                system_prompt=SYSTEM_PROMPT.format(
                    topic=self.cfg.topic,
                    depth=self.cfg.depth,
                    max_pages=self.cfg.max_pages,
                ),
                max_turns=self.cfg.max_turns,
                max_budget_usd=self.cfg.max_budget_usd,
                model=self.cfg.model,
                permission_mode="acceptEdits",
            )

            print(f"\n=== BrainAgent starting ===")
            print(f"  topic:       {self.cfg.topic}")
            print(f"  corpus_dir:  {self.cfg.corpus_dir}")
            print(f"  max_pages:   {self.cfg.max_pages}")
            print(f"  max_turns:   {self.cfg.max_turns}")
            print(f"  max_budget:  ${self.cfg.max_budget_usd}")
            print(f"  log:         {log_path}")
            print(f"\n=== Streaming agent events ===\n")

            t0 = time.time()
            final_result: Optional[dict] = None
            user_prompt = (
                f"Grow the Sentinel corpus on this topic: {self.cfg.topic}\n\n"
                f"Begin by planning your search queries, then execute the loop "
                f"described in the system prompt. Stay within the budget."
            )

            async for msg in query(prompt=user_prompt, options=options):
                self._render_event(msg)
                if isinstance(msg, ResultMessage):
                    final_result = {
                        "duration_ms": getattr(msg, "duration_ms", None),
                        "duration_api_ms": getattr(msg, "duration_api_ms", None),
                        "num_turns": getattr(msg, "num_turns", None),
                        "total_cost_usd": getattr(msg, "total_cost_usd", None),
                        "is_error": getattr(msg, "is_error", False),
                        "result": getattr(msg, "result", None),
                    }

            elapsed = time.time() - t0
            summary = {
                "topic": self.cfg.topic,
                "elapsed_sec": int(elapsed),
                "pages_fetched": ctx.pages_fetched,
                "docs_added": ctx.docs_added,
                "chunks_added": ctx.chunks_added,
                "docs_skipped_dedup": ctx.docs_skipped_dedup,
                "log_path": str(log_path),
                "result": final_result,
            }
            print(f"\n=== BrainAgent done ===")
            for k, v in summary.items():
                if k == "result":
                    continue
                print(f"  {k}: {v}")
            if final_result:
                print(
                    f"  llm: {final_result.get('num_turns')} turns, "
                    f"${final_result.get('total_cost_usd', 0):.4f}, "
                    f"{final_result.get('duration_ms', 0)} ms"
                )
            return summary

    # ---- helpers --------------------------------------------------------

    def _build_store(self) -> CorpusStore:
        embedder = OllamaEmbedder(host=self.cfg.ollama_host, model=self.cfg.embed_model)
        if not embedder.is_available():
            raise RuntimeError(
                f"Embed model {self.cfg.embed_model} not available at {self.cfg.ollama_host}. "
                f"Run: ollama pull {self.cfg.embed_model}"
            )
        return CorpusStore(self.cfg.corpus_dir, embedder)

    def _make_log_path(self) -> Path:
        runs = Path(self.cfg.runs_dir).expanduser()
        runs.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        return runs / f"brain-grow-{ts}.jsonl"

    def _topic_pre_check(self, ctx, log_path: Path) -> Optional[dict]:
        """Refuse to run if the corpus already covers the topic densely.
        Returns a summary dict if the run should be skipped, None to
        proceed. Set cfg.force_topic=True to bypass."""
        try:
            hits = ctx.store.query(self.cfg.topic, top_k=1)
        except Exception as e:
            log.warning("topic_pre_check: corpus query failed: %s — proceeding", e)
            return None
        if not hits:
            return None
        closest = hits[0].get("distance", 1.0)
        if closest >= self.cfg.topic_dense_threshold:
            return None

        matched_title = (hits[0].get("title") or "")[:80]
        matched_source = (hits[0].get("source") or "?")
        msg = (
            f"Topic '{self.cfg.topic}' is already densely covered "
            f"(closest match distance={closest:.3f} < threshold={self.cfg.topic_dense_threshold:.2f}, "
            f"matched: {matched_title} [{matched_source}]). "
            f"Use --force-topic to override."
        )
        print(f"\n=== BrainAgent: topic_pre_check skip ===")
        print(f"  {msg}\n")
        # Mirror the structured event to the JSONL trace so the
        # dashboard / queue caller can see why this run was a no-op.
        brain_tools._log_event(
            "topic_pre_check_skip",
            topic=self.cfg.topic,
            distance=closest,
            threshold=self.cfg.topic_dense_threshold,
            matched_source=matched_source,
            matched_title=matched_title,
        )
        return {
            "topic": self.cfg.topic,
            "elapsed_sec": 0,
            "pages_fetched": 0,
            "docs_added": 0,
            "chunks_added": 0,
            "docs_skipped_dedup": 0,
            "log_path": str(log_path),
            "result": {
                "duration_ms": 0,
                "num_turns": 0,
                "total_cost_usd": 0.0,
                "is_error": False,
                "result_status": "topic_already_dense",
                "result": msg,
                "backend": self.cfg.backend,
                "model": self.cfg.ollama_brain_model,
            },
        }

    def _render_event(self, msg) -> None:
        """Stream a one-line summary of each SDK message to stdout."""
        if isinstance(msg, AssistantMessage):
            for block in msg.content:
                if isinstance(block, TextBlock):
                    text = (block.text or "").strip()
                    if text:
                        print(f"[assistant] {text[:500]}")
                elif isinstance(block, ToolUseBlock):
                    args_summary = self._summarize_args(block.input or {})
                    print(f"[tool→]    {block.name}({args_summary})")
                elif isinstance(block, ThinkingBlock):
                    pass  # too verbose
        elif isinstance(msg, UserMessage):
            for block in msg.content:
                if isinstance(block, ToolResultBlock):
                    text = self._summarize_tool_result(block)
                    print(f"[←tool]    {text[:300]}")
        elif isinstance(msg, SystemMessage):
            sub = getattr(msg, "subtype", "")
            if sub:
                print(f"[system:{sub}]")
        elif isinstance(msg, ResultMessage):
            pass  # final summary printed by run()

    @staticmethod
    def _summarize_args(args: dict) -> str:
        if not args:
            return ""
        parts = []
        for k, v in args.items():
            if isinstance(v, str) and len(v) > 120:
                v = v[:117] + "..."
            parts.append(f"{k}={v!r}")
        return ", ".join(parts)

    @staticmethod
    def _summarize_tool_result(block: ToolResultBlock) -> str:
        c = block.content
        if isinstance(c, str):
            return c.split("\n")[0][:300]
        if isinstance(c, list):
            for item in c:
                if isinstance(item, dict) and item.get("type") == "text":
                    return (item.get("text") or "").split("\n")[0][:300]
        return "(no text)"
