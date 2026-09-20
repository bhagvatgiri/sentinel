"""BrainQueue — async worker that grows the corpus on background topics.

Lets the pentest agent (or an automatic hook) request "research this topic"
without blocking the pentest loop. The worker drains topics one at a time
(parallel brain-grows would multiply LLM cost unpredictably), runs a
LIGHT version of `BrainAgent` per topic (small page cap, small budget),
and ingests into the SAME Chroma corpus the pentest agent's
`corpus_search` reads from. So the pentest's later phases benefit from
context the brain just learned.

Dedup happens at three levels:
1. **In-session topic dedup** — we don't re-process a topic enqueued twice
   in the same pipeline run. Normalized lowercase string match.
2. **Pre-ingest corpus dedup** — `BrainAgent`'s existing
   `check_corpus`/`ingest_text` flow refuses to re-ingest content
   already in the corpus.
3. **Per-page URL dedup** — `Document.make_id` is a stable hash of the
   URL, so re-ingesting the same URL upserts in place rather than
   duplicating chunks.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional


log = logging.getLogger(__name__)


@dataclass
class _ResearchTask:
    topic: str
    requested_by: str       # "pentest:auth", "auto-hook", etc.
    enqueued_at: float = field(default_factory=time.time)


@dataclass
class BrainQueueStats:
    enqueued: int = 0
    processed: int = 0
    skipped_dup: int = 0
    failed: int = 0
    in_flight_topic: Optional[str] = None
    total_cost_usd: float = 0.0
    chunks_added: int = 0


class BrainQueue:
    """Async queue with a single-worker drain. Owned by `PentestPipeline`.

    Designed for honest backpressure: the queue is unbounded, but the
    `max_topics` ceiling stops the worker from running forever — it
    processes at most that many topics per pipeline run, then idles.
    """

    def __init__(
        self,
        *,
        corpus_dir: str,
        ollama_host: str = "http://localhost:11434",
        embed_model: str = "nomic-embed-text",
        max_topics: int = 8,
        max_pages_per_topic: int = 5,
        budget_per_topic_usd: float = 0.50,
        model: Optional[str] = None,
        rate_limit_per_host_sec: float = 1.0,
        event_log: Optional[object] = None,           # sentinel.agent.event_log.EventLog
        backend: str = "ollama",                       # "ollama" | "claude"
        ollama_brain_model: str = "llama3.1:8b",
    ):
        self.corpus_dir = corpus_dir
        self.ollama_host = ollama_host
        self.embed_model = embed_model
        self.max_topics = max_topics
        self.max_pages_per_topic = max_pages_per_topic
        self.budget_per_topic_usd = budget_per_topic_usd
        self.model = model
        self.rate_limit_per_host_sec = rate_limit_per_host_sec
        self.event_log = event_log
        self.backend = backend
        self.ollama_brain_model = ollama_brain_model

        self._queue: asyncio.Queue[_ResearchTask] = asyncio.Queue()
        self._seen: set[str] = set()                  # normalized topics already enqueued
        self._worker_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self.stats = BrainQueueStats()

    # ---- public API -----------------------------------------------------

    def enqueue(self, topic: str, requested_by: str = "unknown") -> str:
        """Enqueue a topic. Returns a status string. Safe to call from any
        thread/loop because asyncio.Queue.put_nowait is thread-safe in
        practice for our usage (single-loop)."""
        norm = self._normalize(topic)
        if not norm:
            return "ignored: empty topic"
        # Reject low-signal topics (header-only sniffs, etc.) — they cost
        # real money and reliably return junk because the topic itself is
        # too vague for a useful web search.
        if self._is_low_signal(topic, requested_by):
            self.stats.skipped_dup += 1  # bucket with skipped for stats simplicity
            self._emit("brain_skipped", topic=topic, requested_by=requested_by,
                       reason="topic too vague (header-only sniff with no body marker)")
            log.info("brain-queue: skipping low-signal topic %r (by %s)", topic, requested_by)
            return f"skipped (low-signal topic): {topic!r}"
        if norm in self._seen:
            self.stats.skipped_dup += 1
            self._emit("brain_skipped", topic=topic, requested_by=requested_by,
                       reason="already in this session")
            return f"skipped (already in this session): {topic!r}"
        if self.stats.enqueued >= self.max_topics:
            self._emit("brain_skipped", topic=topic, requested_by=requested_by,
                       reason=f"max_topics={self.max_topics} reached")
            return f"skipped (max_topics={self.max_topics} reached for this session)"
        self._seen.add(norm)
        self._queue.put_nowait(_ResearchTask(topic=topic, requested_by=requested_by))
        self.stats.enqueued += 1
        self._emit("brain_enqueued", topic=topic, requested_by=requested_by,
                   queue_size=self._queue.qsize())
        log.info("brain-queue: enqueued %r (by %s, queue size=%d)",
                 topic, requested_by, self._queue.qsize())
        return f"enqueued: {topic!r}"

    def _emit(self, kind: str, **payload) -> None:
        if self.event_log is None:
            return
        try:
            self.event_log.emit(kind, **payload)
        except Exception as e:
            log.warning("brain-queue: event emit failed: %s", e)

    async def start(self) -> None:
        """Start the background worker."""
        if self._worker_task is not None:
            return
        self._stop_event.clear()
        self._worker_task = asyncio.create_task(self._run(), name="brain-queue-worker")
        log.info("brain-queue: worker started (max_topics=%d, budget=$%.2f/topic)",
                 self.max_topics, self.budget_per_topic_usd)

    async def stop(self, drain_timeout_sec: float = 30.0) -> None:
        """Stop the worker. Waits up to drain_timeout_sec for the in-flight
        topic to finish; cancels anything still pending."""
        if self._worker_task is None:
            return
        self._stop_event.set()
        try:
            await asyncio.wait_for(self._worker_task, timeout=drain_timeout_sec)
        except asyncio.TimeoutError:
            log.warning("brain-queue: worker didn't stop in %ds, cancelling", drain_timeout_sec)
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        self._worker_task = None
        log.info("brain-queue: worker stopped (processed=%d, skipped=%d, failed=%d)",
                 self.stats.processed, self.stats.skipped_dup, self.stats.failed)

    # ---- worker loop ----------------------------------------------------

    async def _run(self) -> None:
        # Lazy import — keep the module importable for tests without the SDK.
        from sentinel.agent.brain.loop import BrainAgent, BrainConfig

        while not self._stop_event.is_set():
            try:
                task = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            if self.stats.processed >= self.max_topics:
                log.info("brain-queue: max_topics reached, draining (%d remaining)",
                         self._queue.qsize())
                # Drain remaining without processing.
                continue

            self.stats.in_flight_topic = task.topic
            self._emit("brain_started", topic=task.topic,
                       requested_by=task.requested_by)
            log.info("brain-queue: processing %r (requested by %s)",
                     task.topic, task.requested_by)
            try:
                cfg = BrainConfig(
                    topic=task.topic,
                    corpus_dir=self.corpus_dir,
                    ollama_host=self.ollama_host,
                    embed_model=self.embed_model,
                    max_pages=self.max_pages_per_topic,
                    depth=1,
                    max_turns=20,
                    max_budget_usd=self.budget_per_topic_usd,
                    model=self.model,
                    rate_limit_per_host_sec=self.rate_limit_per_host_sec,
                    backend=self.backend,
                    ollama_brain_model=self.ollama_brain_model,
                )
                summary = await BrainAgent(cfg).run()
                self.stats.processed += 1
                self.stats.chunks_added += summary.get("chunks_added", 0) or 0
                result = summary.get("result") or {}
                cost = float(result.get("total_cost_usd") or 0)
                self.stats.total_cost_usd += cost
                # The Ollama loop's hallucination guard sets is_error=True
                # when a run stalls (zero docs ingested, hit max_turns, or
                # chat call timed out). Surface that to the dashboard as
                # brain_stalled rather than dressing it up as brain_completed.
                # Topic pre-check refusals come back is_error=False but with
                # result_status="topic_already_dense" — those are intentional
                # skips, not failures, so emit brain_skipped.
                rstatus = result.get("result_status", "")
                if rstatus == "topic_already_dense":
                    self._emit("brain_skipped", topic=task.topic,
                               reason="topic_already_dense",
                               result_status=rstatus)
                elif result.get("is_error"):
                    self._emit("brain_stalled", topic=task.topic,
                               result_status=rstatus or "incomplete",
                               chunks_added=summary.get("chunks_added", 0) or 0,
                               docs_added=summary.get("docs_added", 0) or 0,
                               docs_skipped_dedup=summary.get("docs_skipped_dedup", 0) or 0,
                               cost_usd=cost,
                               pages_fetched=summary.get("pages_fetched", 0) or 0)
                else:
                    self._emit("brain_completed", topic=task.topic,
                               chunks_added=summary.get("chunks_added", 0) or 0,
                               docs_added=summary.get("docs_added", 0) or 0,
                               docs_skipped_dedup=summary.get("docs_skipped_dedup", 0) or 0,
                               cost_usd=cost,
                               pages_fetched=summary.get("pages_fetched", 0) or 0)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.stats.failed += 1
                # Decorate the error with a likely-cause hint when the SDK
                # swallowed stderr (the canonical Claude SDK message
                # "Check stderr output for details" almost always means
                # either: (a) the model emitted parallel tool_use blocks
                # that hit a dispatch bug, OR (b) the user's claude-mem
                # plugin's SessionStart hook bloated the prompt past a
                # safe threshold, OR (c) Anthropic's cyber-use safeguard
                # rejected the topic phrasing). We attach a hint so the
                # operator doesn't have to re-discover this each time.
                err_text = str(e)[:300]
                if "Check stderr output for details" in err_text:
                    hint = (
                        "SDK swallowed stderr. Likely cause: claude-mem hook "
                        "injected ~60KB of context into the brain session. "
                        "Topic may also have tripped Anthropic's cyber-use "
                        "safeguard. Retry with a more specific topic phrasing."
                    )
                else:
                    hint = ""
                self._emit("brain_failed", topic=task.topic, error=err_text, hint=hint)
                log.exception("brain-queue: failed processing %r: %s", task.topic, e)
            finally:
                self.stats.in_flight_topic = None

    # ---- helpers --------------------------------------------------------

    @staticmethod
    def _normalize(topic: str) -> str:
        s = re.sub(r"\s+", " ", (topic or "").strip().lower())
        return s

    # Topics matching any of these patterns are auto-rejected at enqueue —
    # they consistently produce no useful search results, burn 40k cache
    # tokens setting up the agent, and hit Anthropic rate limits / cyber
    # safeguards more often than they succeed. The pre-warm hook in
    # pipeline.py is the main culprit.
    _LOW_SIGNAL_TOPIC_PATTERNS = (
        re.compile(r"stack signals\s+(server=|x-powered-by=)", re.I),
        re.compile(r"^web application security\s*:\s*$", re.I),
        re.compile(r"^[a-z\s]{1,8}$", re.I),  # one-or-two-word topics rarely have anything to research
    )
    _LOW_SIGNAL_REQUESTED_BY = (
        "header-only signals (no body marker)",
    )

    @classmethod
    def _is_low_signal(cls, topic: str, requested_by: str) -> bool:
        """Reject topics that are guaranteed to waste budget."""
        if not topic or len(topic.strip()) < 12:
            return True
        for pat in cls._LOW_SIGNAL_TOPIC_PATTERNS:
            if pat.search(topic):
                return True
        for marker in cls._LOW_SIGNAL_REQUESTED_BY:
            if marker in (requested_by or ""):
                return True
        return False
