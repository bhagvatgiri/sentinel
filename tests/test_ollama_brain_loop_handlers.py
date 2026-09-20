"""Handler dispatch + error paths for the Ollama brain loop — Phase 101.

Mocks `OllamaClient.chat` so we can drive the loop deterministically.
Asserts: tool calls dispatched correctly, hallucinated tool names produce
error responses (not crashes), bad JSON tolerated, loop terminates when
model stops calling tools.
"""

from __future__ import annotations

import asyncio
import types
from unittest.mock import patch

import pytest

from sentinel.agent.brain import tools as brain_tools
from sentinel.agent.brain.ollama_loop import run_brain_loop


# ---- minimal in-memory BrainContext ---------------------------------------


class _FakeStore:
    def upsert_chunks(self, chunks):
        return len(list(chunks))


class _FakeHttp:
    """Stand-in for httpx.AsyncClient — the test mocks chat so we never
    actually hit the network from the handlers; this is just to satisfy
    BrainContext's required field."""


def _make_ctx(tmp_path):
    ctx = brain_tools.BrainContext(
        store=_FakeStore(),
        http=_FakeHttp(),
        chunk_size=1500,
        chunk_overlap=200,
        rate_limit_per_host_sec=0.0,
        log_path=tmp_path / "brain.jsonl",
    )
    brain_tools.set_context(ctx)
    return ctx


# ---- builder for fake Ollama responses ------------------------------------


def _chat_response(content="", tool_calls=None) -> dict:
    return {"message": {"content": content, "tool_calls": tool_calls or []}}


def _tool_call(name: str, args: dict, call_id: str = "call_1") -> dict:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": args},
    }


# ---- tests -----------------------------------------------------------------


def test_terminates_when_model_returns_no_tool_calls(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path)

    async def fake_chat(self, model, messages, **kw):
        return _chat_response(content="I'm done.")

    from sentinel.agent.ollama_provider import OllamaClient
    monkeypatch.setattr(OllamaClient, "chat", fake_chat)

    summary = asyncio.run(run_brain_loop(
        topic="x",
        ollama_host="http://localhost:11434",
        model="qwen2.5-coder:7b",
        system_prompt="sys",
        user_prompt="user",
        max_turns=3,
    ))
    assert summary["topic"] == "x"
    assert summary["result"]["num_turns"] == 1
    assert summary["result"]["backend"] == "ollama"
    assert summary["result"]["total_cost_usd"] == 0.0


def test_unknown_tool_name_produces_error_response_not_crash(tmp_path, monkeypatch):
    _make_ctx(tmp_path)

    state = {"turn": 0}

    async def fake_chat(self, model, messages, **kw):
        state["turn"] += 1
        if state["turn"] == 1:
            return _chat_response(tool_calls=[_tool_call("nope_not_a_tool", {"x": 1})])
        # Inspect the previous tool message to confirm it has an ERROR.
        prev_tool_msg = next(
            (m for m in reversed(messages) if m["role"] == "tool"), None
        )
        assert prev_tool_msg is not None
        assert "ERROR" in prev_tool_msg["content"]
        assert "nope_not_a_tool" in prev_tool_msg["content"]
        return _chat_response(content="ok, recovered")

    from sentinel.agent.ollama_provider import OllamaClient
    monkeypatch.setattr(OllamaClient, "chat", fake_chat)

    summary = asyncio.run(run_brain_loop(
        topic="x",
        ollama_host="http://localhost:11434",
        model="qwen2.5-coder:7b",
        system_prompt="sys", user_prompt="user",
        max_turns=5,
    ))
    assert summary["result"]["num_turns"] == 2  # crashed once, recovered, done


def test_bad_json_args_handled_gracefully(tmp_path, monkeypatch):
    _make_ctx(tmp_path)
    state = {"turn": 0}

    async def fake_chat(self, model, messages, **kw):
        state["turn"] += 1
        if state["turn"] == 1:
            # Ollama can return arguments as a string; simulate malformed.
            return _chat_response(tool_calls=[{
                "id": "c1", "type": "function",
                "function": {"name": "web_search", "arguments": "{not valid json"},
            }])
        return _chat_response(content="done")

    from sentinel.agent.ollama_provider import OllamaClient
    monkeypatch.setattr(OllamaClient, "chat", fake_chat)

    summary = asyncio.run(run_brain_loop(
        topic="x",
        ollama_host="http://localhost:11434",
        model="qwen2.5-coder:7b",
        system_prompt="sys", user_prompt="user",
        max_turns=3,
    ))
    assert summary["result"]["num_turns"] >= 2


def test_max_turns_caps_runaway_loop(tmp_path, monkeypatch):
    _make_ctx(tmp_path)

    async def fake_chat(self, model, messages, **kw):
        # Always emit a tool_call so the loop never exits naturally.
        return _chat_response(tool_calls=[_tool_call("not_real", {})])

    from sentinel.agent.ollama_provider import OllamaClient
    monkeypatch.setattr(OllamaClient, "chat", fake_chat)

    # early_exit_no_progress_turns=2 means after 2 turns of no progress
    # the loop bails — that beats max_turns and is what we want for a
    # runaway loop test.
    summary = asyncio.run(run_brain_loop(
        topic="x", ollama_host="http://localhost:11434",
        model="qwen2.5-coder:7b",
        system_prompt="sys", user_prompt="user",
        max_turns=10,
        early_exit_no_progress_turns=2,
    ))
    # Should exit early due to no-progress, NOT hit max_turns=10.
    assert summary["result"]["num_turns"] <= 4


def test_handler_exception_returns_text_not_crash(tmp_path, monkeypatch):
    _make_ctx(tmp_path)
    state = {"turn": 0}

    async def fake_chat(self, model, messages, **kw):
        state["turn"] += 1
        if state["turn"] == 1:
            return _chat_response(tool_calls=[_tool_call("web_search", {"query": "x", "max_results": 3})])
        return _chat_response(content="done")

    # Make the web_search handler raise on call.
    async def boom(args):
        raise RuntimeError("synthetic failure")
    monkeypatch.setattr(brain_tools, "web_search",
                         types.SimpleNamespace(handler=boom, name="web_search"))

    # Re-register ALL_TOOLS so the loop sees the patched fn.
    original_all = brain_tools.ALL_TOOLS
    patched_tools = []
    for t in original_all:
        if t.name == "web_search":
            patched_tools.append(types.SimpleNamespace(
                handler=boom, name="web_search",
                description=t.description, input_schema=t.input_schema,
            ))
        else:
            patched_tools.append(t)

    from sentinel.agent.ollama_provider import OllamaClient
    monkeypatch.setattr(OllamaClient, "chat", fake_chat)

    summary = asyncio.run(run_brain_loop(
        topic="x", ollama_host="http://localhost:11434",
        model="qwen2.5-coder:7b",
        system_prompt="sys", user_prompt="user",
        tools=patched_tools,
        max_turns=4,
    ))
    # Loop must keep going past the failing tool call, not crash.
    assert summary["result"]["num_turns"] >= 2


# ---- hallucination guard --------------------------------------------------


def test_no_progress_exit_marks_is_error_true(tmp_path, monkeypatch):
    """Model emits no tool calls AND ctx.docs_added==0 → is_error=True,
    result_status='no_progress'. Guards against llama3.1:8b's 'You have
    ingested 8 new documents.' hallucination."""
    _make_ctx(tmp_path)

    async def fake_chat(self, model, messages, **kw):
        return _chat_response(content="Research complete. 8 documents ingested.")

    from sentinel.agent.ollama_provider import OllamaClient
    monkeypatch.setattr(OllamaClient, "chat", fake_chat)

    summary = asyncio.run(run_brain_loop(
        topic="x", ollama_host="http://localhost:11434",
        model="llama3.1:8b",
        system_prompt="sys", user_prompt="user",
        max_turns=3,
    ))
    assert summary["result"]["is_error"] is True
    assert summary["result"]["result_status"] == "no_progress"


def test_completed_exit_keeps_is_error_false(tmp_path, monkeypatch):
    """Model emits no tool calls AND ctx.docs_added > 0 → is_error=False,
    result_status='completed'."""
    ctx = _make_ctx(tmp_path)
    ctx.docs_added = 1  # pretend an ingest succeeded earlier in the run

    async def fake_chat(self, model, messages, **kw):
        return _chat_response(content="done")

    from sentinel.agent.ollama_provider import OllamaClient
    monkeypatch.setattr(OllamaClient, "chat", fake_chat)

    summary = asyncio.run(run_brain_loop(
        topic="x", ollama_host="http://localhost:11434",
        model="llama3.1:8b",
        system_prompt="sys", user_prompt="user",
        max_turns=3,
    ))
    assert summary["result"]["is_error"] is False
    assert summary["result"]["result_status"] == "completed"


def test_max_turns_exhaust_marks_is_error_true(tmp_path, monkeypatch):
    """Loop hits max_turns without the model ever stopping → defaults
    apply: result_status='incomplete', is_error=True."""
    _make_ctx(tmp_path)

    async def fake_chat(self, model, messages, **kw):
        # Never stops — always emits a tool call to a non-existent tool
        # so the loop continues but no progress is made.
        return _chat_response(tool_calls=[_tool_call("nope", {})])

    from sentinel.agent.ollama_provider import OllamaClient
    monkeypatch.setattr(OllamaClient, "chat", fake_chat)

    summary = asyncio.run(run_brain_loop(
        topic="x", ollama_host="http://localhost:11434",
        model="llama3.1:8b",
        system_prompt="sys", user_prompt="user",
        max_turns=3,
        # disable early-exit so we actually hit max_turns
        early_exit_no_progress_turns=999,
    ))
    assert summary["result"]["is_error"] is True
    assert summary["result"]["result_status"] == "incomplete"


# ---- per-source dedup + URL-novelty (call ingest_text handler directly) ---


class _DedupFakeStore:
    """Minimal fake exposing query() + has_url() + upsert_chunks() so
    ingest_text's dedup gate is exercised end-to-end."""

    def __init__(self, query_return, url_present=False):
        self._query_return = query_return
        self._url_present = url_present
        self.upserts = 0

    def query(self, text, top_k=1, where=None):
        return list(self._query_return)

    def has_url(self, url: str) -> bool:
        return self._url_present

    def upsert_chunks(self, chunks, batch_size=32):
        n = len(list(chunks))
        self.upserts += n
        return n


def _ingest_args(url="https://example.com/new-page", title="New page",
                 text=None, tags=("graphql", "authz")):
    return {
        "url": url,
        "title": title,
        # Default text is long enough to pass the >200-char minimum.
        "text": text or ("graphql authorization bypass research " * 20),
        "tags": list(tags),
    }


def _make_dedup_ctx(tmp_path, store):
    ctx = brain_tools.BrainContext(
        store=store,
        http=_FakeHttp(),
        chunk_size=1500,
        chunk_overlap=200,
        rate_limit_per_host_sec=0.0,
        log_path=tmp_path / "brain.jsonl",
    )
    brain_tools.set_context(ctx)
    return ctx


def test_dedup_books_uses_loosened_threshold(tmp_path):
    """A 0.15-distance match against a books chunk would skip under the
    old global 0.20 gate. With the per-source override it should ingest
    (0.15 > book_dedup_threshold=0.10)."""
    store = _DedupFakeStore(
        query_return=[{
            "distance": 0.15,
            "source": "books",
            "title": "Real-World Bug Hunting",
            "url": "books/rwbh.pdf",
        }],
        url_present=True,  # known URL — proves URL-novelty is NOT what saved this
    )
    ctx = _make_dedup_ctx(tmp_path, store)

    result = asyncio.run(brain_tools.ingest_text.handler(_ingest_args()))
    text_out = "".join(b.get("text", "") for b in result["content"])
    assert "Skipped" not in text_out, f"Expected ingest, got: {text_out[:200]}"
    assert ctx.docs_added == 1
    assert ctx.docs_skipped_dedup == 0


def test_url_novelty_override_allows_ingest_with_tag(tmp_path):
    """A 0.15-distance match against an OWASP chunk would normally skip
    (0.15 < 0.20), but when the URL is novel and the matched source is
    not brain-grow, the override kicks in and a 'complementary-framing'
    tag gets attached."""
    store = _DedupFakeStore(
        query_return=[{
            "distance": 0.15,
            "source": "owasp",
            "title": "OWASP API Security Top 10",
            "url": "https://owasp.org/Top10/",
        }],
        url_present=False,
    )
    ctx = _make_dedup_ctx(tmp_path, store)

    args = _ingest_args(url="https://example.com/never-seen", tags=["graphql"])
    result = asyncio.run(brain_tools.ingest_text.handler(args))
    text_out = "".join(b.get("text", "") for b in result["content"])
    assert "Skipped" not in text_out, f"Expected ingest, got: {text_out[:200]}"
    assert ctx.docs_added == 1
    # Tag was injected by the override path.
    assert "complementary-framing" in text_out


# ---- topic pre-check ------------------------------------------------------


class _PreCheckFakeStore:
    """Fake store for BrainAgent._topic_pre_check tests. Returns a fixed
    distance for every query so we can simulate DENSE / RELATED topics."""

    def __init__(self, distance):
        self._distance = distance

    def query(self, text, top_k=1, where=None):
        return [{
            "id": "x",
            "text": "stub",
            "title": "OWASP API Security Top 10",
            "source": "owasp",
            "url": "https://owasp.org/Top10/",
            "distance": self._distance,
            "metadata": {},
        }]

    def has_url(self, url):
        return False

    def upsert_chunks(self, chunks, batch_size=32):
        return len(list(chunks))


def test_topic_pre_check_skips_dense_topic(tmp_path, monkeypatch):
    """Topic with closest-distance < threshold returns a topic_already_dense
    summary without invoking the Ollama loop."""
    from sentinel.agent.brain.loop import BrainAgent, BrainConfig

    cfg = BrainConfig(topic="SQL injection", corpus_dir=str(tmp_path),
                      runs_dir=str(tmp_path / "runs"))
    agent = BrainAgent(cfg)

    # Bypass the real CorpusStore + httpx context — patch _build_store and
    # let the run() code call our fake.
    monkeypatch.setattr(BrainAgent, "_build_store",
                        lambda self: _PreCheckFakeStore(distance=0.10))

    summary = asyncio.run(agent.run())
    assert summary["result"]["result_status"] == "topic_already_dense"
    assert summary["result"]["is_error"] is False
    assert summary["docs_added"] == 0
    assert summary["pages_fetched"] == 0


def test_topic_pre_check_proceeds_when_force_topic(tmp_path, monkeypatch):
    """force_topic=True bypasses the density check and runs the loop."""
    from sentinel.agent.brain.loop import BrainAgent, BrainConfig

    cfg = BrainConfig(topic="SQL injection", corpus_dir=str(tmp_path),
                      runs_dir=str(tmp_path / "runs"), force_topic=True,
                      ollama_max_turns=1)
    agent = BrainAgent(cfg)

    monkeypatch.setattr(BrainAgent, "_build_store",
                        lambda self: _PreCheckFakeStore(distance=0.10))

    # Mock OllamaClient.chat to return immediately with no tool calls
    # so the loop exits cleanly at turn 1.
    from sentinel.agent.ollama_provider import OllamaClient

    async def fake_chat(self, model, messages, **kw):
        return {"message": {"content": "done", "tool_calls": []}}
    monkeypatch.setattr(OllamaClient, "chat", fake_chat)

    summary = asyncio.run(agent.run())
    # Loop ran (with 0 docs → no_progress) instead of being skipped.
    assert summary["result"]["result_status"] != "topic_already_dense"


def test_topic_pre_check_proceeds_when_topic_thin(tmp_path, monkeypatch):
    """Topic above the threshold proceeds through to the loop."""
    from sentinel.agent.brain.loop import BrainAgent, BrainConfig

    cfg = BrainConfig(topic="Some thin topic", corpus_dir=str(tmp_path),
                      runs_dir=str(tmp_path / "runs"), ollama_max_turns=1)
    agent = BrainAgent(cfg)

    # distance 0.40 is well above the 0.20 threshold → don't skip.
    monkeypatch.setattr(BrainAgent, "_build_store",
                        lambda self: _PreCheckFakeStore(distance=0.40))

    from sentinel.agent.ollama_provider import OllamaClient

    async def fake_chat(self, model, messages, **kw):
        return {"message": {"content": "done", "tool_calls": []}}
    monkeypatch.setattr(OllamaClient, "chat", fake_chat)

    summary = asyncio.run(agent.run())
    assert summary["result"]["result_status"] != "topic_already_dense"


def test_brain_grow_match_does_not_trigger_url_novelty_override(tmp_path):
    """A 0.15-distance match against a prior brain-grow chunk should
    still skip even if the URL is novel — that prevents brain-grow from
    re-ingesting near-duplicate framings of pages it already grew."""
    store = _DedupFakeStore(
        query_return=[{
            "distance": 0.15,
            "source": "brain-grow",
            "title": "GraphQL field-level authz writeup",
            "url": "https://prior.example.com/page",
        }],
        url_present=False,  # URL is novel, but matched source is brain-grow
    )
    ctx = _make_dedup_ctx(tmp_path, store)

    result = asyncio.run(brain_tools.ingest_text.handler(_ingest_args()))
    text_out = "".join(b.get("text", "") for b in result["content"])
    assert "Skipped" in text_out
    assert ctx.docs_added == 0
    assert ctx.docs_skipped_dedup == 1
