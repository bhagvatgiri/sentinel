"""Defensive arg-coercion in ingest_text — Phase 104 follow-up.

Local Ollama models (llama3.1:8b among them) sometimes pass `tags` as a
real Python list, sometimes as a stringified list `"['a','b']"`, and
sometimes as comma-separated `"a, b"` despite the JSON-Schema saying
str. ingest_text must accept all three shapes."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from sentinel.agent.brain import tools as brain_tools


class _FakeStore:
    """Minimal CorpusStore stand-in. Records upserts; no queries match."""
    def __init__(self):
        self.upserted: list[list] = []

    def query(self, text, top_k):
        return []

    def upsert_chunks(self, chunks):
        chunks = list(chunks)
        self.upserted.append(chunks)
        return len(chunks)


def _make_ctx(tmp_path):
    ctx = brain_tools.BrainContext(
        store=_FakeStore(),
        http=None,
        chunk_size=1500,
        chunk_overlap=200,
        rate_limit_per_host_sec=0.0,
        log_path=tmp_path / "brain.jsonl",
    )
    brain_tools.set_context(ctx)
    return ctx


_LONG_TEXT = "x " * 1000  # > 200 chars so it passes length check


def _call(args: dict) -> dict:
    handler = brain_tools.ingest_text.handler
    return asyncio.run(handler(args))


def test_tags_as_real_list(tmp_path):
    _make_ctx(tmp_path)
    out = _call({
        "url": "https://example/a", "title": "Test",
        "text": _LONG_TEXT,
        "tags": ["graphql", "introspection", "cve-2024"],
    })
    assert not out.get("is_error"), out


def test_tags_as_stringified_list_python_repr(tmp_path):
    """Llama3.1 in the smoke test produced this exact shape."""
    _make_ctx(tmp_path)
    out = _call({
        "url": "https://example/b", "title": "Test",
        "text": _LONG_TEXT,
        "tags": "['graphql', 'introspection', 'vulnerability']",
    })
    assert not out.get("is_error"), out


def test_tags_as_comma_separated_string(tmp_path):
    _make_ctx(tmp_path)
    out = _call({
        "url": "https://example/c", "title": "Test",
        "text": _LONG_TEXT,
        "tags": "graphql, introspection, cve-2024",
    })
    assert not out.get("is_error"), out


def test_text_as_list_is_coerced_not_crash(tmp_path):
    """Defensive: if a model passes text as a list of strings, we coerce."""
    _make_ctx(tmp_path)
    out = _call({
        "url": "https://example/d", "title": "Test",
        "text": ["chunk one " * 50, "chunk two " * 50],
        "tags": ["x"],
    })
    # Must not raise AttributeError; either ingests or returns a clean error.
    assert "AttributeError" not in str(out)


def test_url_as_none_handled(tmp_path):
    _make_ctx(tmp_path)
    out = _call({
        "url": None, "title": "Test",
        "text": _LONG_TEXT,
        "tags": [],
    })
    assert "AttributeError" not in str(out)


def test_short_text_falls_back_to_extracted_cache(tmp_path):
    """The architectural fix: when llama3.1:8b passes only 60 chars of
    text, ingest_text recovers the full text from BrainContext's cache
    (populated by extract_text / fetch_url)."""
    ctx = _make_ctx(tmp_path)
    full_text = ("substantive content " * 200)  # > 1000 chars
    ctx.extracted_cache["https://example/cached"] = full_text

    # Model passes a truncated text arg AND the matching URL.
    out = _call({
        "url": "https://example/cached",
        "title": "Test",
        "text": "substantive content substantive cont",  # < 200 chars
        "tags": ["x"],
    })
    # Should not error — recovered from cache.
    assert not out.get("is_error"), out


def test_short_text_with_unknown_url_still_errors(tmp_path):
    """Without a cached URL, short text must still error (no spurious ingest)."""
    _make_ctx(tmp_path)
    out = _call({
        "url": "https://example/never-fetched",
        "title": "Test",
        "text": "short",
        "tags": ["x"],
    })
    assert out.get("is_error")
    assert "too short" in str(out)
