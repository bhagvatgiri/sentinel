"""ENG-03 regression tests for `sentinel.h1.dup_check`.

Hermetic — monkeypatches `sentinel.corpus.store.CorpusStore` with a stub
to avoid real Chroma / Ollama. Tests cover top-K ordering, distance-
based high-duplicate flag, source filtering, and graceful degradation
when the corpus dir is empty / Chroma isn't installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest


class _StubCorpusStore:
    """In-memory stand-in for CorpusStore.

    Records `.query()` kwargs so tests can assert filter passthrough.
    Returns a list of rows that the dup-check module consumes.
    """

    last_kwargs: dict = {}
    rows: list[dict] = []

    def __init__(self, persist_dir, embedder=None):
        # Real signature accepts embedder; dup_check passes None.
        self.persist_dir = persist_dir
        type(self).last_kwargs = {"persist_dir": str(persist_dir)}

    def query(self, query_text, top_k=5, where=None):
        type(self).last_kwargs["query_text"] = query_text
        type(self).last_kwargs["top_k"] = top_k
        type(self).last_kwargs["where"] = where
        return list(type(self).rows)


def _write_report(tmp_path: Path) -> Path:
    """Write a minimal H1 report markdown the dup-checker can read."""
    md = tmp_path / "01-xss.md"
    md.write_text(
        "# Stored XSS in /comments\n\n"
        "**Status:** drafted\n\n"
        "A reflected XSS in the comments endpoint. PoC below.\n"
        "```bash\ncurl https://example.com/comments\n```\n"
    )
    return md


def test_dup_check_returns_top_k_with_distances(tmp_path: Path, monkeypatch):
    """dup_check returns 5 rows ordered by ascending distance, with the
    high-duplicate-risk flag set when distance < HIGH_DUP_DISTANCE (0.25)."""
    import importlib
    dc = importlib.import_module("sentinel.h1.dup_check")

    # Stub rows: mixed distances, including one < 0.25.
    _StubCorpusStore.rows = [
        {"id": "w1", "distance": 0.10, "source": "writeups",
         "title": "XSS via comments", "url": "https://w.example/1",
         "metadata": {}},
        {"id": "w2", "distance": 0.18, "source": "writeups",
         "title": "Similar XSS", "url": "https://w.example/2",
         "metadata": {}},
        {"id": "w3", "distance": 0.30, "source": "writeups",
         "title": "Different XSS angle", "url": "https://w.example/3",
         "metadata": {}},
        {"id": "w4", "distance": 0.45, "source": "writeups",
         "title": "Unrelated", "url": "https://w.example/4",
         "metadata": {}},
        {"id": "w5", "distance": 0.55, "source": "writeups",
         "title": "Way off", "url": "https://w.example/5",
         "metadata": {}},
    ]
    monkeypatch.setattr(dc, "CorpusStore", _StubCorpusStore)
    monkeypatch.setattr(dc, "OllamaEmbedder", lambda *a, **kw: None)

    rep = _write_report(tmp_path)
    rows = dc.dup_check(rep, corpus_dir=tmp_path / "corpus", top_k=5)

    assert len(rows) == 5
    # Ascending distance.
    distances = [r["distance"] for r in rows]
    assert distances == sorted(distances)
    # High-duplicate-risk flag.
    assert rows[0]["high_duplicate_risk"] is True   # 0.10 < 0.25
    assert rows[1]["high_duplicate_risk"] is True   # 0.18 < 0.25
    assert rows[2]["high_duplicate_risk"] is False  # 0.30 >= 0.25
    assert rows[3]["high_duplicate_risk"] is False
    assert rows[4]["high_duplicate_risk"] is False


def test_dup_check_respects_source_filter(tmp_path: Path, monkeypatch):
    """When source_filter is provided, dup_check passes
    `where={"source": <filter>}` through to CorpusStore.query."""
    import importlib
    dc = importlib.import_module("sentinel.h1.dup_check")

    _StubCorpusStore.rows = []
    monkeypatch.setattr(dc, "CorpusStore", _StubCorpusStore)
    monkeypatch.setattr(dc, "OllamaEmbedder", lambda *a, **kw: None)

    rep = _write_report(tmp_path)
    dc.dup_check(
        rep, corpus_dir=tmp_path / "corpus", top_k=3, source_filter="writeups"
    )

    assert _StubCorpusStore.last_kwargs.get("where") == {"source": "writeups"}
    assert _StubCorpusStore.last_kwargs.get("top_k") == 3


def test_dup_check_graceful_when_chroma_missing(tmp_path: Path, monkeypatch):
    """If CorpusStore raises a RuntimeError (chromadb not installed), the
    public dup_check fn returns a structured `corpus_loaded: false` sentinel
    list so the CLI can degrade gracefully."""
    import importlib
    dc = importlib.import_module("sentinel.h1.dup_check")

    def _raise(*args, **kwargs):
        raise RuntimeError("chromadb is required. Install with: ...")

    monkeypatch.setattr(dc, "CorpusStore", _raise)
    monkeypatch.setattr(dc, "OllamaEmbedder", lambda *a, **kw: None)

    rep = _write_report(tmp_path)
    rows = dc.dup_check(rep, corpus_dir=tmp_path / "nonexistent", top_k=5)

    # Empty list (graceful), not an exception.
    assert rows == []
