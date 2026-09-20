"""B6 — Episodic + semantic memory split.

Episodic memory is per-engagement (Chroma collection scoped to one
engagement_id). Semantic memory is the existing cross-engagement corpus.
The recall() helper merges them and sorts by distance.

We use a stub embedder + stub semantic store so the tests run without
chromadb / Ollama (those are optional deps in the test env).
"""

from __future__ import annotations

import pytest

from sentinel.agent.pentest.memory_agent import (
    EpisodicStore, MemoryRecord, recall,
)


# ---- stand-in stores for unit tests ---------------------------------------

class _FakeEmbedder:
    """Returns deterministic vectors derived from text length."""
    def embed_one(self, text: str):
        return [float(len(text)), 0.0, 0.0]
    def embed_batch(self, texts):
        return [self.embed_one(t) for t in texts]


class _FakeEpisodic:
    """In-memory episodic store with the same surface EpisodicStore exposes
    for `query()`. Avoids requiring chromadb."""
    def __init__(self, hits):
        self._hits = hits
    def query(self, _q, top_k=5):
        return self._hits[:top_k]


class _FakeSemantic:
    """Replicates CorpusStore.query signature."""
    def __init__(self, hits):
        self._hits = hits
    def query(self, _q, _k, _where=None):
        return self._hits


def test_recall_episodic_only_returns_episodic_results():
    epi = _FakeEpisodic([
        {"id": "a", "text": "previous IDOR finding on /api/users",
         "distance": 0.1, "scope": "episodic"},
        {"id": "b", "text": "noted XSS in /search",
         "distance": 0.4, "scope": "episodic"},
    ])
    out = recall(query="idor", scope="episodic", episodic=epi)
    assert len(out) == 2
    assert all(r["scope"] == "episodic" for r in out)
    assert out[0]["distance"] == 0.1


def test_recall_semantic_only_returns_semantic_results():
    sem = _FakeSemantic([
        {"id": "x", "text": "OWASP IDOR cheat", "distance": 0.2,
         "source": "owasp", "title": "Access Control"},
    ])
    out = recall(query="idor", scope="semantic", semantic_store=sem)
    assert len(out) == 1
    assert out[0]["scope"] == "semantic"


def test_recall_both_merges_and_sorts_by_distance():
    epi = _FakeEpisodic([
        {"id": "e1", "text": "ep-a", "distance": 0.5, "scope": "episodic"},
    ])
    sem = _FakeSemantic([
        {"id": "s1", "text": "sem-a", "distance": 0.1,
         "source": "owasp", "title": "t"},
        {"id": "s2", "text": "sem-b", "distance": 0.7,
         "source": "owasp", "title": "t"},
    ])
    out = recall(query="q", scope="both", episodic=epi, semantic_store=sem)
    assert len(out) == 3
    distances = [r["distance"] for r in out]
    assert distances == sorted(distances)
    assert out[0]["scope"] == "semantic"      # smallest distance
    # Both tiers represented.
    scopes = {r["scope"] for r in out}
    assert scopes == {"episodic", "semantic"}


def test_recall_handles_episodic_failure_gracefully():
    """If episodic.query raises, semantic tier still returns results."""
    class _Bad:
        def query(self, *a, **kw):
            raise RuntimeError("chromadb missing")
    sem = _FakeSemantic([{"id": "s", "text": "x", "distance": 0.1,
                          "source": "owasp", "title": "t"}])
    out = recall(query="q", scope="both", episodic=_Bad(), semantic_store=sem)
    assert len(out) == 1
    assert out[0]["scope"] == "semantic"


def test_recall_handles_semantic_failure_gracefully():
    class _Bad:
        def query(self, *a, **kw):
            raise RuntimeError("ollama down")
    epi = _FakeEpisodic([{"id": "e", "text": "x", "distance": 0.1,
                          "scope": "episodic"}])
    out = recall(query="q", scope="both", episodic=epi, semantic_store=_Bad())
    assert len(out) == 1
    assert out[0]["scope"] == "episodic"


def test_recall_no_stores_configured_returns_empty():
    out = recall(query="q", scope="both")
    assert out == []


# ---- EpisodicStore (real Chroma path) -------------------------------------

@pytest.mark.skipif(
    pytest.importorskip("chromadb", reason="chromadb optional") is None,
    reason="chromadb not installed",
)
def test_episodic_store_isolates_per_engagement(tmp_path):
    """Two engagements MUST get distinct collections — episodic memory
    for engagement A must NOT surface in engagement B's recall."""
    embedder = _FakeEmbedder()

    ws_a = tmp_path / "ws_a"
    ws_a.mkdir()
    ws_b = tmp_path / "ws_b"
    ws_b.mkdir()

    a = EpisodicStore(ws_a, "eng-2026-Q2-001", embedder)
    b = EpisodicStore(ws_b, "eng-2026-Q2-002", embedder)

    a.add([MemoryRecord(text="a-only-secret", kind="finding", phase="vuln:idor")])
    b.add([MemoryRecord(text="b-only-detail", kind="note", phase="recon")])

    a_results = a.query("a-only-secret", top_k=5)
    b_results = b.query("a-only-secret", top_k=5)

    a_texts = [r["text"] for r in a_results]
    b_texts = [r["text"] for r in b_results]
    assert "a-only-secret" in a_texts
    # B's collection must NOT contain A's record — collection isolation.
    assert "a-only-secret" not in b_texts


@pytest.mark.skipif(
    pytest.importorskip("chromadb", reason="chromadb optional") is None,
    reason="chromadb not installed",
)
def test_episodic_store_idempotent_add(tmp_path):
    """Adding the same record twice must produce one stored entry."""
    ws = tmp_path / "ws"
    ws.mkdir()
    store = EpisodicStore(ws, "eng-id", _FakeEmbedder())
    n1 = store.add([MemoryRecord(text="dup", kind="note", phase="recon")])
    n2 = store.add([MemoryRecord(text="dup", kind="note", phase="recon")])
    assert n1 == 1
    assert n2 == 1
    out = store.query("dup", top_k=5)
    assert len(out) == 1


@pytest.mark.skipif(
    pytest.importorskip("chromadb", reason="chromadb optional") is None,
    reason="chromadb not installed",
)
def test_episodic_store_persists_metadata(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    store = EpisodicStore(ws, "eng", _FakeEmbedder())
    store.add([MemoryRecord(text="hit", kind="finding", phase="exploit:auth",
                             metadata={"severity": "high"})])
    out = store.query("hit", top_k=5)
    assert out
    assert out[0]["kind"] == "finding"
    assert out[0]["phase"] == "exploit:auth"
