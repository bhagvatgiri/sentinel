"""Hermetic tests for sentinel.agent.novelty.scorer.score_novelty (Plan 05-03, NOVEL-04).

No live Ollama. No live Chroma. Every fixture uses a hand-built numpy CorpusIndex +
a MagicMock embedder that returns canned vectors, so the entire suite runs in
milliseconds on a fresh checkout with zero external services installed.

Seven tests, all RED at write-time, all GREEN once scorer.py's NotImplementedError
body gets filled in.

Contract pinned (per Plan 05-03 <interfaces>):

  score_novelty(finding, index, embedder=None) -> float
    * Builds query text from `finding.title + " " + (finding.description or "")`.
    * Embeds via embedder.embed_one (lazily constructs default OllamaEmbedder
      if not supplied — tests inject a MagicMock).
    * embedder.embed_one returns None (Ollama unreachable) -> return 0.0
      (CONSERVATIVE-FAIL: without an embedding we have no novelty signal,
      so downstream escalation does NOT fire).
    * index.size == 0 (operator never ran `novelty refresh-index`) -> return 1.0
      (vacuously novel; Plan 05-04's downstream guard short-circuits escalation
      anyway, so this is informational only).
    * Otherwise: returns 1.0 - clipped_cosine_similarity in [0.0, 1.0].
"""

from __future__ import annotations

from unittest.mock import MagicMock

import numpy as np
import pytest

from sentinel.agent.novelty import CorpusIndex, IndexEntry, score_novelty
from sentinel.core.findings import Finding, Severity


# --- Fixture factories --------------------------------------------------------


def _make_finding(
    *,
    title: str = "SQL injection in /admin",
    description: str = "Parameter id reflects into raw SQL; UNION-based extraction proven.",
) -> Finding:
    """Compact Finding factory matching the existing test pattern in
    tests/test_finding_novelty_score_field.py + tests/test_finding_poc_steps_field.py."""
    return Finding(
        title=title,
        description=description,
        severity=Severity.HIGH,
        scanner="vuln:sqli",
        target="https://example.com",
    )


def _make_entry(chunk_id: str = "c0", title: str = "CWE-89") -> IndexEntry:
    return IndexEntry(
        chunk_id=chunk_id,
        source="mitre-cwe",
        title=title,
        text_preview=f"preview-for-{chunk_id}",
        url=None,
        cve_id=None,
    )


def _index_with(*rows: tuple[np.ndarray, IndexEntry]) -> CorpusIndex:
    """Build a CorpusIndex from N (vector, entry) pairs."""
    if not rows:
        return CorpusIndex(vectors=np.zeros((0, 4), dtype=np.float32), entries=[])
    vectors = np.stack([np.asarray(v, dtype=np.float32) for v, _ in rows])
    entries = [e for _, e in rows]
    return CorpusIndex(vectors=vectors, entries=entries)


# --- Test 1 -------------------------------------------------------------------
def test_score_novelty_matching_corpus_entry_returns_low_score() -> None:
    """Embedding matches a corpus row exactly => cosine_similarity ~ 1.0 =>
    novelty ~ 0.0 (within 1e-6 tolerance)."""
    finding = _make_finding()
    index = _index_with(
        (np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32), _make_entry()),
    )
    embedder = MagicMock()
    embedder.embed_one.return_value = [1.0, 0.0, 0.0, 0.0]

    score = score_novelty(finding, index, embedder=embedder)

    assert isinstance(score, float)
    assert score == pytest.approx(0.0, abs=1e-6)


# --- Test 2 -------------------------------------------------------------------
def test_score_novelty_no_corpus_match_returns_high_score() -> None:
    """Embedding is orthogonal to every corpus row => cosine_similarity ~ 0.0 =>
    novelty ~ 1.0."""
    finding = _make_finding()
    index = _index_with(
        (np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32), _make_entry("c0")),
        (np.array([1.0, 0.1, 0.0, 0.0], dtype=np.float32), _make_entry("c1")),
    )
    embedder = MagicMock()
    embedder.embed_one.return_value = [0.0, 0.0, 1.0, 0.0]  # orthogonal to both rows

    score = score_novelty(finding, index, embedder=embedder)

    assert score == pytest.approx(1.0, abs=1e-3)


# --- Test 3 -------------------------------------------------------------------
def test_score_novelty_partial_match_returns_mid_score() -> None:
    """Embedding has cosine_similarity ~ 0.6 with the nearest corpus row =>
    novelty ~ 0.4 (within 1e-3 tolerance)."""
    finding = _make_finding()
    # corpus row = unit-x; query = normalized [0.6, 0.8] => cosine = 0.6
    index = _index_with(
        (np.array([1.0, 0.0], dtype=np.float32), _make_entry()),
    )
    embedder = MagicMock()
    embedder.embed_one.return_value = [0.6, 0.8]  # |v| = 1.0; dot with [1,0] = 0.6

    score = score_novelty(finding, index, embedder=embedder)

    assert score == pytest.approx(0.4, abs=1e-3)


# --- Test 4 -------------------------------------------------------------------
def test_score_novelty_empty_index_returns_one_point_zero() -> None:
    """No corpus loaded => vacuously novel => 1.0 (Plan 05-04 short-circuits
    escalation when the index is empty, so this is informational only)."""
    finding = _make_finding()
    empty_index = CorpusIndex(vectors=np.zeros((0, 4), dtype=np.float32), entries=[])
    embedder = MagicMock()
    embedder.embed_one.return_value = [1.0, 0.0, 0.0, 0.0]

    score = score_novelty(finding, empty_index, embedder=embedder)

    assert score == 1.0


# --- Test 5 -------------------------------------------------------------------
def test_score_novelty_embedder_returns_none_returns_zero_point_zero() -> None:
    """CONSERVATIVE-FAIL: embedder.embed_one returns None (Ollama unreachable)
    => return 0.0 so downstream escalation does NOT fire (better to under-escalate
    than crash the pipeline)."""
    finding = _make_finding()
    index = _index_with(
        (np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32), _make_entry()),
    )
    embedder = MagicMock()
    embedder.embed_one.return_value = None  # Ollama down / network failure

    score = score_novelty(finding, index, embedder=embedder)

    assert score == 0.0


# --- Test 6 -------------------------------------------------------------------
def test_score_novelty_uses_title_plus_description_as_query() -> None:
    """The query text passed to embedder.embed_one MUST contain both the finding
    title and (a prefix of) the description — Plan 05-03 uses combined semantics
    so the nearest-neighbor search captures vuln-class + context, not just the
    short title."""
    finding = _make_finding(
        title="Reflected XSS in profile page",
        description="The `name` parameter reflects unescaped into the HTML body.",
    )
    index = _index_with(
        (np.array([1.0, 0.0], dtype=np.float32), _make_entry()),
    )
    embedder = MagicMock()
    embedder.embed_one.return_value = [1.0, 0.0]

    score_novelty(finding, index, embedder=embedder)

    assert embedder.embed_one.called
    (call_arg,) = embedder.embed_one.call_args[0]  # positional arg
    assert isinstance(call_arg, str)
    assert "Reflected XSS in profile page" in call_arg
    assert "name" in call_arg and "parameter" in call_arg


# --- Test 7 -------------------------------------------------------------------
def test_score_novelty_clamps_negative_cosine_similarity() -> None:
    """Negative cosine similarity (vectors with negative dot product) clamps
    to 0.0, so novelty caps at 1.0 — never overshoots [0.0, 1.0]."""
    finding = _make_finding()
    index = _index_with(
        (np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32), _make_entry()),
    )
    embedder = MagicMock()
    embedder.embed_one.return_value = [-1.0, 0.0, 0.0, 0.0]  # anti-parallel; cos = -1

    score = score_novelty(finding, index, embedder=embedder)

    assert 0.0 <= score <= 1.0
    # Anti-parallel collapses to similarity 0 after clamp => novelty = 1.0
    assert score == pytest.approx(1.0, abs=1e-6)
