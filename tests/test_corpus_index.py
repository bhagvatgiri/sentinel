"""Hermetic tests for CorpusIndex (Plan 05-02, NOVEL-02).

No live Ollama. No live Chroma. Every fixture is a hand-built numpy array +
list of IndexEntry, so the test suite runs in milliseconds and works on a
fresh checkout with zero external services installed.

Eight tests, all RED at write-time, all GREEN once corpus_index.py's
NotImplementedError bodies get filled in.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from sentinel.agent.novelty import CorpusIndex, IndexEntry, NearestMatch


def _entry(chunk_id: str, source: str = "owasp", title: str = "fixture") -> IndexEntry:
    """Compact factory for hermetic-fixture IndexEntries."""
    return IndexEntry(
        chunk_id=chunk_id,
        source=source,
        title=title,
        text_preview=f"preview-for-{chunk_id}",
        url=None,
        cve_id=None,
    )


# Test 1 -----------------------------------------------------------------
def test_corpus_index_construction_with_two_entries() -> None:
    """size / dim / entries[].chunk_id are wired correctly on a 2x4 fixture."""
    vectors = np.array(
        [[1.0, 0.0, 0.0, 0.0], [0.0, 1.0, 0.0, 0.0]],
        dtype=np.float32,
    )
    entries = [_entry("c0"), _entry("c1")]
    idx = CorpusIndex(vectors=vectors, entries=entries)
    assert idx.size == 2
    assert idx.dim == 4
    assert idx.entries[0].chunk_id == "c0"
    assert idx.entries[1].chunk_id == "c1"


# Test 2 -----------------------------------------------------------------
def test_corpus_index_persist_and_load_round_trip(tmp_path: Path) -> None:
    """persist() writes both sidecar files; load() reconstitutes vectors + entries."""
    vectors = np.array(
        [[0.1, 0.2, 0.3, 0.4], [0.5, 0.6, 0.7, 0.8]],
        dtype=np.float32,
    )
    entries = [
        IndexEntry(
            chunk_id="owasp:auth:0",
            source="owasp",
            title="Authentication",
            text_preview="Password policy guidance",
            url="https://owasp.org/auth",
            cve_id=None,
        ),
        IndexEntry(
            chunk_id="nvd:CVE-2024-1234",
            source="nvd",
            title="CVE-2024-1234: example",
            text_preview="A buffer overflow ...",
            url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
            cve_id="CVE-2024-1234",
        ),
    ]
    idx = CorpusIndex(vectors=vectors, entries=entries)

    persist_dir = tmp_path / "novelty-index"
    idx.persist(persist_dir)

    assert (persist_dir / "vectors.npy").exists()
    assert (persist_dir / "metadata.jsonl").exists()

    reloaded = CorpusIndex.load(persist_dir)
    assert reloaded.size == 2
    assert reloaded.dim == 4
    assert np.allclose(reloaded.vectors, vectors)
    assert reloaded.entries[0].chunk_id == "owasp:auth:0"
    assert reloaded.entries[0].source == "owasp"
    assert reloaded.entries[0].url == "https://owasp.org/auth"
    assert reloaded.entries[1].cve_id == "CVE-2024-1234"
    assert reloaded.entries[1].source == "nvd"


# Test 3 -----------------------------------------------------------------
def test_corpus_index_nearest_returns_top_1_by_cosine() -> None:
    """Identical query vector to row 0 yields cosine_distance ~ 0 + correct entry."""
    vectors = np.array(
        [
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.9, 0.1, 0.0, 0.0],
        ],
        dtype=np.float32,
    )
    entries = [_entry("c0"), _entry("c1"), _entry("c2")]
    idx = CorpusIndex(vectors=vectors, entries=entries)

    query = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    matches = idx.nearest(query, top_k=1)

    assert len(matches) == 1
    assert isinstance(matches[0], NearestMatch)
    assert matches[0].entry.chunk_id == "c0"
    assert matches[0].cosine_distance == pytest.approx(0.0, abs=1e-6)


# Test 4 -----------------------------------------------------------------
def test_corpus_index_nearest_top_k_ordering() -> None:
    """top_k=2 returns lowest-distance match first."""
    vectors = np.array(
        [
            [1.0, 0.0, 0.0, 0.0],   # cosine_distance ~ 0 to query
            [0.0, 1.0, 0.0, 0.0],   # cosine_distance ~ 1 to query
            [0.9, 0.1, 0.0, 0.0],   # cosine_distance > 0, < 1 to query
        ],
        dtype=np.float32,
    )
    entries = [_entry("c0"), _entry("c1"), _entry("c2")]
    idx = CorpusIndex(vectors=vectors, entries=entries)

    query = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    matches = idx.nearest(query, top_k=2)

    assert len(matches) == 2
    # Lowest distance first
    assert matches[0].entry.chunk_id == "c0"
    assert matches[1].entry.chunk_id == "c2"
    # Ascending order: 0 < first.distance <= second.distance
    assert matches[0].cosine_distance <= matches[1].cosine_distance


# Test 5 -----------------------------------------------------------------
def test_corpus_index_nearest_handles_zero_norm_vector() -> None:
    """A zero-norm query MUST NOT raise ZeroDivisionError — returns []."""
    vectors = np.array(
        [[1.0, 0.0, 0.0, 0.0], [0.0, 1.0, 0.0, 0.0]],
        dtype=np.float32,
    )
    entries = [_entry("c0"), _entry("c1")]
    idx = CorpusIndex(vectors=vectors, entries=entries)

    zero_query = np.array([0.0, 0.0, 0.0, 0.0], dtype=np.float32)
    matches = idx.nearest(zero_query, top_k=1)
    assert matches == []


# Test 6 -----------------------------------------------------------------
def test_corpus_index_empty_returns_empty_matches() -> None:
    """An index with size 0 returns [] from nearest regardless of query."""
    empty_vectors = np.zeros((0, 4), dtype=np.float32)
    idx = CorpusIndex(vectors=empty_vectors, entries=[])
    assert idx.size == 0

    query = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    assert idx.nearest(query, top_k=5) == []


# Test 7 -----------------------------------------------------------------
def test_corpus_index_persist_creates_both_sidecar_files(tmp_path: Path) -> None:
    """vectors.npy is a real .npy file; metadata.jsonl has one JSON object per row."""
    vectors = np.array(
        [
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
        ],
        dtype=np.float32,
    )
    entries = [
        _entry("a", source="owasp", title="OWASP-A"),
        _entry("b", source="mitre-cwe", title="CWE-79"),
        _entry("c", source="nvd", title="CVE-2024-0001"),
    ]
    idx = CorpusIndex(vectors=vectors, entries=entries)

    persist_dir = tmp_path / "novelty-index"
    idx.persist(persist_dir)

    # Real numpy .npy round-trip
    reloaded_vectors = np.load(persist_dir / "vectors.npy")
    assert reloaded_vectors.shape == (3, 4)
    assert np.allclose(reloaded_vectors, vectors)

    # JSONL alignment per row
    lines = (persist_dir / "metadata.jsonl").read_text().splitlines()
    assert len(lines) == 3
    parsed = [json.loads(ln) for ln in lines]
    assert parsed[0]["chunk_id"] == "a"
    assert parsed[1]["chunk_id"] == "b"
    assert parsed[2]["chunk_id"] == "c"
    assert parsed[1]["source"] == "mitre-cwe"


# Test 8 -----------------------------------------------------------------
def test_corpus_index_load_rejects_misaligned_files(tmp_path: Path) -> None:
    """vectors.npy with 3 rows + metadata.jsonl with 2 lines raises ValueError."""
    persist_dir = tmp_path / "novelty-index"
    persist_dir.mkdir(parents=True)

    # 3 vector rows
    np.save(
        persist_dir / "vectors.npy",
        np.array(
            [
                [1.0, 0.0, 0.0, 0.0],
                [0.0, 1.0, 0.0, 0.0],
                [0.0, 0.0, 1.0, 0.0],
            ],
            dtype=np.float32,
        ),
    )
    # 2 metadata lines — DELIBERATE misalignment
    meta_lines = [
        json.dumps({
            "chunk_id": "a",
            "source": "owasp",
            "title": "t",
            "text_preview": "p",
            "url": None,
            "cve_id": None,
        }),
        json.dumps({
            "chunk_id": "b",
            "source": "owasp",
            "title": "t",
            "text_preview": "p",
            "url": None,
            "cve_id": None,
        }),
    ]
    (persist_dir / "metadata.jsonl").write_text("\n".join(meta_lines) + "\n")

    with pytest.raises(ValueError, match=r"alignment|rows|mismatch"):
        CorpusIndex.load(persist_dir)
