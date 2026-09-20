"""Hermetic tests for NvdLoader (Plan 05-02, NOVEL-03).

No live Ollama. No live Chroma. Fixtures hand-build the (chunk_id, vector,
metadata, document) tuples that refresh.py's _iter_chroma_chunks helper would
emit; NvdLoader.iter_entries consumes that iterable and yields the
(vector, IndexEntry) pairs the index assembler stitches together.

Six tests, all RED at write-time, all GREEN once nvd_loader.py's
NotImplementedError body gets filled in.
"""

from __future__ import annotations

import numpy as np
import pytest

from sentinel.agent.novelty import IndexEntry, NvdLoader


def _chunk(
    chunk_id: str,
    cve_id: str | None,
    document: str = "fixture document text",
    extra_meta: dict | None = None,
    vector: list[float] | None = None,
) -> tuple[str, np.ndarray, dict, str]:
    """Compact factory for the (chunk_id, vector, metadata, document) tuple shape."""
    meta: dict = {"source": "nvd"}
    if cve_id is not None:
        meta["cve_id"] = cve_id
    if extra_meta:
        meta.update(extra_meta)
    vec = np.asarray(vector if vector is not None else [0.1, 0.2, 0.3], dtype=np.float32)
    return (chunk_id, vec, meta, document)


# Test 1 -----------------------------------------------------------------
def test_nvd_loader_extracts_cve_id_from_metadata() -> None:
    """Single NVD chunk yields IndexEntry with correct cve_id + url."""
    loader = NvdLoader(since_year=2020)
    chunks = [
        _chunk(
            "nvd:CVE-2024-1234",
            cve_id="CVE-2024-1234",
            document="CVE-2024-1234 description text",
        ),
    ]
    out = list(loader.iter_entries(chunks))
    assert len(out) == 1
    vector, entry = out[0]
    assert isinstance(entry, IndexEntry)
    assert entry.cve_id == "CVE-2024-1234"
    assert entry.source == "nvd"
    assert entry.url == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    assert entry.chunk_id == "nvd:CVE-2024-1234"
    # Vector forwarded verbatim
    assert np.allclose(vector, np.array([0.1, 0.2, 0.3], dtype=np.float32))


# Test 2 -----------------------------------------------------------------
def test_nvd_loader_since_year_filters_older() -> None:
    """since_year=2022 drops CVE-2018-* entries; keeps CVE-2024-* entries."""
    loader = NvdLoader(since_year=2022)
    chunks = [
        _chunk("nvd:CVE-2018-0001", cve_id="CVE-2018-0001", document="old"),
        _chunk("nvd:CVE-2024-9999", cve_id="CVE-2024-9999", document="new"),
        _chunk("nvd:CVE-2021-5555", cve_id="CVE-2021-5555", document="also-old"),
    ]
    out = list(loader.iter_entries(chunks))
    assert len(out) == 1
    _vec, entry = out[0]
    assert entry.cve_id == "CVE-2024-9999"


# Test 3 -----------------------------------------------------------------
def test_nvd_loader_truncates_text_preview_to_240() -> None:
    """A 1000-char document yields IndexEntry.text_preview length == 240."""
    long_doc = "A" * 1000
    loader = NvdLoader(since_year=2020)
    chunks = [
        _chunk("nvd:CVE-2024-1111", cve_id="CVE-2024-1111", document=long_doc),
    ]
    out = list(loader.iter_entries(chunks))
    assert len(out) == 1
    _vec, entry = out[0]
    assert len(entry.text_preview) == 240
    assert entry.text_preview == "A" * 240


# Test 4 -----------------------------------------------------------------
def test_nvd_loader_yields_vector_alongside_entry() -> None:
    """iter_entries yields (vector, entry) tuples; vector value preserved."""
    canned = np.array([0.42, 0.17, 0.99, 0.01], dtype=np.float32)
    loader = NvdLoader(since_year=2020)
    chunks = [
        _chunk(
            "nvd:CVE-2024-2222",
            cve_id="CVE-2024-2222",
            vector=list(canned),
            document="payload",
        ),
    ]
    out = list(loader.iter_entries(chunks))
    assert len(out) == 1
    vector, _entry = out[0]
    assert np.allclose(vector, canned)


# Test 5 -----------------------------------------------------------------
def test_nvd_loader_skips_entries_missing_cve_id() -> None:
    """Chunk lacking metadata.cve_id silently skipped (no yield, no crash)."""
    loader = NvdLoader(since_year=2020)
    chunks = [
        _chunk("nvd:?", cve_id=None, document="no cve id"),
        _chunk("nvd:CVE-2024-3333", cve_id="CVE-2024-3333", document="present"),
    ]
    out = list(loader.iter_entries(chunks))
    assert len(out) == 1
    _vec, entry = out[0]
    assert entry.cve_id == "CVE-2024-3333"


# Test 6 -----------------------------------------------------------------
def test_nvd_loader_handles_malformed_cve_id() -> None:
    """Malformed cve_id (year-parse fails) silently skipped — never crashes the loop."""
    loader = NvdLoader(since_year=2020)
    chunks = [
        _chunk("nvd:??", cve_id="not-a-cve", document="malformed"),
        _chunk("nvd:??", cve_id="CVE-bad-id", document="also malformed"),
        _chunk("nvd:CVE-2024-4444", cve_id="CVE-2024-4444", document="good"),
    ]
    # MUST NOT raise
    out = list(loader.iter_entries(chunks))
    assert len(out) == 1
    _vec, entry = out[0]
    assert entry.cve_id == "CVE-2024-4444"
