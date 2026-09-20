"""D2 — CTIBench MITRE-extract eval tests.

Asserts F1-macro and MAD targets from the spec.
"""

from __future__ import annotations

import pytest

from sentinel.benchmark import cti_bench


def test_dataset_size_is_20():
    assert len(cti_bench.SYNTHETIC_EXCERPTS) == 20


def test_run_produces_metrics():
    r = cti_bench.run()
    assert r["n_excerpts"] == 20
    assert "f1_macro" in r
    assert "mad" in r
    assert "per_row" in r


def test_f1_macro_meets_threshold():
    """Spec target: F1-macro >= 0.7 on the 20 synthetic excerpts."""
    r = cti_bench.run()
    assert r["f1_macro"] >= 0.7, (
        f"f1_macro regressed to {r['f1_macro']:.4f} (target 0.7)"
    )


def test_mad_under_15():
    """Spec target: CVSS MAD <= 1.5. CVSS is extracted verbatim from
    each excerpt, so MAD on this synthetic set is ~0.0; the threshold
    keeps the door open for noisier excerpts in future versions."""
    r = cti_bench.run()
    assert r["mad"] <= 1.5, f"MAD regressed to {r['mad']:.4f}"


def test_per_row_shape():
    r = cti_bench.run()
    for row in r["per_row"]:
        assert "excerpt_id" in row
        assert "predicted_techniques" in row
        assert "expected_techniques" in row
        assert isinstance(row["f1"], float)


def test_extract_techniques_routes_through_mapper():
    """Sanity: same input → same output every call (no LLM in the loop)."""
    a = cti_bench.extract_techniques("SQL injection in /api/login")
    b = cti_bench.extract_techniques("SQL injection in /api/login")
    assert a == b
    assert "T1190" in a


def test_extract_cvss_handles_missing():
    assert cti_bench.extract_cvss("no score here") is None
    assert cti_bench.extract_cvss("CVSS 7.5 confirmed") == 7.5
