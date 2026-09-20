"""NOVEL-01 — Finding.novelty_score field, range invariant, FROZEN fingerprint.

Pins the Phase 5 zero-day discovery harness foundation contract: every
subsequent Phase 5 plan (05-02 corpus index, 05-03 scorer, 05-04 RunReport
escalation gate, 05-05 dashboard chip vocabulary) reads or writes this
field. The tests below cover:

1.  Default value: a Finding constructed without specifying novelty_score
    lands with novelty_score == 0.0. This is the backward-compat default;
    every legacy run JSON written by Phases 1-4.5 deserializes through
    Finding(**data_minus_fingerprint) with no novelty_score key and gets
    0.0 for free.
2.  Explicit value: Finding(novelty_score=0.83) preserves the value and
    round-trips through to_dict.
3.  Range invariant — lower bound: Finding(novelty_score=-0.1) raises
    ValueError mentioning "novelty_score" and "[0.0, 1.0]". The Plan 05-03
    scorer is the canonical producer and stays in range by construction;
    this guard catches out-of-band callers that hand-construct a Finding
    with a bogus value.
4.  Range invariant — upper bound: Finding(novelty_score=1.5) raises the
    same ValueError. Catches numpy.float32 overflow / wrong-scale inputs.
5.  Round-trip serialization: Finding -> to_dict -> json.dumps -> json.loads
    -> data_minus_fingerprint -> Finding(**data) produces a Finding with
    the same novelty_score. Plan 05-04's RunReport escalation gate reads
    novelty_score off the deserialized Finding; if the round-trip drops
    the value, the gate silently fails to escalate.
6.  Backward-compat: a legacy dict WITHOUT a novelty_score key (simulating
    a run JSON written by Phases 1-4.5) round-trips through
    Finding(**data) cleanly with novelty_score == 0.0. No KeyError, no
    TypeError — just the documented default.
7.  SAFETY-BOUNDARY: Finding.fingerprint() is FROZEN. A Finding with
    novelty_score=0.0 and an otherwise-identical Finding with
    novelty_score=0.95 produce IDENTICAL fingerprint() output. This is
    the load-bearing dedup-key invariant pinned by CLAUDE.md ("Finding")
    and previously enforced by Plan 03-03 (evidence_state) and Plan 04-01
    (poc_steps). Adding novelty_score must NOT invalidate any existing
    run JSON's dedup key — that would corrupt cross-run deduplication
    and the regression-detection diff (`sentinel report --diff ...`).
"""

from __future__ import annotations

import json

import pytest

from sentinel.core.findings import Finding, Severity


def _make_finding(**overrides) -> Finding:
    """Minimal-required-kwargs builder, mirrors tests/test_finding_poc_steps_field.py."""
    base = dict(
        title="t",
        description="d",
        severity=Severity.LOW,
        scanner="s",
        target="https://example.com",
    )
    base.update(overrides)
    return Finding(**base)


# ---------------------------------------------------------------------------
# Finding.novelty_score field — default, explicit value, range invariant
# ---------------------------------------------------------------------------


def test_finding_default_novelty_score_is_zero():
    """A fresh Finding has novelty_score == 0.0 (Plan 05-01 backward-compat default)."""
    f = _make_finding()
    assert f.novelty_score == 0.0
    assert isinstance(f.novelty_score, float)


def test_finding_accepts_explicit_novelty_score():
    """Passing a novelty_score kwarg lands on the instance and survives to_dict."""
    f = _make_finding(novelty_score=0.83)
    assert f.novelty_score == 0.83
    d = f.to_dict()
    assert d["novelty_score"] == 0.83


def test_finding_post_init_rejects_novelty_score_below_zero():
    """__post_init__ guards the [0.0, 1.0] range invariant on the lower bound."""
    with pytest.raises(ValueError, match=r"novelty_score.*\[0\.0, 1\.0\]"):
        _make_finding(novelty_score=-0.1)


def test_finding_post_init_rejects_novelty_score_above_one():
    """__post_init__ guards the [0.0, 1.0] range invariant on the upper bound."""
    with pytest.raises(ValueError, match=r"novelty_score.*\[0\.0, 1\.0\]"):
        _make_finding(novelty_score=1.5)


# ---------------------------------------------------------------------------
# Round-trip serialization + backward-compat
# ---------------------------------------------------------------------------


def test_finding_to_dict_round_trip_preserves_novelty_score():
    """Finding -> to_dict -> JSON -> Finding(**data) preserves novelty_score exactly."""
    f = _make_finding(novelty_score=0.42)
    d = f.to_dict()

    # JSON round-trip proves the on-disk shape is stable for legacy run JSONs.
    encoded = json.dumps(d)
    decoded = json.loads(encoded)

    # The fingerprint key is computed by to_dict() and is NOT a Finding
    # constructor kwarg — strip before re-hydration (mirrors Plan 04-01).
    decoded.pop("fingerprint", None)
    # severity comes back as a string from the JSON round-trip; coerce
    # back to enum so Finding(**decoded) sees the canonical type.
    decoded["severity"] = Severity(decoded["severity"])

    f2 = Finding(**decoded)
    assert f2.novelty_score == 0.42


def test_finding_roundtrip_without_novelty_score_field():
    """Legacy dict WITHOUT a novelty_score key deserializes cleanly with 0.0.

    This simulates a run JSON written by Phases 1-4.5 (before Plan 05-01
    landed). The Plan 05-01 default must preserve backward-compat — the
    Finding(**data) call MUST NOT raise, and the resulting instance MUST
    have novelty_score == 0.0.
    """
    legacy = {
        "title": "Legacy finding",
        "description": "From a pre-Phase-5 run.json",
        "severity": "high",
        "scanner": "semgrep",
        "target": "/repo/src/foo.py",
        "location": "foo.py:42",
    }
    legacy_constructable = dict(legacy)
    legacy_constructable["severity"] = Severity.from_string(legacy["severity"])
    f = Finding(**legacy_constructable)
    assert f.novelty_score == 0.0


# ---------------------------------------------------------------------------
# FROZEN-fingerprint invariant — the load-bearing safety boundary
# ---------------------------------------------------------------------------


def test_finding_fingerprint_unchanged_by_novelty_score():
    """SAFETY-BOUNDARY: fingerprint() ignores novelty_score entirely.

    Adding novelty_score to a Finding must NOT change its fingerprint —
    that would invalidate the dedup key on every run JSON written by
    Phases 1-4.5 and break the regression-detection diff in
    `sentinel report --diff`. CLAUDE.md ("Finding") freezes the
    fingerprint algorithm; Plan 03-03 pinned this same invariant for
    evidence_state, and Plan 04-01 pinned it for poc_steps. Phase 5 is
    bound by the same FROZEN contract.
    """
    f_bare = _make_finding(
        scanner="semgrep",
        target="/repo/src/auth.py",
        location="auth.py:120",
        title="weak crypto",
        cwe="CWE-327",
    )
    f_with_high_novelty = _make_finding(
        scanner="semgrep",
        target="/repo/src/auth.py",
        location="auth.py:120",
        title="weak crypto",
        cwe="CWE-327",
        novelty_score=0.95,
    )
    assert f_bare.fingerprint() == f_with_high_novelty.fingerprint()
