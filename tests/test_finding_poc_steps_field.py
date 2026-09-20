"""POC-01 — PocStep dataclass + Finding.poc_steps field.

Pins the contract for Phase 4's manual-PoC-reproduction data model. The
seven tests below cover:

1.  PocStep is a dataclass importable from sentinel.core.findings with the
    exact 5 fields named in POC-01 (step_number, description, command,
    expected_output, screenshot_path).
2.  Finding gains a poc_steps: list[PocStep] field defaulting to [].
3.  Round-trip serialization preserves poc_steps content through
    to_dict() + JSON encode/decode + Finding(**data_minus_fingerprint).
4.  Backward-compat: legacy JSON dicts WITHOUT a poc_steps key still
    deserialize cleanly with poc_steps == [] (existing run JSONs from
    Phases 1-3 must not break).
5.  __post_init__ coerces list[dict] entries (from JSON load) into
    list[PocStep] so downstream code never has to dispatch on type.
6.  Non-dict / non-PocStep entries raise TypeError (defensive guard).
7.  Finding.fingerprint() is FROZEN: identical identity fields hash to
    the same fingerprint regardless of whether poc_steps is populated.
    This is the safety-boundary contract — adding poc_steps must NOT
    invalidate any existing run JSON's dedup key.
"""

from __future__ import annotations

import json

import pytest

from sentinel.core.findings import Finding, PocStep, Severity


def _make_finding(**overrides) -> Finding:
    """Minimal-required-kwargs builder, mirrors tests/test_finding_evidence_state.py."""
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
# PocStep dataclass + Finding.poc_steps field
# ---------------------------------------------------------------------------


def test_finding_default_poc_steps_is_empty_list():
    """A fresh Finding has poc_steps == [] (default factory empty list)."""
    f = _make_finding()
    assert f.poc_steps == []
    assert isinstance(f.poc_steps, list)


def test_finding_accepts_pocstep_list():
    """Passing a [PocStep(...)] kwarg lands on the instance unchanged."""
    step = PocStep(
        step_number=1,
        description="Send the request with curl",
        command="curl -s https://example.com/api",
        expected_output="200 OK",
    )
    f = _make_finding(poc_steps=[step])
    assert len(f.poc_steps) == 1
    assert f.poc_steps[0].command == "curl -s https://example.com/api"
    assert f.poc_steps[0].step_number == 1
    assert f.poc_steps[0].description == "Send the request with curl"
    assert f.poc_steps[0].expected_output == "200 OK"
    assert f.poc_steps[0].screenshot_path is None  # default


def test_finding_roundtrip_with_poc_steps():
    """Finding with PocSteps round-trips through to_dict + JSON + Finding(**data)."""
    steps_in = [
        PocStep(
            step_number=1,
            description="Send the request with curl",
            command="curl -s https://example.com/login",
            expected_output="",
        ),
        PocStep(
            step_number=2,
            description="Run: grep",
            command="grep session_id /tmp/cookies",
            expected_output="session_id=abc",
            screenshot_path="/tmp/workspaces/eng/verification/fp/screenshot.png",
        ),
    ]
    f = _make_finding(poc_steps=steps_in)
    d = f.to_dict()

    # to_dict serializes nested PocStep entries as plain dicts (asdict
    # handles nested dataclasses automatically). JSON round-trip proves
    # the on-disk shape is stable.
    encoded = json.dumps(d)
    decoded = json.loads(encoded)

    # The fingerprint key is computed by to_dict() and is NOT a Finding
    # constructor kwarg — strip before re-hydration.
    decoded.pop("fingerprint", None)
    # severity comes back as a string from the JSON round-trip; coerce
    # back to enum so Finding(**decoded) sees the canonical type.
    decoded["severity"] = Severity(decoded["severity"])

    f2 = Finding(**decoded)
    assert len(f2.poc_steps) == 2
    for original, restored in zip(steps_in, f2.poc_steps):
        assert restored.step_number == original.step_number
        assert restored.description == original.description
        assert restored.command == original.command
        assert restored.expected_output == original.expected_output
        assert restored.screenshot_path == original.screenshot_path


def test_finding_roundtrip_without_poc_steps_field():
    """Legacy dict WITHOUT a poc_steps key deserializes cleanly with []."""
    # Simulate a run JSON written before Phase 4 landed — no poc_steps key.
    legacy = {
        "title": "Legacy finding",
        "description": "From a pre-Phase-4 run.json",
        "severity": "high",
        "scanner": "semgrep",
        "target": "/repo/src/foo.py",
        "location": "foo.py:42",
    }
    # Mirror how json-loaded findings are reconstructed elsewhere in
    # the codebase: severity is a string, gets coerced via Severity.
    legacy_constructable = dict(legacy)
    legacy_constructable["severity"] = Severity.from_string(legacy["severity"])
    f = Finding(**legacy_constructable)
    assert f.poc_steps == []


def test_finding_post_init_coerces_dict_entries_to_pocstep():
    """list[dict] input (from JSON load) is coerced to list[PocStep] in __post_init__."""
    step_dict = {
        "step_number": 1,
        "description": "Send the request with curl",
        "command": "curl -s https://example.com",
        "expected_output": "200 OK",
        "screenshot_path": None,
    }
    f = _make_finding(poc_steps=[step_dict])
    assert len(f.poc_steps) == 1
    assert isinstance(f.poc_steps[0], PocStep)
    assert f.poc_steps[0].command == "curl -s https://example.com"
    assert f.poc_steps[0].step_number == 1


def test_finding_post_init_rejects_non_dict_non_pocstep_entries():
    """Defensive guard: a bogus poc_steps entry surfaces immediately as TypeError."""
    with pytest.raises(TypeError, match="poc_steps entry"):
        _make_finding(poc_steps=[42])


def test_finding_fingerprint_unchanged_by_poc_steps():
    """SAFETY-BOUNDARY: fingerprint() ignores poc_steps content entirely.

    Adding poc_steps to a Finding must NOT change its fingerprint — that
    would invalidate the dedup key on every run JSON written by Phases
    1-3. CLAUDE.md ("Finding") freezes the fingerprint algorithm.
    """
    f_bare = _make_finding(
        scanner="semgrep",
        target="/repo/src/auth.py",
        location="auth.py:120",
        title="weak crypto",
        cwe="CWE-327",
    )
    f_with_steps = _make_finding(
        scanner="semgrep",
        target="/repo/src/auth.py",
        location="auth.py:120",
        title="weak crypto",
        cwe="CWE-327",
        poc_steps=[
            PocStep(
                step_number=1,
                description="Run: python",
                command="python -c 'import hashlib; print(hashlib.md5(b\"x\").hexdigest())'",
                expected_output="9dd4e461268c8034f5c8564e155c67a6",
            )
        ],
    )
    assert f_bare.fingerprint() == f_with_steps.fingerprint()
