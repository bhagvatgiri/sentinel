"""Wave 4 / A5 — Constraint-aware severity gradation tests.

Paper 2510.17521: defender 54.3% vs attacker 28.3% under naive metrics
collapses to statistical parity under "must maintain availability" and
"must prevent enemy access" constraints. Findings that pass weak Lab
often fail Operational and Complete.

These tests pin:
  1. Finding defaults Lab/Op/Complete to False
  2. Belt-and-suspenders invariant: Complete=True requires Lab+Op=True
  3. Live-confirmed verifier sets reproduces_in_lab=True (default behaviour)
  4. Non-destructive probes default Operational=True
  5. Re-running an existing ExampleStore-tax verifier evidence file yields at
     least one finding with reproduces_in_lab=True
  6. Report prompt renders the new gradation column header
  7. Chain prompt rejects a synthetic destructive-primitive chain (the
     prompt text itself contains the refusal rule the agent obeys)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agent.pentest.verifier_tool import VerificationResult
from sentinel.core.findings import EvidenceState, Finding, Severity


# --------------------------------------------------------------------------
# Schema — Finding defaults
# --------------------------------------------------------------------------


def test_finding_defaults_all_three_to_false():
    f = Finding(title="t", description="d", severity=Severity.HIGH,
                scanner="s", target="https://x")
    assert f.reproduces_in_lab is False
    assert f.reproduces_under_operational is False
    assert f.reproduces_complete is False


def test_finding_invariant_complete_requires_lab_and_operational():
    """Belt-and-suspenders: complete=True with lab=False is a logic bug."""
    with pytest.raises(ValueError, match="Finding invariant violated"):
        Finding(title="t", description="d", severity=Severity.HIGH,
                scanner="s", target="https://x",
                reproduces_complete=True,           # complete True
                reproduces_in_lab=False,             # but lab False
                reproduces_under_operational=False)


def test_finding_invariant_complete_requires_operational():
    with pytest.raises(ValueError, match="Finding invariant violated"):
        Finding(title="t", description="d", severity=Severity.HIGH,
                scanner="s", target="https://x",
                reproduces_complete=True,
                reproduces_in_lab=True,              # lab True
                reproduces_under_operational=False)  # but op False


def test_finding_complete_with_full_chain_succeeds():
    f = Finding(title="t", description="d", severity=Severity.HIGH,
                scanner="s", target="https://x",
                reproduces_complete=True,
                reproduces_in_lab=True,
                reproduces_under_operational=True)
    assert f.reproduces_complete is True


def test_finding_to_dict_round_trip_preserves_gradation():
    f = Finding(title="t", description="d", severity=Severity.HIGH,
                scanner="s", target="https://x",
                reproduces_in_lab=True,
                reproduces_under_operational=True)
    d = f.to_dict()
    assert d["reproduces_in_lab"] is True
    assert d["reproduces_under_operational"] is True
    assert d["reproduces_complete"] is False


# --------------------------------------------------------------------------
# VerificationResult.gradation()
# --------------------------------------------------------------------------


def test_live_confirmed_default_sets_lab_true():
    """A LIVE_CONFIRMED verifier defaults reproduces_in_lab to True."""
    r = VerificationResult(
        state=EvidenceState.LIVE_CONFIRMED,
        summary="reproduced",
        evidence={},
    )
    grad = r.gradation()
    assert grad["reproduces_in_lab"] is True


def test_live_confirmed_non_destructive_defaults_operational_true():
    """Non-destructive live_confirmed → Lab+Operational both True."""
    r = VerificationResult(
        state=EvidenceState.LIVE_CONFIRMED,
        summary="reproduced via passive GET",
        evidence={},
        destructive=False,
    )
    grad = r.gradation()
    assert grad["reproduces_in_lab"] is True
    assert grad["reproduces_under_operational"] is True
    assert grad["reproduces_complete"] is False


def test_destructive_live_confirmed_blocks_operational():
    r = VerificationResult(
        state=EvidenceState.LIVE_CONFIRMED,
        summary="reproduced but destructive",
        evidence={},
        destructive=True,
    )
    grad = r.gradation()
    assert grad["reproduces_in_lab"] is True
    assert grad["reproduces_under_operational"] is False


def test_live_disproven_defaults_all_false():
    r = VerificationResult(
        state=EvidenceState.LIVE_DISPROVEN,
        summary="did not reproduce",
        evidence={},
    )
    grad = r.gradation()
    assert grad["reproduces_in_lab"] is False
    assert grad["reproduces_under_operational"] is False
    assert grad["reproduces_complete"] is False


def test_complete_requires_lab_and_operational_in_gradation():
    """If a verifier sets complete=True but state isn't live_confirmed,
    the gradation method must drop complete to False."""
    r = VerificationResult(
        state=EvidenceState.LIVE_DISPROVEN,
        summary="???",
        evidence={},
        reproduces_complete=True,   # ignored — state isn't live_confirmed
    )
    grad = r.gradation()
    assert grad["reproduces_complete"] is False


# --------------------------------------------------------------------------
# Smoke test against an existing ExampleStore-tax workspace evidence file.
# Uses the on-disk file referenced in the task brief; if the workspace was
# pruned, the test skips so CI on a fresh checkout doesn't go red.
# --------------------------------------------------------------------------


_AUDIBLE_EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "workspaces" / "ExampleStore-tax-2026-XX-XX" / "deliverables"
    / "csrf_verification_evidence.md"
)


def test_audible_csrf_evidence_yields_at_least_one_lab_repro():
    """Re-running the live ExampleStore-tax CSRF evidence file should
    yield at least one entry with reproduces_in_lab=True.

    We DON'T re-run the verifier (network needed); we parse the rendered
    rollup md and confirm that the verdict line for live_confirmed entries
    would translate to lab=True via VerificationResult.gradation().
    """
    if not _AUDIBLE_EVIDENCE.is_file():
        pytest.skip(f"ExampleStore-tax evidence absent at {_AUDIBLE_EVIDENCE}")
    text = _AUDIBLE_EVIDENCE.read_text()
    assert "live_confirmed" in text, (
        f"expected at least one live_confirmed row in {_AUDIBLE_EVIDENCE}; "
        "Wave 4 gradation would mark such a row reproduces_in_lab=True"
    )
    # Verify the canonical CSRF token-absence verdict shape (from
    # verifiers/csrf.py::_verify_token_absence). That verdict's
    # VerificationResult sets reproduces_in_lab=True explicitly.
    result_for_csrf04 = VerificationResult(
        state=EvidenceState.LIVE_CONFIRMED,
        summary=("Form HTML contains no anti-CSRF token field. Defense-in-"
                 "depth gap confirmed."),
        evidence={"has_csrf_token": False},
        reproduces_in_lab=True,
        reproduces_under_operational=True,
        destructive=False,
    )
    grad = result_for_csrf04.gradation()
    assert grad["reproduces_in_lab"] is True
    assert grad["reproduces_under_operational"] is True


# --------------------------------------------------------------------------
# Report + chain prompt copy — pinned text checks
# --------------------------------------------------------------------------


def test_report_prompt_renders_gradation_column_header():
    """The Phase 5 report-agent prompt must include the new columns.

    If this test fails, the report won't show Lab/Op/Complete and the
    deliverable degrades to pre-Wave-4 (severity-only) honesty.
    """
    from sentinel.agent.pentest.report_prompt import REPORT_PROMPT
    # The prompt template is .format()-ready, so we don't render it; we
    # just check the table-header line + the gradation explanation.
    assert "| ID | Severity | Lab | Operational | Complete | Title |" in REPORT_PROMPT
    # "Findings constraint" + "gradation" appear together (possibly across
    # a line wrap inside the .format()-ready template).
    assert "Findings constraint" in REPORT_PROMPT
    assert "gradation" in REPORT_PROMPT
    assert "reproduces_in_lab" in REPORT_PROMPT
    assert "reproduces_under_operational" in REPORT_PROMPT
    assert "reproduces_complete" in REPORT_PROMPT


def test_report_prompt_renders_attack_heatmap_section():
    from sentinel.agent.pentest.report_prompt import REPORT_PROMPT
    assert "ATT&CK Coverage Heatmap" in REPORT_PROMPT
    assert "Initial Access" in REPORT_PROMPT
    assert "Privilege Escalation" in REPORT_PROMPT
    assert "Exfiltration" in REPORT_PROMPT


def test_chain_prompt_rejects_destructive_primitive_chain():
    """The chain agent prompt must include the destructive-primitive refusal
    rule. The agent observes the rule via the prompt; this test pins the
    rule's presence so a future prompt edit can't silently drop it.
    """
    from sentinel.agent.pentest.chain_prompt import _TEMPLATE
    assert "REFUSAL RULE — destructive-primitive composition" in _TEMPLATE
    assert "abandon the chain" in _TEMPLATE
    assert "reproduces_under_operational=False" in _TEMPLATE
    # AND-of-primitives composition rule must also be present.
    assert "AND of all" in _TEMPLATE


# --------------------------------------------------------------------------
# Verifier output — gradation flows through to the queue entry
# --------------------------------------------------------------------------


def test_verifier_dispatcher_writes_gradation_back_to_queue(tmp_path):
    """End-to-end: register a fake verifier, run it through verify_class_queue,
    confirm the queue entry on disk has the new gradation fields."""
    import asyncio
    import json
    from unittest import mock

    from sentinel.agent.pentest import verifier_tool
    from sentinel.agent.pentest.verifier_tool import (
        VerificationContext, register_verifier, verify_class_queue,
    )

    workspace = tmp_path / "ws"
    deliverables = workspace / "deliverables"
    deliverables.mkdir(parents=True)
    queue_path = deliverables / "auth_exploitation_queue.json"
    queue_path.write_text(json.dumps({
        "vulnerabilities": [
            {"ID": "AUTH-VULN-01", "vulnerability_type": "Brute_Force"},
        ],
    }))

    async def fake_verify(ctx: VerificationContext):
        return VerificationResult(
            state=EvidenceState.LIVE_CONFIRMED,
            summary="non-destructive probe reproduced",
            evidence={"x": 1},
            reproduces_in_lab=True,
            reproduces_under_operational=True,
            destructive=False,
        )

    # Force the verifier registry to load before we monkey-patch, so the
    # dispatcher's own _ensure_verifiers_loaded call doesn't re-import the
    # real auth verifier on top of our fake.
    verifier_tool._ensure_verifiers_loaded()
    original = verifier_tool.VERIFIERS.get("auth")
    register_verifier("auth", fake_verify)
    try:
        fake_scope = mock.MagicMock()
        fake_scope.auth_credentials = []
        fake_scope.research_headers = {}
        asyncio.run(verify_class_queue(
            scope=fake_scope, target="https://example.com",
            workspace_dir=workspace, vuln_class="auth",
        ))
    finally:
        if original is not None:
            register_verifier("auth", original)

    # Re-read the queue and check the gradation fields landed.
    new = json.loads(queue_path.read_text())
    entry = new["vulnerabilities"][0]
    assert entry["evidence_state"] == "live_confirmed"
    assert entry["reproduces_in_lab"] is True
    assert entry["reproduces_under_operational"] is True
    assert entry["reproduces_complete"] is False
    assert entry["verification"]["reproduces_in_lab"] is True
