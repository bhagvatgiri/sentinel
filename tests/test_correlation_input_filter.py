"""correlation_input_filter — Plan 03-05 Task 2 (VERIFY-08).

Scope.correlation_input_filter loaded with default 'verified_only';
_filter_findings_for_correlation enforces the three filter modes; correlation
prompt accepts optional `findings` kwarg with back-compat None fallback.

| filter mode               | evidence_state values that PASS                    |
|---------------------------|----------------------------------------------------|
| verified_only (default)   | VERIFIED, LIVE_CONFIRMED                           |
| include_manual_required   | + MANUAL_REQUIRED, MANUAL_VERIFICATION_REQUIRED,   |
|                           |   REQUIRES_TEST_CREDENTIALS, REQUIRES_TWO_ACCOUNTS |
| all                       | everything (with PENDING/RECON_INFERRED warning)   |
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import pytest
import yaml

from sentinel.core.findings import EvidenceState, Finding, Severity
from sentinel.core.scope import Scope, ScopeError


# ---- Helpers ------------------------------------------------------------


_BASE_SCOPE: dict = {
    "client": "t-client",
    "engagement_id": "t-eng",
    "authorized_by": "t@local",
    "valid_from": "2026-01-01",
    "valid_until": "2030-12-31",
    "targets": {"domains": ["127.0.0.1"]},
}


def _write_scope_yaml(tmp_path: Path, extra: Optional[dict] = None) -> Path:
    """Drop a minimal-but-valid scope.yaml + return its path."""
    data = dict(_BASE_SCOPE)
    if extra:
        data.update(extra)
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def _make_finding(state: EvidenceState, *, title: str = "f") -> Finding:
    return Finding(
        title=f"{title}-{state.value}",
        description="d",
        severity=Severity.HIGH,
        scanner="test",
        target="http://127.0.0.1",
        location=state.value,  # makes fingerprints unique
        evidence_state=state,
    )


def _all_states_findings() -> list[Finding]:
    """Build one Finding for every EvidenceState value."""
    return [_make_finding(s) for s in EvidenceState]


# ---- Test 1: default value ----------------------------------------------


def test_scope_loads_default_correlation_input_filter(tmp_path):
    scope_path = _write_scope_yaml(tmp_path)
    audit_path = tmp_path / ".audit.jsonl"
    scope = Scope.load(scope_path, audit_log_path=audit_path)
    assert scope.correlation_input_filter == "verified_only"


# ---- Test 2: explicit value ---------------------------------------------


def test_scope_loads_explicit_filter_value(tmp_path):
    scope_path = _write_scope_yaml(
        tmp_path, {"correlation_input_filter": "include_manual_required"},
    )
    audit_path = tmp_path / ".audit.jsonl"
    scope = Scope.load(scope_path, audit_log_path=audit_path)
    assert scope.correlation_input_filter == "include_manual_required"


def test_scope_loads_all_filter_value(tmp_path):
    scope_path = _write_scope_yaml(
        tmp_path, {"correlation_input_filter": "all"},
    )
    audit_path = tmp_path / ".audit.jsonl"
    scope = Scope.load(scope_path, audit_log_path=audit_path)
    assert scope.correlation_input_filter == "all"


# ---- Test 3: invalid value rejected -------------------------------------


def test_scope_rejects_invalid_filter_value(tmp_path):
    scope_path = _write_scope_yaml(
        tmp_path, {"correlation_input_filter": "verifeid_only"},
    )
    with pytest.raises(ScopeError) as ei:
        Scope.load(scope_path, audit_log_path=tmp_path / ".audit.jsonl")
    msg = str(ei.value).lower()
    assert "correlation_input_filter" in msg
    # The valid values should appear in the error message for operator help.
    assert "verified_only" in msg
    assert "include_manual_required" in msg
    assert "all" in msg


# ---- Test 4: verified_only filter ---------------------------------------


def test_filter_verified_only_keeps_verified_and_live_confirmed_only():
    from sentinel.agent.pentest.pipeline import _filter_findings_for_correlation
    findings = _all_states_findings()
    filtered, _weak = _filter_findings_for_correlation(findings, "verified_only")
    states = {f.evidence_state for f in filtered}
    assert states == {
        EvidenceState.VERIFIED, EvidenceState.LIVE_CONFIRMED,
    }


# ---- Test 5: include_manual_required filter -----------------------------


def test_filter_include_manual_required_adds_manual_states():
    from sentinel.agent.pentest.pipeline import _filter_findings_for_correlation
    findings = _all_states_findings()
    filtered, _weak = _filter_findings_for_correlation(
        findings, "include_manual_required",
    )
    states = {f.evidence_state for f in filtered}
    assert states == {
        EvidenceState.VERIFIED,
        EvidenceState.LIVE_CONFIRMED,
        EvidenceState.MANUAL_REQUIRED,
        EvidenceState.MANUAL_VERIFICATION_REQUIRED,
        EvidenceState.REQUIRES_TEST_CREDENTIALS,
        EvidenceState.REQUIRES_TWO_ACCOUNTS,
    }
    # UNREPRODUCIBLE / LIVE_DISPROVEN / VERIFICATION_ERROR / RECON_INFERRED /
    # PENDING are all blocked.
    blocked = {
        EvidenceState.UNREPRODUCIBLE, EvidenceState.LIVE_DISPROVEN,
        EvidenceState.VERIFICATION_ERROR, EvidenceState.RECON_INFERRED,
        EvidenceState.PENDING,
    }
    assert states.isdisjoint(blocked)


# ---- Test 6: all filter -------------------------------------------------


def test_filter_all_passes_everything():
    from sentinel.agent.pentest.pipeline import _filter_findings_for_correlation
    findings = _all_states_findings()
    filtered, _weak = _filter_findings_for_correlation(findings, "all")
    assert len(filtered) == len(findings)
    # Order preserved.
    assert [f.evidence_state for f in filtered] == [
        f.evidence_state for f in findings
    ]


# ---- Test 7: unknown mode warns + falls back to all ---------------------


def test_filter_unknown_mode_warns_and_falls_back_to_all(caplog):
    from sentinel.agent.pentest.pipeline import _filter_findings_for_correlation
    findings = _all_states_findings()
    with caplog.at_level(logging.WARNING):
        filtered, _weak = _filter_findings_for_correlation(findings, "verifeid_only")
    # Defensive fallback: every finding returned.
    assert len(filtered) == len(findings)
    # A warning about the unknown filter is emitted.
    assert any(
        "unknown correlation_input_filter" in r.message.lower()
        or "verifeid_only" in r.message.lower()
        for r in caplog.records
    )


# ---- Test 8: all mode warns on pending passthrough ----------------------


def test_filter_all_warns_on_pending_passthrough(caplog):
    from sentinel.agent.pentest.pipeline import _filter_findings_for_correlation
    pending = _make_finding(EvidenceState.PENDING)
    verified = _make_finding(EvidenceState.VERIFIED)
    with caplog.at_level(logging.WARNING):
        filtered, weak = _filter_findings_for_correlation(
            [pending, verified], "all",
        )
    # PENDING passes through (we warn but don't drop).
    assert pending in filtered
    # D8: PENDING is reported in weak_passthrough for the audit-log entry.
    assert pending in weak
    assert verified not in weak
    # A warning about PENDING / verify-phase-may-not-have-run was emitted.
    assert any(
        "verify phase may not have run" in r.message.lower()
        for r in caplog.records
    )


# ---- Test 9: render_correlation_prompt consumes findings parameter -----


def test_render_correlation_prompt_consumes_findings_parameter():
    from sentinel.agent.pentest.correlation import render_correlation_prompt
    f = Finding(
        title="UniquePromptToken-XYZ",
        description="d", severity=Severity.HIGH, scanner="t",
        target="http://x", evidence_state=EvidenceState.VERIFIED,
    )
    rendered = render_correlation_prompt(
        client="c", engagement_id="e", target="http://x",
        workspace="/tmp/w", max_turns=10, max_budget_usd=1.0,
        findings=[f],
    )
    assert "UniquePromptToken-XYZ" in rendered


# ---- Test 10: back-compat — None findings → no failure -----------------


def test_render_correlation_prompt_back_compat_without_findings():
    """When findings=None (or omitted), the prompt renders without crash
    and falls back to the legacy queue-file-reading instructions."""
    from sentinel.agent.pentest.correlation import render_correlation_prompt
    # Omit findings entirely
    rendered = render_correlation_prompt(
        client="c", engagement_id="e", target="http://x",
        workspace="/tmp/w", max_turns=10, max_budget_usd=1.0,
    )
    assert "chain_execution_evidence.md" in rendered
    # Same with explicit findings=None.
    rendered2 = render_correlation_prompt(
        client="c", engagement_id="e", target="http://x",
        workspace="/tmp/w", max_turns=10, max_budget_usd=1.0,
        findings=None,
    )
    assert rendered2 == rendered


# ---- Test 11: bench scope has the filter comment ------------------------


def test_bench_juice_shop_scope_has_filter_comment():
    bench = Path("bench/juice-shop/scope.yaml")
    assert bench.is_file(), "bench/juice-shop/scope.yaml missing"
    text = bench.read_text()
    # The plan documents the field via at least one commented line.
    assert "correlation_input_filter" in text


# ---- Test 12: empty findings list ---------------------------------------


def test_filter_correlation_handles_empty_findings_list():
    from sentinel.agent.pentest.pipeline import _filter_findings_for_correlation
    for mode in ("verified_only", "include_manual_required", "all"):
        # D8: now returns (kept, weak_passthrough); both empty for [].
        assert _filter_findings_for_correlation([], mode) == ([], [])


# ---- Bonus: event_styles registers correlation_input_filter_applied -----


def test_event_styles_registers_correlation_input_filter_applied():
    from sentinel.web.event_styles import EVENT_STYLES
    assert "correlation_input_filter_applied" in EVENT_STYLES
    entry = EVENT_STYLES["correlation_input_filter_applied"]
    # Plan specifies chip=info, group=phase.
    assert entry["chip"] == "info"
    assert entry["group"] == "phase"
    assert entry.get("icon"), "missing icon"
    assert entry.get("label"), "missing label"
