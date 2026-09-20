"""Verify-phase-03 hermetic tests — Plan 03-05 Task 1 (VERIFY-05).

The new `verify-phase-03` pipeline phase runs BETWEEN the existing `exploit:*`
phases and `chain_execute` / `correlation`. For each finding emitted by Phase 2
/ 2.5 / exploit that does NOT already carry `evidence_state == VERIFIED` (new
Phase 3 path) or `evidence_state == LIVE_CONFIRMED` (existing Phase 2.5 path),
the new phase:

  (a) Generates a PoC via `render_poc_prompt(finding)` + asks the agent to write
      it to `deliverables/poc_<fingerprint>.xml` via the agent's Write tool.
  (b) After `_run_phase` returns, reads that file from disk (PhaseResult has NO
      `.text` and NO `.findings` field — see pipeline.py:314-321), feeds it to
      `parse_poc_block`.
  (c) Calls `execute_poc(...)` (Plan 03-04 sandbox) with `scope=scope` (threaded
      to prevent any scope-bypass).
  (d) Writes back the resulting `SandboxResult.evidence_state` to the finding.

Already-verified findings (LIVE_CONFIRMED / VERIFIED) are skipped.

All tests are hermetic: no real LLM, no real subprocess, no network. `_run_phase`
is monkeypatched to fake the agent's PoC write; `execute_poc` is monkeypatched
to inject canned `SandboxResult` verdicts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock

import pytest

from sentinel.agent.pentest.pipeline import (
    PentestPipeline,
    PipelineConfig,
    PhaseResult,
)
from sentinel.agent.poc import ParsedPoc, SandboxResult
from sentinel.core.findings import EvidenceState, Finding, Severity


CANNED_POC_XML = (
    "<poc>"
    "<language>shell</language>"
    "<command>curl http://127.0.0.1/ping</command>"
    "<expected_output_regex>pong</expected_output_regex>"
    "<rationale>r</rationale>"
    "</poc>"
)


# ---- Helpers ------------------------------------------------------------


def _make_finding(
    *,
    title: str = "Test finding",
    evidence_state: EvidenceState = EvidenceState.RECON_INFERRED,
    scanner: str = "test-scanner",
    target: str = "http://127.0.0.1",
    location: Optional[str] = None,
) -> Finding:
    """Build a Finding with controllable evidence_state."""
    return Finding(
        title=title,
        description="test description",
        severity=Severity.HIGH,
        scanner=scanner,
        target=target,
        location=location,
        evidence_state=evidence_state,
    )


def _make_scope(tmp_path: Path):
    """Construct a minimal Scope object via Scope.load on a tmp yaml."""
    from sentinel.core.scope import Scope
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        "client: test-client\n"
        "engagement_id: test-eng-verify-phase\n"
        "authorized_by: t@local\n"
        "valid_from: 2026-01-01\n"
        "valid_until: 2030-12-31\n"
        "targets:\n"
        "  domains: [127.0.0.1, localhost]\n"
        "  ips: [127.0.0.1/32]\n"
        "rate_limits:\n"
        "  requests_per_second: 5\n"
    )
    audit_path = tmp_path / ".audit.jsonl"
    scope = Scope.load(scope_path, audit_log_path=audit_path)
    return scope


def _make_pipeline(
    tmp_path: Path,
    *,
    verify_after_exploit: bool = True,
    skip_phases: Optional[list[str]] = None,
    cost_cap_strict: bool = False,
    max_budget_per_scan_usd: float = 100.0,
) -> PentestPipeline:
    cfg = PipelineConfig(
        target="http://127.0.0.1",
        scope_path=str(tmp_path / "scope.yaml"),
        verify_after_exploit=verify_after_exploit,
        skip_phases=list(skip_phases or []),
        cost_cap_strict=cost_cap_strict,
        max_budget_per_scan_usd=max_budget_per_scan_usd,
    )
    return PentestPipeline(cfg)


def _setup_run_phase_writes_canned_poc(monkeypatch, workspace: Path,
                                        *, success: bool = True,
                                        write_file: bool = True,
                                        body: str = CANNED_POC_XML):
    """Monkeypatch PentestPipeline._run_phase to (a) write the canned PoC XML
    file based on the per-finding phase name, and (b) return a successful
    PhaseResult.
    """
    deliverables = workspace / "deliverables"
    deliverables.mkdir(parents=True, exist_ok=True)

    async def fake_run_phase(self, *, name, system_prompt, user_prompt,
                             tools, max_turns, agents=None):
        # phase_name is e.g. "verify-phase-03:abcd1234"
        if write_file and ":" in name:
            fp = name.split(":", 1)[1]
            (deliverables / f"poc_{fp}.xml").write_text(body)
        return PhaseResult(
            name=name, duration_sec=1, cost_usd=0.01, turns=1,
            success=success, error=None if success else "stub",
        )

    monkeypatch.setattr(PentestPipeline, "_run_phase", fake_run_phase)


# ---- Test 1 -------------------------------------------------------------


def test_pipeline_config_verify_after_exploit_default_true():
    cfg = PipelineConfig(target="http://x", scope_path="/dev/null")
    assert cfg.verify_after_exploit is True


# ---- Test 2 -------------------------------------------------------------


def test_run_verify_phase_03_skipped_when_disabled(tmp_path, monkeypatch):
    scope = _make_scope(tmp_path)
    pipeline = _make_pipeline(tmp_path, verify_after_exploit=False)
    workspace = tmp_path / "workspace"
    (workspace / "deliverables").mkdir(parents=True)
    f = _make_finding(evidence_state=EvidenceState.RECON_INFERRED)
    original = f.evidence_state

    # execute_poc should never be invoked when verify is disabled.
    called = {"n": 0}

    def fake_execute_poc(**kw):
        called["n"] += 1
        return SandboxResult(
            evidence_state=EvidenceState.VERIFIED, pattern_name=None,
            rationale="x", evidence_bundle_path=None, exit_code=0,
            stdout_bytes=0, stderr_bytes=0, duration_sec=0.0,
            expected_output_matched=True, out_of_scope_url=None,
            screenshot_path=None,
        )

    monkeypatch.setattr(
        "sentinel.agent.pentest.pipeline.execute_poc", fake_execute_poc
    )

    import asyncio
    result = asyncio.run(pipeline._run_verify_phase_03(
        scope, workspace, scope.audit_log, [f], event_log=None,
    ))
    assert result == []
    assert called["n"] == 0
    assert f.evidence_state == original


# ---- Test 3 -------------------------------------------------------------


def test_run_verify_phase_03_skipped_when_in_skip_phases(
    tmp_path, monkeypatch
):
    scope = _make_scope(tmp_path)
    pipeline = _make_pipeline(
        tmp_path, verify_after_exploit=True,
        skip_phases=["verify-phase-03"],
    )
    workspace = tmp_path / "workspace"
    (workspace / "deliverables").mkdir(parents=True)
    f = _make_finding(evidence_state=EvidenceState.RECON_INFERRED)
    called = {"n": 0}

    def fake_execute_poc(**kw):
        called["n"] += 1
        raise AssertionError("execute_poc should not be called when phase is skipped")

    monkeypatch.setattr(
        "sentinel.agent.pentest.pipeline.execute_poc", fake_execute_poc
    )

    import asyncio
    result = asyncio.run(pipeline._run_verify_phase_03(
        scope, workspace, scope.audit_log, [f], event_log=None,
    ))
    assert result == []
    assert called["n"] == 0


# ---- Test 4 -------------------------------------------------------------


def test_run_verify_phase_03_skips_already_verified_findings(
    tmp_path, monkeypatch
):
    scope = _make_scope(tmp_path)
    pipeline = _make_pipeline(tmp_path)
    workspace = tmp_path / "workspace"
    (workspace / "deliverables").mkdir(parents=True)

    _setup_run_phase_writes_canned_poc(monkeypatch, workspace)
    call_record = {"calls": []}

    def fake_execute_poc(**kw):
        call_record["calls"].append(kw["finding"].fingerprint())
        return SandboxResult(
            evidence_state=EvidenceState.VERIFIED, pattern_name=None,
            rationale="ok", evidence_bundle_path=None, exit_code=0,
            stdout_bytes=0, stderr_bytes=0, duration_sec=0.0,
            expected_output_matched=True, out_of_scope_url=None,
            screenshot_path=None,
        )

    monkeypatch.setattr(
        "sentinel.agent.pentest.pipeline.execute_poc", fake_execute_poc
    )

    f_verified = _make_finding(
        title="already verified",
        evidence_state=EvidenceState.VERIFIED,
    )
    f_live = _make_finding(
        title="already live-confirmed",
        evidence_state=EvidenceState.LIVE_CONFIRMED,
        location="lvl-1",
    )
    f_pending = _make_finding(
        title="needs verification",
        evidence_state=EvidenceState.RECON_INFERRED,
        location="lvl-2",
    )

    import asyncio
    asyncio.run(pipeline._run_verify_phase_03(
        scope, workspace, scope.audit_log,
        [f_verified, f_live, f_pending], event_log=None,
    ))

    # Only the RECON_INFERRED finding should have been verified.
    assert call_record["calls"] == [f_pending.fingerprint()]
    # Verified + live-confirmed kept their states.
    assert f_verified.evidence_state == EvidenceState.VERIFIED
    assert f_live.evidence_state == EvidenceState.LIVE_CONFIRMED
    # The pending one was promoted.
    assert f_pending.evidence_state == EvidenceState.VERIFIED


# ---- Test 5 -------------------------------------------------------------


def test_run_verify_phase_03_promotes_pending_to_verified_on_match(
    tmp_path, monkeypatch
):
    scope = _make_scope(tmp_path)
    pipeline = _make_pipeline(tmp_path)
    workspace = tmp_path / "workspace"
    (workspace / "deliverables").mkdir(parents=True)
    _setup_run_phase_writes_canned_poc(monkeypatch, workspace)
    monkeypatch.setattr(
        "sentinel.agent.pentest.pipeline.execute_poc",
        lambda **kw: SandboxResult(
            evidence_state=EvidenceState.VERIFIED, pattern_name=None,
            rationale="match", evidence_bundle_path=None, exit_code=0,
            stdout_bytes=10, stderr_bytes=0, duration_sec=0.1,
            expected_output_matched=True, out_of_scope_url=None,
            screenshot_path=None,
        ),
    )
    f = _make_finding(evidence_state=EvidenceState.PENDING)
    import asyncio
    asyncio.run(pipeline._run_verify_phase_03(
        scope, workspace, scope.audit_log, [f], event_log=None,
    ))
    assert f.evidence_state == EvidenceState.VERIFIED


# ---- Test 6 -------------------------------------------------------------


def test_run_verify_phase_03_promotes_pending_to_unreproducible_on_mismatch(
    tmp_path, monkeypatch
):
    scope = _make_scope(tmp_path)
    pipeline = _make_pipeline(tmp_path)
    workspace = tmp_path / "workspace"
    (workspace / "deliverables").mkdir(parents=True)
    _setup_run_phase_writes_canned_poc(monkeypatch, workspace)
    monkeypatch.setattr(
        "sentinel.agent.pentest.pipeline.execute_poc",
        lambda **kw: SandboxResult(
            evidence_state=EvidenceState.UNREPRODUCIBLE, pattern_name=None,
            rationale="no-match", evidence_bundle_path=None, exit_code=0,
            stdout_bytes=10, stderr_bytes=0, duration_sec=0.1,
            expected_output_matched=False, out_of_scope_url=None,
            screenshot_path=None,
        ),
    )
    f = _make_finding(evidence_state=EvidenceState.PENDING)
    import asyncio
    asyncio.run(pipeline._run_verify_phase_03(
        scope, workspace, scope.audit_log, [f], event_log=None,
    ))
    assert f.evidence_state == EvidenceState.UNREPRODUCIBLE


# ---- Test 7 -------------------------------------------------------------


def test_run_verify_phase_03_stores_destructive_classifier_match(
    tmp_path, monkeypatch
):
    scope = _make_scope(tmp_path)
    pipeline = _make_pipeline(tmp_path)
    workspace = tmp_path / "workspace"
    (workspace / "deliverables").mkdir(parents=True)
    _setup_run_phase_writes_canned_poc(monkeypatch, workspace)
    monkeypatch.setattr(
        "sentinel.agent.pentest.pipeline.execute_poc",
        lambda **kw: SandboxResult(
            evidence_state=EvidenceState.MANUAL_REQUIRED,
            pattern_name="sql_drop_table",
            rationale="r",
            evidence_bundle_path=None, exit_code=None,
            stdout_bytes=0, stderr_bytes=0, duration_sec=0.0,
            expected_output_matched=None, out_of_scope_url=None,
            screenshot_path=None,
        ),
    )
    f = _make_finding(evidence_state=EvidenceState.RECON_INFERRED)
    import asyncio
    asyncio.run(pipeline._run_verify_phase_03(
        scope, workspace, scope.audit_log, [f], event_log=None,
    ))
    assert f.evidence_state == EvidenceState.MANUAL_REQUIRED
    assert f.destructive_classifier_match == {
        "pattern": "sql_drop_table", "rationale": "r",
    }


# ---- Test 8 -------------------------------------------------------------


def test_run_verify_phase_03_parse_failure_marks_manual_required(
    tmp_path, monkeypatch
):
    """When _run_phase succeeds but emits a malformed PoC (no <poc> tag),
    parse_poc_block returns None — finding becomes MANUAL_REQUIRED and
    execute_poc is NEVER called."""
    scope = _make_scope(tmp_path)
    pipeline = _make_pipeline(tmp_path)
    workspace = tmp_path / "workspace"
    (workspace / "deliverables").mkdir(parents=True)
    _setup_run_phase_writes_canned_poc(
        monkeypatch, workspace, body="this is not a poc block",
    )
    called = {"n": 0}

    def fake_execute_poc(**kw):
        called["n"] += 1
        raise AssertionError("execute_poc should not run on malformed PoC")

    monkeypatch.setattr(
        "sentinel.agent.pentest.pipeline.execute_poc", fake_execute_poc
    )
    f = _make_finding(evidence_state=EvidenceState.PENDING)
    import asyncio
    asyncio.run(pipeline._run_verify_phase_03(
        scope, workspace, scope.audit_log, [f], event_log=None,
    ))
    assert f.evidence_state == EvidenceState.MANUAL_REQUIRED
    assert called["n"] == 0


# ---- Test 8b ------------------------------------------------------------


def test_run_verify_phase_03_missing_deliverable_marks_manual_required(
    tmp_path, monkeypatch
):
    """When _run_phase succeeds but writes NO file, the loop marks
    MANUAL_REQUIRED and skips execute_poc."""
    scope = _make_scope(tmp_path)
    pipeline = _make_pipeline(tmp_path)
    workspace = tmp_path / "workspace"
    (workspace / "deliverables").mkdir(parents=True)
    _setup_run_phase_writes_canned_poc(
        monkeypatch, workspace, write_file=False,
    )
    called = {"n": 0}

    def fake_execute_poc(**kw):
        called["n"] += 1
        raise AssertionError("execute_poc should not run when no PoC file exists")

    monkeypatch.setattr(
        "sentinel.agent.pentest.pipeline.execute_poc", fake_execute_poc
    )
    f = _make_finding(evidence_state=EvidenceState.PENDING)
    import asyncio
    asyncio.run(pipeline._run_verify_phase_03(
        scope, workspace, scope.audit_log, [f], event_log=None,
    ))
    assert f.evidence_state == EvidenceState.MANUAL_REQUIRED
    assert called["n"] == 0


# ---- Test 9 -------------------------------------------------------------


def test_run_verify_phase_03_cost_cap_aborts_between_findings(
    tmp_path, monkeypatch
):
    """When cost_cap_strict + over-cap, the loop aborts BEFORE executing any
    finding (zero verifications). The pre-check at top of the verify phase
    fires once and a `scan_aborted_cost_cap` audit event lands."""
    scope = _make_scope(tmp_path)
    pipeline = _make_pipeline(
        tmp_path, cost_cap_strict=True, max_budget_per_scan_usd=0.10,
    )
    pipeline._scan_spend_usd = 0.20  # already over the cap
    workspace = tmp_path / "workspace"
    (workspace / "deliverables").mkdir(parents=True)
    _setup_run_phase_writes_canned_poc(monkeypatch, workspace)

    called = {"n": 0}
    def fake_execute_poc(**kw):
        called["n"] += 1
        return SandboxResult(
            evidence_state=EvidenceState.VERIFIED, pattern_name=None,
            rationale="x", evidence_bundle_path=None, exit_code=0,
            stdout_bytes=0, stderr_bytes=0, duration_sec=0.0,
            expected_output_matched=True, out_of_scope_url=None,
            screenshot_path=None,
        )
    monkeypatch.setattr(
        "sentinel.agent.pentest.pipeline.execute_poc", fake_execute_poc
    )

    # Capture audit events.
    audit_events: list[tuple[str, dict]] = []
    original_write = scope.audit_log.write

    def spy_write(event, payload, *, mode=None):
        audit_events.append((event, payload))
        return original_write(event, payload, mode=mode)

    monkeypatch.setattr(scope.audit_log, "write", spy_write)

    f1 = _make_finding(evidence_state=EvidenceState.RECON_INFERRED, title="f1")
    f2 = _make_finding(
        evidence_state=EvidenceState.RECON_INFERRED, title="f2", location="x",
    )

    import asyncio
    pipeline._audit = scope.audit_log
    result = asyncio.run(pipeline._run_verify_phase_03(
        scope, workspace, scope.audit_log, [f1, f2], event_log=None,
    ))
    # Zero findings verified.
    assert called["n"] == 0
    # A scan_aborted_cost_cap audit event was written.
    cost_cap_events = [e for e in audit_events if e[0] == "scan_aborted_cost_cap"]
    assert len(cost_cap_events) == 1, (
        f"expected exactly 1 scan_aborted_cost_cap audit event; got {audit_events}"
    )


# ---- Test 10 ------------------------------------------------------------


def test_run_verify_phase_03_scope_threaded_to_execute_poc(
    tmp_path, monkeypatch
):
    """execute_poc must be called with scope=scope (no scope-bypass surface)."""
    scope = _make_scope(tmp_path)
    pipeline = _make_pipeline(tmp_path)
    workspace = tmp_path / "workspace"
    (workspace / "deliverables").mkdir(parents=True)
    _setup_run_phase_writes_canned_poc(monkeypatch, workspace)

    last_kw: dict = {}
    def fake_execute_poc(**kw):
        last_kw.update(kw)
        return SandboxResult(
            evidence_state=EvidenceState.VERIFIED, pattern_name=None,
            rationale="x", evidence_bundle_path=None, exit_code=0,
            stdout_bytes=0, stderr_bytes=0, duration_sec=0.0,
            expected_output_matched=True, out_of_scope_url=None,
            screenshot_path=None,
        )
    monkeypatch.setattr(
        "sentinel.agent.pentest.pipeline.execute_poc", fake_execute_poc
    )

    f = _make_finding(evidence_state=EvidenceState.PENDING)
    import asyncio
    asyncio.run(pipeline._run_verify_phase_03(
        scope, workspace, scope.audit_log, [f], event_log=None,
    ))
    # Same scope object passed through (identity, not equality — proves no
    # scope_bypass / clone surface in the pipeline glue).
    assert last_kw["scope"] is scope


# ---- Test 11 ------------------------------------------------------------


def test_run_verify_phase_03_completes_for_each_finding(
    tmp_path, monkeypatch
):
    """Each finding produces an entry in the returned SandboxResult list.

    NOTE: Resume-checkpoint marker handling is delegated to _run_phase (which
    runs commit_phase per invocation). The verify-phase-03 helper itself
    returns the SandboxResult list. This test asserts the verify phase ran
    end-to-end for two findings and returned 2 results.
    """
    scope = _make_scope(tmp_path)
    pipeline = _make_pipeline(tmp_path)
    workspace = tmp_path / "workspace"
    (workspace / "deliverables").mkdir(parents=True)
    _setup_run_phase_writes_canned_poc(monkeypatch, workspace)
    monkeypatch.setattr(
        "sentinel.agent.pentest.pipeline.execute_poc",
        lambda **kw: SandboxResult(
            evidence_state=EvidenceState.VERIFIED, pattern_name=None,
            rationale="x", evidence_bundle_path=None, exit_code=0,
            stdout_bytes=0, stderr_bytes=0, duration_sec=0.0,
            expected_output_matched=True, out_of_scope_url=None,
            screenshot_path=None,
        ),
    )
    f1 = _make_finding(
        evidence_state=EvidenceState.PENDING, title="f1", location="l1",
    )
    f2 = _make_finding(
        evidence_state=EvidenceState.PENDING, title="f2", location="l2",
    )
    import asyncio
    results = asyncio.run(pipeline._run_verify_phase_03(
        scope, workspace, scope.audit_log, [f1, f2], event_log=None,
    ))
    assert len(results) == 2
    assert all(isinstance(r, SandboxResult) for r in results)
