"""STREAM-04 — hermetic tests for the verify-phase-03 streaming subscriber.

The streaming subscriber (`PentestPipeline._install_verify_phase_03_streaming`)
registers ONCE against the EXACT-MATCH kind ``'phase_completed'`` (NOT a glob —
see ``KIND_PHASE_COMPLETED='phase_completed'`` at ``sentinel/agent/event_log.py:50``)
with an INTERNAL filter on ``event['phase'].startswith('exploit:')``. When an
exploit class lands, the callback reconstructs that class's findings from the
per-class queue file and kicks off per-finding PoC runs via
``loop.create_task(self._verify_one_finding(...))`` — fire-and-forget onto the
running asyncio loop so the upstream phase's ``emit`` returns immediately and
the next exploit class continues running in parallel.

Load-bearing invariants pinned here:

  - Opt-out preservation: ``cfg.verify_after_exploit=False`` OR
    ``'verify-phase-03' in cfg.skip_phases`` MUST short-circuit installation.
    No subscriber registered, no stream events emitted.
  - ONE subscription registered on exact-match ``'phase_completed'`` with
    ``callback_name='verify_phase_03.streaming'``.
  - Internal filter: non-exploit phases (``vuln:``, ``recon``, ``correlation``)
    do NOT trigger any per-finding verify task.
  - Per-fingerprint dedup set (``self._streaming_verified_fingerprints``)
    reserved BEFORE ``create_task`` so a duplicate ``phase_completed`` emit
    for the same class does NOT spawn duplicate tasks.
  - Existing batch sweep at ``_run_verify_phase_03`` (pipeline.py:1234)
    awaits any pending streaming tasks via ``asyncio.gather`` then SKIPS
    fingerprints the streaming path already touched. No double-verify.
  - Subscriber exception isolation: a crash in the streaming callback does
    NOT remove the subscription; the next ``phase_completed`` event still
    fires the callback normally.
  - Four-layer defense preserved transitively: the streaming path calls
    ``self._verify_one_finding`` with the SAME scope/audit identity as the
    batch path. The four defense layers (classify_destructive →
    scope.authorize_url → subprocess timeout → expected_output_regex)
    live inside ``execute_poc`` (Plan 03-04). Regression coverage of those
    four layers lives in
    ``tests/test_poc_sandbox.py::test_execute_poc_destructive_short_circuits_without_subprocess``,
    ``tests/test_poc_sandbox.py::test_execute_poc_oos_url_blocked_before_subprocess``,
    ``tests/test_poc_sandbox.py::test_execute_poc_timeout_marks_unreproducible``,
    and ``tests/test_poc_sandbox.py::test_execute_poc_regex_match_marks_verified``.
    Test 12 below asserts the identity-pass-through; defense semantics inherit
    transitively from those Plan 03-04 tests.
  - Uninstall removes the subscription cleanly.

Runs offline. No network. No Claude SDK. No Ollama. No Chroma. No real
subprocess. ``_verify_one_finding`` is monkeypatched throughout so the
sandbox + subprocess paths never fire.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock

import pytest

from sentinel.agent import event_log as elog
from sentinel.agent.pentest import event_subscribers as subs
from sentinel.agent.pentest.pipeline import PentestPipeline, PipelineConfig
from sentinel.agent.poc import SandboxResult
from sentinel.core.findings import EvidenceState, Finding, Severity


# ---- Autouse reset fixture (same pattern as test_event_subscribers.py /
#      test_correlation_streaming.py) --------------------------------------


@pytest.fixture(autouse=True)
def _reset_subs():
    subs.clear_subscribers()
    subs.reset_halt()
    yield
    subs.clear_subscribers()
    subs.reset_halt()


@pytest.fixture
def tmp_log(tmp_path: Path) -> elog.EventLog:
    return elog.EventLog(tmp_path / "events.jsonl")


# ---- Helpers -------------------------------------------------------------


def _make_finding(
    *,
    title: str = "f",
    evidence_state: EvidenceState = EvidenceState.RECON_INFERRED,
    location: Optional[str] = None,
    scanner: str = "pentest-xss",
    target: str = "http://127.0.0.1",
) -> Finding:
    return Finding(
        title=title,
        description="desc",
        severity=Severity.HIGH,
        scanner=scanner,
        target=target,
        location=location,
        evidence_state=evidence_state,
    )


def _write_queue(workspace: Path, cls: str, findings: list[Finding]) -> Path:
    deliv_dir = workspace / "deliverables"
    deliv_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for f in findings:
        entries.append({
            "vulnerability_type": f.title,
            "notes": f.description,
            "severity_estimate": f.severity.value,
            "source_endpoint": f.target,
            "vulnerable_parameter": f.location,
            "evidence_state": f.evidence_state.value,
        })
    payload = {"vulnerabilities": entries}
    path = deliv_dir / f"{cls}_exploitation_queue.json"
    path.write_text(json.dumps(payload))
    return path


def _build_pipeline(
    *,
    verify_after_exploit: bool = True,
    skip_phases: Optional[list[str]] = None,
) -> PentestPipeline:
    cfg = PipelineConfig(
        target="http://127.0.0.1",
        scope_path="/dev/null",
        verify_after_exploit=verify_after_exploit,
        skip_phases=list(skip_phases or []),
    )
    return PentestPipeline(cfg)


def _make_scope(tmp_path: Path):
    from sentinel.core.scope import Scope
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        "client: test-client\n"
        "engagement_id: test-eng-verify-streaming\n"
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


def _ok_sandbox_result() -> SandboxResult:
    return SandboxResult(
        evidence_state=EvidenceState.VERIFIED,
        pattern_name=None,
        rationale="ok",
        evidence_bundle_path=None,
        exit_code=0,
        stdout_bytes=10,
        stderr_bytes=0,
        duration_sec=0.0,
        expected_output_matched=True,
        out_of_scope_url=None,
        screenshot_path=None,
    )


# ---- Test 1 — install respects opt-out: verify_after_exploit=False -------


def test_install_returns_none_when_verify_after_exploit_disabled(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    pipeline = _build_pipeline(verify_after_exploit=False)
    scope = _make_scope(tmp_path)

    before = len(subs.subscriptions())
    handle = pipeline._install_verify_phase_03_streaming(
        workspace=tmp_path, scope=scope, audit=scope.audit_log,
        event_log=tmp_log,
    )
    after = len(subs.subscriptions())

    assert handle is None
    assert after == before  # No subscriber registered.


# ---- Test 2 — install respects opt-out: 'verify-phase-03' in skip_phases -


def test_install_returns_none_when_phase_in_skip_phases(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    pipeline = _build_pipeline(skip_phases=["verify-phase-03"])
    scope = _make_scope(tmp_path)

    before = len(subs.subscriptions())
    handle = pipeline._install_verify_phase_03_streaming(
        workspace=tmp_path, scope=scope, audit=scope.audit_log,
        event_log=tmp_log,
    )
    after = len(subs.subscriptions())

    assert handle is None
    assert after == before


# ---- Test 3 — install registers ONE subscription on 'phase_completed' ----


def test_install_registers_one_phase_completed_subscription(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    pipeline = _build_pipeline()
    scope = _make_scope(tmp_path)

    # Filter out the STREAM-05 cost-cap watchdog (auto-installed on first
    # subscribe per Plan 04.5-05) so the delta accounting reflects only
    # the user-level subscription this test exercises.
    def _user_subs():
        return [
            h for h in subs.subscriptions()
            if h.callback_name != "event_subscribers.cost_cap_watchdog"
        ]

    before = len(_user_subs())
    handle = pipeline._install_verify_phase_03_streaming(
        workspace=tmp_path, scope=scope, audit=scope.audit_log,
        event_log=tmp_log,
    )
    after = _user_subs()

    assert handle is not None
    assert len(after) == before + 1
    registered = after[-1]
    assert registered.event_kind_pattern == "phase_completed"
    assert registered.callback_name == "verify_phase_03.streaming"


# ---- Test 4 — install emits streaming_phase_started ----------------------


def test_install_emits_streaming_phase_started_event(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    pipeline = _build_pipeline()
    scope = _make_scope(tmp_path)

    pipeline._install_verify_phase_03_streaming(
        workspace=tmp_path, scope=scope, audit=scope.audit_log,
        event_log=tmp_log,
    )

    started = [
        e for e in tmp_log.all_events()
        if e["kind"] == "streaming_phase_started"
    ]
    assert len(started) == 1
    assert started[0]["phase"] == "verify-phase-03"
    assert started[0]["trigger_phase"] == "pipeline_startup"


# ---- Test 5 — callback ignores non-exploit phase_completed ---------------


def test_callback_ignores_non_exploit_phase_completed(
    tmp_path: Path, tmp_log: elog.EventLog, monkeypatch,
):
    """When phase_completed fires for a vuln:/recon/correlation/report
    phase, the streaming callback MUST NOT schedule any verify task.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    # Write a queue with one pending finding (so if the filter is wrong,
    # the callback would have something to verify).
    _write_queue(workspace, "xss", [
        _make_finding(evidence_state=EvidenceState.RECON_INFERRED),
    ])

    pipeline = _build_pipeline()
    scope = _make_scope(tmp_path)

    call_count = {"n": 0}

    async def fake_verify_one_finding(self, **kw):
        call_count["n"] += 1
        return None

    monkeypatch.setattr(
        PentestPipeline, "_verify_one_finding", fake_verify_one_finding,
    )

    async def run_test():
        pipeline._install_verify_phase_03_streaming(
            workspace=workspace, scope=scope, audit=scope.audit_log,
            event_log=tmp_log,
        )
        for phase in (
            "vuln:xss", "recon", "correlation", "report",
            "verify-phase-03", "chain_execute",
        ):
            tmp_log.emit("phase_completed", phase=phase)
        # Give the loop a chance to run any (incorrectly) scheduled tasks.
        await asyncio.sleep(0.05)

    asyncio.run(run_test())
    assert call_count["n"] == 0


# ---- Test 6 — callback fires for exploit phase_completed ----------------


def test_callback_fires_for_exploit_phase_runs_only_eligible_findings(
    tmp_path: Path, tmp_log: elog.EventLog, monkeypatch,
):
    """Emit phase_completed for exploit:xss with a queue holding one
    RECON_INFERRED + one VERIFIED finding. Only the RECON_INFERRED finding
    is eligible — _verify_one_finding called exactly ONCE.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    pending = _make_finding(
        title="pending", evidence_state=EvidenceState.RECON_INFERRED,
        location="loc-pending",
    )
    already = _make_finding(
        title="already-verified", evidence_state=EvidenceState.VERIFIED,
        location="loc-already",
    )
    _write_queue(workspace, "xss", [pending, already])

    pipeline = _build_pipeline()
    scope = _make_scope(tmp_path)

    calls = []

    async def fake_verify_one_finding(self, *, scope, workspace, audit,
                                       finding, event_log, deliverables_dir):
        calls.append(finding)
        return _ok_sandbox_result()

    monkeypatch.setattr(
        PentestPipeline, "_verify_one_finding", fake_verify_one_finding,
    )

    async def run_test():
        pipeline._install_verify_phase_03_streaming(
            workspace=workspace, scope=scope, audit=scope.audit_log,
            event_log=tmp_log,
        )
        tmp_log.emit("phase_completed", phase="exploit:xss")
        # Allow the fire-and-forget tasks to run.
        await asyncio.sleep(0.05)

    asyncio.run(run_test())
    assert len(calls) == 1
    # The eligible finding was the RECON_INFERRED one.
    assert calls[0].title == "pending"


# ---- Test 7 — fingerprint registry prevents duplicate streaming work -----


def test_duplicate_phase_completed_does_not_double_verify(
    tmp_path: Path, tmp_log: elog.EventLog, monkeypatch,
):
    """Two phase_completed emits for the same exploit class MUST yield
    exactly ONE _verify_one_finding call per finding (per-fingerprint
    dedup set reserved BEFORE create_task).
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    f = _make_finding(
        title="dedup", evidence_state=EvidenceState.RECON_INFERRED,
        location="loc-dedup",
    )
    _write_queue(workspace, "xss", [f])

    pipeline = _build_pipeline()
    scope = _make_scope(tmp_path)

    call_count = {"n": 0}

    async def fake_verify_one_finding(self, **kw):
        call_count["n"] += 1
        return _ok_sandbox_result()

    monkeypatch.setattr(
        PentestPipeline, "_verify_one_finding", fake_verify_one_finding,
    )

    async def run_test():
        pipeline._install_verify_phase_03_streaming(
            workspace=workspace, scope=scope, audit=scope.audit_log,
            event_log=tmp_log,
        )
        tmp_log.emit("phase_completed", phase="exploit:xss")
        tmp_log.emit("phase_completed", phase="exploit:xss")
        await asyncio.sleep(0.05)

    asyncio.run(run_test())
    assert call_count["n"] == 1


# ---- Test 8 — batch sweep skips streaming-verified fingerprints ---------


def test_batch_sweep_skips_streaming_verified_fingerprints(
    tmp_path: Path, tmp_log: elog.EventLog, monkeypatch,
):
    """The existing _run_verify_phase_03 batch sweep MUST skip findings
    whose fingerprint is already in pipeline._streaming_verified_fingerprints.
    """
    pipeline = _build_pipeline()
    scope = _make_scope(tmp_path)
    workspace = tmp_path / "ws"
    (workspace / "deliverables").mkdir(parents=True)

    f_a = _make_finding(
        title="A", evidence_state=EvidenceState.RECON_INFERRED, location="a",
    )
    f_b = _make_finding(
        title="B", evidence_state=EvidenceState.RECON_INFERRED, location="b",
    )

    # Pre-populate the streaming registry with f_a's fingerprint.
    pipeline._streaming_verified_fingerprints = {f_a.fingerprint()}

    calls = []

    async def fake_verify_one_finding(self, *, scope, workspace, audit,
                                       finding, event_log, deliverables_dir):
        calls.append(finding.fingerprint())
        return _ok_sandbox_result()

    monkeypatch.setattr(
        PentestPipeline, "_verify_one_finding", fake_verify_one_finding,
    )

    asyncio.run(pipeline._run_verify_phase_03(
        scope, workspace, scope.audit_log, [f_a, f_b], event_log=tmp_log,
    ))

    # Only f_b verified by batch (f_a was already streaming-verified).
    assert calls == [f_b.fingerprint()]


# ---- Test 9 — batch sweep awaits pending streaming tasks ----------------


def test_batch_sweep_awaits_pending_streaming_tasks(
    tmp_path: Path, tmp_log: elog.EventLog, monkeypatch,
):
    """Pre-populate pipeline._streaming_verify_tasks with a pending task.
    _run_verify_phase_03 MUST await it (asyncio.gather) and reset the list.
    """
    pipeline = _build_pipeline()
    scope = _make_scope(tmp_path)
    workspace = tmp_path / "ws"
    (workspace / "deliverables").mkdir(parents=True)

    # No findings in the batch path — we only care about the await.
    async def fake_verify_one_finding(self, **kw):
        return _ok_sandbox_result()

    monkeypatch.setattr(
        PentestPipeline, "_verify_one_finding", fake_verify_one_finding,
    )

    completion_marker = {"done": False}

    async def slow_streaming_task():
        await asyncio.sleep(0.05)
        completion_marker["done"] = True

    async def run_test():
        loop = asyncio.get_running_loop()
        # Pre-populate the streaming-task list with a pending task.
        pipeline._streaming_verify_tasks = [loop.create_task(slow_streaming_task())]
        # Pass empty findings list — only the await-pending block fires.
        await pipeline._run_verify_phase_03(
            scope, workspace, scope.audit_log, [], event_log=tmp_log,
        )
        return list(pipeline._streaming_verify_tasks)

    remaining = asyncio.run(run_test())
    # The slow task must have completed and the list must be cleared.
    assert completion_marker["done"] is True
    assert remaining == []


# ---- Test 10 — no running loop is non-fatal -----------------------------


def test_no_running_loop_does_not_crash_callback(
    tmp_path: Path, tmp_log: elog.EventLog, monkeypatch,
):
    """Outside an asyncio context, the streaming callback MUST NOT raise.
    It either silently defers to the batch sweep or logs at debug. Either
    way: no exception escapes, no _verify_one_finding scheduled.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    _write_queue(workspace, "xss", [
        _make_finding(evidence_state=EvidenceState.RECON_INFERRED),
    ])

    pipeline = _build_pipeline()
    scope = _make_scope(tmp_path)

    call_count = {"n": 0}

    async def fake_verify_one_finding(self, **kw):
        call_count["n"] += 1

    monkeypatch.setattr(
        PentestPipeline, "_verify_one_finding", fake_verify_one_finding,
    )

    # Install + emit OUTSIDE an asyncio context (no event loop running).
    pipeline._install_verify_phase_03_streaming(
        workspace=workspace, scope=scope, audit=scope.audit_log,
        event_log=tmp_log,
    )
    # This MUST NOT raise — there is no running loop, so the callback
    # has to defer cleanly.
    tmp_log.emit("phase_completed", phase="exploit:xss")
    # No tasks scheduled (no loop to schedule them on).
    assert call_count["n"] == 0


# ---- Test 11 — callback exception isolation -----------------------------


def test_callback_crash_does_not_remove_subscription(
    tmp_path: Path, tmp_log: elog.EventLog, monkeypatch,
):
    """Force _reconstruct_findings_from_single_queue to raise. The callback
    must catch + log; the subscription stays alive; a subsequent emit for
    a different exploit class still fires the callback normally.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    # BOTH queues exist so both emits reach _reconstruct_findings_from_single_queue
    # (the `if not queue_path.is_file(): return` early-exit short-circuits
    # the callback before it can reach reconstruct, which would skip the
    # flaky_reconstruct call we want to trigger).
    _write_queue(workspace, "xss", [
        _make_finding(
            title="xss-finding", evidence_state=EvidenceState.RECON_INFERRED,
            location="xss-loc",
        ),
    ])
    _write_queue(workspace, "sqli", [
        _make_finding(
            title="sqli-finding", evidence_state=EvidenceState.RECON_INFERRED,
            location="sqli-loc",
        ),
    ])

    pipeline = _build_pipeline()
    scope = _make_scope(tmp_path)

    # Patch the reconstructor to raise on first call, succeed on second.
    call_log = {"n": 0}
    original_reconstruct = None  # type: ignore[var-annotated]

    def flaky_reconstruct(self, queue_path):
        call_log["n"] += 1
        if call_log["n"] == 1:
            raise RuntimeError("synthetic crash")
        # Real call on second invocation.
        return original_reconstruct(self, queue_path)

    # Monkeypatch the reconstruct method (defined on PentestPipeline by
    # the GREEN implementation). Capture the original first so the second
    # call delegates through.
    async def run_test():
        nonlocal original_reconstruct
        original_reconstruct = PentestPipeline._reconstruct_findings_from_single_queue
        monkeypatch.setattr(
            PentestPipeline,
            "_reconstruct_findings_from_single_queue",
            flaky_reconstruct,
        )

        verify_calls = {"n": 0}

        async def fake_verify_one_finding(self, **kw):
            verify_calls["n"] += 1
            return _ok_sandbox_result()

        monkeypatch.setattr(
            PentestPipeline, "_verify_one_finding", fake_verify_one_finding,
        )

        pipeline._install_verify_phase_03_streaming(
            workspace=workspace, scope=scope, audit=scope.audit_log,
            event_log=tmp_log,
        )
        # First emit — reconstruct raises; callback catches + returns.
        tmp_log.emit("phase_completed", phase="exploit:xss")
        # Subscription must still be active.
        registered = subs.subscriptions()
        assert any(
            h.callback_name == "verify_phase_03.streaming" for h in registered
        ), "subscription was removed after a callback crash"
        # Second emit (for a different class) — reconstruct succeeds.
        tmp_log.emit("phase_completed", phase="exploit:sqli")
        await asyncio.sleep(0.05)
        return verify_calls["n"]

    n_verified = asyncio.run(run_test())
    # First emit failed in reconstruct → 0 verifies; second emit succeeded
    # → 1 verify (for the sqli RECON_INFERRED finding).
    assert n_verified == 1


# ---- Test 12 — four-layer defense pass-through (identity check) ---------


def test_streaming_path_threads_same_scope_and_audit_as_batch(
    tmp_path: Path, tmp_log: elog.EventLog, monkeypatch,
):
    """The streaming subscriber calls _verify_one_finding with the SAME
    scope + audit objects passed at install time. This proves the four-layer
    defense (classify_destructive → scope.authorize_url → subprocess timeout
    → expected_output_regex) is preserved transitively — the streaming path
    delegates to the SAME _verify_one_finding → execute_poc that the batch
    path uses.

    Regression coverage of the 4 defense layers lives in Plan 03-04:
      - tests/test_poc_sandbox.py::test_execute_poc_destructive_short_circuits_without_subprocess
      - tests/test_poc_sandbox.py::test_execute_poc_oos_url_blocked_before_subprocess
      - tests/test_poc_sandbox.py::test_execute_poc_timeout_marks_unreproducible
      - tests/test_poc_sandbox.py::test_execute_poc_regex_match_marks_verified
    Defense semantics inherit transitively from those tests via this
    identity-pass-through assertion.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    _write_queue(workspace, "xss", [
        _make_finding(
            title="four-layer", evidence_state=EvidenceState.RECON_INFERRED,
            location="ll",
        ),
    ])

    pipeline = _build_pipeline()
    scope = _make_scope(tmp_path)

    captured_kwargs = {}

    async def fake_verify_one_finding(self, *, scope, workspace, audit,
                                       finding, event_log, deliverables_dir):
        captured_kwargs["scope"] = scope
        captured_kwargs["audit"] = audit
        captured_kwargs["event_log"] = event_log
        captured_kwargs["workspace"] = workspace
        captured_kwargs["finding"] = finding
        return _ok_sandbox_result()

    monkeypatch.setattr(
        PentestPipeline, "_verify_one_finding", fake_verify_one_finding,
    )

    async def run_test():
        pipeline._install_verify_phase_03_streaming(
            workspace=workspace, scope=scope, audit=scope.audit_log,
            event_log=tmp_log,
        )
        tmp_log.emit("phase_completed", phase="exploit:xss")
        await asyncio.sleep(0.05)

    asyncio.run(run_test())
    # IDENTITY assertion (is, not ==) — same objects threaded all the way
    # through to _verify_one_finding.
    assert captured_kwargs["scope"] is scope
    assert captured_kwargs["audit"] is scope.audit_log
    assert captured_kwargs["event_log"] is tmp_log
    assert captured_kwargs["workspace"] == workspace
    assert captured_kwargs["finding"].title == "four-layer"


# ---- Test 13 — uninstall removes the subscription -----------------------


def test_uninstall_removes_subscription(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    pipeline = _build_pipeline()
    scope = _make_scope(tmp_path)

    # Filter out the STREAM-05 cost-cap watchdog (auto-installed on first
    # subscribe per Plan 04.5-05) so the delta accounting reflects only
    # the user-level subscription this test exercises.
    def _user_subs():
        return [
            h for h in subs.subscriptions()
            if h.callback_name != "event_subscribers.cost_cap_watchdog"
        ]

    before = len(_user_subs())
    pipeline._install_verify_phase_03_streaming(
        workspace=tmp_path, scope=scope, audit=scope.audit_log,
        event_log=tmp_log,
    )
    after_install = len(_user_subs())
    assert after_install == before + 1

    pipeline._uninstall_verify_phase_03_streaming()
    after_uninstall = len(_user_subs())
    assert after_uninstall == before
