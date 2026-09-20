"""STREAM-02 — hermetic tests for the streaming CorrelationContext accumulator.

The accumulator (`sentinel.agent.pentest.correlation.CorrelationContext`) subscribes
ONCE to `'phase_completed'` (the exact-match kind the pipeline emits — see
``KIND_PHASE_COMPLETED='phase_completed'`` at ``sentinel/agent/event_log.py:50``)
and filters internally on ``event['phase'].startswith('vuln:')`` OR
``event['phase'].startswith('exploit:')``. For each matching event it reads the
per-class deliverable + queue file from disk into a structured AccumulatorEntry.

Load-bearing invariants pinned here:

  - VERIFY-08 contract preserved: the accumulator's filter step imports
    ``_FILTER_ALLOWLISTS`` from pipeline.py — single source of truth — so the
    streaming-mode subset cannot diverge from the batch-mode subset.
  - ONE subscription registered, NOT two — production emit shape is
    ``kind='phase_completed'`` with the per-class identifier in
    ``event['phase']``.
  - Subscriber crashes are caught inside ``absorb()`` (defensive try/except)
    so the Plan 04.5-01 dispatcher records ``subscriber_fired`` with
    outcome='ok'.
  - Finding.fingerprint() dedup applied in ``all_findings()`` — same finding
    surfaced by two phase events counts once.
  - ``drain_streaming_to_prompt(context, **kwargs)`` is byte-identical to
    ``render_correlation_prompt(findings=context.all_findings(), **kwargs)``.
  - ``render_correlation_prompt`` back-compat (findings=None path) is
    unchanged from the pre-Plan-04.5-02 byte shape.

Runs offline. No network. No Claude SDK. No Ollama. No Chroma.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentinel.agent import event_log as elog
from sentinel.agent.pentest import event_subscribers as subs
from sentinel.core.findings import EvidenceState, Finding, Severity


# ---- Autouse reset fixture (same pattern as test_event_subscribers.py) ----


@pytest.fixture(autouse=True)
def _reset_subs():
    subs.clear_subscribers()
    subs.reset_halt()
    yield
    subs.clear_subscribers()
    subs.reset_halt()


@pytest.fixture
def tmp_log(tmp_path: Path) -> elog.EventLog:
    # Separate dir from workspace so the event log JSONL doesn't collide.
    return elog.EventLog(tmp_path / "events.jsonl")


# ---- Helpers --------------------------------------------------------------


def _make_finding(
    state: EvidenceState,
    *,
    title: str = "f",
    location: str | None = None,
    scanner: str | None = None,
) -> Finding:
    """Build a Finding whose fingerprint is unique per (title, location, scanner)."""
    return Finding(
        title=f"{title}-{state.value}",
        description=f"description for {title}",
        severity=Severity.HIGH,
        scanner=scanner or "test-scanner",
        target="http://127.0.0.1",
        location=location or state.value,
        evidence_state=state,
    )


def _write_queue(
    workspace: Path,
    cls: str,
    findings: list[Finding],
    *,
    shape: str = "dict",
) -> Path:
    """Drop a <cls>_exploitation_queue.json into workspace/deliverables/.

    shape='dict' produces ``{"vulnerabilities": [...]}`` (the canonical Plan 03-05
    shape); shape='list' produces a bare list. Both must be tolerated by the
    accumulator (matches ``_collect_findings_for_verify`` shape tolerance at
    pipeline.py:811-814).
    """
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
    payload = entries if shape == "list" else {"vulnerabilities": entries}
    path = deliv_dir / f"{cls}_exploitation_queue.json"
    path.write_text(json.dumps(payload))
    return path


def _write_deliverable(workspace: Path, cls: str, kind: str) -> Path:
    """Drop a stub deliverable file alongside the queue. Contents don't matter
    for the accumulator (which is queue-driven) — written only so the
    ``deliverable_path`` field can resolve to an existing file when the test
    chooses to assert it.
    """
    deliv_dir = workspace / "deliverables"
    deliv_dir.mkdir(parents=True, exist_ok=True)
    if kind == "vuln":
        path = deliv_dir / f"{cls}_analysis_deliverable.md"
    else:
        path = deliv_dir / f"{cls}_exploitation_evidence.md"
    path.write_text(f"# {cls} {kind}\n\nstub\n")
    return path


# ---- Test 1 — empty accumulator ------------------------------------------


def test_empty_accumulator_returns_empty_findings(tmp_path: Path):
    from sentinel.agent.pentest.correlation import CorrelationContext

    ctx = CorrelationContext(workspace=tmp_path)
    assert ctx.all_findings() == []
    assert ctx.entries == []


# ---- Test 2 — install registers ONE subscription on 'phase_completed' ----


def test_install_registers_one_phase_completed_subscription(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.correlation import CorrelationContext

    ctx = CorrelationContext(workspace=tmp_path)
    mock_audit = MagicMock()

    # Filter out the STREAM-05 cost-cap watchdog (auto-installed on first
    # subscribe per Plan 04.5-05) so the delta accounting reflects only
    # the user-level subscription this test exercises.
    def _user_subs():
        return [
            h for h in subs.subscriptions()
            if h.callback_name != "event_subscribers.cost_cap_watchdog"
        ]

    before = len(_user_subs())
    ctx.install(event_log=tmp_log, audit_log=mock_audit)
    after = _user_subs()

    # Exactly ONE new user-level subscription registered.
    assert len(after) == before + 1
    handle = after[-1]
    # Exact-match on 'phase_completed' (NOT a glob) — must match the literal
    # KIND_PHASE_COMPLETED constant the pipeline emits.
    assert handle.event_kind_pattern == "phase_completed"
    assert handle.callback_name == "correlation.absorb"


# ---- Test 3 — install emits streaming_phase_started ----------------------


def test_install_emits_streaming_phase_started_event(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.correlation import CorrelationContext

    ctx = CorrelationContext(workspace=tmp_path)
    ctx.install(event_log=tmp_log, audit_log=None)

    started = [
        e for e in tmp_log.all_events()
        if e["kind"] == "streaming_phase_started"
    ]
    assert len(started) == 1
    assert started[0]["phase"] == "correlation"
    assert started[0]["trigger_phase"] == "pipeline_startup"


# ---- Test 4 — absorb a vuln phase_completed event ------------------------


def test_absorb_vuln_phase_completed_reads_queue_and_filters(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    """Write a queue with 1 VERIFIED + 1 UNREPRODUCIBLE finding; emit
    phase_completed for vuln:xss. Default filter_mode='verified_only' admits
    only the VERIFIED one.
    """
    from sentinel.agent.pentest.correlation import CorrelationContext

    workspace = tmp_path / "ws"
    workspace.mkdir()
    _write_deliverable(workspace, "xss", "vuln")
    _write_queue(workspace, "xss", [
        _make_finding(EvidenceState.VERIFIED, title="reflected"),
        _make_finding(EvidenceState.UNREPRODUCIBLE, title="dom"),
    ])

    ctx = CorrelationContext(workspace=workspace)
    ctx.install(event_log=tmp_log, audit_log=None)

    tmp_log.emit("phase_completed", phase="vuln:xss")

    assert len(ctx.entries) == 1
    entry = ctx.entries[0]
    assert entry.phase_name == "vuln:xss"
    assert entry.deliverable_path.name == "xss_analysis_deliverable.md"
    assert entry.queue_path is not None
    assert entry.queue_path.name == "xss_exploitation_queue.json"
    # Default filter_mode='verified_only' drops UNREPRODUCIBLE.
    assert len(entry.findings) == 1
    assert entry.findings[0].evidence_state == EvidenceState.VERIFIED

    assert len(ctx.all_findings()) == 1


# ---- Test 5 — absorb an exploit phase_completed event --------------------


def test_absorb_exploit_phase_completed_reads_queue_and_filters(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.correlation import CorrelationContext

    workspace = tmp_path / "ws"
    workspace.mkdir()
    _write_deliverable(workspace, "sqli", "exploit")
    _write_queue(workspace, "sqli", [
        _make_finding(EvidenceState.LIVE_CONFIRMED, title="boolean"),
    ])

    ctx = CorrelationContext(workspace=workspace)
    ctx.install(event_log=tmp_log, audit_log=None)

    tmp_log.emit("phase_completed", phase="exploit:sqli")

    assert len(ctx.entries) == 1
    entry = ctx.entries[0]
    assert entry.phase_name == "exploit:sqli"
    assert entry.deliverable_path.name == "sqli_exploitation_evidence.md"
    assert entry.queue_path is not None
    assert entry.queue_path.name == "sqli_exploitation_queue.json"
    assert len(entry.findings) == 1
    assert entry.findings[0].evidence_state == EvidenceState.LIVE_CONFIRMED


# ---- Test 6 — non-vuln/non-exploit phases are no-ops ---------------------


def test_absorb_ignores_non_vuln_non_exploit_phases(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    """recon, correlation, report, chain_execute, verify-phase-03, intel-brief
    must NOT trigger an entry append.
    """
    from sentinel.agent.pentest.correlation import CorrelationContext

    workspace = tmp_path / "ws"
    workspace.mkdir()

    ctx = CorrelationContext(workspace=workspace)
    ctx.install(event_log=tmp_log, audit_log=None)

    for phase in [
        "recon", "correlation", "report", "chain_execute",
        "verify-phase-03", "intel-brief",
    ]:
        tmp_log.emit("phase_completed", phase=phase)

    assert ctx.entries == []


# ---- Test 7 — VERIFY-08 filter modes (three sub-cases + import contract) -


def test_filter_mode_verified_only_admits_only_verified_and_live_confirmed(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.correlation import CorrelationContext

    workspace = tmp_path / "ws"
    workspace.mkdir()
    findings = [
        _make_finding(EvidenceState.VERIFIED, title="a"),
        _make_finding(EvidenceState.LIVE_CONFIRMED, title="b"),
        _make_finding(EvidenceState.MANUAL_REQUIRED, title="c"),
        _make_finding(EvidenceState.UNREPRODUCIBLE, title="d"),
    ]
    _write_deliverable(workspace, "xss", "vuln")
    _write_queue(workspace, "xss", findings)

    ctx = CorrelationContext(workspace=workspace, filter_mode="verified_only")
    ctx.install(event_log=tmp_log, audit_log=None)
    tmp_log.emit("phase_completed", phase="vuln:xss")

    states = sorted(f.evidence_state.value for f in ctx.all_findings())
    assert states == sorted(["verified", "live_confirmed"])


def test_filter_mode_include_manual_required_admits_manual_states(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.correlation import CorrelationContext

    workspace = tmp_path / "ws"
    workspace.mkdir()
    findings = [
        _make_finding(EvidenceState.VERIFIED, title="a"),
        _make_finding(EvidenceState.LIVE_CONFIRMED, title="b"),
        _make_finding(EvidenceState.MANUAL_REQUIRED, title="c"),
        _make_finding(EvidenceState.MANUAL_VERIFICATION_REQUIRED, title="d"),
        _make_finding(EvidenceState.REQUIRES_TEST_CREDENTIALS, title="e"),
        _make_finding(EvidenceState.REQUIRES_TWO_ACCOUNTS, title="f"),
        _make_finding(EvidenceState.UNREPRODUCIBLE, title="g"),
    ]
    _write_deliverable(workspace, "xss", "vuln")
    _write_queue(workspace, "xss", findings)

    ctx = CorrelationContext(
        workspace=workspace, filter_mode="include_manual_required",
    )
    ctx.install(event_log=tmp_log, audit_log=None)
    tmp_log.emit("phase_completed", phase="vuln:xss")

    states = sorted(f.evidence_state.value for f in ctx.all_findings())
    expected = sorted([
        "verified", "live_confirmed", "manual-required",
        "manual_verification_required", "requires_test_credentials",
        "requires_two_accounts",
    ])
    assert states == expected


def test_filter_mode_all_admits_every_state(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.correlation import CorrelationContext

    workspace = tmp_path / "ws"
    workspace.mkdir()
    findings = [
        _make_finding(EvidenceState.VERIFIED, title="a"),
        _make_finding(EvidenceState.UNREPRODUCIBLE, title="b"),
        _make_finding(EvidenceState.MANUAL_REQUIRED, title="c"),
    ]
    _write_deliverable(workspace, "xss", "vuln")
    _write_queue(workspace, "xss", findings)

    ctx = CorrelationContext(workspace=workspace, filter_mode="all")
    ctx.install(event_log=tmp_log, audit_log=None)
    tmp_log.emit("phase_completed", phase="vuln:xss")

    assert len(ctx.all_findings()) == 3


def test_filter_allowlist_is_imported_from_pipeline_single_source_of_truth():
    """The allowlist MUST be imported from pipeline.py — never re-declared in
    correlation.py. This is the VERIFY-08 contract guarantee: streaming mode
    and batch mode share the EXACT same allowlist mapping.
    """
    from sentinel.agent.pentest.pipeline import _FILTER_ALLOWLISTS

    # correlation.py must not declare a top-level _FILTER_ALLOWLISTS of its own.
    import sentinel.agent.pentest.correlation as corr_mod

    # If correlation re-declared the allowlist as a module-level name, it would
    # shadow the import — assert it does not.
    own_allowlist = getattr(corr_mod, "_FILTER_ALLOWLISTS", None)
    if own_allowlist is not None:
        # Allowed ONLY if it IS the pipeline one (re-export, not redeclaration).
        assert own_allowlist is _FILTER_ALLOWLISTS, (
            "correlation._FILTER_ALLOWLISTS must be the same object as "
            "pipeline._FILTER_ALLOWLISTS (single source of truth)"
        )


# ---- Test 8 — deduplication by Finding.fingerprint() --------------------


def test_all_findings_dedups_by_fingerprint(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    """Same finding (identical scanner+target+location+title) emitted from two
    different phase queues must count ONCE in all_findings().
    """
    from sentinel.agent.pentest.correlation import CorrelationContext

    workspace = tmp_path / "ws"
    workspace.mkdir()

    # Same fingerprint (same title + location + scanner + target).
    shared = _make_finding(
        EvidenceState.VERIFIED,
        title="shared", location="loc-1", scanner="test-scanner",
    )

    _write_deliverable(workspace, "xss", "vuln")
    _write_queue(workspace, "xss", [shared])
    _write_deliverable(workspace, "xss", "exploit")
    # Both queues live at the same path (xss_exploitation_queue.json) — that's
    # the contract: one queue per class, both vuln and exploit phases read it.
    # So the second write does NOT happen — both events see the same queue.

    ctx = CorrelationContext(workspace=workspace)
    ctx.install(event_log=tmp_log, audit_log=None)
    tmp_log.emit("phase_completed", phase="vuln:xss")
    tmp_log.emit("phase_completed", phase="exploit:xss")

    # Two entries appended (one per event).
    assert len(ctx.entries) == 2
    # But dedup collapses to one finding.
    fps = [f.fingerprint() for f in ctx.all_findings()]
    assert len(fps) == 1
    assert len(set(fps)) == 1


# ---- Test 9 — defensive: missing queue file -----------------------------


def test_absorb_handles_missing_queue_file_gracefully(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    """No csrf_exploitation_queue.json on disk; emit phase_completed for
    vuln:csrf; absorb appends an entry with findings=[] and the dispatch hook's
    subscriber_fired event records outcome='ok' (the exception was caught
    INSIDE absorb, not raised out).
    """
    from sentinel.agent.pentest.correlation import CorrelationContext

    workspace = tmp_path / "ws"
    (workspace / "deliverables").mkdir(parents=True)

    ctx = CorrelationContext(workspace=workspace)
    ctx.install(event_log=tmp_log, audit_log=None)
    tmp_log.emit("phase_completed", phase="vuln:csrf")

    # Entry appended with empty findings list (queue file was missing).
    assert len(ctx.entries) == 1
    assert ctx.entries[0].findings == []
    assert ctx.entries[0].queue_path is None  # missing on disk

    # subscriber_fired event has outcome='ok' (absorb caught its own crash).
    fired = [e for e in tmp_log.all_events() if e["kind"] == "subscriber_fired"]
    correlation_fired = [
        e for e in fired if e["callback_name"] == "correlation.absorb"
    ]
    assert len(correlation_fired) == 1
    assert correlation_fired[0]["outcome"] == "ok"


# ---- Test 10 — defensive: malformed JSON --------------------------------


def test_absorb_handles_malformed_queue_json_gracefully(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.correlation import CorrelationContext

    workspace = tmp_path / "ws"
    deliv = workspace / "deliverables"
    deliv.mkdir(parents=True)
    (deliv / "csrf_exploitation_queue.json").write_text("not-json {{{")

    ctx = CorrelationContext(workspace=workspace)
    ctx.install(event_log=tmp_log, audit_log=None)
    tmp_log.emit("phase_completed", phase="vuln:csrf")

    # Entry appended with empty findings.
    assert len(ctx.entries) == 1
    assert ctx.entries[0].findings == []

    # Dispatch reports outcome='ok' (graceful handling, not 'error').
    fired = [e for e in tmp_log.all_events() if e["kind"] == "subscriber_fired"]
    correlation_fired = [
        e for e in fired if e["callback_name"] == "correlation.absorb"
    ]
    assert len(correlation_fired) == 1
    assert correlation_fired[0]["outcome"] == "ok"


# ---- Test 11 — uninstall removes the subscription ----------------------


def test_uninstall_removes_subscription(tmp_path: Path, tmp_log: elog.EventLog):
    from sentinel.agent.pentest.correlation import CorrelationContext

    # Filter out the STREAM-05 cost-cap watchdog (auto-installed on first
    # subscribe per Plan 04.5-05) so the delta accounting reflects only
    # the user-level subscription this test exercises.
    def _user_subs():
        return [
            h for h in subs.subscriptions()
            if h.callback_name != "event_subscribers.cost_cap_watchdog"
        ]

    ctx = CorrelationContext(workspace=tmp_path)
    before = len(_user_subs())
    ctx.install(event_log=tmp_log, audit_log=None)
    assert len(_user_subs()) == before + 1

    ctx.uninstall()
    assert len(_user_subs()) == before
    # Further events do not invoke absorb.
    tmp_log.emit("phase_completed", phase="vuln:xss")
    assert ctx.entries == []


# ---- Test 12 — drain_streaming_to_prompt byte-identity vs render direct -


def test_drain_streaming_to_prompt_matches_direct_render(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    """drain_streaming_to_prompt(context, **kwargs) MUST equal
    render_correlation_prompt(findings=context.all_findings(), **kwargs)
    byte-for-byte. The helper is a trivial passthrough; this test pins
    that contract so future migration of the call site is one symbol.
    """
    from sentinel.agent.pentest.correlation import (
        CorrelationContext, drain_streaming_to_prompt, render_correlation_prompt,
    )

    workspace = tmp_path / "ws"
    workspace.mkdir()
    _write_deliverable(workspace, "xss", "vuln")
    _write_queue(workspace, "xss", [
        _make_finding(EvidenceState.VERIFIED, title="a"),
    ])
    _write_deliverable(workspace, "sqli", "vuln")
    _write_queue(workspace, "sqli", [
        _make_finding(EvidenceState.LIVE_CONFIRMED, title="b"),
    ])
    _write_deliverable(workspace, "idor", "exploit")
    _write_queue(workspace, "idor", [
        _make_finding(EvidenceState.VERIFIED, title="c"),
    ])

    ctx = CorrelationContext(workspace=workspace)
    ctx.install(event_log=tmp_log, audit_log=None)
    tmp_log.emit("phase_completed", phase="vuln:xss")
    tmp_log.emit("phase_completed", phase="vuln:sqli")
    tmp_log.emit("phase_completed", phase="exploit:idor")

    kwargs = dict(
        client="acme", engagement_id="eng-1", target="https://t",
        workspace=str(workspace), max_turns=10, max_budget_usd=5.0,
        env_context_block="",
    )

    direct = render_correlation_prompt(findings=ctx.all_findings(), **kwargs)
    drained = drain_streaming_to_prompt(ctx, **kwargs)

    assert drained == direct


# ---- Test 13 — render_correlation_prompt back-compat unchanged ----------


def test_render_correlation_prompt_back_compat_unchanged(tmp_path: Path):
    """When called WITHOUT the findings kwarg, the prompt body must be
    unchanged from the pre-Plan-04.5-02 baseline. Snapshot the shape: when
    findings is None, no 'Pre-filtered findings' block appears.
    """
    from sentinel.agent.pentest.correlation import render_correlation_prompt

    out = render_correlation_prompt(
        client="acme", engagement_id="eng-1", target="https://t",
        workspace=str(tmp_path), max_turns=10, max_budget_usd=5.0,
        env_context_block="",
    )

    # Pre-Plan-03-05 back-compat guarantee — no streaming findings block.
    assert "## Pre-filtered findings" not in out
    # But the canonical correlation prompt body IS present.
    assert "cross-vulnerability correlation agent" in out
    assert "chain_analysis_deliverable.md" in out


# ---- Test 14 — bare-list queue shape tolerance --------------------------


def test_absorb_tolerates_bare_list_queue_shape(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    """Some legacy queues are bare lists rather than dict-with-vulnerabilities.
    Match pipeline._collect_findings_for_verify's tolerance.
    """
    from sentinel.agent.pentest.correlation import CorrelationContext

    workspace = tmp_path / "ws"
    workspace.mkdir()
    _write_deliverable(workspace, "xss", "vuln")
    _write_queue(workspace, "xss", [
        _make_finding(EvidenceState.VERIFIED, title="a"),
    ], shape="list")

    ctx = CorrelationContext(workspace=workspace)
    ctx.install(event_log=tmp_log, audit_log=None)
    tmp_log.emit("phase_completed", phase="vuln:xss")

    assert len(ctx.entries) == 1
    assert len(ctx.entries[0].findings) == 1
