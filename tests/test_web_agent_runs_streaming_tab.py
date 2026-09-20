"""Phase 4.5 Plan 04.5-06 (STREAM-06) — dashboard Streaming panel tests.

Hermetic FastAPI TestClient tests covering:

- ``derive_streaming_state(events)`` helper: buckets ``subscriber_fired`` /
  ``streaming_phase_started`` / ``subscribers_halted`` events into a
  per-downstream-phase dict (correlation / report / verify-phase-03 /
  cost_cap_watchdog / _other).
- ``/agent-runs/<job_id>`` route renders the Streaming panel inline with
  the existing phase ladder + brain panel + activity stream.
- ``/agent-runs/<job_id>/refresh`` HTMX partial includes the panel so the
  2s-poll picks it up during a live run.
- Halted banner only renders when ``subscribers_halted`` has fired.
- Empty state renders cleanly for legacy runs with no streaming activity.

All tests run with the default ``-m 'not integration'`` filter; no network,
no docker, no live shim, no live Ollama. Test fixture seeds a tmp events
JSONL via ``EventLog.emit`` (the same writer side Plan 04.5-01 landed) +
``app.dependency_overrides`` shapes for the FastAPI TestClient pattern
established in tests/test_agent_runs_delete.py + tests/test_web_state_route.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# ---- helpers --------------------------------------------------------------


def _make_client(tmp_path, monkeypatch):
    """Hermetic FastAPI TestClient with runs_dir pointed at tmp_path.

    Mirrors tests/test_agent_runs_delete.py exactly so the test harness is
    consistent with the other agent-runs route tests.
    """
    from fastapi.testclient import TestClient
    from sentinel.ui.state import UIConfig
    cfg = UIConfig(
        vault_path=str(tmp_path / "vault"),
        corpus_dir=str(tmp_path / "corpus"),
        scopes_dir=str(tmp_path / "scopes"),
        runs_dir=str(tmp_path / "runs"),
        ollama_host="http://localhost:11434",
        ollama_model="llama3.1:8b",
        embed_model="nomic-embed-text",
        project_dir=str(tmp_path),
    )
    monkeypatch.setattr(UIConfig, "load", classmethod(lambda cls: cfg))

    # Patch DEFAULT_EVENTS_DIR so the route resolves event-log paths inside
    # our tmp tree (the route uses elog.events_path(job_id) which expands
    # DEFAULT_EVENTS_DIR at call time).
    from sentinel.agent import event_log as elog
    monkeypatch.setattr(elog, "DEFAULT_EVENTS_DIR", Path(cfg.runs_dir))
    Path(cfg.runs_dir).mkdir(parents=True, exist_ok=True)

    from sentinel.web.app import create_app
    app = create_app()
    return TestClient(app), cfg


def _seed_events(runs_dir: Path, job_id: str, events: list[dict]) -> Path:
    """Write a synthetic events-<job_id>.jsonl into runs_dir, return the path.

    Each dict gets a ``ts`` injected (monotonic per-event index) if it
    doesn't already have one — so test assertions on last_absorbed_ts /
    install_ts have a deterministic value.
    """
    runs_dir.mkdir(parents=True, exist_ok=True)
    path = runs_dir / f"events-{job_id}.jsonl"
    lines = []
    for idx, ev in enumerate(events, start=1):
        ev_out = dict(ev)
        ev_out.setdefault("ts", float(idx))
        lines.append(json.dumps(ev_out, default=str))
    path.write_text("\n".join(lines) + "\n")
    return path


# ---- Test 1 — derive_streaming_state: empty events -----------------------


def test_derive_streaming_state_empty_events():
    """An empty event list returns a clean shape with all zeros / Nones."""
    from sentinel.web.routes.agent_runs import derive_streaming_state
    state = derive_streaming_state([])
    assert state["phases"] == {}
    assert state["halted"]["is_halted"] is False
    assert state["halted"]["reason"] is None
    assert state["halted"]["ts"] is None
    assert state["halted"]["triggered_by"] is None
    assert state["total_subscriber_fired"] == 0
    assert state["total_streaming_phases"] == 0


# ---- Test 2 — derive_streaming_state: install-only -----------------------


def test_derive_streaming_state_install_only():
    """A streaming_phase_started event records install_ts; absorbed_count
    stays at 0 until a subscriber_fired event lands."""
    from sentinel.web.routes.agent_runs import derive_streaming_state
    events = [
        {"kind": "streaming_phase_started", "phase": "correlation", "ts": 100.0},
    ]
    state = derive_streaming_state(events)
    assert "correlation" in state["phases"]
    assert state["phases"]["correlation"]["install_ts"] == 100.0
    assert state["phases"]["correlation"]["absorbed_count"] == 0
    assert state["phases"]["correlation"]["error_count"] == 0
    assert state["phases"]["correlation"]["last_absorbed_ts"] is None
    assert state["phases"]["correlation"]["per_trigger"] == {}
    assert state["total_subscriber_fired"] == 0
    assert state["total_streaming_phases"] == 1


# ---- Test 3 — derive_streaming_state: single absorb ----------------------


def test_derive_streaming_state_single_absorb():
    """One subscriber_fired event (callback_name='correlation.absorb') is
    bucketed under 'correlation' with absorbed_count=1."""
    from sentinel.web.routes.agent_runs import derive_streaming_state
    events = [
        {"kind": "streaming_phase_started", "phase": "correlation", "ts": 100.0},
        {
            "kind": "subscriber_fired",
            "callback_name": "correlation.absorb",
            "trigger_kind": "phase_completed",
            "trigger_ts": 110.5,
            "outcome": "ok",
            "ts": 110.6,
        },
    ]
    state = derive_streaming_state(events)
    info = state["phases"]["correlation"]
    assert info["absorbed_count"] == 1
    assert info["per_trigger"]["phase_completed"] == 1
    assert info["last_absorbed_ts"] == 110.6
    assert info["error_count"] == 0
    assert state["total_subscriber_fired"] == 1


# ---- Test 4 — derive_streaming_state: error outcome counted --------------


def test_derive_streaming_state_error_counted():
    """A subscriber_fired event with outcome='error' increments error_count."""
    from sentinel.web.routes.agent_runs import derive_streaming_state
    events = [
        {
            "kind": "subscriber_fired",
            "callback_name": "correlation.absorb",
            "trigger_kind": "phase_completed",
            "outcome": "error",
            "error": "RuntimeError('synthetic')",
            "ts": 10.0,
        },
    ]
    state = derive_streaming_state(events)
    info = state["phases"]["correlation"]
    assert info["absorbed_count"] == 1
    assert info["error_count"] == 1


# ---- Test 5 — derive_streaming_state: halt fired -------------------------


def test_derive_streaming_state_halt_fired():
    """A subscribers_halted event records reason / ts / triggered_by."""
    from sentinel.web.routes.agent_runs import derive_streaming_state
    events = [
        {
            "kind": "subscribers_halted",
            "reason": "cost_cap_tripped",
            "triggered_by": "scan_aborted_cost_cap",
            "ts": 200.0,
        },
    ]
    state = derive_streaming_state(events)
    assert state["halted"]["is_halted"] is True
    assert state["halted"]["reason"] == "cost_cap_tripped"
    assert state["halted"]["ts"] == 200.0
    assert state["halted"]["triggered_by"] == "scan_aborted_cost_cap"


# ---- Test 6 — derive_streaming_state: multiple phases --------------------


def test_derive_streaming_state_multiple_phases():
    """Mix of correlation.absorb + report.absorb + verify_phase_03.streaming
    callback_names produces 3 user-phase buckets; total_subscriber_fired is
    the sum across all phases."""
    from sentinel.web.routes.agent_runs import derive_streaming_state
    events = [
        {"kind": "streaming_phase_started", "phase": "correlation", "ts": 1.0},
        {"kind": "streaming_phase_started", "phase": "report", "ts": 2.0},
        {"kind": "streaming_phase_started", "phase": "verify-phase-03", "ts": 3.0},
        {
            "kind": "subscriber_fired",
            "callback_name": "correlation.absorb",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
            "ts": 10.0,
        },
        {
            "kind": "subscriber_fired",
            "callback_name": "report.absorb",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
            "ts": 11.0,
        },
        {
            "kind": "subscriber_fired",
            "callback_name": "verify_phase_03.streaming",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
            "ts": 12.0,
        },
        {
            "kind": "subscriber_fired",
            "callback_name": "verify_phase_03.streaming",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
            "ts": 13.0,
        },
    ]
    state = derive_streaming_state(events)
    # Should bucket into 3 user-visible phases (correlation / report /
    # verify-phase-03). cost_cap_watchdog / _other only appear when their
    # callback_names show up; we don't seed any so they should be absent.
    assert "correlation" in state["phases"]
    assert "report" in state["phases"]
    assert "verify-phase-03" in state["phases"]
    assert "cost_cap_watchdog" not in state["phases"]
    assert "_other" not in state["phases"]
    # total_subscriber_fired = sum of all absorbed_counts.
    assert state["total_subscriber_fired"] == 4
    # total_streaming_phases counts distinct phases that installed OR fired.
    assert state["total_streaming_phases"] == 3


# ---- Test 7 — derive_streaming_state: unknown callback_name → _other -----


def test_derive_streaming_state_unknown_callback_bucketed_under_other():
    """A subscriber_fired with an unknown callback_name lands in '_other'
    (defensive — future subscribers don't crash the dashboard)."""
    from sentinel.web.routes.agent_runs import derive_streaming_state
    events = [
        {
            "kind": "subscriber_fired",
            "callback_name": "something.new.future.callback",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
            "ts": 50.0,
        },
    ]
    state = derive_streaming_state(events)
    assert "_other" in state["phases"]
    assert state["phases"]["_other"]["absorbed_count"] == 1


# ---- Test 8 — route renders Streaming panel (happy path) -----------------


def test_route_renders_streaming_panel_happy_path(tmp_path, monkeypatch):
    """A tmp events JSONL with the full streaming event mix renders a panel
    showing all three downstream phases."""
    client, cfg = _make_client(tmp_path, monkeypatch)
    runs_dir = Path(cfg.runs_dir)
    _seed_events(runs_dir, "happy-job", [
        {"kind": "pipeline_started", "target": "https://example.test"},
        {"kind": "phase_started", "phase": "recon"},
        {"kind": "streaming_phase_started", "phase": "correlation"},
        {"kind": "streaming_phase_started", "phase": "report"},
        {"kind": "streaming_phase_started", "phase": "verify-phase-03"},
        {
            "kind": "subscriber_fired",
            "callback_name": "correlation.absorb",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
        },
        {
            "kind": "subscriber_fired",
            "callback_name": "report.absorb",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
        },
        {
            "kind": "subscriber_fired",
            "callback_name": "verify_phase_03.streaming",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
        },
    ])

    r = client.get("/agent-runs/happy-job")
    assert r.status_code == 200
    assert 'data-testid="streaming-panel"' in r.text
    # All three user-visible downstream phase cards render.
    assert 'data-testid="streaming-phase-correlation"' in r.text
    assert 'data-testid="streaming-phase-report"' in r.text
    assert 'data-testid="streaming-phase-verify-phase-03"' in r.text
    # Empty state should NOT render — there IS streaming activity.
    assert 'data-testid="streaming-empty-state"' not in r.text


# ---- Test 9 — route renders empty state for legacy runs ------------------


def test_route_renders_empty_state_for_legacy_runs(tmp_path, monkeypatch):
    """Legacy run (only pipeline + phase events, NO streaming activity)
    renders the empty-state message, not a misleading empty panel."""
    client, cfg = _make_client(tmp_path, monkeypatch)
    runs_dir = Path(cfg.runs_dir)
    _seed_events(runs_dir, "legacy-job", [
        {"kind": "pipeline_started", "target": "https://example.test"},
        {"kind": "phase_started", "phase": "recon"},
        {"kind": "phase_completed", "phase": "recon", "cost_usd": 0.05, "turns": 12},
    ])

    r = client.get("/agent-runs/legacy-job")
    assert r.status_code == 200
    # Panel still renders (so operators always know what they're looking at).
    assert 'data-testid="streaming-panel"' in r.text
    # Empty state explicitly says nothing happened.
    assert 'data-testid="streaming-empty-state"' in r.text
    # Halted banner ABSENT (no subscribers_halted event).
    assert 'data-testid="streaming-halted-banner"' not in r.text


# ---- Test 10 — route renders halted banner -------------------------------


def test_route_renders_halted_banner(tmp_path, monkeypatch):
    """A subscribers_halted event in the fixture renders a red halted banner
    that mentions the reason. This is the load-bearing UI surface for
    Plan 04.5-05's cost-cap watchdog."""
    client, cfg = _make_client(tmp_path, monkeypatch)
    runs_dir = Path(cfg.runs_dir)
    _seed_events(runs_dir, "halted-job", [
        {"kind": "pipeline_started", "target": "https://example.test"},
        {"kind": "streaming_phase_started", "phase": "correlation"},
        {
            "kind": "subscriber_fired",
            "callback_name": "correlation.absorb",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
        },
        {
            "kind": "subscribers_halted",
            "reason": "cost_cap_tripped",
            "triggered_by": "scan_aborted_cost_cap",
        },
    ])

    r = client.get("/agent-runs/halted-job")
    assert r.status_code == 200
    # Halted banner present AND mentions the reason.
    assert 'data-testid="streaming-halted-banner"' in r.text
    assert "cost_cap_tripped" in r.text


# ---- Test 11 — HTMX refresh partial includes the panel -------------------


def test_htmx_refresh_partial_includes_streaming_panel(tmp_path, monkeypatch):
    """The 2s-poll HTMX partial route includes the streaming panel — proves
    the panel updates live during a run, not just on the initial full-page
    load. Without this the panel would freeze at page-load state."""
    client, cfg = _make_client(tmp_path, monkeypatch)
    runs_dir = Path(cfg.runs_dir)
    _seed_events(runs_dir, "refresh-job", [
        {"kind": "pipeline_started", "target": "https://example.test"},
        {"kind": "streaming_phase_started", "phase": "correlation"},
        {
            "kind": "subscriber_fired",
            "callback_name": "correlation.absorb",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
        },
    ])

    r = client.get("/agent-runs/refresh-job/refresh")
    assert r.status_code == 200
    # The HTMX partial response MUST include the streaming panel.
    assert 'data-testid="streaming-panel"' in r.text
    # And the correlation card.
    assert 'data-testid="streaming-phase-correlation"' in r.text


# ---- Test 12 — no 500 on missing event log -------------------------------


def test_route_returns_404_on_missing_event_log_not_500(tmp_path, monkeypatch):
    """The streaming-panel extension MUST NOT change the existing 404
    behavior when an event log doesn't exist. Defensive — the new template
    context kwarg should not crash on the missing-log path."""
    client, _cfg = _make_client(tmp_path, monkeypatch)
    r = client.get("/agent-runs/nonexistent-job")
    # Existing behavior: 404 (HTTPException raised before template render).
    assert r.status_code == 404


# ---- Test 13 — per_trigger counts under many events ----------------------


def test_derive_streaming_state_per_trigger_counts():
    """Multiple subscriber_fired events for the same downstream phase with
    a mix of trigger_kinds produce a correct per_trigger histogram. The
    `scan_aborted_cost_cap` callback (event_subscribers.cost_cap_watchdog)
    is bucketed UNDER cost_cap_watchdog, NOT under correlation — so
    correlation.per_trigger only counts the 4 phase_completed events."""
    from sentinel.web.routes.agent_runs import derive_streaming_state
    events = [
        # 4 correlation absorbs of phase_completed
        {
            "kind": "subscriber_fired",
            "callback_name": "correlation.absorb",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
            "ts": 1.0,
        },
        {
            "kind": "subscriber_fired",
            "callback_name": "correlation.absorb",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
            "ts": 2.0,
        },
        {
            "kind": "subscriber_fired",
            "callback_name": "correlation.absorb",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
            "ts": 3.0,
        },
        {
            "kind": "subscriber_fired",
            "callback_name": "correlation.absorb",
            "trigger_kind": "phase_completed",
            "outcome": "ok",
            "ts": 4.0,
        },
        # 1 cost-cap watchdog fire on scan_aborted_cost_cap (NOT correlation)
        {
            "kind": "subscriber_fired",
            "callback_name": "event_subscribers.cost_cap_watchdog",
            "trigger_kind": "scan_aborted_cost_cap",
            "outcome": "ok",
            "ts": 5.0,
        },
    ]
    state = derive_streaming_state(events)
    # Correlation phase only sees the 4 phase_completed triggers.
    assert state["phases"]["correlation"]["per_trigger"] == {"phase_completed": 4}
    # Cost-cap watchdog gets its own bucket with the single fire.
    assert state["phases"]["cost_cap_watchdog"]["absorbed_count"] == 1


# ---- Test 14 — cost-cap watchdog footer row renders ----------------------


def test_route_renders_cost_cap_watchdog_footer_row(tmp_path, monkeypatch):
    """When the cost-cap watchdog has fired, the panel renders a small
    footer row showing fire count. Proves the watchdog is observable
    on the dashboard (per CLAUDE.md UI parity rule for Plan 04.5-05)."""
    client, cfg = _make_client(tmp_path, monkeypatch)
    runs_dir = Path(cfg.runs_dir)
    _seed_events(runs_dir, "watchdog-job", [
        {"kind": "pipeline_started", "target": "https://example.test"},
        {"kind": "streaming_phase_started", "phase": "correlation"},
        {
            "kind": "subscriber_fired",
            "callback_name": "event_subscribers.cost_cap_watchdog",
            "trigger_kind": "scan_aborted_cost_cap",
            "outcome": "ok",
        },
    ])

    r = client.get("/agent-runs/watchdog-job")
    assert r.status_code == 200
    assert 'data-testid="streaming-cost-cap-watchdog-row"' in r.text
    # Footer text mentions the fire count.
    assert "cost-cap watchdog: fired 1" in r.text
