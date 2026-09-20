"""Tests for sentinel.web.run_status.compute_run_status.

This is the single helper that BOTH the agent-runs list view and the
agent-runs detail view call to derive the badge ('running' / 'stalled' /
'completed' / 'failed' / 'aborted' / 'initializing' / 'unknown'). Before
this helper existed, the list view applied a staleness check while the
detail view did not, so the same run rendered as "Stalled" in the list
and "Running" in the detail — the bug these tests pin down.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from sentinel.web.run_status import compute_run_status


def _write_events(path: Path, events: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")


def _touch(path: Path, age_seconds: float) -> None:
    """Backdate the mtime so the staleness check sees the file as `age_seconds` old."""
    t = time.time() - age_seconds
    os.utime(path, (t, t))


def test_missing_path_returns_unknown(tmp_path: Path):
    assert compute_run_status(tmp_path / "does-not-exist.jsonl") == "unknown"


def test_empty_file_recent_is_initializing(tmp_path: Path):
    p = tmp_path / "events.jsonl"
    p.write_text("")  # empty
    # Default fresh mtime — file just created.
    assert compute_run_status(p, stall_after_seconds=60) == "initializing"


def test_empty_file_old_is_stalled(tmp_path: Path):
    p = tmp_path / "events.jsonl"
    p.write_text("")
    _touch(p, age_seconds=600)
    assert compute_run_status(p, stall_after_seconds=60) == "stalled"


def test_fresh_in_flight_run_is_running(tmp_path: Path):
    p = tmp_path / "events.jsonl"
    _write_events(p, [
        {"ts": time.time() - 5, "kind": "pipeline_started", "target": "x"},
        {"ts": time.time() - 1, "kind": "phase_started", "phase": "recon"},
    ])
    # File was just written → mtime is now → age ~0 → 'running'.
    assert compute_run_status(p, stall_after_seconds=60) == "running"


def test_in_flight_run_past_threshold_is_stalled(tmp_path: Path):
    p = tmp_path / "events.jsonl"
    _write_events(p, [
        {"ts": time.time() - 1000, "kind": "pipeline_started", "target": "x"},
        {"ts": time.time() - 900, "kind": "phase_started", "phase": "recon"},
    ])
    _touch(p, age_seconds=900)
    assert compute_run_status(p, stall_after_seconds=60) == "stalled"


def test_pipeline_completed_is_completed(tmp_path: Path):
    p = tmp_path / "events.jsonl"
    _write_events(p, [
        {"ts": 100, "kind": "pipeline_started"},
        {"ts": 200, "kind": "phase_started", "phase": "recon"},
        {"ts": 300, "kind": "phase_completed", "phase": "recon"},
        {"ts": 400, "kind": "pipeline_completed", "total_cost_usd": 1.23},
    ])
    # Even when the file is stale, a terminal marker wins over staleness.
    _touch(p, age_seconds=3600)
    assert compute_run_status(p, stall_after_seconds=60) == "completed"


def test_pipeline_aborted_is_aborted(tmp_path: Path):
    p = tmp_path / "events.jsonl"
    _write_events(p, [
        {"ts": 100, "kind": "pipeline_started"},
        {"ts": 200, "kind": "phase_started", "phase": "recon"},
        {"ts": 300, "kind": "phase_failed", "phase": "recon", "error": "killed"},
        {"ts": 400, "kind": "pipeline_aborted", "reason": "external kill"},
    ])
    _touch(p, age_seconds=3600)
    assert compute_run_status(p, stall_after_seconds=60) == "aborted"


def test_phase_failed_alone_does_not_make_run_failed(tmp_path: Path):
    """phase_failed is NOT a run-terminal kind — the pipeline can keep going.
    A run with phase_failed but no pipeline_completed / pipeline_aborted and
    a fresh mtime should still be 'running'."""
    p = tmp_path / "events.jsonl"
    _write_events(p, [
        {"ts": time.time() - 10, "kind": "pipeline_started"},
        {"ts": time.time() - 5, "kind": "phase_started", "phase": "recon"},
        {"ts": time.time() - 1, "kind": "phase_failed", "phase": "recon",
         "error": "transient"},
    ])
    assert compute_run_status(p, stall_after_seconds=60) == "running"


def test_terminal_marker_in_tail_window_wins_over_mtime(tmp_path: Path):
    """If the tail contains pipeline_completed, status is 'completed' even
    if the file mtime is fresh (e.g. someone touched the file)."""
    p = tmp_path / "events.jsonl"
    _write_events(p, [
        {"ts": 100, "kind": "pipeline_started"},
        {"ts": 200, "kind": "pipeline_completed"},
    ])
    # Fresh mtime, but terminal marker present → completed.
    assert compute_run_status(p, stall_after_seconds=60) == "completed"


def test_whatnot_phase1_corpse_renders_as_aborted(tmp_path: Path, monkeypatch):
    """End-to-end against the shape of the real ExampleMarket-phase1 corpse log
    that Part 1 closed retroactively — three phase_failed + one
    pipeline_aborted should resolve to 'aborted'."""
    p = tmp_path / "events.jsonl"
    closure_ts = 1779853234
    _write_events(p, [
        {"ts": 1779848688.2, "kind": "pipeline_started",
         "target": "https://www.ExampleMarket.com"},
        {"ts": 1779848872.1, "kind": "phase_started", "phase": "vuln:takeover"},
        {"ts": 1779848872.2, "kind": "phase_started", "phase": "vuln:redirect"},
        {"ts": 1779848872.3, "kind": "phase_started", "phase": "vuln:graphql"},
        {"ts": closure_ts, "kind": "phase_failed", "phase": "vuln:takeover",
         "error": "killed externally", "duration_sec": 4361.8},
        {"ts": closure_ts, "kind": "phase_failed", "phase": "vuln:redirect",
         "error": "killed externally", "duration_sec": 4361.8},
        {"ts": closure_ts, "kind": "phase_failed", "phase": "vuln:graphql",
         "error": "killed externally", "duration_sec": 4361.8},
        {"ts": closure_ts, "kind": "pipeline_aborted",
         "reason": "process killed externally; no clean shutdown"},
    ])
    _touch(p, age_seconds=3600)  # corpse — definitely past staleness threshold.
    assert compute_run_status(p, stall_after_seconds=60) == "aborted"


def test_corrupt_tail_lines_do_not_crash(tmp_path: Path):
    """A truncated last line (mid-write crash) shouldn't raise."""
    p = tmp_path / "events.jsonl"
    p.write_text(
        json.dumps({"ts": 100, "kind": "pipeline_started"}) + "\n"
        + '{"ts": 200, "kind": "phase_st'  # truncated, no newline
    )
    # No terminal marker found, mtime is fresh → 'running'.
    assert compute_run_status(p, stall_after_seconds=60) == "running"


def test_stall_threshold_override_takes_effect(tmp_path: Path):
    p = tmp_path / "events.jsonl"
    _write_events(p, [
        {"ts": time.time() - 200, "kind": "pipeline_started"},
    ])
    _touch(p, age_seconds=200)
    # Default 60s → stalled.
    assert compute_run_status(p, stall_after_seconds=60) == "stalled"
    # Bump threshold to 600s → still running.
    assert compute_run_status(p, stall_after_seconds=600) == "running"
