"""Verify _target_from_event_logs auto-discovers the target URL from
the most recent runs/events-*.jsonl when the workspace doesn't have a
session.json (which is the case for Sentinel PentestPipeline workspaces).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from sentinel.agent import event_log as elog
from sentinel.cli import _target_from_event_logs


def _write_event_log(runs_dir: Path, job_id: str, *,
                     workspace: str, target: str = "https://t.example.com") -> Path:
    runs_dir.mkdir(parents=True, exist_ok=True)
    p = runs_dir / f"events-{job_id}.jsonl"
    p.write_text(
        json.dumps({
            "ts": 1000.0, "kind": elog.KIND_PIPELINE_STARTED,
            "client": "testco", "engagement_id": "test-eng",
            "target": target, "job_id": job_id,
            "workspace": workspace, "audit_log": "/tmp/.audit",
            "corpus_dir": None, "repo_path": None, "auto_brain": False,
        }) + "\n"
    )
    return p


def test_target_discovered_from_event_log(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    _write_event_log(runs, "job1",
                     workspace="/path/to/workspaces/2026-test-eng",
                     target="https://discovered.example.com")
    monkeypatch.setattr(elog, "DEFAULT_EVENTS_DIR", runs)
    target = _target_from_event_logs("2026-test-eng")
    assert target == "https://discovered.example.com"


def test_target_missing_event_log_returns_none(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    runs.mkdir()
    monkeypatch.setattr(elog, "DEFAULT_EVENTS_DIR", runs)
    target = _target_from_event_logs("nope")
    assert target is None


def test_target_picks_matching_workspace(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    _write_event_log(runs, "job-a",
                     workspace="/wsroot/other-engagement",
                     target="https://wrong.example.com")
    _write_event_log(runs, "job-b",
                     workspace="/wsroot/2026-test-eng",
                     target="https://right.example.com")
    monkeypatch.setattr(elog, "DEFAULT_EVENTS_DIR", runs)
    target = _target_from_event_logs("2026-test-eng")
    assert target == "https://right.example.com"


def test_target_event_log_no_matching_event(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    runs.mkdir()
    # Event log exists but has no pipeline_started for our workspace
    p = runs / "events-other.jsonl"
    p.write_text(json.dumps({
        "ts": 1000.0, "kind": elog.KIND_PIPELINE_STARTED,
        "workspace": "/path/different-eng", "target": "https://x.com",
    }) + "\n")
    monkeypatch.setattr(elog, "DEFAULT_EVENTS_DIR", runs)
    target = _target_from_event_logs("our-eng")
    assert target is None
