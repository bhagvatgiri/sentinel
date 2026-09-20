"""Hermetic FastAPI TestClient tests for /agent-runs/<job_id>/bbot route.

Mirrors tests/test_web_oob_panel.py — uses create_app() +
UIConfig + get_config override, writes synthetic events-<job_id>.jsonl
into the test runs_dir.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.ui.state import UIConfig
from sentinel.web.app import create_app
from sentinel.web.deps import get_config


@pytest.fixture
def client_with_runs(tmp_path: Path):
    """TestClient with UIConfig.runs_dir pointed at tmp_path/runs."""
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    cfg = UIConfig(
        vault_path=str(tmp_path / "vault"),
        corpus_dir=str(tmp_path / "corpus"),
        scopes_dir=str(tmp_path / "engagements"),
        runs_dir=str(runs_dir),
        ollama_host="http://localhost:11434",
        ollama_model="llama3.1:8b",
        embed_model="nomic-embed-text",
        project_dir=str(tmp_path),
    )
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            yield c, runs_dir
    finally:
        app.dependency_overrides.clear()


def _write_event(runs_dir: Path, job_id: str, kind: str, payload: dict) -> None:
    """Append one event-log line for the test job (event_log.emit shape:
    ts + kind + flat payload keys, see sentinel/agent/event_log.py)."""
    log_path = runs_dir / f"events-{job_id}.jsonl"
    rec = {"ts": time.time(), "kind": kind, **payload}
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def test_bbot_panel_empty_state(client_with_runs):
    """With no bbot events, the panel renders an empty state."""
    client, runs = client_with_runs
    # Some unrelated noise event — verifies the panel ignores non-bbot kinds.
    _write_event(runs, "job1", "phase_completed", {"phase": "recon"})
    r = client.get("/agent-runs/job1/bbot")
    assert r.status_code == 200
    body = r.text.lower()
    assert ("no bbot" in body or "no recon" in body or "no runs" in body), (
        f"empty-state copy missing; got: {body[:300]}"
    )


def test_bbot_panel_renders_run(client_with_runs):
    client, runs = client_with_runs
    _write_event(runs, "job1", "bbot_run_completed", {
        "target": "target.com",
        "modules": "subfinder,httpx",
        "intensity": "passive",
        "total_events": 42,
        "duration_s": 18.5,
    })
    r = client.get("/agent-runs/job1/bbot")
    assert r.status_code == 200
    assert "target.com" in r.text
    assert "subfinder" in r.text or "42" in r.text


def test_bbot_panel_multiple_runs(client_with_runs):
    client, runs = client_with_runs
    _write_event(runs, "job1", "bbot_run_completed", {
        "target": "t1.com", "modules": "subfinder",
        "intensity": "passive", "total_events": 10, "duration_s": 5.0,
    })
    _write_event(runs, "job1", "bbot_run_completed", {
        "target": "t2.com", "modules": "all",
        "intensity": "active", "total_events": 25, "duration_s": 12.5,
    })
    r = client.get("/agent-runs/job1/bbot")
    assert r.status_code == 200
    assert "t1.com" in r.text and "t2.com" in r.text
