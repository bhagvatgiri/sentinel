"""Hermetic FastAPI TestClient tests for /agent-runs/<job_id>/visual route.

Mirrors tests/test_web_bbot_panel.py — uses create_app() + UIConfig +
get_config override, writes synthetic events-<job_id>.jsonl into the
test runs_dir.
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
    """Append one event-log line. event_log writes ts + kind + flat payload."""
    log_path = runs_dir / f"events-{job_id}.jsonl"
    rec = {"ts": time.time(), "kind": kind, **payload}
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def test_visual_panel_empty_state(client_with_runs):
    """With no visual events, the panel renders an empty state."""
    client, runs = client_with_runs
    # Unrelated noise event — panel must ignore it.
    _write_event(runs, "job1", "phase_completed", {"phase": "recon"})
    r = client.get("/agent-runs/job1/visual")
    assert r.status_code == 200
    body = r.text.lower()
    assert ("no screenshots" in body or "no visual" in body or
            "no captures" in body), (
        f"empty-state copy missing; got: {body[:300]}"
    )


def test_visual_panel_renders_captures(client_with_runs):
    """visual_recon_captured + visual_triage_completed render together."""
    client, runs = client_with_runs
    _write_event(runs, "job1", "visual_recon_captured", {
        "url": "https://admin.target.com",
        "screenshot_path": "/runs/.tmp/screenshots/job1/admin.png",
    })
    _write_event(runs, "job1", "visual_triage_completed", {
        "screenshot_path": "/runs/.tmp/screenshots/job1/admin.png",
        "description": "Jenkins login page with default install hint visible",
    })
    r = client.get("/agent-runs/job1/visual")
    assert r.status_code == 200
    assert "admin.target.com" in r.text
    assert "Jenkins" in r.text or "jenkins" in r.text.lower()


def test_visual_panel_capture_without_triage(client_with_runs):
    """A capture without a matching triage still renders; description blank/N/A."""
    client, runs = client_with_runs
    _write_event(runs, "job1", "visual_recon_captured", {
        "url": "https://untriaged.target.com",
        "screenshot_path": "/runs/.tmp/screenshots/job1/untriaged.png",
    })
    r = client.get("/agent-runs/job1/visual")
    assert r.status_code == 200
    assert "untriaged.target.com" in r.text
