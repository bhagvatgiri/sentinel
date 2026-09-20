"""Hermetic FastAPI TestClient tests for /agent-runs/<job_id>/oauth-installs.

Mirrors tests/test_web_oob_panel.py — create_app() + UIConfig + get_config
override, writes synthetic events-<job_id>.jsonl into the test runs_dir.
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
    log_path = runs_dir / f"events-{job_id}.jsonl"
    rec = {"ts": time.time(), "kind": kind, **payload}
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def test_oauth_installs_empty_state(client_with_runs):
    client, runs = client_with_runs
    _write_event(runs, "job1", "phase_completed", {"phase": "vuln"})
    r = client.get("/agent-runs/job1/oauth-installs")
    assert r.status_code == 200
    assert "no oauth installs" in r.text.lower()


def test_oauth_installs_renders_captures(client_with_runs):
    client, runs = client_with_runs
    _write_event(runs, "job1", "oauth_install_started", {"app_name": "ExampleChat-ws1"})
    _write_event(runs, "job1", "oauth_install_completed",
                 {"app_name": "ExampleChat-ws1", "has_refresh_token": True,
                  "has_user_refresh_token": True})
    r = client.get("/agent-runs/job1/oauth-installs")
    assert r.status_code == 200
    assert "ExampleChat-ws1" in r.text
    # bot + user refresh checkmarks rendered
    assert "✓" in r.text


def test_oauth_installs_renders_failure(client_with_runs):
    client, runs = client_with_runs
    _write_event(runs, "job1", "oauth_install_started", {"app_name": "broken-app"})
    _write_event(runs, "job1", "oauth_install_failed",
                 {"app_name": "broken-app", "error": "consent button missing"})
    r = client.get("/agent-runs/job1/oauth-installs")
    assert r.status_code == 200
    assert "broken-app" in r.text
    assert "consent button missing" in r.text


def test_oauth_installs_unknown_job_empty(client_with_runs):
    client, _ = client_with_runs
    r = client.get("/agent-runs/nonexistent-job/oauth-installs")
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert "no oauth installs" in r.text.lower()
