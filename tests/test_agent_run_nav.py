"""Hermetic test for the agent-run detail page nav strip.

UI parity check (2026-XX-XX): /agent-runs/<job> must link to the three
panel routes added by Plans 2/3/4 — /oob, /bbot, /visual — so the
operator can navigate to them without typing URLs manually.
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
def client_with_runs(tmp_path: Path, monkeypatch):
    # The agent_run_detail route resolves events via elog.events_path() with
    # no runs_dir kwarg, which defaults to Path("./runs") (cwd-relative).
    # chdir into tmp_path so the synthetic event log lands where the route
    # will read it from.
    monkeypatch.chdir(tmp_path)
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


def _seed_event(runs_dir: Path, job_id: str) -> None:
    log_path = runs_dir / f"events-{job_id}.jsonl"
    rec = {"ts": time.time(), "kind": "phase_started", "phase": "recon"}
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def test_agent_run_page_links_to_oob_panel(client_with_runs):
    client, runs = client_with_runs
    _seed_event(runs, "job1")
    r = client.get("/agent-runs/job1")
    assert r.status_code == 200, r.text[:300]
    assert "/agent-runs/job1/oob" in r.text


def test_agent_run_page_links_to_bbot_panel(client_with_runs):
    client, runs = client_with_runs
    _seed_event(runs, "job1")
    r = client.get("/agent-runs/job1")
    assert r.status_code == 200
    assert "/agent-runs/job1/bbot" in r.text


def test_agent_run_page_links_to_visual_panel(client_with_runs):
    client, runs = client_with_runs
    _seed_event(runs, "job1")
    r = client.get("/agent-runs/job1")
    assert r.status_code == 200
    assert "/agent-runs/job1/visual" in r.text


def test_agent_run_nav_strip_present(client_with_runs):
    """The nav strip itself (data-testid hook) must render."""
    client, runs = client_with_runs
    _seed_event(runs, "job1")
    r = client.get("/agent-runs/job1")
    assert r.status_code == 200
    assert 'data-testid="agent-run-nav"' in r.text
