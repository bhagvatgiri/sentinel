"""Regression guard for issue C2 — agent_run_detail must honor cfg.runs_dir.

Before the fix, the route called `elog.events_path(job_id)` which defaults to
`./runs/` (cwd-relative). Operators running with a custom UIConfig.runs_dir
saw "no event log" on the dashboard even when the events file existed at the
configured path. The OOB / bbot / visual sub-routes already honored cfg via
`_runs_dir(cfg)` — this route was the odd one out.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path):
    from sentinel.web.app import create_app
    from sentinel.web.deps import get_config
    from sentinel.ui.state import UIConfig

    app = create_app()
    cfg = UIConfig(runs_dir=str(tmp_path), corpus_dir=str(tmp_path / "corpus"))
    app.dependency_overrides[get_config] = lambda: cfg
    yield TestClient(app)


def _write_event(tmp_path: Path, run_id: str, kind: str, **payload):
    import time
    log_path = tmp_path / f"events-{run_id}.jsonl"
    record = {"ts": time.time(), "kind": kind, **payload}
    with open(log_path, "a") as f:
        f.write(json.dumps(record) + "\n")


def test_agent_run_detail_reads_from_cfg_runs_dir(client, tmp_path):
    """Events written under cfg.runs_dir are visible on /agent-runs/<job_id>."""
    _write_event(tmp_path, "job-c2-test", "pipeline_started",
                 client="test-client", engagement_id="test", job_id="job-c2-test",
                 target="http://example.com", corpus_dir="", workspace="",
                 repo_path="", audit_log="", auto_brain=False)
    r = client.get("/agent-runs/job-c2-test")
    assert r.status_code == 200, (
        f"expected 200 reading from cfg.runs_dir; got {r.status_code} — "
        f"route is still reading from cwd-relative ./runs/"
    )


def test_agent_run_detail_404_when_no_event_log_anywhere(client, tmp_path):
    """No event log at cfg.runs_dir → 404 (not a 500 / not a silent read of ./runs/)."""
    r = client.get("/agent-runs/nonexistent-job")
    assert r.status_code == 404
