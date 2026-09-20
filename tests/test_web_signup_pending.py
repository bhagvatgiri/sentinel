"""FastAPI TestClient tests for the signup-pending dashboard surface.

Covers:
  1. Empty /signup-pending → 200 with "No pending"
  2. /signup-pending with one pending → 200 with URL + reason rendered
  3. POST /signup-pending/<rid>/complete → appends completion + password
     never appears in response body
  4. Per-job /agent-runs/<id>/signup/pending empty → 200, no exception
  5. Per-job /agent-runs/<id>/signup/pending with pending → 200 with URL
  6. /agent-runs/<id>/captcha-count fragment: 3 events → body contains "3";
     missing events file → 200 with body containing "0"
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


def _write_pending(runs_dir: Path, job_id: str, *, rid: str, url: str,
                    reason: str = "test", phase: str = "vuln:auth") -> None:
    log = runs_dir / f"signup-{job_id}.jsonl"
    log.write_text(json.dumps({
        "ts": time.time(), "id": rid, "status": "pending",
        "url": url, "reason": reason, "phase": phase,
    }, sort_keys=True) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Test 1: empty cross-job page
# ---------------------------------------------------------------------------
def test_signup_pending_empty_state_renders_200(client_with_runs):
    client, _ = client_with_runs
    resp = client.get("/signup-pending")
    assert resp.status_code == 200
    assert "No pending" in resp.text


# ---------------------------------------------------------------------------
# Test 2: cross-job page with one pending
# ---------------------------------------------------------------------------
def test_signup_pending_renders_pending_records(client_with_runs):
    client, runs = client_with_runs
    _write_pending(runs, "test-job-1",
                    rid="rid12345678",
                    url="https://target.example.com/signup",
                    reason="captcha unsolvable")
    resp = client.get("/signup-pending")
    assert resp.status_code == 200
    assert "target.example.com/signup" in resp.text
    assert "captcha unsolvable" in resp.text


# ---------------------------------------------------------------------------
# Test 3: POST complete appends record + password NEVER in response body
# ---------------------------------------------------------------------------
def test_post_complete_appends_record_and_hides_password(client_with_runs):
    client, runs = client_with_runs
    _write_pending(runs, "test-job-2", rid="r2",
                    url="https://t.example.com/signup")
    resp = client.post(
        "/signup-pending/r2/complete",
        data={
            "job_id": "test-job-2",
            "username": "alice",
            "password": "hunter2-super-secret",
            "operator_note": "test signal",
        },
    )
    assert resp.status_code == 200
    # Password must NEVER be echoed in HTML.
    assert "hunter2-super-secret" not in resp.text
    # Completion record was appended.
    log = runs / "signup-test-job-2.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines()
    completions = [
        json.loads(l) for l in lines if l.strip()
        and json.loads(l).get("status") == "completed"
    ]
    assert len(completions) == 1
    assert completions[0]["username"] == "alice"
    assert completions[0]["password"] == "hunter2-super-secret"
    assert completions[0]["id"] == "r2"


# ---------------------------------------------------------------------------
# Test 4: per-job pending — empty
# ---------------------------------------------------------------------------
def test_per_job_signup_pending_empty(client_with_runs):
    client, _ = client_with_runs
    resp = client.get("/agent-runs/no-such-job/signup/pending")
    assert resp.status_code == 200
    # No exception, body is minimal (template renders an invisible <div>)


# ---------------------------------------------------------------------------
# Test 5: per-job pending with one record
# ---------------------------------------------------------------------------
def test_per_job_signup_pending_with_record(client_with_runs):
    client, runs = client_with_runs
    _write_pending(runs, "live-job-5", rid="r5",
                    url="https://api.example.com/register")
    resp = client.get("/agent-runs/live-job-5/signup/pending")
    assert resp.status_code == 200
    assert "api.example.com/register" in resp.text


# ---------------------------------------------------------------------------
# Test 6: captcha-count fragment — 3 events → "3"; missing file → "0"
# ---------------------------------------------------------------------------
def test_captcha_count_fragment_renders_event_count(client_with_runs):
    client, runs = client_with_runs
    events = runs / "events-captcha-job.jsonl"
    # Mix 3 captcha_solved with 2 unrelated events
    lines = []
    for i in range(3):
        lines.append(json.dumps({
            "ts": time.time(), "kind": "captcha_solved",
            "url": f"https://t.example.com/p{i}",
            "type": "DataDome", "solver": "nopecha",
        }))
    lines.append(json.dumps({"ts": time.time(), "kind": "browser_get"}))
    lines.append(json.dumps({"ts": time.time(), "kind": "phase_started"}))
    events.write_text("\n".join(lines) + "\n", encoding="utf-8")

    resp = client.get("/agent-runs/captcha-job/captcha-count")
    assert resp.status_code == 200
    assert "3" in resp.text, (
        f"expected count 3 in body, got: {resp.text!r}"
    )


def test_captcha_count_fragment_zero_when_no_events_file(client_with_runs):
    client, _ = client_with_runs
    resp = client.get("/agent-runs/never-ran/captcha-count")
    assert resp.status_code == 200
    # Empty-state body MUST still contain the literal '0' so HTMX polling
    # has a deterministic shape (template renders hidden div with the count).
    assert "0" in resp.text
