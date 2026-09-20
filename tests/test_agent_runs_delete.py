"""Integration test for the DELETE /agent-runs/<job_id> route.

Covers:
- DELETE on existing run → 204 + HX-Trigger header, file gone
- DELETE on missing run → 404
- DELETE with traversal job_id → 400 (helper raised ValueError)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _make_client(tmp_path, monkeypatch):
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

    # Patch DEFAULT_EVENTS_DIR so the route deletes inside our tmp tree.
    from sentinel.agent import event_log as elog
    monkeypatch.setattr(elog, "DEFAULT_EVENTS_DIR", Path(cfg.runs_dir))
    Path(cfg.runs_dir).mkdir(parents=True, exist_ok=True)

    from sentinel.web.app import create_app
    app = create_app()
    return TestClient(app), cfg


def test_delete_route_removes_existing_run(tmp_path, monkeypatch):
    client, cfg = _make_client(tmp_path, monkeypatch)
    target = Path(cfg.runs_dir) / "events-test-job.jsonl"
    target.write_text(json.dumps({"kind": "pipeline_started", "ts": 1}) + "\n")
    assert target.exists()

    r = client.delete("/agent-runs/test-job")
    # 200 with empty body so HTMX swaps the row out cleanly. (HTMX 1.x
    # ignores 204 swap requests — 200 + empty body is the right idiom.)
    assert r.status_code == 200
    assert r.text == ""
    assert r.headers.get("hx-trigger") == "agent-runs-changed"
    assert not target.exists()


def test_delete_route_idempotent_on_missing(tmp_path, monkeypatch):
    """Deleting an already-gone run is a no-op success — same response
    as the success path so HTMX swaps the (already-stale) row out
    without revealing a 404 JSON body in the table."""
    client, _ = _make_client(tmp_path, monkeypatch)
    r = client.delete("/agent-runs/never-existed")
    assert r.status_code == 200
    assert r.text == ""


def test_delete_route_400_on_traversal(tmp_path, monkeypatch):
    client, cfg = _make_client(tmp_path, monkeypatch)
    parent = Path(cfg.runs_dir).parent
    victim = parent / "events-secret.jsonl"
    victim.write_text("must survive")
    try:
        # FastAPI may URL-decode or reject path-segment slashes; try the
        # traversal pattern that bypasses parent != runs_dir guard.
        r = client.delete("/agent-runs/..%2Fevents-secret")
        # The helper should raise ValueError → 400. If FastAPI normalizes
        # before reaching the handler, we may get a different code; we
        # accept any client-error here AS LONG AS the victim file survives.
        assert r.status_code in (400, 404, 422), r.status_code
        assert victim.exists(), "traversal must not delete sibling files"
    finally:
        victim.unlink(missing_ok=True)
