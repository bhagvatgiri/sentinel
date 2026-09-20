"""CLI `triage-findings` + /findings/<run>/gate dashboard route (UI parity)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.ui.state import UIConfig
from sentinel.web.app import create_app
from sentinel.web.deps import get_config


_RUN = {
    "findings": [
        {"title": "IDOR cross-tenant", "evidence_state": "live_confirmed",
         "description": "another user's PII via unauthorized access", "severity": "high"},
        {"title": "Missing security headers", "evidence_state": "live_confirmed",
         "description": "no CSP / HSTS"},
        {"title": "x", "evidence_state": "live_disproven", "description": "n/a"},
    ]
}


# ---- CLI ------------------------------------------------------------------


def test_cli_triage_findings_text(tmp_path, capsys):
    from sentinel.cli import main
    p = tmp_path / "run.json"
    p.write_text(json.dumps(_RUN))
    rc = main(["triage-findings", "--findings-json", str(p)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "GO" in out and "HOLD" in out
    assert "Summary:" in out
    assert "Never submit HOLD" in out


def test_cli_triage_findings_json(tmp_path, capsys):
    from sentinel.cli import main
    p = tmp_path / "run.json"
    p.write_text(json.dumps(_RUN))
    rc = main(["triage-findings", "--findings-json", str(p), "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["go"] >= 1
    assert data["counts"]["hold"] >= 2


def test_cli_triage_findings_missing_file(tmp_path, capsys):
    from sentinel.cli import main
    rc = main(["triage-findings", "--findings-json", str(tmp_path / "nope.json")])
    assert rc == 2


def test_cli_triage_findings_queue_shape(tmp_path, capsys):
    from sentinel.cli import main
    p = tmp_path / "queue.json"
    p.write_text(json.dumps({"vulnerabilities": _RUN["findings"]}))
    rc = main(["triage-findings", "--findings-json", str(p)])
    assert rc == 0
    assert "Summary:" in capsys.readouterr().out


# ---- dashboard route ------------------------------------------------------


@pytest.fixture
def client_with_runs(tmp_path: Path):
    runs_dir = tmp_path / "runs"; runs_dir.mkdir()
    cfg = UIConfig(
        vault_path=str(tmp_path / "vault"), corpus_dir=str(tmp_path / "corpus"),
        scopes_dir=str(tmp_path / "engagements"), runs_dir=str(runs_dir),
        ollama_host="http://localhost:11434", ollama_model="llama3.1:8b",
        embed_model="nomic-embed-text", project_dir=str(tmp_path),
        workspaces_dir=str(tmp_path / "workspaces"),
    )
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            yield c, runs_dir
    finally:
        app.dependency_overrides.clear()


def test_gate_route_renders(client_with_runs):
    client, runs = client_with_runs
    (runs / "run1.json").write_text(json.dumps(_RUN))
    r = client.get("/findings/run1.json/gate")
    assert r.status_code == 200
    assert "IDOR cross-tenant" in r.text
    assert "Missing security headers" in r.text
    # counts present
    assert "GO" in r.text and "HOLD" in r.text


def test_gate_route_not_shadowed_by_fingerprint(client_with_runs):
    """`gate` must hit the gate route, not the /{fingerprint} PoC route."""
    client, runs = client_with_runs
    (runs / "run1.json").write_text(json.dumps(_RUN))
    r = client.get("/findings/run1.json/gate")
    assert r.status_code == 200
    assert 'data-testid="submission-gate"' in r.text


def test_gate_route_unknown_run_404(client_with_runs):
    client, _ = client_with_runs
    r = client.get("/findings/missing.json/gate")
    assert r.status_code == 404
