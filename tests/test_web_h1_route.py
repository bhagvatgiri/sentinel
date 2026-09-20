"""ENG-04 regression tests for the /h1/submissions FastAPI route + the
CLI `sentinel h1 ...` subcommands.

Hermetic — overrides `get_config` via `app.dependency_overrides` so no
test touches the operator's real `~/.sentinel/` config (canonical
pattern established by Plan 01-03 `test_web_state_route.py`). The CLI
tests use direct `_do_h1` invocation rather than subprocess to keep
the test fast and to avoid loading the full argparse env.

UI parity is mandatory: every CLI surface must have a `/h1/submissions`
dashboard surface; this test file holds the regression for both.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


# ---- /h1/submissions FastAPI route tests --------------------------------


def _make_client(tmp_path: Path) -> TestClient:
    """Build a TestClient with a hermetic `get_config` override pointing
    at `tmp_path`."""
    from sentinel.web.app import create_app
    from sentinel.web.deps import get_config
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

    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    return TestClient(app)


def _write_ledger(tmp_path: Path, rows: list[dict]) -> Path:
    """Write a fixture ledger under tmp_path/.sentinel/h1-submissions.jsonl
    so the route picks it up via Path.home() monkeypatching."""
    sd = tmp_path / ".sentinel"
    sd.mkdir(parents=True, exist_ok=True)
    ledger = sd / "h1-submissions.jsonl"
    with ledger.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    return ledger


def test_h1_submissions_route_renders_ledger(tmp_path: Path, monkeypatch):
    """GET /h1/submissions renders the ledger table with data-testid
    anchor + at least one row from the fixture ledger."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    _write_ledger(tmp_path, [
        {
            "submitted_at": "2026-XX-XXT15:00:00Z",
            "engagement_id": "acme-bbp",
            "file": "01-xss.md",
            "title": "Stored XSS in /comments",
            "h1_report_id": "9999999",
            "h1_url": "https://hackerone.com/reports/9999999",
            "weakness": "CWE-79",
            "severity": "high",
            "operator": "jack",
        },
    ])

    client = _make_client(tmp_path)
    r = client.get("/h1/submissions")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    body = r.text
    assert 'data-testid="h1-submission-ledger"' in body
    assert "acme-bbp" in body
    assert "01-xss.md" in body
    assert "9999999" in body


def test_h1_submissions_route_json_surface(tmp_path: Path, monkeypatch):
    """Accept: application/json returns a JSON rows array."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    _write_ledger(tmp_path, [
        {
            "submitted_at": "2026-XX-XXT15:00:00Z",
            "engagement_id": "acme-bbp",
            "file": "01-xss.md",
            "title": "X",
            "h1_report_id": "9999999",
            "h1_url": "",
            "weakness": "",
            "severity": "high",
            "operator": "",
        },
    ])

    client = _make_client(tmp_path)
    r = client.get("/h1/submissions", headers={"Accept": "application/json"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert "rows" in body
    assert len(body["rows"]) == 1
    assert body["rows"][0]["engagement_id"] == "acme-bbp"


def test_h1_submissions_route_empty_state(tmp_path: Path, monkeypatch):
    """When the ledger is missing, the HTML route still renders (200)
    with an empty-state placeholder and the data-testid anchor."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    # No ledger written.
    client = _make_client(tmp_path)
    r = client.get("/h1/submissions")
    assert r.status_code == 200
    body = r.text
    assert 'data-testid="h1-submission-ledger"' in body


# ---- CLI integration tests ----------------------------------------------


def test_cli_h1_record_submission_writes_ledger_and_audit(
    tmp_path: Path, monkeypatch, capsys
):
    """`sentinel h1 record-submission ...` via direct main() call writes
    a JSONL row + a hash-chained audit-log event."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.chdir(tmp_path)

    from sentinel.cli import main
    from sentinel.core.scope import AuditLog

    rc = main([
        "h1", "record-submission",
        "acme-bbp",
        "01-xss.md",
        "--submitted-at", "2026-XX-XXT15:00:00Z",
        "--h1-report-id", "9999999",
        "--weakness", "CWE-79",
        "--severity", "high",
    ])
    assert rc == 0

    ledger = tmp_path / ".sentinel" / "h1-submissions.jsonl"
    assert ledger.is_file()
    row = json.loads(ledger.read_text().splitlines()[0])
    assert row["engagement_id"] == "acme-bbp"
    assert row["file"] == "01-xss.md"

    audit = tmp_path / ".audit-acme-bbp.jsonl"
    assert audit.is_file()
    ok, err = AuditLog.verify(audit)
    assert ok is True, err

    captured = capsys.readouterr()
    assert "recorded" in captured.out.lower()


def test_cli_h1_prepare_passes_scope(tmp_path: Path, monkeypatch):
    """When --scope <yaml> is provided, _do_h1 loads the Scope and passes
    it through to prepare(). Monkeypatches both Scope.load and prepare
    to capture call args without touching real engagement files."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.chdir(tmp_path)

    captured_scope: dict = {}

    class FakeScope:
        engagement_id = "acme-bbp"

        @classmethod
        def load(cls, path, audit_log_path=None):
            captured_scope["scope_path"] = str(path)
            return cls()

        def authorize_url(self, url):
            return None

    captured_prepare: dict = {}

    def fake_prepare(report_path, *, scope=None, output_dir=None):
        captured_prepare["scope"] = scope
        captured_prepare["report_path"] = report_path
        out = Path(output_dir) if output_dir else Path(report_path).parent
        out.mkdir(parents=True, exist_ok=True)
        cp = out / (Path(report_path).stem + ".curls.sh")
        cp.write_text("#!/usr/bin/env bash\n")
        return cp, None

    # Patch scope module attribute used inside _do_h1.
    import sentinel.cli as cli_mod
    monkeypatch.setattr(cli_mod, "Scope", FakeScope)

    import importlib
    prep_mod = importlib.import_module("sentinel.h1.prepare")
    monkeypatch.setattr(prep_mod, "prepare", fake_prepare)
    # Also patch the re-exported reference used inside _do_h1.
    import sentinel.h1 as h1_pkg
    monkeypatch.setattr(h1_pkg, "prepare", fake_prepare)

    # Create a stub report + scope file (contents don't matter — Scope.load is faked).
    report = tmp_path / "01-test.md"
    report.write_text("# T\n\n```bash\ncurl https://example.com/a\n```\n")
    scope_yaml = tmp_path / "scope.yaml"
    scope_yaml.write_text("client: acme\nengagement_id: acme-bbp\n")

    rc = cli_mod.main([
        "h1", "prepare", str(report), "--scope", str(scope_yaml),
    ])
    assert rc == 0
    # The Scope object was constructed AND passed to prepare().
    assert captured_prepare.get("scope") is not None
    assert isinstance(captured_prepare["scope"], FakeScope)
    assert captured_scope.get("scope_path") == str(scope_yaml)


def test_cli_h1_help_lists_three_subcommands(capsys):
    """`sentinel h1 --help` exits 0 and prints all three subcommand
    names. argparse calls sys.exit(0) on --help."""
    from sentinel.cli import main
    with pytest.raises(SystemExit) as exc:
        main(["h1", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "record-submission" in out
    assert "dup-check" in out
    assert "prepare" in out
