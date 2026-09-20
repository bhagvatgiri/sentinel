"""Regression test for UI parity gap (2026-XX-XX): the /scan page's mode
dropdown was missing scan-apk / scan-cloud / scan-dfir, so operators could
only launch those scans from the CLI. The form must expose all three.
"""

from __future__ import annotations

from pathlib import Path

import yaml


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
    Path(cfg.runs_dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.scopes_dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.vault_path).mkdir(parents=True, exist_ok=True)
    Path(cfg.corpus_dir).mkdir(parents=True, exist_ok=True)
    # Drop a valid scope so the form has something to bind to and POST
    # tests can exercise the per-mode argv builder.
    scope_path = Path(cfg.scopes_dir) / "test.yaml"
    scope_path.write_text(yaml.safe_dump({
        "client": "test-client",
        "engagement_id": "2026-XX-XX-test",
        "authorized_by": "tester@example.com",
        "valid_from": "2025-01-01",
        "valid_until": "2099-12-31",
        "targets": {"domains": ["example.com"]},
    }))
    from sentinel.web.app import create_app
    app = create_app()
    return TestClient(app), cfg, scope_path


def test_scan_form_lists_scan_apk_scan_cloud_scan_dfir(tmp_path, monkeypatch):
    """GET /scan must include scan-apk / scan-cloud / scan-dfir as <option>
    values so operators can launch them from the dashboard. Closes the
    UI-parity gap discovered by the 2026-XX-XX audit."""
    client, _, _ = _make_client(tmp_path, monkeypatch)
    body = client.get("/scan").text
    for new_mode in ("scan-apk", "scan-cloud", "scan-dfir"):
        assert f'value="{new_mode}"' in body, (
            f"Expected /scan mode dropdown to include {new_mode!r}, but "
            f"the <option value=\"{new_mode}\"> was missing. "
            f"SCAN_MODES in sentinel/web/routes/scan.py must list it."
        )


def test_scan_apk_argv_contains_apk_path_and_scope(tmp_path, monkeypatch):
    """POST /scan/run for mode=scan-apk must produce an argv that includes
    the APK path positional and --scope <scope yaml>. Validated by
    inspecting the rendered status fragment (which echoes argv_str)."""
    client, _, scope_path = _make_client(tmp_path, monkeypatch)
    # Patch jobs.launch so we don't actually start a subprocess.
    from sentinel.web import jobs as _jobs

    class _StubJob:
        job_id = "test-job-1"
        is_running = False
        argv = ["sentinel", "scan-apk", "/tmp/app.apk", "--scope", str(scope_path)]
        returncode = None
        elapsed_sec = 0
        log_tail = []
        expected_run_json = None
        started_at = 0.0

        def tail(self, n):
            return []

    monkeypatch.setattr(_jobs, "launch",
                        lambda argv, cwd, expected_run_json=None: _StubJob())
    r = client.post("/scan/run", data={
        "engagement": scope_path.name,
        "mode": "scan-apk",
        "target": "/tmp/app.apk",
    })
    assert r.status_code == 200
    assert "scan-apk" in r.text
    assert "/tmp/app.apk" in r.text
    assert "--scope" in r.text


def test_scan_cloud_argv_omits_positional_target(tmp_path, monkeypatch):
    """POST /scan/run for mode=scan-cloud must NOT pass a positional
    target — the CLI takes only --scope and provider flags."""
    client, _, scope_path = _make_client(tmp_path, monkeypatch)
    from sentinel.web import jobs as _jobs

    captured: dict = {}

    class _StubJob:
        job_id = "test-job-2"
        is_running = False
        argv: list[str] = []
        returncode = None
        elapsed_sec = 0
        log_tail = []
        expected_run_json = None
        started_at = 0.0

        def tail(self, n):
            return []

    def _fake_launch(argv, cwd, expected_run_json=None):
        captured["argv"] = list(argv)
        _StubJob.argv = list(argv)
        return _StubJob()

    monkeypatch.setattr(_jobs, "launch", _fake_launch)
    r = client.post("/scan/run", data={
        "engagement": scope_path.name,
        "mode": "scan-cloud",
        "target": "",  # explicitly empty — scope bounds the run
    })
    assert r.status_code == 200, r.text
    argv = captured["argv"]
    # Second arg is the subcommand; no positional target should follow it.
    assert argv[1] == "scan-cloud"
    assert "--scope" in argv
    # The next arg after "scan-cloud" must be a flag (starts with --), not
    # a stray positional from the form's target field.
    sc_idx = argv.index("scan-cloud")
    assert argv[sc_idx + 1].startswith("--"), (
        f"scan-cloud should have no positional target; got argv={argv!r}"
    )


def test_scan_dfir_argv_contains_input_file_and_scope(tmp_path, monkeypatch):
    """POST /scan/run for mode=scan-dfir must include the input-file
    positional and --scope <scope yaml>."""
    client, _, scope_path = _make_client(tmp_path, monkeypatch)
    from sentinel.web import jobs as _jobs

    captured: dict = {}

    class _StubJob:
        job_id = "test-job-3"
        is_running = False
        argv: list[str] = []
        returncode = None
        elapsed_sec = 0
        log_tail = []
        expected_run_json = None
        started_at = 0.0

        def tail(self, n):
            return []

    def _fake_launch(argv, cwd, expected_run_json=None):
        captured["argv"] = list(argv)
        _StubJob.argv = list(argv)
        return _StubJob()

    monkeypatch.setattr(_jobs, "launch", _fake_launch)
    r = client.post("/scan/run", data={
        "engagement": scope_path.name,
        "mode": "scan-dfir",
        "target": "/tmp/incident.pcap",
    })
    assert r.status_code == 200, r.text
    argv = captured["argv"]
    assert argv[1] == "scan-dfir"
    assert "/tmp/incident.pcap" in argv
    assert "--scope" in argv
