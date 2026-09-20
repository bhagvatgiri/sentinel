"""STATE-02 regression test for the FastAPI dashboard surfaces of
CURRENT_STATE.md.

Acceptance criteria from `.planning/REQUIREMENTS.md` STATE-02:

  Operator can read the CURRENT_STATE.md content from the dashboard at
  two surfaces with full parity to the CLI `sentinel state --show`
  output:

  1. Machine-readable JSON at `/state` (Accept: application/json) AND
     at `/state.json` (Accept-header-agnostic).
  2. Human-readable Current State panel on the Dashboard home (`/`)
     showing engagements + H1 queue without operator navigation.

Both surfaces call `build_snapshot()` fresh on every request — no
caching. The Plan 02 phase-end hook keeps the underlying file fresh;
this plan ensures the web surfaces stay in lockstep with it.

This test is fully hermetic: it overrides `get_config` via
`app.dependency_overrides` so no test touches the operator's real
`~/.sentinel/` config, `~/sentinel-corpus`, or live `runs/` directory.

Runs offline, no network, no Claude SDK, no Ollama, no Chroma.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.web.app import create_app
from sentinel.web.deps import get_config
from sentinel.ui.state import UIConfig


def _build_fixture_project(tmp_path: Path) -> Path:
    """Build a minimal valid project tree the snapshot can scan.

    Lays out `tmp_path/workspaces/<engagement>/...` so `build_snapshot`
    finds one engagement with a single completed phase and one drafted
    H1 report. This mirrors the layout used by `tests/test_current_state.py`
    so future snapshot-shape changes break this test in lockstep.
    """
    project = tmp_path / "project"
    project.mkdir()

    ws = project / "workspaces" / "2026-XX-XX-acme-stateroute"
    (ws / "deliverables" / "h1-submissions").mkdir(parents=True)

    (ws / ".completed_phases.json").write_text(
        json.dumps({"completed": ["recon"], "last_phase": "recon"})
    )
    (ws / "deliverables" / "recon_deliverable.md").write_text("# Recon\n")
    (ws / "deliverables" / "h1-submissions" / "01-xss.md").write_text(
        "# H1 Report — Acme: Stored XSS in /comments\n"
        "\n"
        "**Status:** Ready to submit.\n"
    )

    # Empty runs/ and memory/ — snapshot must handle these as empty lists.
    (project / "runs").mkdir()
    (project / "memory").mkdir()

    return project


@pytest.fixture
def client(tmp_path: Path):
    """Hermetic TestClient — `get_config` is overridden to point at
    `tmp_path`, so no loader (Ollama health, Chroma stats, vault counts,
    runs glob) touches the operator's real filesystem or network.

    The loaders enumerated in `sentinel/web/routes/dashboard.py` all
    short-circuit to empty/safe defaults when their `cfg` directories
    don't exist under `tmp_path`. The Ollama health probe is timeout-
    bounded by `OllamaClient.is_available`, so even if it can't reach
    localhost:11434 the test still completes promptly.
    """
    project = _build_fixture_project(tmp_path)
    cfg = UIConfig(
        vault_path=str(tmp_path / "vault"),
        corpus_dir=str(tmp_path / "corpus"),
        scopes_dir=str(tmp_path / "scopes"),
        runs_dir=str(project / "runs"),
        ollama_host="http://localhost:11434",
        ollama_model="llama3.1:8b",
        embed_model="nomic-embed-text",
        project_dir=str(project),
    )

    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.clear()


# ---- Tests --------------------------------------------------------------


def test_state_json_returns_snapshot_shape(client: TestClient):
    """GET /state.json returns 200 + a JSON body with the six top-level
    snapshot keys, regardless of Accept header."""
    r = client.get("/state.json")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    expected_keys = {
        "generated_at",
        "project_root",
        "engagements",
        "recent_runs",
        "recent_phase_events",
        "memory_index",
    }
    assert expected_keys.issubset(body.keys())
    # The fixture engagement must round-trip into the JSON.
    eng_ids = [e["id"] for e in body["engagements"]]
    assert "2026-XX-XX-acme-stateroute" in eng_ids


def test_state_html_still_works(client: TestClient):
    """GET /state (no Accept header) returns 200 with HTML — the existing
    behavior must be preserved after adding the JSON surface."""
    r = client.get("/state")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    # The state.html template's header is "# Sentinel — Current State"
    # passed through render_markdown then HTML-escaped in <pre><code>.
    # The bare H1 title is also rendered at the top of the page.
    body = r.text
    assert "Current state" in body or "Current State" in body
    assert "2026-XX-XX-acme-stateroute" in body


def test_state_accept_json_returns_json(client: TestClient):
    """GET /state with `Accept: application/json` content-negotiates
    to JSON (not HTML), with the same snapshot shape as /state.json."""
    r = client.get("/state", headers={"Accept": "application/json"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert "engagements" in body
    eng_ids = [e["id"] for e in body["engagements"]]
    assert "2026-XX-XX-acme-stateroute" in eng_ids


def test_dashboard_home_includes_current_state_panel(client: TestClient):
    """GET / renders the new Current State panel — identifiable by the
    `data-testid="current-state-panel"` attribute the regression test
    targets — and contains at least one engagement ID from the fixture."""
    r = client.get("/")
    assert r.status_code == 200
    body = r.text
    assert 'data-testid="current-state-panel"' in body
    # The engagement must appear in the rendered panel.
    assert "2026-XX-XX-acme-stateroute" in body


def test_state_json_parity_with_dashboard_panel(client: TestClient):
    """The engagement IDs in /state.json MUST also appear as text in the
    Dashboard home HTML. Proves the panel and the JSON surface render
    the same underlying snapshot — future drift breaks this loudly.
    """
    j = client.get("/state.json").json()
    html = client.get("/").text
    # Every engagement ID in the JSON body must be present in the HTML.
    for eng in j["engagements"]:
        assert eng["id"] in html, (
            f"engagement {eng['id']} present in /state.json but missing "
            f"from dashboard home — parity broken"
        )
