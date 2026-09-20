"""STATE-03 regression test — Blocked H1 submissions section in `sentinel state`.

Acceptance criteria from `.planning/REQUIREMENTS.md` STATE-03:

  Operator running `sentinel state --update` sees a `## Blocked H1 submissions`
  section in `CURRENT_STATE.md` listing every drafted H1 report whose pacing
  window has elapsed since the same engagement's most-recent submission, but
  submission hasn't fired.

Heuristic for "blocked":
  - Pacing-elapsed: engagement has at least one submitted report, and
    `now - last_submitted_mtime >= pacing_hours`.
  - No-prior-submission: engagement has zero submitted reports, and the
    drafted report's mtime is `>= pacing_hours` ago.

Hermeticity contract (CRITICAL):
  - Tests that exercise the blocked-H1 LOGIC (1, 2, 3, 6, 7) call
    `build_snapshot(project, pacing_hours=N)` OR `_scan_blocked_h1_submissions(
    engagements, pacing_hours=N, now_epoch=fixed)` with `pacing_hours` PASSED
    EXPLICITLY. This bypasses `_load_pacing_hours_from_yaml()` so the
    operator's real `~/.sentinel/notify.yaml` cannot leak in.
  - Tests 4 + 5 (YAML loader edge cases) and Tests 8 + 9 (TestClient
    integration) monkeypatch `Path.home()` to a tmp dir so the loader resolves
    to a per-test config.

Runs offline, no network, no Claude SDK, no Ollama, no Chroma.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.state import build_snapshot, render_markdown
from sentinel.state import current_state as cs
from sentinel.web.app import create_app
from sentinel.web.deps import get_config
from sentinel.ui.state import UIConfig


# ---- Fixture helpers -----------------------------------------------------


def _set_mtime(p: Path, *, hours_ago: float) -> None:
    """Set both atime + mtime of `p` to `hours_ago` from now."""
    target = time.time() - (hours_ago * 3600.0)
    os.utime(p, (target, target))


def _build_engagement_with_reports(
    tmp_path: Path,
    *,
    eng_id: str = "2026-XX-XX-acme-bbp",
    submitted_hours_ago: float | None = None,
    drafted_hours_ago: float = 1.0,
) -> Path:
    """Build a minimal project tree with one engagement and 1-2 H1 reports.

    If `submitted_hours_ago` is None, no submitted report is written (clean
    slate). Otherwise, a `submitted (H1-1234)` report is written with mtime
    `submitted_hours_ago` hours ago. The drafted report's mtime is
    `drafted_hours_ago` hours ago.
    """
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)

    ws = project / "workspaces" / eng_id
    h1 = ws / "deliverables" / "h1-submissions"
    h1.mkdir(parents=True)
    # `.completed_phases.json` so the engagement is picked up.
    (ws / ".completed_phases.json").write_text(
        json.dumps({"completed": ["report"], "last_phase": "report"})
    )

    drafted = h1 / "01-drafted.md"
    drafted.write_text(
        "# H1 Report — Acme: drafted finding\n"
        "\n"
        "**Status:** Ready to submit — live evidence captured.\n"
    )
    _set_mtime(drafted, hours_ago=drafted_hours_ago)

    if submitted_hours_ago is not None:
        submitted = h1 / "02-submitted.md"
        submitted.write_text(
            "# H1 Report — Acme: prior submission\n"
            "\n"
            "**Status:** submitted (H1-1234)\n"
        )
        _set_mtime(submitted, hours_ago=submitted_hours_ago)

    # Empty runs/ + memory/ so unrelated scans short-circuit cleanly.
    (project / "runs").mkdir(exist_ok=True)
    (project / "memory").mkdir(exist_ok=True)

    return project


# ---- Tests 1-3 + 6: blocked-H1 logic (explicit `pacing_hours`) ----------


def test_blocked_h1_pacing_elapsed(tmp_path: Path):
    """Submitted 10h ago + drafted 1h ago → drafted is blocked
    (pacing-elapsed: 10h > 4h pacing).
    """
    project = _build_engagement_with_reports(
        tmp_path, submitted_hours_ago=10.0, drafted_hours_ago=1.0
    )
    # Explicit pacing_hours — bypasses YAML loader.
    snap = build_snapshot(
        project, pacing_hours=4, memory_dir=project / "memory"
    )
    blocked = snap["blocked_h1_submissions"]
    assert len(blocked) == 1
    row = blocked[0]
    assert row["engagement_id"] == "2026-XX-XX-acme-bbp"
    assert row["file"] == "01-drafted.md"
    assert row["reason"] == "pacing-elapsed"
    assert snap["h1_pacing_hours"] == 4


def test_blocked_h1_pacing_not_elapsed(tmp_path: Path):
    """Submitted 30min ago + drafted 1h ago → drafted NOT blocked
    (pacing window still in flight; wait it out).
    """
    project = _build_engagement_with_reports(
        tmp_path, submitted_hours_ago=0.5, drafted_hours_ago=1.0
    )
    snap = build_snapshot(
        project, pacing_hours=4, memory_dir=project / "memory"
    )
    assert snap["blocked_h1_submissions"] == []


def test_blocked_h1_no_prior_submission(tmp_path: Path):
    """No submitted report + drafted 6h ago → blocked (no-prior-submission).

    Drafted has been sitting for ≥4h with no submission ever made for this
    engagement — it's stale and operator should remember to submit.
    """
    project = _build_engagement_with_reports(
        tmp_path, submitted_hours_ago=None, drafted_hours_ago=6.0
    )
    snap = build_snapshot(
        project, pacing_hours=4, memory_dir=project / "memory"
    )
    blocked = snap["blocked_h1_submissions"]
    assert len(blocked) == 1
    row = blocked[0]
    assert row["reason"] == "no-prior-submission"
    assert row["drafted_age_hours"] >= 5  # ~6h rounded


def test_blocked_h1_no_prior_submission_not_yet_aged(tmp_path: Path):
    """No submitted report + drafted 1h ago → NOT blocked yet
    (drafted recently, clean slate — operator just drafted it).
    """
    project = _build_engagement_with_reports(
        tmp_path, submitted_hours_ago=None, drafted_hours_ago=1.0
    )
    snap = build_snapshot(
        project, pacing_hours=4, memory_dir=project / "memory"
    )
    assert snap["blocked_h1_submissions"] == []


def test_is_submitted_unit():
    """`_is_submitted` recognizes all known H1 status tokens as submitted
    and returns False for drafted / Ready-to-submit / empty.
    """
    assert cs._is_submitted("submitted")
    assert cs._is_submitted("submitted (H1-1234)")
    assert cs._is_submitted("triaged")
    assert cs._is_submitted("closed")
    assert cs._is_submitted("accepted")
    assert cs._is_submitted("duplicate")
    assert cs._is_submitted("N/A")
    assert cs._is_submitted("informative")
    # Drafted-ish tokens:
    assert not cs._is_submitted("drafted")
    assert not cs._is_submitted("Ready to submit")
    assert not cs._is_submitted("")
    assert not cs._is_submitted(None)  # type: ignore[arg-type]


# ---- Tests 4 + 5: YAML-loader hermeticity --------------------------------


def test_blocked_h1_yaml_override(tmp_path: Path, monkeypatch):
    """`~/.sentinel/notify.yaml` with `h1_pacing_hours: 8` makes the loader
    return 8 (overrides default 4).

    Uses `monkeypatch.setattr(Path, "home", lambda: tmp_path)` to redirect
    `Path.home()` to a tmp dir so the operator's real config is untouched.
    """
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    cfg_dir = tmp_path / ".sentinel"
    cfg_dir.mkdir()
    (cfg_dir / "notify.yaml").write_text("h1_pacing_hours: 8\n")

    assert cs._load_pacing_hours_from_yaml() == 8


def test_blocked_h1_yaml_missing_returns_default(tmp_path: Path, monkeypatch):
    """Missing `~/.sentinel/notify.yaml` → loader returns the default 4.

    Uses `monkeypatch.setattr(Path, "home", lambda: tmp_path)` so even if the
    operator's real home contains a notify.yaml it cannot influence this test.
    """
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    # No .sentinel/ dir created — file is genuinely missing.
    assert cs._load_pacing_hours_from_yaml() == 4


# ---- Tests 6 + 7: render_markdown + CLI behavior -------------------------


def test_render_markdown_blocked_section(tmp_path: Path):
    """`render_markdown` emits a `## Blocked H1 submissions` section
    containing the engagement id, file name, and reason.
    """
    project = _build_engagement_with_reports(
        tmp_path, submitted_hours_ago=10.0, drafted_hours_ago=1.0
    )
    snap = build_snapshot(
        project, pacing_hours=4, memory_dir=project / "memory"
    )
    md = render_markdown(snap)
    assert "## Blocked H1 submissions" in md
    assert "2026-XX-XX-acme-bbp" in md
    assert "01-drafted.md" in md
    assert "pacing-elapsed" in md
    # Pacing header advertises the configured hours.
    assert "(pacing: 4h)" in md


def test_render_markdown_blocked_section_empty_placeholder(tmp_path: Path):
    """When no reports are blocked, `render_markdown` emits the explicit
    placeholder instead of a degenerate empty table.
    """
    project = _build_engagement_with_reports(
        tmp_path, submitted_hours_ago=None, drafted_hours_ago=1.0
    )
    snap = build_snapshot(
        project, pacing_hours=4, memory_dir=project / "memory"
    )
    md = render_markdown(snap)
    assert "## Blocked H1 submissions" in md
    assert "_No H1 submissions blocked on pacing._" in md


def test_cli_state_update_writes_blocked_section(tmp_path: Path, monkeypatch):
    """`_do_state(args)` with `args.pacing_hours = 4` writes CURRENT_STATE.md
    containing the `## Blocked H1 submissions` section.

    We invoke the CLI handler directly (not via subprocess) and pass
    `pacing_hours` explicitly so the operator's real notify.yaml cannot
    influence the result. Belt-and-braces: also monkeypatch Path.home() to
    tmp_path so even an accidental YAML lookup hits a tmp config.
    """
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    project = _build_engagement_with_reports(
        tmp_path, submitted_hours_ago=10.0, drafted_hours_ago=1.0
    )

    from sentinel.cli import _do_state
    from argparse import Namespace

    args = Namespace(
        update=True,
        show=False,
        project_dir=str(project),
        workspaces_root=None,
        runs_dir=None,
        memory_dir=str(project / "memory"),
        pacing_hours=4,
    )
    rc = _do_state(args)
    assert rc == 0

    current_state_md = (project / "CURRENT_STATE.md").read_text()
    assert "## Blocked H1 submissions" in current_state_md
    assert "01-drafted.md" in current_state_md
    assert "pacing-elapsed" in current_state_md


# ---- Tests 8 + 9: dashboard panel + /state.json integration --------------


@pytest.fixture
def client_with_blocked(tmp_path: Path, monkeypatch):
    """Hermetic TestClient with `Path.home()` redirected to tmp_path
    (so build_snapshot's fallback to `_load_pacing_hours_from_yaml`
    cannot read the operator's real config).

    Builds a project with one engagement that has both a submitted-10h-ago
    and a drafted-1h-ago report — drafted is blocked under default pacing=4.
    """
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    project = _build_engagement_with_reports(
        tmp_path, submitted_hours_ago=10.0, drafted_hours_ago=1.0
    )
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


def test_dashboard_home_shows_blocked_h1_table(client_with_blocked: TestClient):
    """GET / contains the `data-testid="blocked-h1-section"` anchor and the
    drafted-blocked file name as text. UI parity with the CLI markdown.
    """
    r = client_with_blocked.get("/")
    assert r.status_code == 200
    body = r.text
    assert 'data-testid="blocked-h1-section"' in body
    # The blocked-row text appears in the table.
    assert "01-drafted.md" in body
    assert "pacing-elapsed" in body


def test_state_json_includes_blocked_h1_key(client_with_blocked: TestClient):
    """GET /state.json contains `blocked_h1_submissions` and
    `h1_pacing_hours` keys with the expected shape.
    """
    r = client_with_blocked.get("/state.json")
    assert r.status_code == 200
    body = r.json()
    assert "blocked_h1_submissions" in body
    assert "h1_pacing_hours" in body
    assert isinstance(body["blocked_h1_submissions"], list)
    assert len(body["blocked_h1_submissions"]) == 1
    row = body["blocked_h1_submissions"][0]
    assert row["file"] == "01-drafted.md"
    assert row["reason"] == "pacing-elapsed"
    assert "drafted_age_hours" in row
    assert "title" in row
    assert "status" in row
    # Default pacing (from missing yaml under monkeypatched home) is 4.
    assert body["h1_pacing_hours"] == 4
