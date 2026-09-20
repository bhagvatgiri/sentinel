"""Tests for `sentinel.state.current_state` — fixture-driven, deterministic."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from sentinel.state import current_state as cs


@pytest.fixture
def fixture_project(tmp_path: Path) -> Path:
    """Build a minimal project tree with one engagement + runs + memory."""
    project = tmp_path / "project"
    project.mkdir()

    ws = project / "workspaces" / "2026-XX-XX-acme-bbp"
    (ws / "deliverables" / "h1-submissions").mkdir(parents=True)

    # .completed_phases.json
    (ws / ".completed_phases.json").write_text(
        json.dumps(
            {
                "completed": ["recon", "vuln:xss", "report"],
                "last_phase": "report",
                "metadata": {
                    "cost_usd": 1.23,
                    "turns": 42,
                    "duration_sec": 600,
                    "error": None,
                },
            }
        )
    )

    # A few deliverables.
    deliv = ws / "deliverables"
    (deliv / "recon_deliverable.md").write_text("# Recon\n")
    (deliv / "xss_analysis_deliverable.md").write_text("# XSS\n")

    # An H1 report with explicit Status line.
    (deliv / "h1-submissions" / "01-xss-stored.md").write_text(
        "# H1 Report — Acme: Stored XSS in /comments\n"
        "\n"
        "**Status:** Ready to submit — live evidence captured 2026-XX-XX.\n"
    )
    # A second report without an explicit status (should default to drafted).
    (deliv / "h1-submissions" / "02-idor.md").write_text(
        "# H1 Submission — Acme: IDOR on /api/orders\n\nDescription...\n"
    )
    # An AUTHORIZATION artifact that should be excluded from H1 row count.
    (deliv / "h1-submissions" / "AUTHORIZATION-grant.md").write_text(
        "# Authorization Grant\n"
    )

    # A run JSON.
    runs = project / "runs"
    runs.mkdir()
    (runs / "acme-2026-XX-XX-acme-bbp.json").write_text(
        json.dumps(
            {
                "scope": {"client": "acme", "engagement_id": "2026-XX-XX-acme-bbp"},
                "scanners_run": ["pentest-agent"],
                "errors": [],
                "findings": [{"title": "f1"}, {"title": "f2"}],
            }
        )
    )

    # An event log with phase events.
    log = runs / "events-cli-2026-XX-XX-acme-bbp-1234567890.jsonl"
    base_ts = time.time() - 60
    log_lines = [
        {"ts": base_ts, "kind": "phase_started", "phase": "recon"},
        {"ts": base_ts + 30, "kind": "phase_completed", "phase": "recon"},
        {"ts": base_ts + 60, "kind": "phase_completed", "phase": "report"},
    ]
    log.write_text("\n".join(json.dumps(ev) for ev in log_lines) + "\n")

    # Memory dir with an index.
    mem = project / "memory"
    mem.mkdir()
    (mem / "MEMORY.md").write_text(
        "- [Test memory one](one.md) — description hook one\n"
        "- [Test memory two](two.md) — description hook two\n"
    )

    return project


def test_build_snapshot_engagement(fixture_project: Path):
    snap = cs.build_snapshot(
        fixture_project, memory_dir=fixture_project / "memory"
    )
    assert len(snap["engagements"]) == 1
    e = snap["engagements"][0]
    assert e["id"] == "2026-XX-XX-acme-bbp"
    assert e["completed_phases"] == ["recon", "vuln:xss", "report"]
    assert e["last_phase"] == "report"
    assert e["n_completed_phases"] == 3
    assert e["n_deliverables_md"] == 2  # recon + xss; h1 dir is separate


def test_build_snapshot_h1_reports(fixture_project: Path):
    snap = cs.build_snapshot(
        fixture_project, memory_dir=fixture_project / "memory"
    )
    h1 = snap["engagements"][0]["h1_reports"]
    files = [r["file"] for r in h1]
    assert "01-xss-stored.md" in files
    assert "02-idor.md" in files
    # AUTHORIZATION artifact excluded:
    assert "AUTHORIZATION-grant.md" not in files
    statuses = {r["file"]: r["status"] for r in h1}
    assert statuses["01-xss-stored.md"] == "Ready to submit"
    assert statuses["02-idor.md"] == "drafted"


def test_build_snapshot_recent_runs(fixture_project: Path):
    snap = cs.build_snapshot(
        fixture_project, memory_dir=fixture_project / "memory"
    )
    runs = snap["recent_runs"]
    assert len(runs) == 1
    assert runs[0]["client"] == "acme"
    assert runs[0]["n_findings"] == 2


def test_build_snapshot_phase_events(fixture_project: Path):
    snap = cs.build_snapshot(
        fixture_project, memory_dir=fixture_project / "memory"
    )
    evs = snap["recent_phase_events"]
    # Three events written; should all show up sorted desc by ts.
    assert len(evs) == 3
    kinds = [e["kind"] for e in evs]
    assert "phase_completed" in kinds
    # Newest first.
    assert evs[0]["ts_epoch"] >= evs[-1]["ts_epoch"]
    # Engagement parsed from the events-*.jsonl filename.
    assert evs[0]["engagement"] == "2026-XX-XX-acme-bbp"


def test_build_snapshot_memory_index(fixture_project: Path):
    snap = cs.build_snapshot(
        fixture_project, memory_dir=fixture_project / "memory"
    )
    mem = snap["memory_index"]
    titles = [m["title"] for m in mem]
    assert "Test memory one" in titles
    assert "Test memory two" in titles


def test_render_markdown_smoke(fixture_project: Path):
    snap = cs.build_snapshot(
        fixture_project, memory_dir=fixture_project / "memory"
    )
    md = cs.render_markdown(snap)
    assert "# Sentinel — Current State" in md
    assert "2026-XX-XX-acme-bbp" in md
    assert "01-xss-stored.md" in md
    assert "Ready to submit" in md
    assert "Test memory one" in md
    # Markdown shape: contains pipe-delimited tables.
    assert "| Engagement | Last phase " in md
    assert "| H1 submission queue" not in md  # heading not table row
    assert "## H1 submission queue" in md


def test_update_current_state_writes_file(fixture_project: Path):
    out = cs.update_current_state(
        fixture_project, memory_dir=fixture_project / "memory"
    )
    assert out == fixture_project / "CURRENT_STATE.md"
    assert out.is_file()
    assert "# Sentinel — Current State" in out.read_text()


def test_update_current_state_safe_swallows_errors(tmp_path: Path):
    # Pass a path that doesn't exist and isn't writeable; safe variant returns None.
    bad = tmp_path / "no-such" / "thing"
    result = cs.update_current_state_safe(
        "/totally/nonexistent/path",
        output_path=bad / "CURRENT_STATE.md",
    )
    # Either it succeeded (rare) or returned None — must not raise.
    assert result is None or result == bad / "CURRENT_STATE.md"


def test_update_current_state_with_status_success(fixture_project: Path):
    """STATE-01 Task 1 — successful refresh returns (Path, None)."""
    path, err = cs.update_current_state_with_status(
        fixture_project, memory_dir=fixture_project / "memory"
    )
    assert err is None
    assert path == fixture_project / "CURRENT_STATE.md"
    assert path.is_file()


def test_update_current_state_with_status_failure_returns_error(tmp_path: Path):
    """STATE-01 Task 1 — write failure returns (None, non-empty str) and does NOT raise."""
    # Use an output_path whose parent's parent points to a file (not a directory),
    # so mkdir(parents=True) raises NotADirectoryError.
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a dir")
    bad_target = blocker / "child" / "CURRENT_STATE.md"

    path, err = cs.update_current_state_with_status(
        tmp_path, output_path=bad_target
    )
    assert path is None
    assert isinstance(err, str)
    assert len(err) > 0


def test_update_current_state_safe_still_backward_compatible(fixture_project: Path):
    """STATE-01 Task 1 — `update_current_state_safe` still returns Path | None."""
    result = cs.update_current_state_safe(
        fixture_project, memory_dir=fixture_project / "memory"
    )
    assert result == fixture_project / "CURRENT_STATE.md"


def test_update_current_state_with_status_is_importable_from_package():
    """STATE-01 Task 1 — package re-export resolves; not just submodule path."""
    from sentinel.state import update_current_state_with_status  # noqa: F401
    # Also confirm full public surface is importable from package.
    from sentinel.state import (  # noqa: F401
        build_snapshot,
        render_markdown,
        update_current_state,
        update_current_state_safe,
        update_current_state_with_status,
    )


def test_no_workspaces_no_runs(tmp_path: Path):
    # Project with no workspaces or runs — snapshot should still build cleanly.
    project = tmp_path / "empty"
    project.mkdir()
    snap = cs.build_snapshot(project, memory_dir=project / "memory")
    assert snap["engagements"] == []
    assert snap["recent_runs"] == []
    assert snap["recent_phase_events"] == []
    md = cs.render_markdown(snap)
    assert "_No workspaces found" in md
    assert "_No `runs/*.json` files found._" in md


def test_status_extraction_variants():
    # Multiple format variants the regex should handle.
    assert cs._extract_status("**Status:** Ready to submit — captured...") == "Ready to submit"
    assert cs._extract_status("Status: drafted\n") == "drafted"
    assert cs._extract_status("> **Status:** submitted\n") == "submitted"
    assert cs._extract_status("no status here") == "drafted"
