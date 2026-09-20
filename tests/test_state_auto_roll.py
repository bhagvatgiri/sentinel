"""STATE-01 regression test for the pipeline phase-end CURRENT_STATE.md
auto-roll hook.

Acceptance criteria from `.planning/REQUIREMENTS.md` STATE-01:

(a) When the pipeline completes a phase, `update_current_state_safe()` is
    invoked exactly once and CURRENT_STATE.md reflects the new phase state
    within one phase tick.
(b) A `FileNotFoundError`, `PermissionError`, or any other `OSError` raised
    by `update_current_state_safe()` is swallowed at the phase-end hook —
    the pipeline continues to the next phase as if the refresh had
    succeeded.
(c) Every refresh attempt (success OR swallowed failure) emits a
    `state_update` or `state_update_failed` event to the structured event
    log, registered in `sentinel/web/event_styles.py`, so operators can
    see refresh activity in the agent-runs dashboard.

The hook itself is inline inside `PentestPipeline._run_phase()`. To make
it testable without spinning up the whole pipeline, the implementation
extracts the 4-step logic into a module-level helper
`_refresh_current_state_with_events(project_root, event_log, phase)`. This
test imports the helper directly and exercises it with a fake event_log.

Runs offline, no network, no Claude SDK calls.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.agent.pentest.pipeline import _refresh_current_state_with_events
from sentinel.state import current_state as cs


class _FakeEventLog:
    """Records every `emit(kind, **fields)` call into `self.events`."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def emit(self, kind: str, **fields) -> None:
        self.events.append({"kind": kind, **fields})


def _make_minimal_project(tmp_path: Path) -> Path:
    """Build the minimal on-disk layout `build_snapshot` needs.

    Default `workspaces_root=project_root/"workspaces"` resolution inside
    `build_snapshot` finds the engagement; the helper does NOT receive a
    `workspaces_root=` kwarg, so the test must lay the directory out at
    that exact path.
    """
    (tmp_path / "workspaces").mkdir()
    (tmp_path / "runs").mkdir()
    # Memory dir is optional but we pass a fresh one to avoid leaking the
    # operator's real `~/.claude/.../memory` into the snapshot.
    (tmp_path / "memory").mkdir()
    return tmp_path


def _add_engagement(project_root: Path, engagement_id: str, *, last_phase: str) -> None:
    ws = project_root / "workspaces" / engagement_id
    ws.mkdir(parents=True)
    (ws / "deliverables").mkdir()
    (ws / ".completed_phases.json").write_text(
        json.dumps({"completed": [last_phase], "last_phase": last_phase})
    )


def test_phase_end_hook_emits_state_update_on_success(tmp_path: Path):
    """(a) + (c) — successful refresh emits exactly one `state_update` event."""
    project = _make_minimal_project(tmp_path)
    _add_engagement(project, "2026-XX-XX-acme-test", last_phase="recon")

    fake = _FakeEventLog()
    _refresh_current_state_with_events(project, fake, "recon")

    # CURRENT_STATE.md was written (acceptance (a)).
    assert (project / "CURRENT_STATE.md").is_file()

    # Exactly one event, of kind `state_update` (acceptance (c)).
    assert len(fake.events) == 1
    assert fake.events[0]["kind"] == "state_update"
    assert fake.events[0]["phase"] == "recon"


def test_phase_end_hook_swallows_oserror_emits_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """(b) + (c) — failure returned by underlying call does NOT raise; emits
    `state_update_failed` with a `reason` field."""
    project = _make_minimal_project(tmp_path)
    fake = _FakeEventLog()

    # Monkeypatch to simulate the underlying call returning (None, str-err).
    def _fake_with_status(_project_dir, **kwargs):
        return None, "PermissionError: [Errno 13] Permission denied: '/x'"

    # Patch the symbol on the pipeline's import target. The helper imports
    # `update_current_state_with_status` lazily inside its body, so we patch
    # the source module — both lookups resolve to the same function object.
    monkeypatch.setattr(
        "sentinel.state.update_current_state_with_status", _fake_with_status
    )
    monkeypatch.setattr(
        cs, "update_current_state_with_status", _fake_with_status
    )

    # Must NOT raise.
    _refresh_current_state_with_events(project, fake, "vuln:xss")

    assert len(fake.events) == 1
    ev = fake.events[0]
    assert ev["kind"] == "state_update_failed"
    assert ev["phase"] == "vuln:xss"
    assert "Permission" in ev["reason"]
    assert len(ev["reason"]) <= 300  # truncated per design


def test_phase_end_hook_swallows_raised_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """(b) — even if `update_current_state_with_status` itself RAISES (not just
    returns (None, err)), the outer try/except catches it and still emits a
    `state_update_failed` event."""
    project = _make_minimal_project(tmp_path)
    fake = _FakeEventLog()

    def _boom(_project_dir, **kwargs):
        raise RuntimeError("internal bug in update_current_state_with_status")

    monkeypatch.setattr(
        "sentinel.state.update_current_state_with_status", _boom
    )
    monkeypatch.setattr(cs, "update_current_state_with_status", _boom)

    # Must NOT raise even though the call itself raises.
    _refresh_current_state_with_events(project, fake, "report")

    assert len(fake.events) == 1
    ev = fake.events[0]
    assert ev["kind"] == "state_update_failed"
    assert ev["phase"] == "report"
    assert "internal bug" in ev["reason"]


def test_new_engagement_visible_within_one_tick(tmp_path: Path):
    """(a) — a new engagement added between two phase-end ticks shows up in
    the CURRENT_STATE.md rendered on the second tick."""
    project = _make_minimal_project(tmp_path)
    fake = _FakeEventLog()

    # First tick — no engagements yet.
    _refresh_current_state_with_events(project, fake, "phase-1")
    content_a = (project / "CURRENT_STATE.md").read_text()
    assert "2026-XX-XX-newengagement" not in content_a

    # Operator drops a new workspace mid-pipeline.
    _add_engagement(project, "2026-XX-XX-newengagement", last_phase="recon")

    # Second tick — the new engagement must appear.
    _refresh_current_state_with_events(project, fake, "phase-2")
    content_b = (project / "CURRENT_STATE.md").read_text()
    assert "2026-XX-XX-newengagement" in content_b

    # Two ticks fired, two events of kind `state_update`.
    kinds = [e["kind"] for e in fake.events]
    assert kinds == ["state_update", "state_update_failed"] or kinds == [
        "state_update",
        "state_update",
    ]
    # The second event MUST be a success — the first might also be success.
    assert fake.events[-1]["kind"] == "state_update"


def test_helper_handles_no_event_log_gracefully(tmp_path: Path):
    """If `event_log` is None (e.g. headless CLI), helper must still not raise."""
    project = _make_minimal_project(tmp_path)
    # Pass None for event_log — must not raise, must still write the file.
    _refresh_current_state_with_events(project, None, "recon")
    assert (project / "CURRENT_STATE.md").is_file()
