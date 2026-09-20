"""Regression tests for EventLog.emit signature contract — task #72.

Bug history (2026-XX-XX ExamplePay scan):
  - tools.py:431 was calling event_log.emit(kind, {payload_dict}) — passing
    the payload as a positional second arg
  - EventLog.emit declares (self, kind: str, **payload) — kwargs only
  - Each call raised TypeError, caught and logged as WARNING
  - Three warnings fired in 90s right before the scan stalled
  - Fix: change call to event_log.emit(kind, **{...}) or emit(kind, k1=v1, ...)

These tests pin the API contract so the bug can't recur silently.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.agent.event_log import EventLog


@pytest.fixture
def evlog(tmp_path):
    return EventLog(tmp_path / "events.jsonl")


def test_emit_accepts_kind_plus_kwargs(evlog):
    """The canonical happy path — kind positional, payload as kwargs."""
    result = evlog.emit("test_kind", phase="recon", note="hello")
    assert result is not None
    # Verify it actually wrote to disk
    lines = evlog.path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed.get("kind") == "test_kind" or parsed.get("phase") == "recon"


def test_emit_rejects_positional_payload_dict(evlog):
    """Calling emit(kind, {dict}) must raise TypeError. This is the bug
    pattern from tools.py:431 — pin it as forbidden so a future regression
    introducing the same shape gets caught."""
    with pytest.raises(TypeError, match=r"takes 2 positional"):
        evlog.emit("test_kind", {"phase": "recon", "note": "hello"})


def test_emit_with_unpacked_dict_works(evlog):
    """The fix pattern: spread a dict via ** into kwargs."""
    payload = {"phase": "recon", "note": "hello", "n": 42}
    result = evlog.emit("test_kind", **payload)
    assert result is not None
    parsed = json.loads(evlog.path.read_text(encoding="utf-8").strip())
    # Some shape of "n=42" should be in the persisted record
    assert "42" in evlog.path.read_text() or parsed.get("n") == 42


def test_chain_step_emit_pattern(evlog):
    """The exact call shape used at tools.py:431 (post-fix). Pins the
    behavior so the chain-step emission keeps working as the call site
    is refactored."""
    evlog.emit(
        "chain_step_ok",
        chain_id="chain_admin_session_takeover_005",
        step_index=3,
        primitive_type="js_exec_browser_context",
        is_rollback=False,
    )
    text = evlog.path.read_text(encoding="utf-8")
    assert "chain_admin_session_takeover_005" in text
    assert "js_exec_browser_context" in text
