"""Tests for sentinel.agent.pentest.control_channel — Phase B (#64).

The channel is an append-only directive queue. Tests cover:
  - enqueue persists messages to disk
  - history() returns all messages in order with pending/consumed state
  - drain() returns pending messages and marks them consumed
  - drain() is idempotent — calling again returns []
  - render_directives_for_prompt formats messages for prompt injection
  - the consumed file stays separate so the channel itself is immutable
"""

from __future__ import annotations

import json

import pytest

from sentinel.agent.pentest.control_channel import (
    ControlChannel,
    OperatorMessage,
    render_directives_for_prompt,
)


@pytest.fixture
def chan(tmp_path):
    return ControlChannel("test-job-001", runs_dir=tmp_path)


def test_enqueue_persists_message_to_disk(chan):
    msg = chan.enqueue("skip vuln:ssrf")
    assert msg.content == "skip vuln:ssrf"
    assert msg.role == "operator"
    assert msg.consumed_at is None
    assert chan.channel_path.exists()
    raw = chan.channel_path.read_text(encoding="utf-8").strip()
    assert "skip vuln:ssrf" in raw


def test_history_returns_messages_in_order(chan):
    chan.enqueue("first")
    chan.enqueue("second")
    chan.enqueue("third")
    msgs = chan.history()
    assert [m.content for m in msgs] == ["first", "second", "third"]
    # All pending until drained
    assert all(m.consumed_at is None for m in msgs)


def test_drain_returns_pending_and_marks_consumed(chan):
    chan.enqueue("focus on /admin")
    chan.enqueue("what's the current target?")
    pending = chan.drain()
    assert [m.content for m in pending] == ["focus on /admin", "what's the current target?"]
    # All have a consumed_at after drain
    assert all(m.consumed_at is not None for m in pending)
    # History reflects the consumed state too
    history = chan.history()
    assert all(m.consumed_at is not None for m in history)


def test_drain_is_idempotent(chan):
    chan.enqueue("once")
    first = chan.drain()
    second = chan.drain()
    assert len(first) == 1
    assert second == []  # nothing pending


def test_drain_picks_up_messages_added_after_first_drain(chan):
    chan.enqueue("early")
    chan.drain()
    chan.enqueue("late")
    pending = chan.drain()
    assert [m.content for m in pending] == ["late"]


def test_channel_file_remains_append_only_after_drain(chan):
    chan.enqueue("a")
    chan.enqueue("b")
    pre_drain_lines = chan.channel_path.read_text().count("\n")
    chan.drain()
    post_drain_lines = chan.channel_path.read_text().count("\n")
    # Channel file UNCHANGED — only the consumed sidecar gets written
    assert pre_drain_lines == post_drain_lines
    assert chan.consumed_path.exists()


def test_render_directives_for_prompt_empty_returns_empty_string():
    assert render_directives_for_prompt([]) == ""


def test_render_directives_for_prompt_formats_with_priority_marker():
    msgs = [
        OperatorMessage(ts=1.0, job_id="j", role="operator", content="skip ssrf"),
        OperatorMessage(ts=2.0, job_id="j", role="operator", content="focus on auth"),
    ]
    rendered = render_directives_for_prompt(msgs)
    assert "OPERATOR DIRECTIVES" in rendered
    assert "highest priority" in rendered
    assert "skip ssrf" in rendered
    assert "focus on auth" in rendered
    # Trailing newlines so the next prompt content is visually separated
    assert rendered.endswith("\n\n")
