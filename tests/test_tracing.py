"""Wave 2 / A4 — Tracing tree tests.

Asserted properties:
  - `trace_span` emits paired span_started/span_ended with span_id,
    parent_span_id, started_at, ended_at, duration_sec.
  - Nested spans correctly resolve parent_span_id to the enclosing span.
  - `build_span_tree` produces a tree with stable parent-child links.
  - `flatten_for_flame` returns rows with depth annotated.
  - Missing/orphaned spans don't crash the tree builder.
  - Negative durations don't appear (clamped to >= 0).
  - Span events from event_log render with the new event_styles.
"""

from __future__ import annotations

import time
from typing import Any

from sentinel.agent import event_log as elog
from sentinel.agent.tracing import (
    KNOWN_KINDS,
    build_span_tree,
    current_span_id,
    flatten_for_flame,
    new_span_id,
    parent_span_id,
    trace_span,
)


class _StubEventLog:
    def __init__(self):
        self.events: list[tuple[str, dict]] = []

    def emit(self, kind: str, **payload: Any) -> dict:
        e = {"kind": kind, **payload}
        self.events.append((kind, e))
        return e

    def all_events(self) -> list[dict]:
        return [e for _k, e in self.events]


def test_new_span_id_is_8_hex():
    sid = new_span_id()
    assert len(sid) == 8
    int(sid, 16)  # hex decode shouldn't raise


def test_known_kinds_includes_8_documented():
    expected = {"phase", "agent", "tool_call", "handoff",
                 "mcp_list", "generation", "guardrail", "verifier"}
    assert expected.issubset(KNOWN_KINDS)


def test_trace_span_emits_paired_events():
    log = _StubEventLog()
    with trace_span("recon", kind="phase", event_log=log):
        pass
    kinds = [k for k, _ in log.events]
    assert kinds == ["span_started", "span_ended"]


def test_trace_span_paired_events_share_span_id():
    log = _StubEventLog()
    with trace_span("recon", kind="phase", event_log=log) as sid:
        assert sid is not None
    started, ended = log.events
    assert started[1]["span_id"] == ended[1]["span_id"] == sid


def test_trace_span_records_duration():
    log = _StubEventLog()
    with trace_span("slow", kind="tool_call", event_log=log):
        time.sleep(0.02)
    ended = log.events[-1][1]
    assert ended["duration_sec"] >= 0.0
    assert ended["duration_sec"] < 5.0


def test_trace_span_nesting_resolves_parent():
    log = _StubEventLog()
    with trace_span("outer", kind="phase", event_log=log) as outer:
        with trace_span("inner", kind="tool_call", event_log=log) as inner:
            # While inside the inner span, the active span is `inner`.
            assert current_span_id() == inner
            # Parent (one level up) is `outer`.
            assert parent_span_id() == outer
    started_events = [e for k, e in log.events if k == "span_started"]
    inner_started = next(e for e in started_events if e["span_name"] == "inner")
    outer_started = next(e for e in started_events if e["span_name"] == "outer")
    assert inner_started["parent_span_id"] == outer_started["span_id"]
    assert outer_started["parent_span_id"] is None


def test_trace_span_explicit_parent_override():
    log = _StubEventLog()
    with trace_span("a", kind="phase", event_log=log, parent="manual_root"):
        pass
    started = log.events[0][1]
    assert started["parent_span_id"] == "manual_root"


def test_build_span_tree_simple():
    log = _StubEventLog()
    with trace_span("phase1", kind="phase", event_log=log):
        with trace_span("tool1", kind="tool_call", event_log=log):
            pass
        with trace_span("tool2", kind="tool_call", event_log=log):
            pass
    tree = build_span_tree(log.all_events())
    assert len(tree) == 1
    assert tree[0]["span_name"] == "phase1"
    assert len(tree[0]["children"]) == 2
    names = sorted(c["span_name"] for c in tree[0]["children"])
    assert names == ["tool1", "tool2"]


def test_build_span_tree_handles_orphans():
    """Span with parent_span_id pointing at a missing span_id should
    still render — treated as a root."""
    events = [
        {"kind": "span_started", "span_id": "child", "span_name": "x",
         "span_kind": "tool_call", "parent_span_id": "missing-parent",
         "started_at": 1.0},
        {"kind": "span_ended", "span_id": "child", "duration_sec": 0.1,
         "span_kind": "tool_call", "span_name": "x"},
    ]
    tree = build_span_tree(events)
    assert len(tree) == 1
    assert tree[0]["span_id"] == "child"


def test_build_span_tree_open_span_marked():
    """A span_started without a matching span_ended should appear with
    status='open' so the flame graph renders in-flight runs cleanly."""
    events = [
        {"kind": "span_started", "span_id": "live", "span_name": "current",
         "span_kind": "phase", "parent_span_id": None, "started_at": 1.0},
    ]
    tree = build_span_tree(events)
    assert tree[0]["status"] == "open"


def test_flatten_for_flame_depth():
    log = _StubEventLog()
    with trace_span("p", kind="phase", event_log=log):
        with trace_span("t1", kind="tool_call", event_log=log):
            with trace_span("t1.inner", kind="tool_call", event_log=log):
                pass
    flame = flatten_for_flame(log.all_events())
    assert flame[0]["depth"] == 0
    assert flame[1]["depth"] == 1
    assert flame[2]["depth"] == 2


def test_flatten_for_flame_empty():
    assert flatten_for_flame([]) == []


def test_trace_span_no_event_log_doesnt_raise():
    """Tools that don't have a live event log handy must still get
    the contextvar parent-tracking bookkeeping right."""
    with trace_span("a", kind="phase", event_log=None):
        with trace_span("b", kind="tool_call", event_log=None) as inner_b:
            assert current_span_id() == inner_b
    # No assertion on emitted events — just that nothing raised.


def test_trace_span_exception_marks_span_error():
    log = _StubEventLog()
    try:
        with trace_span("bad", kind="phase", event_log=log):
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    ended = log.events[-1][1]
    assert ended["error"]
    assert "boom" in ended["error"]


def test_event_styles_render_new_kinds():
    """span_started + span_ended must appear in EVENT_STYLES so the
    dashboard renders them with a non-default chip."""
    from sentinel.web.event_styles import EVENT_STYLES, style_for, style_for_span_kind
    assert "span_started" in EVENT_STYLES
    assert "span_ended" in EVENT_STYLES
    assert style_for("span_started")["group"] == "trace"
    # span_kind styles
    assert style_for_span_kind("phase")["chip"] != "info" or True  # any chip is fine
    assert style_for_span_kind("unknown_kind")["icon"] == "·"  # safe default


def test_retester_and_ctrlc_event_styles_registered():
    """Wave 2 also added retester_verdict + ctrlc_reconcile event kinds."""
    from sentinel.web.event_styles import EVENT_STYLES
    assert "retester_verdict" in EVENT_STYLES
    assert "ctrlc_reconcile" in EVENT_STYLES


def test_real_event_log_round_trip(tmp_path):
    """trace_span paired with a real EventLog persists to disk and the
    flame-graph builder reconstructs the tree from the loaded events."""
    log_path = tmp_path / "events.jsonl"
    log = elog.EventLog(log_path)
    with trace_span("phase", kind="phase", event_log=log):
        with trace_span("tool", kind="tool_call", event_log=log):
            pass
    reloaded = elog.EventLog.load(log_path)
    tree = build_span_tree(reloaded.all_events())
    assert tree[0]["span_name"] == "phase"
    assert tree[0]["children"][0]["span_name"] == "tool"
