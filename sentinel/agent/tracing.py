"""Wave 2 / A4 — Typed parent-child span tree for agent runs.

CAI's `sdk/agents/tracing/span_data.py` defines 8 typed Span subclasses
(Agent / Function / Handoff / Guardrail / Generation / MCPListTools /
Response / Custom) plus a `BatchTraceProcessor` daemon thread with
exponential backoff. Sentinel's existing `event_log.emit(kind, payload)`
is flat — no parent/child, no per-span duration, no kind taxonomy that
would let the dashboard render a flame graph.

This module adds the missing primitive: a context-manager API that
emits `span_started` + `span_ended` events with a `parent_span_id`
chain. Every existing `event_log.emit` call still works; events with no
parent_span_id render as flat (back-compat). The dashboard reads the
ended-events to build a flame graph.

Design choices vs CAI:
- We don't ship a separate trace processor — the existing EventLog
  IS the processor. Spans are just events with extra fields.
- Span IDs are short (8-char hex) instead of CAI's 32-char so the
  flame graph URL stays compact.
- A module-level "current span stack" is contextvar-backed so nested
  spans in async tasks don't bleed across tasks. CAI does this with
  thread-local; we mirror in asyncio land.
- `kind` is a str rather than an enum so plugin tools can introduce
  new span kinds without editing this module. The 8 documented kinds
  are: phase, agent, tool_call, handoff, mcp_list, generation,
  guardrail, verifier.
"""

from __future__ import annotations

import contextlib
import contextvars
import secrets
import time
from typing import Any, Iterator, Optional


# ---- Span ID + active-stack contextvar ---------------------------------

# 8-char hex is collision-resistant enough for one run (~10^9 spans before
# collision risk) and renders cleanly in the flame graph.
def new_span_id() -> str:
    return secrets.token_hex(4)


# Active span stack — populated by `trace_span` enter/exit. Contextvar
# rather than module-global so two concurrent asyncio.gather'd phases
# don't claim each other as parents.
_active_stack: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar(
    "_sentinel_span_stack", default=tuple()
)


def current_span_id() -> Optional[str]:
    """Return the innermost active span_id, or None if no span is open."""
    stack = _active_stack.get()
    return stack[-1] if stack else None


def parent_span_id() -> Optional[str]:
    """Return the parent of the innermost active span (one level up)."""
    stack = _active_stack.get()
    return stack[-2] if len(stack) >= 2 else None


# ---- Public API: trace_span ---------------------------------------------

# Known span kinds. Plugin tools may introduce new kinds without editing
# this set — it's informational, not authoritative.
KNOWN_KINDS = frozenset({
    "phase", "agent", "tool_call", "handoff",
    "mcp_list", "generation", "guardrail", "verifier",
})


@contextlib.contextmanager
def trace_span(
    name: str,
    *,
    kind: str,
    event_log: Any = None,
    parent: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> Iterator[str]:
    """Yield a span_id; auto-emit `span_started` + `span_ended` with duration.

    Usage:
        with trace_span("vuln:auth", kind="phase", event_log=elog) as sid:
            ... run phase ...
            # nested spans pick up `sid` as their parent automatically
            with trace_span("tool:run_bash", kind="tool_call", event_log=elog):
                ...

    `parent` overrides automatic parent inference (rarely needed —
    pipeline uses it when a phase span wraps a parallel asyncio task
    whose contextvar copy doesn't include the launching phase span).

    `event_log` is the run's EventLog; if None, the span runs but emits
    nothing (useful for tests + tools that don't have a live log handy).
    """
    span_id = new_span_id()
    inferred_parent = parent if parent is not None else current_span_id()

    # Push onto the active stack BEFORE emitting span_started so any
    # synchronous emits made during start handlers see this span as
    # the current span.
    stack = _active_stack.get()
    token = _active_stack.set(stack + (span_id,))

    started_at = time.time()
    payload_started = {
        "span_id": span_id,
        "span_kind": kind,
        "span_name": name,
        "parent_span_id": inferred_parent,
        "started_at": started_at,
    }
    if metadata:
        payload_started["metadata"] = dict(metadata)

    if event_log is not None:
        try:
            event_log.emit("span_started", **payload_started)
        except Exception:
            # Tracing is observability — must never break the run.
            pass

    error_str: Optional[str] = None
    try:
        yield span_id
    except BaseException as e:
        error_str = f"{type(e).__name__}: {str(e)[:240]}"
        raise
    finally:
        ended_at = time.time()
        duration = max(0.0, ended_at - started_at)
        payload_ended = {
            "span_id": span_id,
            "span_kind": kind,
            "span_name": name,
            "parent_span_id": inferred_parent,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_sec": round(duration, 4),
            "error": error_str,
        }
        if event_log is not None:
            try:
                event_log.emit("span_ended", **payload_ended)
            except Exception:
                pass
        _active_stack.reset(token)


# ---- Helpers for the flame-graph view -----------------------------------

def build_span_tree(events: list[dict]) -> list[dict]:
    """Build a parent-child tree of spans from a flat list of events.

    Returns a list of root spans; each span has a `children` list. Spans
    are matched by (span_started.span_id == span_ended.span_id). Spans
    with no matching `span_ended` are still included (status="open") so
    the flame graph renders in-flight runs cleanly.

    Robust to malformed input — events without span_id are ignored,
    not raised.
    """
    spans: dict[str, dict] = {}
    for e in events:
        kind = e.get("kind")
        if kind not in ("span_started", "span_ended"):
            continue
        sid = e.get("span_id")
        if not sid:
            continue
        if sid not in spans:
            spans[sid] = {
                "span_id": sid,
                "span_kind": e.get("span_kind", "unknown"),
                "span_name": e.get("span_name", "?"),
                "parent_span_id": e.get("parent_span_id"),
                "started_at": None,
                "ended_at": None,
                "duration_sec": 0.0,
                "status": "open",
                "error": None,
                "children": [],
            }
        s = spans[sid]
        if kind == "span_started":
            s["started_at"] = e.get("started_at") or e.get("ts")
            # Update mutable defaults from the started event.
            s["span_kind"] = e.get("span_kind", s["span_kind"])
            s["span_name"] = e.get("span_name", s["span_name"])
            s["parent_span_id"] = e.get("parent_span_id", s["parent_span_id"])
        elif kind == "span_ended":
            s["ended_at"] = e.get("ended_at") or e.get("ts")
            s["duration_sec"] = float(e.get("duration_sec") or 0.0)
            s["error"] = e.get("error")
            s["status"] = "error" if e.get("error") else "ok"

    # Stitch children. Spans with parent_span_id missing or unknown are
    # roots — keeps a malformed tree renderable.
    roots: list[dict] = []
    for sid, s in spans.items():
        pid = s["parent_span_id"]
        if pid and pid in spans:
            spans[pid]["children"].append(s)
        else:
            roots.append(s)

    # Stable order by started_at within each level.
    def _sort(node: dict) -> None:
        node["children"].sort(key=lambda n: (n.get("started_at") or 0))
        for c in node["children"]:
            _sort(c)
    roots.sort(key=lambda n: (n.get("started_at") or 0))
    for r in roots:
        _sort(r)
    return roots


def flatten_for_flame(events: list[dict]) -> list[dict]:
    """Return a flat list of span dicts with depth (for flame-graph rendering).

    Each row: {span_id, span_name, span_kind, depth, started_at,
    duration_sec, status, error, parent_span_id}. Depth is 0-indexed
    from the root of each tree.
    """
    tree = build_span_tree(events)
    out: list[dict] = []

    def _walk(node: dict, depth: int) -> None:
        out.append({
            "span_id": node["span_id"],
            "span_name": node["span_name"],
            "span_kind": node["span_kind"],
            "parent_span_id": node["parent_span_id"],
            "depth": depth,
            "started_at": node["started_at"],
            "ended_at": node["ended_at"],
            "duration_sec": node["duration_sec"],
            "status": node["status"],
            "error": node["error"],
        })
        for c in node["children"]:
            _walk(c, depth + 1)

    for r in tree:
        _walk(r, 0)
    return out


__all__ = [
    "KNOWN_KINDS",
    "build_span_tree",
    "current_span_id",
    "flatten_for_flame",
    "new_span_id",
    "parent_span_id",
    "trace_span",
]
