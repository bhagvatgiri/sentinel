"""Structured event log for agent runs.

Two consumers:

1. **Live dashboard** — reads the in-memory tail every couple seconds.
2. **Forensic replay** — reads the on-disk JSONL after the run.

The pipeline + brain queue + tools all `emit(kind, **payload)` events.
The dashboard's `grouped()` helper carves the stream into the three
panels the UI shows: phase ladder, brain panel, recent activity.

JSONL is append-only and one event per line. Schema is loose — every
event has `ts` (float) + `kind` (str) and any other keys are
kind-specific.
"""

from __future__ import annotations

import collections
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional


log = logging.getLogger(__name__)


# Where event files live. One file per `job_id`, named events-<job_id>.jsonl.
DEFAULT_EVENTS_DIR = Path("./runs")


def events_path(job_id: str, *, runs_dir: Path | str | None = None) -> Path:
    """Resolve the on-disk path for a given job_id's event log.

    ``runs_dir=None`` resolves ``DEFAULT_EVENTS_DIR`` at call time (NOT
    import time) so monkeypatching the module-level default works in
    tests (same convention as ``delete_event_log`` already used).
    """
    if runs_dir is None:
        runs_dir = DEFAULT_EVENTS_DIR
    runs_dir = Path(runs_dir).expanduser()
    runs_dir.mkdir(parents=True, exist_ok=True)
    return runs_dir / f"events-{job_id}.jsonl"


# ---- known event kinds ---------------------------------------------------

# Pipeline lifecycle
KIND_PIPELINE_STARTED = "pipeline_started"
KIND_PIPELINE_COMPLETED = "pipeline_completed"
KIND_PHASE_STARTED = "phase_started"
KIND_PHASE_COMPLETED = "phase_completed"
KIND_PHASE_FAILED = "phase_failed"

# Pentest agent activity
KIND_TOOL_CALLED = "tool_called"
KIND_TOOL_RESULT = "tool_result"
KIND_AGENT_TEXT = "agent_text"

# Brain queue activity
KIND_BRAIN_ENQUEUED = "brain_enqueued"
KIND_BRAIN_SKIPPED = "brain_skipped"
KIND_BRAIN_STARTED = "brain_started"
KIND_BRAIN_COMPLETED = "brain_completed"
KIND_BRAIN_FAILED = "brain_failed"

# Brain agent's per-source activity (when the brain itself is running)
KIND_BRAIN_SEARCH = "brain_search"
KIND_BRAIN_FETCH = "brain_fetch"
KIND_BRAIN_INGEST = "brain_ingest"
KIND_BRAIN_DEDUP_SKIP = "brain_dedup_skip"

# Phase 3.5 — chain-attack executor
KIND_CHAIN_STARTED = "chain_started"
KIND_CHAIN_STEP_OK = "chain_step_ok"
KIND_CHAIN_STEP_FAIL = "chain_step_fail"
KIND_CHAIN_COMPLETED = "chain_completed"
KIND_CHAIN_ABANDONED = "chain_abandoned"


# ---- writer + tail buffer -----------------------------------------------

class EventLog:
    """Append events to JSONL on disk + keep an in-memory tail for the
    dashboard. Safe for single-writer use (pipeline owns the instance).

    For the dashboard side, see `EventLog.load(path)` which reads the
    full file into memory (capped) — it's a separate instance from the
    writer side and read-only.
    """

    def __init__(self, path: Path, *, in_memory_tail: int = 500):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._tail: collections.deque[dict] = collections.deque(maxlen=in_memory_tail)

    def emit(self, kind: str, **payload: Any) -> dict:
        """Append an event. Returns the event dict (so callers can chain
        or log it elsewhere)."""
        event = {"ts": time.time(), "kind": kind, **payload}
        self._tail.append(event)
        try:
            with self.path.open("a") as fh:
                fh.write(json.dumps(event, default=str) + "\n")
        except OSError as e:
            log.warning("event_log: write to %s failed: %s", self.path, e)
        # Phase 4.5 STREAM-01 — fan out to registered subscribers AFTER the
        # JSONL line is on disk + the in-memory tail is updated. Lazy import
        # avoids a circular dep: event_subscribers TYPE_CHECKING-imports
        # AuditLog which lives in sentinel.core.scope, and pipeline.py
        # imports both. Defensive try/except — a subscriber dispatch failure
        # must never break the pipeline's emit contract (same pattern as the
        # OSError wrap on the file write above).
        try:
            from sentinel.agent.pentest import event_subscribers as _subs
            _subs.dispatch(self, event)
        except Exception as e:  # noqa: BLE001
            log.warning("event_log: subscriber dispatch failed: %s", e)
        return event

    def all_events(self) -> list[dict]:
        return list(self._tail)

    def events_since(self, ts: float) -> list[dict]:
        return [e for e in self._tail if e.get("ts", 0) > ts]

    @classmethod
    def load(cls, path: Path | str, *, max_events: int = 200_000) -> "EventLog":
        """Read an existing JSONL into a new EventLog. Used by the
        dashboard route — read effectively all of it so the early
        `pipeline_started` + `phase_started` events stay in the
        in-memory window. Without this, long runs (>2k events) drop
        the early phase markers and the dashboard renders 'unknown'
        + 'Pipeline hasn't reported any phase events yet'."""
        path = Path(path).expanduser()
        log_obj = cls(path, in_memory_tail=max_events)
        if not path.is_file():
            return log_obj
        try:
            with path.open() as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        log_obj._tail.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError as e:
            log.warning("event_log: read from %s failed: %s", path, e)
        return log_obj

    # ---- analytics for the dashboard --------------------------------

    def grouped(self) -> dict:
        """Carve the event stream into dashboard-shaped state.

        Returns a dict with keys:
        - meta: pipeline started/completed timestamps + status
        - phases: list of {name, status, started_at, completed_at, cost_usd, turns, current_tool}
        - brain: {in_flight, queued, processed, skipped_dup, failed,
                  total_cost_usd, chunks_added, recent_topics}
        - recent: last N raw events (for the activity stream panel)
        """
        events = list(self._tail)
        meta = self._derive_meta(events)
        phases = self._derive_phases(events)
        brain = self._derive_brain(events)
        recent = list(reversed(events))[:60]  # newest first
        return {
            "meta": meta,
            "phases": phases,
            "brain": brain,
            "recent": recent,
            "total_events": len(events),
        }

    @staticmethod
    def _derive_meta(events: list[dict]) -> dict:
        started = next((e for e in events if e["kind"] == KIND_PIPELINE_STARTED), None)
        completed = next((e for e in reversed(events)
                          if e["kind"] == KIND_PIPELINE_COMPLETED), None)
        # Status precedence (2026-XX-XX fix for "Unknown" badge):
        #   completed     → terminal: pipeline_completed event present
        #   running       → pipeline_started present, no completion yet
        #   initializing  → events present but no pipeline_started (file
        #                   just created, pipeline_started not yet flushed,
        #                   OR we hit the in-memory cap and the early
        #                   marker rolled off — better than "unknown")
        #   unknown       → genuinely empty event log (should never happen
        #                   for a real run; only when load() races a
        #                   freshly-touched file)
        if completed:
            status = "completed"
        elif started:
            status = "running"
        elif events:
            status = "initializing"
        else:
            status = "unknown"
        return {
            "started_at": (started or {}).get("ts"),
            "started_payload": started or {},
            "completed_at": (completed or {}).get("ts"),
            "completed_payload": completed or {},
            "status": status,
        }

    @staticmethod
    def _derive_phases(events: list[dict]) -> list[dict]:
        # Order by started_at; map name → state as we walk.
        phases: dict[str, dict] = {}
        for e in events:
            kind = e["kind"]
            name = e.get("phase")
            if kind == KIND_PHASE_STARTED and name:
                phases[name] = {
                    "name": name, "status": "running",
                    "started_at": e["ts"], "completed_at": None,
                    "cost_usd": 0.0, "turns": 0,
                    "current_tool": None, "current_tool_args": None,
                    "error": None,
                }
            elif kind == KIND_PHASE_COMPLETED and name and name in phases:
                phases[name].update({
                    "status": "ok",
                    "completed_at": e["ts"],
                    "cost_usd": float(e.get("cost_usd", 0) or 0),
                    "turns": int(e.get("turns", 0) or 0),
                    "current_tool": None, "current_tool_args": None,
                })
            elif kind == KIND_PHASE_FAILED and name and name in phases:
                phases[name].update({
                    "status": "failed",
                    "completed_at": e["ts"],
                    "error": e.get("error") or "unknown",
                    "current_tool": None, "current_tool_args": None,
                })
            elif kind == KIND_TOOL_CALLED and name and name in phases:
                if phases[name]["status"] == "running":
                    phases[name]["current_tool"] = e.get("tool_name")
                    phases[name]["current_tool_args"] = e.get("args_summary")
        # Stable order by started_at.
        return sorted(phases.values(), key=lambda p: p.get("started_at") or 0)

    @staticmethod
    def _derive_brain(events: list[dict]) -> dict:
        in_flight: Optional[str] = None
        queued: list[str] = []
        processed: list[dict] = []
        skipped: list[dict] = []
        failed: list[dict] = []
        total_cost = 0.0
        chunks_added = 0
        # Track each topic's lifecycle: enqueued → started → completed/failed
        topic_state: dict[str, dict] = {}

        for e in events:
            kind = e["kind"]
            topic = e.get("topic")
            if kind == KIND_BRAIN_ENQUEUED and topic:
                topic_state[topic] = {"topic": topic, "state": "queued",
                                      "enqueued_at": e["ts"],
                                      "requested_by": e.get("requested_by", "")}
            elif kind == KIND_BRAIN_SKIPPED and topic:
                skipped.append({"topic": topic, "reason": e.get("reason", ""),
                                "ts": e["ts"]})
            elif kind == KIND_BRAIN_STARTED and topic:
                if topic in topic_state:
                    topic_state[topic]["state"] = "in_flight"
                    topic_state[topic]["started_at"] = e["ts"]
                in_flight = topic
            elif kind == KIND_BRAIN_COMPLETED and topic:
                in_flight = None
                if topic in topic_state:
                    topic_state[topic].update({
                        "state": "completed",
                        "completed_at": e["ts"],
                        "chunks_added": int(e.get("chunks_added", 0) or 0),
                        "cost_usd": float(e.get("cost_usd", 0) or 0),
                    })
                processed.append({
                    "topic": topic, "ts": e["ts"],
                    "chunks_added": int(e.get("chunks_added", 0) or 0),
                    "cost_usd": float(e.get("cost_usd", 0) or 0),
                })
                total_cost += float(e.get("cost_usd", 0) or 0)
                chunks_added += int(e.get("chunks_added", 0) or 0)
            elif kind == KIND_BRAIN_FAILED and topic:
                in_flight = None
                if topic in topic_state:
                    topic_state[topic]["state"] = "failed"
                failed.append({"topic": topic, "ts": e["ts"],
                               "error": e.get("error", "unknown")})

        queued = [t["topic"] for t in topic_state.values() if t["state"] == "queued"]

        return {
            "in_flight": in_flight,
            "queued": queued,
            "processed": processed[-10:],  # last 10
            "skipped": skipped[-10:],
            "failed": failed[-5:],
            "total_cost_usd": total_cost,
            "chunks_added": chunks_added,
            "topic_count": len(topic_state),
        }


# ---- helpers --------------------------------------------------------------

def derive_job_id_from_env(default: Optional[str] = None) -> str:
    """Pipeline calls this at startup. UI-launched jobs get SENTINEL_JOB_ID
    in their env (set by `jobs.launch`); CLI-launched runs get a fresh
    timestamp-based ID."""
    env = os.environ.get("SENTINEL_JOB_ID", "").strip()
    if env:
        # Sanitize: only [a-zA-Z0-9_-]
        safe = re.sub(r"[^A-Za-z0-9_-]", "-", env)[:64]
        if safe:
            return safe
    if default:
        return default
    return f"cli-{time.strftime('%Y%m%d-%H%M%S')}"


def delete_event_log(job_id: str, *, runs_dir: Path | str | None = None) -> bool:
    """Remove the events JSONL (and any sibling .tail* buffer) for a job_id.

    Scope: ONLY the dashboard's view of the run. Workspace deliverables
    and the engagement audit log (`<workspace>/.audit-*.jsonl`) are NOT
    touched — they live elsewhere on disk and are the legal artifact.

    Defense-in-depth: refuses paths that escape runs_dir (job_id traversal
    via "../foo" etc.). Returns True if at least one file was removed,
    False if the events file didn't exist (idempotent — caller can ignore).
    Raises ValueError if the job_id resolves outside runs_dir.

    `runs_dir=None` resolves DEFAULT_EVENTS_DIR at call time (NOT import
    time), so monkeypatching the module-level default works in tests.
    """
    if runs_dir is None:
        runs_dir = DEFAULT_EVENTS_DIR
    runs_dir = Path(runs_dir).expanduser().resolve()
    target = events_path(job_id, runs_dir=runs_dir).resolve()
    # The resolved target must sit DIRECTLY inside runs_dir. Use parents
    # check so a "../" job_id can't escape (target.parent != runs_dir).
    if target.parent != runs_dir:
        raise ValueError(
            f"refusing to delete outside runs_dir: target={target} runs_dir={runs_dir}"
        )
    removed = False
    candidates = [target]
    # Pick up any .tail* sibling buffers that may exist for live runs.
    candidates.extend(runs_dir.glob(f"events-{job_id}.tail*"))
    for p in candidates:
        try:
            p.unlink()
            removed = True
        except FileNotFoundError:
            continue
        except OSError as e:
            log.warning("delete_event_log: failed to unlink %s: %s", p, e)
    return removed


def list_event_logs(runs_dir: Path | str = DEFAULT_EVENTS_DIR) -> list[dict]:
    """List every events-*.jsonl in runs_dir, newest first.
    Each entry: {job_id, path, mtime, size_bytes, status}.
    `status` is sniffed from the LAST event in the file."""
    runs_dir = Path(runs_dir).expanduser()
    if not runs_dir.is_dir():
        return []
    out: list[dict] = []
    for p in runs_dir.glob("events-*.jsonl"):
        try:
            stat = p.stat()
        except OSError:
            continue
        job_id = p.stem.removeprefix("events-")
        status = _sniff_status(p)
        out.append({
            "job_id": job_id,
            "path": str(p),
            "mtime": stat.st_mtime,
            "size_bytes": stat.st_size,
            "status": status,
        })
    return sorted(out, key=lambda x: x["mtime"], reverse=True)


def _sniff_status(path: Path, *, tail_bytes: int = 4096) -> str:
    """Cheap status check — read the tail of the file and look for a
    pipeline_completed event.

    Status values: completed | failed | running | stalled | initializing | unknown.
    `initializing` is for files that exist but have 0 events yet (just created).
    `unknown` is reserved for true IO failures.
    """
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - tail_bytes))
            tail = fh.read().decode("utf-8", errors="ignore")
    except OSError:
        return "unknown"
    if size == 0:
        # File exists but is empty — pipeline opened the log but hasn't
        # written anything yet. Recent → initializing; old → stalled.
        try:
            age = time.time() - path.stat().st_mtime
            return "initializing" if age < 30 else "stalled"
        except OSError:
            return "unknown"
    for line in reversed(tail.strip().splitlines()):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = ev.get("kind", "")
        if kind == KIND_PIPELINE_COMPLETED:
            return "completed"
        if kind == KIND_PHASE_FAILED:
            return "failed"
    # No explicit completion marker — if the file was modified recently,
    # call it "running"; otherwise "stalled".
    try:
        age = time.time() - path.stat().st_mtime
        return "running" if age < 60 else "stalled"
    except OSError:
        return "unknown"
