"""Agent-run dashboard — live + replay view of an autonomous-pentest run.

Reads the structured EventLog (`runs/events-<job_id>.jsonl`) the pipeline
writes as it runs. Renders four panels:

- **Phase ladder** — per-phase status (queued/running/ok/failed),
  current tool, cost, turn count, duration.
- **Brain panel** — in-flight topic, queued list, per-topic
  status (processed/skipped/failed), $/chunks totals.
- **Activity stream** — last N events, newest first, kind-tagged.
- **Streaming subscribers** (Phase 4.5 STREAM-06) — per-downstream-phase
  card view of subscriber_fired / streaming_phase_started /
  subscribers_halted events; halted banner when the cost-cap watchdog
  has fired; empty state for legacy runs without streaming activity.

HTMX-polled every 2s while the run is active; static once it completes.

Routes:
- GET /agent-runs                      — list of all event logs (newest first)
- GET /agent-runs/<job_id>             — full page for one run
- GET /agent-runs/<job_id>/refresh     — HTMX partial swapped every 2s
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from sentinel.agent import event_log as elog
from sentinel.ui.state import UIConfig
from sentinel.web.deps import get_config
from sentinel.web.run_status import compute_run_status


router = APIRouter()

log = logging.getLogger(__name__)


# ---- Phase 4.5 STREAM-06 — derive_streaming_state helper ----------------
#
# Maps subscriber_fired callback_name values to the downstream-phase bucket
# the dashboard card-list renders. Lives at module scope so tests + the
# route handler share one source of truth.
#
# The user-visible buckets are the three Phase 4.5 streaming subscribers
# (Plans 04.5-02 / 04.5-03 / 04.5-04):
#   correlation.absorb                 -> 'correlation'      (Plan 04.5-02)
#   report.absorb                      -> 'report'           (Plan 04.5-04)
#   verify_phase_03.streaming          -> 'verify-phase-03'  (Plan 04.5-03)
#
# The cost-cap watchdog (Plan 04.5-05) is a system-row, surfaced as a small
# footer line rather than a primary card:
#   event_subscribers.cost_cap_watchdog -> 'cost_cap_watchdog'
#
# Any future / unknown callback_name lands in '_other' so the dashboard
# stays defensive — a future subscriber doesn't crash the panel.

_CALLBACK_TO_PHASE: dict[str, str] = {
    "correlation.absorb": "correlation",
    "report.absorb": "report",
    "verify_phase_03.streaming": "verify-phase-03",
    "event_subscribers.cost_cap_watchdog": "cost_cap_watchdog",
}


def _empty_phase_bucket() -> dict[str, Any]:
    """Initial shape for one downstream-phase bucket. Defensive defaults so
    every field is present even before the first event lands."""
    return {
        "install_ts": None,
        "absorbed_count": 0,
        "per_trigger": {},
        "last_absorbed_ts": None,
        "error_count": 0,
        "recent_triggers": [],
    }


def derive_streaming_state(events: list[dict]) -> dict:
    """Walk every event ONCE and bucket the Phase 4.5 streaming events
    (subscriber_fired / streaming_phase_started / subscribers_halted) by
    downstream-phase name.

    Returns a dict shaped::

        {
          'phases': {
            'correlation': {
              'install_ts': float | None,
              'absorbed_count': int,
              'per_trigger': {'phase_completed': N, ...},
              'last_absorbed_ts': float | None,
              'error_count': int,
              'recent_triggers': [
                {'trigger_kind': str, 'ts': float, 'outcome': str},
                ...  # last 5
              ],
            },
            'report': {...},
            'verify-phase-03': {...},
            'cost_cap_watchdog': {...},   # only if watchdog fired
            '_other': {...},              # only if an unknown callback fired
          },
          'halted': {
            'is_halted': bool,
            'reason': str | None,
            'ts': float | None,
            'triggered_by': str | None,
          },
          'total_subscriber_fired': int,
          'total_streaming_phases': int,
        }

    Defensive contract (matches `_derive_phases` style at
    sentinel/agent/event_log.py:208-242):

    - Never raises on a malformed event dict — missing keys default to None
      / 0 / empty.
    - O(n) single walk; no nested iteration; safe on the 200_000-event cap
      from `EventLog.load`.
    - `total_subscriber_fired` is the sum of every bucket's absorbed_count
      (including cost_cap_watchdog + _other so operators see the full
      number, not just user-visible phases).
    - `total_streaming_phases` is the count of distinct downstream phases
      that either had a streaming_phase_started event fire OR absorbed at
      least one subscriber_fired.
    """
    phases: dict[str, dict[str, Any]] = {}
    halted = {
        "is_halted": False,
        "reason": None,
        "ts": None,
        "triggered_by": None,
    }

    for ev in events:
        if not isinstance(ev, dict):
            continue
        kind = ev.get("kind")
        if kind == "streaming_phase_started":
            # The phase name comes from event['phase'] — Plans 04.5-02..04
            # emit this lifecycle event with phase=<downstream-phase-name>.
            phase_name = ev.get("phase")
            if not phase_name or not isinstance(phase_name, str):
                continue
            bucket = phases.setdefault(phase_name, _empty_phase_bucket())
            # First install wins — subsequent re-installs (idempotency
            # in production code) don't move the timestamp.
            if bucket["install_ts"] is None:
                ts = ev.get("ts")
                if isinstance(ts, (int, float)):
                    bucket["install_ts"] = float(ts)
        elif kind == "subscriber_fired":
            callback_name = ev.get("callback_name") or ""
            phase_name = _CALLBACK_TO_PHASE.get(callback_name, "_other")
            bucket = phases.setdefault(phase_name, _empty_phase_bucket())
            bucket["absorbed_count"] += 1
            outcome = ev.get("outcome", "ok")
            if outcome == "error":
                bucket["error_count"] += 1
            ts = ev.get("ts")
            if isinstance(ts, (int, float)):
                bucket["last_absorbed_ts"] = float(ts)
            trigger_kind = ev.get("trigger_kind")
            if trigger_kind:
                bucket["per_trigger"][trigger_kind] = (
                    bucket["per_trigger"].get(trigger_kind, 0) + 1
                )
            # Cap recent_triggers at 5 — keeps the panel compact + bounds
            # memory regardless of how many subscriber_fired events landed.
            bucket["recent_triggers"].append({
                "trigger_kind": trigger_kind,
                "ts": ts if isinstance(ts, (int, float)) else None,
                "outcome": outcome,
            })
            if len(bucket["recent_triggers"]) > 5:
                bucket["recent_triggers"] = bucket["recent_triggers"][-5:]
        elif kind == "subscribers_halted":
            halted["is_halted"] = True
            halted["reason"] = ev.get("reason")
            ts = ev.get("ts")
            if isinstance(ts, (int, float)):
                halted["ts"] = float(ts)
            halted["triggered_by"] = ev.get("triggered_by")

    total_subscriber_fired = sum(p["absorbed_count"] for p in phases.values())
    total_streaming_phases = len(phases)

    return {
        "phases": phases,
        "halted": halted,
        "total_subscriber_fired": total_subscriber_fired,
        "total_streaming_phases": total_streaming_phases,
    }


@router.get("/agent-runs", name="agent_runs_index")
def agent_runs_index(request: Request):
    runs = elog.list_event_logs()
    # Unify the status badge with the detail view by re-computing it through
    # sentinel.web.run_status.compute_run_status. `elog._sniff_status` and
    # `_derive_meta` historically disagreed (one knew about stalled, the
    # other didn't). Now both views funnel through the same helper.
    for r in runs:
        path = r.get("path")
        if path:
            r["status"] = compute_run_status(path)
    return request.app.state.templates.TemplateResponse(
        request,
        "agent_runs_index.html",
        {"active_nav": "Agent runs", "runs": runs},
    )


@router.get("/agent-runs/{job_id}", name="agent_run_detail")
def agent_run_detail(
    request: Request,
    job_id: str,
    cfg: UIConfig = Depends(get_config),
):
    # Read events from cfg.runs_dir (NOT the cwd-relative default that
    # elog.events_path falls back to). The OOB / bbot / visual sub-panels
    # already honor cfg via _runs_dir(); this main route was missing it —
    # caught by the post-ExampleChat-scan audit pass 2026-XX-XX (issue C2).
    path = _runs_dir(cfg) / f"events-{job_id}.jsonl"
    if not path.is_file():
        raise HTTPException(404, f"no event log for job {job_id!r}")
    log_obj = elog.EventLog.load(path)
    state = log_obj.grouped()
    # Unify the run-status badge with the list view. `_derive_meta` only
    # knows 'running' / 'completed' / 'initializing'; it never returns
    # 'stalled' or 'aborted'. Re-derive through the shared helper.
    state["meta"]["status"] = compute_run_status(path)
    streaming_state = derive_streaming_state(log_obj.all_events())
    return request.app.state.templates.TemplateResponse(
        request,
        "agent_run.html",
        {
            "active_nav": "Agent runs",
            "job_id": job_id,
            "state": state,
            "events_path": str(path),
            "streaming": streaming_state,
        },
    )


@router.get("/agent-runs/{job_id}/refresh", name="agent_run_refresh")
def agent_run_refresh(request: Request, job_id: str):
    path = elog.events_path(job_id)
    if not path.is_file():
        raise HTTPException(404, f"no event log for job {job_id!r}")
    log_obj = elog.EventLog.load(path)
    state = log_obj.grouped()
    # Same staleness/aborted override as the parent detail route — the
    # HTMX refresh swaps the body every 2s and would otherwise revert the
    # badge to 'running' for stalled/aborted runs.
    state["meta"]["status"] = compute_run_status(path)
    streaming_state = derive_streaming_state(log_obj.all_events())
    return request.app.state.templates.TemplateResponse(
        request,
        "_components/agent_run_body.html",
        {
            "job_id": job_id,
            "state": state,
            "streaming": streaming_state,
        },
    )


@router.delete("/agent-runs/{job_id}", name="agent_run_delete")
def agent_run_delete(job_id: str):
    """Remove the dashboard's view of one run (events JSONL + tail buffers).

    Workspace deliverables and the engagement audit log are NOT touched —
    those live under workspaces/<engagement>/ and remain the legal artifact.

    Returns `200 ""` on both success AND already-gone (idempotent UX —
    HTMX swaps the empty body into the row's outerHTML, making it vanish
    from the table on the first click). 400 is reserved for traversal
    refusal (the helper raised ValueError). HTMX 1.x does NOT swap on
    204, which is why we use 200 with empty body instead.
    """
    try:
        elog.delete_event_log(job_id)
    except ValueError:
        # Path-traversal attempt or job_id resolves outside runs_dir.
        raise HTTPException(400, "invalid job_id")
    # Empty body + 200 → HTMX swaps "" into closest tr's outerHTML → row
    # vanishes. Same result whether the file was actually present or not.
    return Response(
        status_code=200, content="", media_type="text/html",
        headers={"HX-Trigger": "agent-runs-changed"},
    )


# ---- OOB callbacks panel (2026-XX-XX) ----------------------------------
#
# Per-run dashboard panel listing OOB tokens registered + callbacks
# received. Reads `runs/events-<job_id>.jsonl` for kind in
# {oob_token_registered, oob_callback_received} (emitted by
# sentinel/agent/pentest/oob_tool.py). Empty-state when no OOB activity.
#
# 404 NOT used for missing event log — empty-state is friendlier (an
# operator landing here mid-run before the agent registered any token
# would otherwise see a 404 and assume the panel was broken).

def _runs_dir(cfg: UIConfig) -> Path:
    return Path(getattr(cfg, "runs_dir", "./runs")).expanduser()


@router.get("/agent-runs/{job_id}/oob", name="agent_run_oob_panel")
def oob_panel(
    request: Request, job_id: str,
    cfg: UIConfig = Depends(get_config),
):
    """Render the OOB callbacks panel for an agent run."""
    runs = _runs_dir(cfg)
    events_path = runs / f"events-{job_id}.jsonl"
    tokens: list[dict] = []
    callbacks: list[dict] = []
    if events_path.is_file():
        try:
            for line in events_path.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # event_log writes `kind`; tolerate `event` too in case a
                # future writer uses AuditLog naming.
                kind = rec.get("kind") or rec.get("event") or ""
                if kind == "oob_token_registered":
                    tokens.append({
                        "ts": rec.get("ts", ""),
                        "token": rec.get("token", ""),
                        "full_url": rec.get("full_url", ""),
                        "purpose": rec.get("purpose", ""),
                    })
                elif kind == "oob_callback_received":
                    callbacks.append({
                        "ts": rec.get("ts", ""),
                        "token": rec.get("token", ""),
                        "count": rec.get("count", 0),
                        "protocols": rec.get("protocols", []) or [],
                    })
        except OSError as e:
            log.warning("oob_panel: read failed for %s: %s", events_path, e)
    return request.app.state.templates.TemplateResponse(
        request, "oob_panel.html",
        {
            "active_nav": "Agent runs",
            "job_id": job_id,
            "tokens": tokens,
            "callbacks": callbacks,
        },
    )


# ---- /agent-runs/<job_id>/oauth-installs ------------------------------------
# OAuth-install panel (2026-XX-XX). Surfaces oauth_install_started/completed/
# failed events emitted by sentinel/agent/pentest/oauth_install_tool.py. One
# row per app: started/completed timestamps, presence of bot+user refresh
# tokens, any failure reason. Empty-state (no 404) when no OAuth activity.

@router.get("/agent-runs/{job_id}/oauth-installs", name="agent_run_oauth_installs")
def oauth_installs_panel(
    request: Request, job_id: str,
    cfg: UIConfig = Depends(get_config),
):
    """Render the OAuth-installs panel for an agent run."""
    runs = _runs_dir(cfg)
    events_path = runs / f"events-{job_id}.jsonl"
    installs: dict[str, dict] = {}  # app_name -> row
    if events_path.is_file():
        try:
            for line in events_path.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                kind = rec.get("kind") or rec.get("event") or ""
                if not kind.startswith("oauth_install_"):
                    continue
                app_name = rec.get("app_name", "(unknown)")
                row = installs.setdefault(app_name, {"app_name": app_name})
                if kind == "oauth_install_started":
                    row["started_ts"] = rec.get("ts", "")
                elif kind == "oauth_install_completed":
                    row["completed_ts"] = rec.get("ts", "")
                    row["has_refresh_token"] = bool(rec.get("has_refresh_token"))
                    row["has_user_refresh_token"] = bool(rec.get("has_user_refresh_token"))
                elif kind == "oauth_install_failed":
                    row["failed_reason"] = rec.get("error", "(no reason)")
        except OSError as e:
            log.warning("oauth_installs_panel: read failed for %s: %s", events_path, e)
    return request.app.state.templates.TemplateResponse(
        request, "oauth_installs_panel.html",
        {
            "active_nav": "Agent runs",
            "job_id": job_id,
            "installs": list(installs.values()),
        },
    )


# ---- /agent-runs/<job_id>/bbot ----------------------------------------------
# bbot recon-orchestrator panel (2026-XX-XX). Surfaces bbot_run_completed
# events emitted by sentinel/agent/pentest/bbot_tool.py:run_bbot. Empty-state
# when no bbot activity. 404 NOT used for missing event log — friendlier to
# show an empty panel mid-run than to imply the route is broken.

@router.get("/agent-runs/{job_id}/bbot", name="agent_run_bbot_panel")
def bbot_panel(
    request: Request, job_id: str,
    cfg: UIConfig = Depends(get_config),
):
    """Render the bbot recon runs panel for an agent run."""
    runs = _runs_dir(cfg)
    events_path = runs / f"events-{job_id}.jsonl"
    bbot_runs: list[dict] = []
    if events_path.is_file():
        try:
            for line in events_path.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # event_log writes `kind`; tolerate `event` too in case a
                # future writer uses AuditLog naming.
                kind = rec.get("kind") or rec.get("event") or ""
                if kind == "bbot_run_completed":
                    bbot_runs.append({
                        "ts": rec.get("ts", ""),
                        "target": rec.get("target", ""),
                        "modules": rec.get("modules", ""),
                        "intensity": rec.get("intensity", ""),
                        "total_events": rec.get("total_events", 0),
                        "duration_s": rec.get("duration_s", 0),
                    })
        except OSError as e:
            log.warning("bbot_panel: read failed for %s: %s", events_path, e)
    return request.app.state.templates.TemplateResponse(
        request, "bbot_panel.html",
        {
            "active_nav": "Agent runs",
            "job_id": job_id,
            "runs": bbot_runs,
        },
    )


# ---- /agent-runs/<job_id>/visual --------------------------------------------
# Visual-triage panel (2026-XX-XX). Surfaces visual_recon_captured +
# visual_triage_completed events emitted by
# sentinel/agent/pentest/visual_triage_tool.py. Captures keyed by
# screenshot_path so a capture without a triage still renders (description
# left blank). Empty state when no visual activity. 404 NOT used for missing
# event log — show empty panel mid-run instead of implying a broken route.

@router.get("/agent-runs/{job_id}/visual", name="agent_run_visual_panel")
def visual_panel(
    request: Request, job_id: str,
    cfg: UIConfig = Depends(get_config),
):
    """Render the visual triage panel for an agent run."""
    runs = _runs_dir(cfg)
    events_path = runs / f"events-{job_id}.jsonl"
    # screenshot_path -> {url, ts, description}
    captures: dict[str, dict] = {}
    if events_path.is_file():
        try:
            for line in events_path.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                kind = rec.get("kind") or rec.get("event") or ""
                if kind == "visual_recon_captured":
                    p = rec.get("screenshot_path", "")
                    if not p:
                        continue
                    entry = captures.setdefault(p, {
                        "ts": rec.get("ts", ""), "url": "", "description": "",
                    })
                    entry["url"] = rec.get("url", "") or entry.get("url", "")
                elif kind == "visual_triage_completed":
                    p = rec.get("screenshot_path", "")
                    if not p:
                        continue
                    entry = captures.setdefault(p, {
                        "ts": rec.get("ts", ""), "url": "", "description": "",
                    })
                    entry["description"] = rec.get("description", "")
        except OSError as e:
            log.warning(
                "visual_panel: read failed for %s: %s", events_path, e,
            )
    return request.app.state.templates.TemplateResponse(
        request, "visual_panel.html",
        {
            "active_nav": "Agent runs",
            "job_id": job_id,
            "captures": list(captures.items()),
        },
    )
