"""Wave 2 / A4 — Flame-graph trace view of any historical or live run.

Reads `runs/events-<job_id>.jsonl` and assembles the typed span tree
into a flame-graph rendering. Each row is one span (a phase, agent,
tool_call, handoff, etc.); width is proportional to wall time; depth
is the parent-child nesting.

Routes:
- GET /traces                — list every job_id that has any span events
- GET /traces/<job_id>       — flame graph for one run

Implementation note:
We use a CSS-grid + colored bars rather than D3/Plotly. The data set is
already shaped to one row per span (`flatten_for_flame()`), so a static
HTML render is fast, prints cleanly, and avoids a JS chart dependency
on the dashboard. HTMX powers the live-refresh; static for completed runs.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from sentinel.agent import event_log as elog
from sentinel.agent import tracing as p_tracing
from sentinel.web.event_styles import style_for_span_kind


router = APIRouter()


@router.get("/traces", name="traces_index")
def traces_index(request: Request):
    """List every event log that has at least one span_started event.

    Newest first. Each row links to /traces/<job_id>.
    """
    runs = elog.list_event_logs()
    runs_with_spans = []
    for r in runs:
        try:
            log_obj = elog.EventLog.load(r["path"])
            events = log_obj.all_events()
        except Exception:
            continue
        n_spans = sum(1 for e in events if e.get("kind") == "span_started")
        if n_spans == 0:
            continue
        runs_with_spans.append({**r, "n_spans": n_spans})
    return request.app.state.templates.TemplateResponse(
        request,
        "traces.html",
        {
            "active_nav": "Agent runs",
            "view": "index",
            "runs": runs_with_spans,
        },
    )


@router.get("/traces/{job_id}", name="trace_detail")
def trace_detail(request: Request, job_id: str):
    """Flame graph for one run."""
    path = elog.events_path(job_id)
    if not path.is_file():
        raise HTTPException(404, f"no event log for job {job_id!r}")
    log_obj = elog.EventLog.load(path)
    events = log_obj.all_events()
    rows = p_tracing.flatten_for_flame(events)
    if not rows:
        return request.app.state.templates.TemplateResponse(
            request,
            "traces.html",
            {
                "active_nav": "Agent runs",
                "view": "empty",
                "job_id": job_id,
                "events_path": str(path),
            },
        )

    # Compute the time bounds for the flame layout.
    starts = [r["started_at"] for r in rows if r.get("started_at")]
    ends = [r.get("ended_at") or r.get("started_at") or 0 for r in rows]
    t0 = min(starts) if starts else 0
    t_end = max(ends) if ends else t0
    total_dur = max(0.001, t_end - t0)

    # Annotate each row with layout deltas + style chips.
    annotated = []
    for r in rows:
        s = r.get("started_at") or t0
        d = max(0.001, float(r.get("duration_sec") or 0.0))
        if r.get("status") == "open":
            d = max(0.001, t_end - s)
        offset_pct = round(100 * (s - t0) / total_dur, 4)
        width_pct = round(100 * d / total_dur, 4)
        if width_pct < 0.5:
            width_pct = 0.5
        kind_style = style_for_span_kind(r.get("span_kind", ""))
        annotated.append({
            **r,
            "offset_pct": offset_pct,
            "width_pct": width_pct,
            "kind_style": kind_style,
            "duration_label": _humanize_duration(d),
        })

    # Slowest 10 (only completed spans) for the side panel.
    completed = [r for r in annotated if r.get("status") != "open"]
    slowest = sorted(completed, key=lambda r: -float(r.get("duration_sec") or 0.0))[:10]

    # Per-kind aggregates.
    kind_totals: dict[str, dict] = {}
    for r in completed:
        k = r.get("span_kind") or "unknown"
        kind_totals.setdefault(k, {"count": 0, "total_sec": 0.0})
        kind_totals[k]["count"] += 1
        kind_totals[k]["total_sec"] += float(r.get("duration_sec") or 0.0)
    kind_summary = sorted(
        [{"kind": k, **v, "style": style_for_span_kind(k)}
         for k, v in kind_totals.items()],
        key=lambda r: -r["total_sec"],
    )

    return request.app.state.templates.TemplateResponse(
        request,
        "traces.html",
        {
            "active_nav": "Agent runs",
            "view": "detail",
            "job_id": job_id,
            "events_path": str(path),
            "rows": annotated,
            "slowest": slowest,
            "kind_summary": kind_summary,
            "total_dur_sec": total_dur,
            "n_spans": len(rows),
        },
    )


def _humanize_duration(sec: float) -> str:
    if sec < 1:
        return f"{int(sec * 1000)}ms"
    if sec < 60:
        return f"{sec:.1f}s"
    m = int(sec // 60)
    s = sec % 60
    return f"{m}m{s:.0f}s"
