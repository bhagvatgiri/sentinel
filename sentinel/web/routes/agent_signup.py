"""Dashboard surface for human-in-the-loop signup (Quick 260517-f7a, 2026-XX-XX).

Renders pending signup requests emitted by `human_signup_tool.human_signup`,
gives the operator a form (username + password + operator_note) plus a Skip
button. On submit the route appends a completion / skip record to the
matching `runs/signup-<job_id>.jsonl`; the agent's blocked tool call sees
it on its next 2s poll and persists creds + synthesizes a
`scope.auth_credentials` entry.

CLAUDE.md UI-parity rule: every CLI/tool surface ships its dashboard mirror
in the same change.

Also serves the per-job `Captcha solves` counter (HTMX fragment) — kept
out of the main agent_runs handler per planner pin B3 so the count's render
path is independently testable and the existing handler stays untouched.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse

from sentinel.agent.pentest.human_signup_tool import (
    list_pending, signup_log_path, _read_records, _append,
)
from sentinel.ui.state import UIConfig
from sentinel.web.deps import get_config


log = logging.getLogger(__name__)
router = APIRouter()


def _runs_dir(cfg: UIConfig) -> Path:
    """Where the per-job signup JSONLs live. Mirrors human_login_tool default."""
    return Path(getattr(cfg, "runs_dir", "./runs")).expanduser()


def _all_pending(cfg: UIConfig) -> list[dict]:
    """Walk every runs/signup-<job_id>.jsonl, return one flat list of
    pending requests with job_id injected so the cross-job page can
    route the POST back to the right file."""
    runs = _runs_dir(cfg)
    out: list[dict] = []
    if not runs.is_dir():
        return out
    for path in sorted(runs.glob("signup-*.jsonl")):
        # filename = signup-<job_id>.jsonl
        name = path.name
        job_id = name[len("signup-"):-len(".jsonl")]
        records = _read_records(path)
        for r in list_pending(records):
            r2 = dict(r)
            r2["job_id"] = job_id
            out.append(r2)
    out.sort(key=lambda x: x.get("ts", 0.0))
    return out


# ---------------------------------------------------------------------------
# Cross-job pending list
# ---------------------------------------------------------------------------

@router.get("/signup-pending")
def signup_pending(request: Request,
                    cfg: UIConfig = Depends(get_config)):
    """Operator landing page — lists every pending signup across every job."""
    pending = _all_pending(cfg)
    return request.app.state.templates.TemplateResponse(
        request, "signup_pending.html",
        {"requests": pending, "cfg": cfg},
    )


# ---------------------------------------------------------------------------
# Per-job inline card (HTMX-polled from agent_run.html)
# ---------------------------------------------------------------------------

@router.get("/agent-runs/{job_id}/signup/pending")
def per_job_signup_pending(request: Request, job_id: str,
                            cfg: UIConfig = Depends(get_config)):
    """HTMX-polled list of pending signup requests for one job."""
    records = _read_records(signup_log_path(job_id, _runs_dir(cfg)))
    pending = list_pending(records)
    # Inject job_id so the template can render hidden form field
    pending = [{**p, "job_id": job_id} for p in pending]
    return request.app.state.templates.TemplateResponse(
        request, "_components/signup_pending_panel.html",
        {"requests": pending, "job_id": job_id, "cfg": cfg},
    )


# ---------------------------------------------------------------------------
# Complete + Skip — POST handlers
# ---------------------------------------------------------------------------

@router.post("/signup-pending/{request_id}/complete")
def signup_complete(
    request: Request, request_id: str,
    job_id: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    operator_note: str = Form(""),
    cfg: UIConfig = Depends(get_config),
):
    """Operator submitted credentials — append a completion record to the
    matching signup-<job_id>.jsonl. The agent's polling tool call picks
    it up within ~2s, writes ~/.sentinel/<eid>.creds.json (mode 0o600),
    and synthesizes a scope.auth_credentials entry."""
    log_path = signup_log_path(job_id, _runs_dir(cfg))
    _append(log_path, {
        "ts": time.time(),
        "id": request_id,
        "status": "completed",
        "username": username,
        "password": password,
        "operator_note": operator_note,
    })
    log.info("signup_complete: job=%s request=%s", job_id, request_id)
    # Re-render the cross-job list so the operator sees the row disappear.
    pending = _all_pending(cfg)
    return request.app.state.templates.TemplateResponse(
        request, "signup_pending.html",
        {"requests": pending, "cfg": cfg,
         "flash_ok": (
             "Signup recorded. The agent will pick up creds within ~2s "
             "and synthesize a scope.auth_credentials entry."
         )},
    )


@router.post("/signup-pending/{request_id}/skip")
def signup_skip(
    request: Request, request_id: str,
    job_id: str = Form(...),
    cfg: UIConfig = Depends(get_config),
):
    """Operator clicked Skip — agent's tool call returns _err, falls back
    to unauth probes."""
    log_path = signup_log_path(job_id, _runs_dir(cfg))
    _append(log_path, {
        "ts": time.time(),
        "id": request_id,
        "status": "skipped",
    })
    log.info("signup_skip: job=%s request=%s", job_id, request_id)
    pending = _all_pending(cfg)
    return request.app.state.templates.TemplateResponse(
        request, "signup_pending.html",
        {"requests": pending, "cfg": cfg,
         "flash_ok": "Skipped — agent will fall back to unauth probes."},
    )


# ---------------------------------------------------------------------------
# Captcha-solves HTMX fragment (planner pin B3)
# ---------------------------------------------------------------------------

@router.get("/agent-runs/{job_id}/captcha-count")
def captcha_count_fragment(
    request: Request, job_id: str,
    cfg: UIConfig = Depends(get_config),
):
    """HTMX fragment endpoint — counts captcha_solved records in
    runs/events-<job_id>.jsonl and renders the small counter card.
    Kept outside the main agent_runs route handler so the count's
    render path is independently testable + the existing handler is
    not modified."""
    runs = _runs_dir(cfg)
    events_path = runs / f"events-{job_id}.jsonl"
    count = 0
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
                # event_log writes `kind` (see sentinel/agent/event_log.py
                # line 105). Tolerate `event` too in case a future writer
                # uses the AuditLog naming.
                if rec.get("kind") == "captcha_solved" or rec.get("event") == "captcha_solved":
                    count += 1
        except OSError as e:
            log.warning("captcha_count: read failed for %s: %s", events_path, e)
    return request.app.state.templates.TemplateResponse(
        request, "_components/captcha_solves_card.html",
        {"count": count, "job_id": job_id},
    )
