"""Dashboard surface for human-in-the-loop login (2026-XX-XX).

Renders pending login requests emitted by `human_login_tool.request_human_login`,
gives the operator three buttons:

  - "Open in your Chrome" → POST → calls Chrome CDP `PUT /json/new?url=...`
    so the operator's per-engagement Chrome opens the right URL with the
    profile that owns its cookies.
  - "I've signed in" → POST → appends `{status: completed}` to
    `runs/login-<job_id>.jsonl`. The agent's blocked tool call sees it
    on its next 2s poll and returns _ok with refreshed cookies.
  - "Skip" → POST → appends `{status: skipped}`. The agent's tool call
    returns _err so it can fall back to unauth probes.

CLAUDE.md UI-parity rule: every CLI/tool surface ships its dashboard
mirror in the same change.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from urllib import error, parse, request

from fastapi import APIRouter, Depends, HTTPException, Request

from sentinel.agent.pentest.human_login_tool import (
    list_pending, login_log_path, _read_records,
)
from sentinel.ui.state import UIConfig
from sentinel.web.deps import get_config


log = logging.getLogger(__name__)
router = APIRouter()


def _runs_dir(cfg: UIConfig) -> Path:
    """Where the per-job login JSONL lives. Mirrors pipeline default."""
    return Path(getattr(cfg, "runs_dir", "./runs")).expanduser()


def _scope_for_job(job_id: str) -> dict:
    """Best-effort: read the engagement scope from the event log's first line.

    The pipeline emits `pipeline_started` first with `client / engagement_id /
    workspace / audit_log` — those tell us where to find the scope yaml so
    we can resolve the CDP port for the "Open in Chrome" handler.
    """
    runs = Path("./runs")
    event_path = runs / f"events-{job_id}.jsonl"
    if not event_path.is_file():
        return {}
    try:
        with event_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("kind") == "pipeline_started":
                    return rec
    except OSError:
        pass
    return {}


def _resolve_cdp_port(job_id: str) -> int:
    """Find scope.chrome_cdp_port for this job. Defaults 9222."""
    info = _scope_for_job(job_id)
    audit_path = info.get("audit_log") or info.get("audit")
    if audit_path:
        # audit log path implies engagement dir — find the matching scope yaml
        eng = info.get("engagement_id", "")
        engagements = Path("./engagements")
        if eng and engagements.is_dir():
            for cand in engagements.glob("*.yaml"):
                try:
                    import yaml as _yaml
                    sd = _yaml.safe_load(cand.read_bytes()) or {}
                    if str(sd.get("engagement_id")) == eng:
                        return int(sd.get("chrome_cdp_port") or 9222)
                except Exception:
                    continue
    return 9222


# ---- routes ---------------------------------------------------------------


@router.get("/agent-runs/{job_id}/login/pending")
def login_pending(request: Request, job_id: str,
                   cfg: UIConfig = Depends(get_config)):
    """HTMX-polled list of pending login requests for this job."""
    log_path = login_log_path(job_id, _runs_dir(cfg))
    records = _read_records(log_path)
    pending = list_pending(records)
    return request.app.state.templates.TemplateResponse(
        request, "_components/agent_login_panel.html",
        {"pending": pending, "job_id": job_id, "cfg": cfg},
    )


@router.post("/agent-runs/{job_id}/login/{request_id}/complete")
def login_complete(request: Request, job_id: str, request_id: str,
                    cfg: UIConfig = Depends(get_config)):
    """Operator clicked 'I've signed in' — append completion record."""
    log_path = login_log_path(job_id, _runs_dir(cfg))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": time.time(), "id": request_id, "status": "completed",
               "operator_note": "marked complete from dashboard"}
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    log.info("login_complete: job=%s request=%s", job_id, request_id)
    # Re-render the panel (HTMX swap).
    records = _read_records(log_path)
    pending = list_pending(records)
    return request.app.state.templates.TemplateResponse(
        request, "_components/agent_login_panel.html",
        {"pending": pending, "job_id": job_id, "cfg": cfg,
         "flash_ok": "Signed in — agent will refresh cookies + resume."},
    )


@router.post("/agent-runs/{job_id}/login/{request_id}/skip")
def login_skip(request: Request, job_id: str, request_id: str,
                cfg: UIConfig = Depends(get_config)):
    """Operator clicked 'Skip' — agent's tool call will return _err."""
    log_path = login_log_path(job_id, _runs_dir(cfg))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": time.time(), "id": request_id, "status": "skipped"}
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    log.info("login_skip: job=%s request=%s", job_id, request_id)
    records = _read_records(log_path)
    pending = list_pending(records)
    return request.app.state.templates.TemplateResponse(
        request, "_components/agent_login_panel.html",
        {"pending": pending, "job_id": job_id, "cfg": cfg,
         "flash_ok": "Skipped — agent will fall back to unauth probes."},
    )


@router.post("/agent-runs/{job_id}/login/{request_id}/open")
def login_open(request: Request, job_id: str, request_id: str,
                cfg: UIConfig = Depends(get_config)):
    """Open the request URL in the operator's CDP-attached Chrome.

    Uses Chrome's DevTools `PUT /json/new?url=...` so the tab opens in the
    profile that owns the engagement cookies (NOT the operator's default
    browser, where cookies wouldn't help the agent).
    """
    log_path = login_log_path(job_id, _runs_dir(cfg))
    records = _read_records(log_path)
    pending = list_pending(records)
    target_request = next((p for p in pending if p.get("id") == request_id), None)
    if target_request is None:
        raise HTTPException(status_code=404, detail="Pending login request not found")
    url = target_request.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="Login request has no URL")
    cdp_port = _resolve_cdp_port(job_id)
    try:
        # Verify Chrome is reachable first.
        with request.app.state if False else (lambda: None)():
            pass
    except Exception:
        pass
    encoded = parse.quote(url, safe="")
    try:
        req = request.app  # for type clarity
    except Exception:
        pass
    # Plain urllib PUT to the Chrome DevTools API.
    try:
        cdp_req = __import__("urllib.request", fromlist=["Request"]).Request(
            f"http://localhost:{cdp_port}/json/new?{encoded}",
            method="PUT",
        )
        with __import__("urllib.request", fromlist=["urlopen"]).urlopen(cdp_req, timeout=3.0) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body) if body.strip() else {}
        if not isinstance(data, dict) or data.get("type") != "page":
            raise HTTPException(status_code=502,
                                 detail=f"Chrome did not return a page target: {data!r}")
        flash = (
            f"Opened {url} in your Chrome (CDP port {cdp_port}). Sign in / "
            f"create the account in that tab, then click 'I've signed in' below."
        )
    except error.URLError as e:
        raise HTTPException(
            status_code=503,
            detail=(f"No Chrome listening on CDP port {cdp_port}. "
                    f"Run `sentinel chrome bootstrap --scope <yaml>` first. ({e})"),
        )
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=502, detail=f"Chrome returned non-JSON: {e}")

    # Re-render the panel with the flash message.
    return request.app.state.templates.TemplateResponse(
        request, "_components/agent_login_panel.html",
        {"pending": pending, "job_id": job_id, "cfg": cfg, "flash_ok": flash},
    )
