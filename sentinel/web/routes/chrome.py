"""Chrome profile management — Real-Chrome-via-CDP DataDome bypass UI.

Mirror of `sentinel chrome bootstrap/status/attach/clean` CLI. Renders
per-engagement profile status (running, version, session warmth) with
buttons to bootstrap / verify / shut down. Required so CLI-only changes
don't break the CLAUDE.md UI-parity rule.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

import yaml

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request

from sentinel.agent import chrome_profile as _cp
from sentinel.ui.state import UIConfig, list_engagements
from sentinel.web.deps import get_config


log = logging.getLogger(__name__)
router = APIRouter()


def _scope_path(cfg: UIConfig, filename: str) -> Path:
    """Resolve scope filename → absolute Path with traversal-safety check.

    Same pattern as sentinel/web/routes/engagements.py — basename only,
    no slashes / dotdot.
    """
    if "/" in filename or "\\" in filename or filename.startswith("..") or filename.startswith("."):
        raise HTTPException(status_code=400, detail=f"Invalid filename: {filename!r}")
    p = (Path(cfg.scopes_dir).expanduser() / filename).resolve()
    if not p.is_file():
        raise HTTPException(status_code=404, detail=f"Scope file not found: {filename}")
    return p


def _load_scope_dict(path: Path) -> dict:
    """Lightweight YAML load — full Scope.load opens an audit log we don't want."""
    try:
        return yaml.safe_load(path.read_bytes()) or {}
    except yaml.YAMLError as e:
        raise HTTPException(status_code=500, detail=f"Bad YAML in {path.name}: {e}")


def _profile_dir_for(scope_dict: dict) -> Path:
    """Same fallback logic as chrome_profile.resolve_profile_dir but
    operates on raw dict (no Scope object needed)."""
    raw = scope_dict.get("chrome_profile_dir")
    if raw:
        return Path(str(raw)).expanduser().resolve()
    eng_id = str(scope_dict.get("engagement_id", "default"))
    return (_cp.DEFAULT_PROFILE_ROOT / eng_id).resolve()


def _cdp_port_for(scope_dict: dict) -> int:
    raw = scope_dict.get("chrome_cdp_port")
    try:
        port = int(raw) if raw else _cp.DEFAULT_CDP_PORT
    except (TypeError, ValueError):
        port = _cp.DEFAULT_CDP_PORT
    return port


def _profile_status(scope_dict: dict) -> dict:
    """Compute the row data for one engagement's Chrome profile.

    Returns a dict with: profile_dir, profile_exists, cdp_port,
    chrome_running (bool), chrome_browser_version (Optional[str]),
    strategy_enabled (whether browser_strategy is set to cdp/agent_browser_cdp).
    """
    profile_dir = _profile_dir_for(scope_dict)
    cdp_port = _cdp_port_for(scope_dict)
    info = _cp.attach_status(cdp_port)
    strategy = (str(scope_dict.get("browser_strategy") or "")).lower()
    return {
        "profile_dir": str(profile_dir),
        "profile_exists": profile_dir.exists(),
        "cdp_port": cdp_port,
        "chrome_running": info is not None,
        "chrome_browser_version": (info or {}).get("Browser", "") if info else "",
        "strategy_enabled": strategy in ("cdp", "agent_browser_cdp"),
        "strategy_value": strategy,
    }


# ---- list view ------------------------------------------------------------


@router.get("/chrome")
def chrome_list(request: Request, cfg: UIConfig = Depends(get_config)):
    """List engagements with per-engagement Chrome profile status."""
    engagements = list_engagements(cfg.scopes_dir)
    rows = []
    for e in engagements:
        try:
            sd = _load_scope_dict(Path(e["path"]))
        except HTTPException:
            continue
        status = _profile_status(sd)
        rows.append({
            "engagement": e,
            "status": status,
        })
    return request.app.state.templates.TemplateResponse(
        request, "chrome_list.html",
        {"active_nav": "Chrome", "rows": rows, "cfg": cfg},
    )


# ---- detail view ----------------------------------------------------------


@router.get("/chrome/{filename}")
def chrome_detail(request: Request, filename: str, cfg: UIConfig = Depends(get_config)):
    path = _scope_path(cfg, filename)
    sd = _load_scope_dict(path)
    status = _profile_status(sd)
    targets = sd.get("targets") or {}
    domains = [d for d in (targets.get("domains") or []) if "*" not in d]
    probe_url = f"https://{domains[0]}/" if domains else ""
    return request.app.state.templates.TemplateResponse(
        request, "chrome_detail.html",
        {
            "active_nav": "Chrome",
            "filename": filename,
            "engagement": {
                "client": sd.get("client", "?"),
                "engagement_id": sd.get("engagement_id", "?"),
                "authorized_by": sd.get("authorized_by", "?"),
            },
            "status": status,
            "probe_url": probe_url,
            "domains": domains,
            "cfg": cfg,
        },
    )


# ---- POST actions ---------------------------------------------------------


@router.post("/chrome/{filename}/bootstrap")
def chrome_bootstrap(
    request: Request,
    filename: str,
    cfg: UIConfig = Depends(get_config),
):
    """Spawn the operator's real Chrome with --remote-debugging-port + per-eng profile."""
    path = _scope_path(cfg, filename)
    sd = _load_scope_dict(path)
    profile_dir = _profile_dir_for(sd)
    cdp_port = _cdp_port_for(sd)
    try:
        result = _cp.bootstrap_profile(profile_dir=profile_dir, cdp_port=cdp_port)
    except _cp.ChromeBinaryNotFound as e:
        return request.app.state.templates.TemplateResponse(
            request, "chrome_detail.html",
            {
                "active_nav": "Chrome",
                "filename": filename,
                "engagement": {"client": sd.get("client", "?"),
                                "engagement_id": sd.get("engagement_id", "?"),
                                "authorized_by": sd.get("authorized_by", "?")},
                "status": _profile_status(sd),
                "probe_url": "",
                "domains": [],
                "cfg": cfg,
                "flash_error": str(e),
            },
            status_code=400,
        )
    except RuntimeError as e:
        return request.app.state.templates.TemplateResponse(
            request, "chrome_detail.html",
            {
                "active_nav": "Chrome",
                "filename": filename,
                "engagement": {"client": sd.get("client", "?"),
                                "engagement_id": sd.get("engagement_id", "?"),
                                "authorized_by": sd.get("authorized_by", "?")},
                "status": _profile_status(sd),
                "probe_url": "",
                "domains": [],
                "cfg": cfg,
                "flash_error": str(e),
            },
            status_code=409,
        )
    log.info("chrome_bootstrap from web: pid=%d port=%d profile=%s",
              result.pid, cdp_port, profile_dir)
    return request.app.state.templates.TemplateResponse(
        request, "chrome_detail.html",
        {
            "active_nav": "Chrome",
            "filename": filename,
            "engagement": {"client": sd.get("client", "?"),
                            "engagement_id": sd.get("engagement_id", "?"),
                            "authorized_by": sd.get("authorized_by", "?")},
            "status": _profile_status(sd),
            "probe_url": "",
            "domains": [],
            "cfg": cfg,
            "flash_ok": (
                f"Chrome launched (PID {result.pid}). Solve any DataDome "
                f"challenge + sign in to your target manually in the opened "
                f"window. Profile saves to disk; you can close the window "
                f"when done."
            ),
        },
    )


@router.post("/chrome/{filename}/verify")
def chrome_verify(
    request: Request,
    filename: str,
    cfg: UIConfig = Depends(get_config),
):
    """Probe an in-scope URL via the attached Chrome to test session warmth."""
    path = _scope_path(cfg, filename)
    sd = _load_scope_dict(path)
    cdp_port = _cdp_port_for(sd)
    targets = sd.get("targets") or {}
    domains = [d for d in (targets.get("domains") or []) if "*" not in d]
    probe_url = f"https://{domains[0]}/" if domains else None

    if not probe_url:
        return request.app.state.templates.TemplateResponse(
            request, "chrome_detail.html",
            {
                "active_nav": "Chrome",
                "filename": filename,
                "engagement": {"client": sd.get("client", "?"),
                                "engagement_id": sd.get("engagement_id", "?"),
                                "authorized_by": sd.get("authorized_by", "?")},
                "status": _profile_status(sd),
                "probe_url": "",
                "domains": [],
                "cfg": cfg,
                "flash_error": "Scope has no concrete domain to probe (only wildcards).",
            },
            status_code=400,
        )

    verdict = asyncio.run(_cp.verify_session(cdp_port=cdp_port, probe_url=probe_url))
    flash_kwargs = {}
    if verdict.get("ok"):
        flash_kwargs["flash_ok"] = (
            f"HTTP {verdict.get('status')} on {verdict.get('final_url')} — "
            f"title={verdict.get('title','')!r} — "
            f"{'AUTHENTICATED' if verdict.get('looks_authenticated') else 'NOT AUTH (redirected to login)'}"
        )
    else:
        flash_kwargs["flash_error"] = verdict.get("error", "verify failed")
    return request.app.state.templates.TemplateResponse(
        request, "chrome_detail.html",
        {
            "active_nav": "Chrome",
            "filename": filename,
            "engagement": {"client": sd.get("client", "?"),
                            "engagement_id": sd.get("engagement_id", "?"),
                            "authorized_by": sd.get("authorized_by", "?")},
            "status": _profile_status(sd),
            "probe_url": probe_url,
            "domains": domains,
            "verify_verdict": verdict,
            "cfg": cfg,
            **flash_kwargs,
        },
    )


@router.post("/chrome/{filename}/clean")
def chrome_clean(
    request: Request,
    filename: str,
    background: BackgroundTasks,
    cfg: UIConfig = Depends(get_config),
):
    """Gracefully shut down the attached Chrome (does NOT purge the profile dir).

    SHUTDOWN-01 (2026-XX-XX): the underlying shutdown_chrome chain
    (CDP WebSocket -> /json/close urlopen -> SIGTERM via lsof) can take
    10-15 seconds in the worst case (WebSocket connect timeouts +
    lsof latency + post-SIGTERM wait), which previously caused the
    operator's HTTP client to time out (HTTP 000 on curl). Refactored
    to dispatch via FastAPI BackgroundTasks so the response returns in
    ~50ms; the operator polls GET /chrome/{filename} for the actual
    chrome_running status. See post-mortem in .planning/phases/
    03-exploit-verification-loop/03-01-PLAN.md (SHUTDOWN-01).

    Failure observability: shutdown_chrome's per-strategy failures
    now log at WARNING level (SHUTDOWN-02 in the same plan), so the
    operator sees which strategy failed in the default log stream
    without needing SHIM_LOG_LEVEL=DEBUG.
    """
    path = _scope_path(cfg, filename)
    sd = _load_scope_dict(path)
    cdp_port = _cdp_port_for(sd)
    # Dispatch the actual shutdown via BackgroundTasks. FastAPI runs the
    # task AFTER the HTTP response is sent, so the client sees a fast
    # response and the chrome shutdown proceeds in the background.
    background.add_task(_cp.shutdown_chrome, cdp_port=cdp_port, timeout_sec=8.0)
    msg = (
        f"Chrome shutdown initiated on port {cdp_port}. "
        f"Refresh this page in ~10 seconds to see final state. "
        f"If shutdown stalls, check the server log for "
        f"'shutdown_chrome:' WARNING entries."
    )
    return request.app.state.templates.TemplateResponse(
        request, "chrome_detail.html",
        {
            "active_nav": "Chrome",
            "filename": filename,
            "engagement": {"client": sd.get("client", "?"),
                            "engagement_id": sd.get("engagement_id", "?"),
                            "authorized_by": sd.get("authorized_by", "?")},
            "status": _profile_status(sd),
            "probe_url": "",
            "domains": [],
            "cfg": cfg,
            "flash_ok": msg,
        },
    )
