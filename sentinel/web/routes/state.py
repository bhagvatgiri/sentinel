"""Session-continuity dashboard route — exposes CURRENT_STATE.md.

Mirrors the `sentinel state` CLI subcommand so an operator can read the
single-page snapshot from the dashboard without dropping to a terminal.
GET /state shows the rendered snapshot; POST /state/refresh rebuilds it.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse

from sentinel.state import build_snapshot, render_markdown, update_current_state_safe
from sentinel.ui.state import UIConfig
from sentinel.web.deps import get_config


log = logging.getLogger(__name__)
router = APIRouter()


def _project_dir(cfg: UIConfig) -> Path:
    return Path(cfg.project_dir).expanduser()


def _wants_json(request: Request) -> bool:
    """Substring-match `application/json` in the Accept header.

    Strict equality would miss `application/json, text/plain;q=0.5` style
    headers; substring match is the standard FastAPI/Starlette idiom for
    content negotiation when only two surfaces exist (HTML default + JSON
    opt-in).
    """
    accept = request.headers.get("accept", "") or ""
    return "application/json" in accept.lower()


@router.get("/state", name="state_index")
def state_index(request: Request, cfg: UIConfig = Depends(get_config)):
    """Render CURRENT_STATE.md as the dashboard's session-continuity page.

    Content-negotiated:
      * `Accept: application/json` → raw `build_snapshot()` dict as JSON
        (STATE-02 machine-readable surface, parity with `/state.json`).
      * Otherwise → HTML template (the existing behavior preserved).

    Builds the snapshot fresh on every request (cheap — a few file reads).
    The on-disk CURRENT_STATE.md is only refreshed by the explicit POST.
    """
    snap = build_snapshot(_project_dir(cfg))
    if _wants_json(request):
        return JSONResponse(snap)
    md = render_markdown(snap)
    return request.app.state.templates.TemplateResponse(
        request,
        "state.html",
        {
            "active_nav": "State",
            "cfg": cfg,
            "snapshot": snap,
            "rendered_markdown": md,
        },
    )


@router.get("/state.json", name="state_json")
def state_json(request: Request, cfg: UIConfig = Depends(get_config)):
    """Always-JSON sibling to `/state`.

    Accept-header-agnostic so curl / scripts that don't set an Accept
    header still get JSON. Returns the identical `build_snapshot()` dict
    `/state` returns under `Accept: application/json` — no shape drift.
    """
    return JSONResponse(build_snapshot(_project_dir(cfg)))


@router.post("/state/refresh", name="state_refresh")
def state_refresh(cfg: UIConfig = Depends(get_config)):
    """Rebuild CURRENT_STATE.md on disk and redirect back to /state."""
    update_current_state_safe(_project_dir(cfg))
    return RedirectResponse(url="/state", status_code=303)
