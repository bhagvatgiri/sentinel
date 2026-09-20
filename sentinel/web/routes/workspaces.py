"""Pentest workspaces — list + detail.

Each workspace is a directory under `workspaces/` produced by a
`sentinel scan-autonomous` run. The list view shows what shipped (deliverables
+ completed phases). The detail view links to the live event log if the run is
in flight, lets the operator resume from the last successful phase, and
optionally ingests this workspace's deliverables back into the corpus as
cross-engagement memory.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request

from sentinel.ui.state import UIConfig, list_workspaces
from sentinel.web.deps import get_config


log = logging.getLogger(__name__)
router = APIRouter()

WORKSPACES_DIR_NAME = "workspaces"


def _workspaces_root(cfg: UIConfig) -> Path:
    return Path(cfg.project_dir).expanduser() / WORKSPACES_DIR_NAME


@router.get("/workspaces", name="workspaces_index")
def workspaces_index(request: Request, cfg: UIConfig = Depends(get_config)):
    root = _workspaces_root(cfg)
    rows = list_workspaces(root)
    return request.app.state.templates.TemplateResponse(
        request, "workspaces_list.html",
        {
            "active_nav": "Workspaces",
            "cfg": cfg,
            "rows": rows,
            "workspaces_root": str(root),
            "n_total": len(rows),
            "n_complete": sum(1 for r in rows if r["completed_phases"] and "report" in r["completed_phases"]),
        },
    )


@router.get("/workspaces/{name}", name="workspaces_detail")
def workspaces_detail(name: str, request: Request, cfg: UIConfig = Depends(get_config)):
    if "/" in name or name.startswith(".."):
        raise HTTPException(400, "invalid workspace name")
    root = _workspaces_root(cfg)
    ws = root / name
    if not ws.is_dir():
        raise HTTPException(404, f"no workspace at {ws}")

    rows = list_workspaces(root)
    meta = next((r for r in rows if r["name"] == name), None)
    if meta is None:
        raise HTTPException(404, f"workspace {name} not found in index")

    deliv = ws / "deliverables"
    deliverables: list[dict] = []
    if deliv.is_dir():
        for f in sorted(deliv.glob("*.md")):
            try:
                size = f.stat().st_size
            except OSError:
                size = 0
            deliverables.append({
                "filename": f.name,
                "stem": f.stem,
                "size": size,
            })

    return request.app.state.templates.TemplateResponse(
        request, "workspaces_detail.html",
        {
            "active_nav": "Workspaces",
            "cfg": cfg,
            "meta": meta,
            "deliverables": deliverables,
            "audit_path": str(ws / f".audit-{name}.jsonl"),
        },
    )


@router.get("/workspaces/{name}/deliverable/{filename}", name="workspaces_deliverable")
def workspaces_deliverable(name: str, filename: str, request: Request,
                            cfg: UIConfig = Depends(get_config)):
    """Render a single deliverable's markdown content as HTML (uses
    safe_markdown via the template). Returned as a fragment for HTMX swap."""
    if "/" in name or name.startswith("..") or "/" in filename or filename.startswith(".."):
        raise HTTPException(400, "invalid path")
    root = _workspaces_root(cfg)
    target = root / name / "deliverables" / filename
    if not target.is_file():
        raise HTTPException(404, f"no deliverable at {target}")
    try:
        text = target.read_text()
    except OSError as e:
        raise HTTPException(500, f"read failed: {e}")
    return request.app.state.templates.TemplateResponse(
        request, "_components/workspace_deliverable.html",
        {"filename": filename, "text": text},
    )
