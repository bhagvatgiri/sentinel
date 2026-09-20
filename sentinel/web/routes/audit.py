"""Audit log viewer — list .audit-*.jsonl files, show entries + verify chain."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request

from sentinel.core.scope import AuditLog
from sentinel.ui.state import UIConfig, list_audit_logs
from sentinel.web.deps import get_config

router = APIRouter()


@router.get("/audit")
def audit_index(request: Request, cfg: UIConfig = Depends(get_config)):
    logs = list_audit_logs(cfg.scopes_dir)
    return request.app.state.templates.TemplateResponse(
        request, "audit_list.html",
        {"active_nav": "Audit", "logs": logs, "cfg": cfg},
    )


@router.get("/audit/{filename}")
def audit_detail(request: Request, filename: str, cfg: UIConfig = Depends(get_config)):
    if "/" in filename or filename.startswith(".."):
        raise HTTPException(400, "invalid filename")
    # Audit logs live next to the scope dir.
    scopes = Path(cfg.scopes_dir).expanduser()
    candidates = [scopes / filename, scopes.parent / filename]
    log_path = next((p for p in candidates if p.is_file()), None)
    if not log_path:
        raise HTTPException(404, f"audit log not found: {filename}")

    ok, err = AuditLog.verify(log_path)
    entries: list[dict] = []
    for line in log_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return request.app.state.templates.TemplateResponse(
        request, "audit_detail.html",
        {
            "active_nav": "Audit",
            "filename": filename,
            "log_path": str(log_path),
            "ok": ok,
            "err": err,
            "entries": entries,
            "cfg": cfg,
        },
    )
