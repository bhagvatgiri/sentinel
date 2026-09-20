"""Tools — health check for every scanner + Sentinel config (settings)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request

from sentinel.core.tool_inventory import check_all, check_all_grouped
from sentinel.ui.state import UIConfig
from sentinel.web.deps import get_config

router = APIRouter()


@router.get("/tools")
def tools(request: Request, cfg: UIConfig = Depends(get_config)):
    rows = check_all()
    grouped = check_all_grouped()
    n_ok = sum(1 for r in rows if r["ok"])
    return request.app.state.templates.TemplateResponse(
        request, "tools.html",
        {
            "active_nav": "Tools",
            "cfg": cfg,
            "rows": rows,                # flat list (legacy template)
            "grouped": grouped,          # tier -> [rows] for tier-headed table
            "tier_order": ["passive", "active", "network", "ai"],
            "n_ok": n_ok,
            "n_total": len(rows),
        },
    )


@router.post("/tools/config")
def save_config(
    request: Request,
    cfg: UIConfig = Depends(get_config),
    vault_path: str = Form(...),
    corpus_dir: str = Form(...),
    scopes_dir: str = Form(...),
    runs_dir: str = Form(...),
    ollama_host: str = Form(...),
    ollama_model: str = Form(...),
    embed_model: str = Form(...),
):
    cfg.vault_path = vault_path.strip()
    cfg.corpus_dir = corpus_dir.strip()
    cfg.scopes_dir = scopes_dir.strip()
    cfg.runs_dir = runs_dir.strip()
    cfg.ollama_host = ollama_host.strip()
    cfg.ollama_model = ollama_model.strip()
    cfg.embed_model = embed_model.strip()
    cfg.save()
    return tools(request, cfg)
