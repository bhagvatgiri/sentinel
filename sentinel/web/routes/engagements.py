"""Engagements — list scope files, create new, drill into detail."""

from __future__ import annotations

import hashlib
from datetime import date, timedelta
from pathlib import Path
from typing import Optional

import yaml

from fastapi import APIRouter, Depends, Form, HTTPException, Request

from sentinel.ui.state import UIConfig, list_engagements, list_runs
from sentinel.web.deps import get_config

router = APIRouter()


@router.get("/engagements")
def engagements_list(request: Request, cfg: UIConfig = Depends(get_config)):
    engagements = list_engagements(cfg.scopes_dir)
    today = date.today()
    rows = []
    for e in engagements:
        from sentinel.web.routes.scan import _load_scope, _derive_target  # reuse
        scope = _load_scope(e["path"])
        targets = scope.get("targets") or {}
        try:
            vf = date.fromisoformat(str(e["valid_from"]))
            vu = date.fromisoformat(str(e["valid_until"]))
            valid_now = vf <= today <= vu
        except Exception:
            valid_now = False
        rows.append({
            "engagement": e,
            "valid_now": valid_now,
            "n_repos": len(targets.get("repos") or []),
            "n_domains": len(targets.get("domains") or []),
            "n_ips": len(targets.get("ips") or []),
        })
    return request.app.state.templates.TemplateResponse(
        request, "engagements_list.html",
        {"active_nav": "Engagements", "rows": rows, "cfg": cfg},
    )


@router.get("/engagements/new")
def engagements_new(request: Request, cfg: UIConfig = Depends(get_config)):
    from sentinel.engagements import list_templates as _list_templates
    today = date.today()
    return request.app.state.templates.TemplateResponse(
        request, "engagements_new.html",
        {
            "active_nav": "Engagements",
            "default_engagement_id": today.strftime("%Y-Q%q-pentest-001").replace("Q%q", f"Q{(today.month-1)//3+1}"),
            "today": today.isoformat(),
            "default_until": (today + timedelta(days=90)).isoformat(),
            "cfg": cfg,
            "templates": _list_templates(),
        },
    )


@router.post("/engagements")
def engagements_create(
    request: Request,
    cfg: UIConfig = Depends(get_config),
    template: str = Form("private"),
    client: str = Form(...),
    engagement_id: str = Form(...),
    authorized_by: str = Form(...),
    authorization_doc: str = Form(""),
    valid_from: str = Form(...),
    valid_until: str = Form(...),
    repos: str = Form(""),
    domains: str = Form(""),
    ips: str = Form(""),
    out_of_scope: str = Form(""),
    rate_limit_rps: int = Form(0),
    research_handle: str = Form(""),
):
    """Create a scope.yaml + workspace dir using the shared wizard backend.

    The CLI subcommand (`sentinel new-engagement`) and this POST handler
    both call into `sentinel.engagements.wizard.create_engagement` so
    behaviour stays in lockstep — bug fixes / template defaults land in
    one place.
    """
    from sentinel.engagements import EngagementSpec, create_engagement

    repos_list = [r.strip() for r in repos.splitlines() if r.strip()]
    domains_list = [d.strip() for d in domains.splitlines() if d.strip()]
    ips_list = [i.strip() for i in ips.splitlines() if i.strip()]
    oos_list = [o.strip() for o in out_of_scope.splitlines() if o.strip()]

    spec = EngagementSpec(
        template=template,
        client=client.strip(),
        engagement_id=engagement_id.strip(),
        authorized_by=authorized_by.strip(),
        authorization_doc=authorization_doc.strip(),
        valid_from=valid_from,
        valid_until=valid_until,
        repos=tuple(repos_list),
        domains=tuple(domains_list),
        ips=tuple(ips_list),
        out_of_scope=tuple(oos_list),
        research_handle=research_handle.strip(),
        rate_limit_rps_override=(int(rate_limit_rps) or None),
    )
    workspaces_root = Path(cfg.project_dir).expanduser() / "workspaces"
    try:
        result = create_engagement(
            spec, scopes_dir=cfg.scopes_dir, workspaces_root=workspaces_root,
        )
    except FileExistsError as exc:
        raise HTTPException(409, str(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc)) from exc

    return request.app.state.templates.TemplateResponse(
        request, "engagements_created.html",
        {
            "active_nav": "Engagements",
            "filename": result.scope_path.name,
            "path": str(result.scope_path),
            "sha256": result.sha256,
            "yaml_text": result.yaml_text,
            "template_notes": result.template_notes,
            "workspace_dir": str(result.workspace_dir),
            "cfg": cfg,
        },
    )


@router.get("/engagements/{filename}")
def engagement_detail(request: Request, filename: str, cfg: UIConfig = Depends(get_config)):
    if "/" in filename or filename.startswith(".."):
        raise HTTPException(400, "invalid filename")
    path = Path(cfg.scopes_dir).expanduser() / filename
    if not path.is_file():
        raise HTTPException(404, f"no scope at {path}")
    yaml_text = path.read_text()
    try:
        scope = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError as e:
        raise HTTPException(500, f"invalid YAML: {e}")
    sha = hashlib.sha256(yaml_text.encode()).hexdigest()
    # Runs whose scope.engagement_id matches.
    eng_id = scope.get("engagement_id", "")
    runs = [r for r in list_runs(cfg.runs_dir) if r["engagement"] == eng_id]
    audit_path = path.parent / f".audit-{eng_id}.jsonl"
    # Phase 3 / Phase 11 — surface auth_credentials block (no secrets).
    import os
    creds_summary: list[dict] = []
    for c in (scope.get("auth_credentials") or []):
        env_name = c.get("password_env") or c.get("token_env") or ""
        env_set = bool(os.environ.get(env_name)) if env_name else False
        creds_summary.append({
            "name": c.get("name", "?"),
            "method": c.get("method", "?"),
            "username": c.get("username", ""),
            "url": c.get("url", ""),
            "env_var": env_name,
            "env_set": env_set,
        })
    return request.app.state.templates.TemplateResponse(
        request, "engagements_detail.html",
        {
            "active_nav": "Engagements",
            "filename": filename,
            "path": str(path),
            "scope": scope,
            "yaml_text": yaml_text,
            "sha256": sha,
            "runs": runs,
            "audit_path": str(audit_path) if audit_path.exists() else None,
            "cfg": cfg,
            "creds_summary": creds_summary,
        },
    )
