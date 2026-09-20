"""Dashboard — GET /

Renders health pills, severity-breakdown stat cards, recent runs, engagements
summary. All loaders read fresh from disk on each request (no caching).
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from fastapi import APIRouter, Depends, Request

from sentinel.ui.state import (
    UIConfig,
    list_runs,
    list_engagements,
    list_audit_logs,
    list_workspaces,
    vault_knowledge_stats,
    corpus_chroma_stats,
    ollama_status,
    embedder_status,
)
from sentinel.agent.pentest import payloads as payload_bank
from sentinel.state import build_snapshot
from sentinel.web.deps import get_config

router = APIRouter()


@router.get("/", name="dashboard")
def dashboard(request: Request, cfg: UIConfig = Depends(get_config)):
    runs = list_runs(cfg.runs_dir)
    engagements = list_engagements(cfg.scopes_dir)
    audit_logs = list_audit_logs(cfg.scopes_dir)

    # Health checks
    ollama_chat = ollama_status(cfg.ollama_host, cfg.ollama_model)
    ollama_embed = embedder_status(cfg.ollama_host, cfg.embed_model)
    health = [
        ("Ollama chat",     ollama_chat.get("available", False)),
        ("Ollama embedder", ollama_embed.get("available", False)),
        ("Vault",           Path(cfg.vault_path).expanduser().is_dir()),
        ("Corpus",          Path(cfg.corpus_dir).expanduser().is_dir()),
        ("Scopes",          Path(cfg.scopes_dir).expanduser().is_dir()),
        ("Runs",            Path(cfg.runs_dir).expanduser().is_dir()),
    ]

    # Severity totals across all runs (cheap — only reads run JSON if needed)
    sev_total = Counter()
    for r in runs:
        try:
            d = json.loads(Path(r["path"]).read_text())
            for f in d.get("findings", []):
                sev_total[(f.get("severity") or "info").lower()] += 1
        except Exception:
            pass

    # Phase 10 — workspaces + cross-engagement memory tiles
    workspaces_root = Path(cfg.project_dir).expanduser() / "workspaces"
    workspaces = list_workspaces(workspaces_root)
    n_workspaces = len(workspaces)
    n_workspaces_complete = sum(
        1 for w in workspaces
        if "report" in w["completed_phases"]
    )
    # Past-engagement memory: build the candidate source labels for every
    # known engagement (the past_engagements ingester writes chunks under
    # `past-engagement-<client>-<engagement_id>`). state.corpus_chroma_stats
    # used to hardcode a 7-source list and miss these — now we pass the
    # candidates as extra_sources so they're discoverable at request time.
    past_eng_candidates: list[str] = []
    for eng in engagements:
        eid = eng.get("engagement_id") or eng.get("filename")
        client = eng.get("client")
        if not eid:
            continue
        past_eng_candidates.append(
            f"past-engagement-{client}-{eid}" if client
            else f"past-engagement-{eid}"
        )

    past_engagement_chunks = 0
    try:
        cstats = corpus_chroma_stats(
            cfg.corpus_dir, cfg.ollama_host, cfg.embed_model,
            extra_sources=past_eng_candidates,
        )
        for source, count in (cstats.get("per_source") or {}).items():
            if source and source.startswith("past-engagement-"):
                past_engagement_chunks += int(count or 0)
    except Exception:
        past_engagement_chunks = 0

    # Payload library — was hardcoded in the template; now read live so
    # Wave 1 (csrf, file_upload, jwt_oauth) and any future class shows up
    # immediately on the dashboard without a template edit.
    payload_classes = sorted(payload_bank.all_classes())
    n_payload_classes = len(payload_classes)
    n_payload_entries = sum(
        len(items)
        for cls in payload_classes
        for items in payload_bank._PAYLOAD_REGISTRY[cls].values()
    )

    # STATE-02: render the same `build_snapshot()` dict the /state route
    # serves so the operator sees in-flight engagements + H1 queue on
    # the Dashboard home without dropping to a separate page.
    # Fresh on every request — no caching layer.
    snapshot = build_snapshot(Path(cfg.project_dir).expanduser())

    return request.app.state.templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "active_nav": "Dashboard",
            "cfg": cfg,
            "runs": runs[:8],
            "engagements": engagements,
            "audit_logs": audit_logs,
            "health": health,
            "sev_total": sev_total,
            "n_workspaces": n_workspaces,
            "n_workspaces_complete": n_workspaces_complete,
            "past_engagement_chunks": past_engagement_chunks,
            "payload_classes": payload_classes,
            "n_payload_classes": n_payload_classes,
            "n_payload_entries": n_payload_entries,
            "snapshot": snapshot,
        },
    )
