"""Wave 4 / A6 — ATT&CK Coverage Heatmap dashboard route.

GET /attack-heatmap            — index, lists every run with a quick
                                 coverage snapshot
GET /attack-heatmap/{run}      — per-run heatmap (rows = tactics,
                                 columns = findings exercising that tactic)

The route reuses the same run JSON files /findings already consumes; no
new on-disk artifact required. Findings missing tags are auto-tagged via
attack_mapper at render time so a historical run that pre-dated Wave 4
still gets its kill-chain plotted.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from sentinel.core.attack_mapper import (
    CLASS_TO_ATTACK_CAPEC,
    TACTIC_ORDER,
    infer_attack_capec,
    tactic_for_technique,
)
from sentinel.core.findings import Finding, Severity, Status
from sentinel.ui.state import UIConfig, list_runs
from sentinel.web.deps import get_config
from sentinel.web.event_styles import attack_tactic_slug, style_for


log = logging.getLogger(__name__)

router = APIRouter()


def _findings_from_dicts(dicts: list[dict]) -> list[Finding]:
    """Reconstruct findings from a run JSON, auto-tagging if attack
    fields aren't present (so pre-Wave-4 runs render nicely)."""
    out: list[Finding] = []
    for d in dicts:
        try:
            f = Finding(
                title=d.get("title", ""),
                description=d.get("description", ""),
                severity=Severity.from_string(d.get("severity")),
                scanner=d.get("scanner", "?"),
                target=d.get("target", "?"),
                location=d.get("location"),
                cwe=d.get("cwe"),
                cve=d.get("cve"),
                cvss=d.get("cvss"),
                references=d.get("references") or [],
                raw=d.get("raw") or {},
                status=Status(d.get("status", "new")) if d.get("status") in {s.value for s in Status} else Status.NEW,
                remediation=d.get("remediation"),
                triage_notes=d.get("triage_notes"),
                reproduces_in_lab=bool(d.get("reproduces_in_lab", False)),
                reproduces_under_operational=bool(d.get("reproduces_under_operational", False)),
                reproduces_complete=bool(d.get("reproduces_complete", False)),
                attack_technique_ids=list(d.get("attack_technique_ids", []) or []),
                capec_ids=list(d.get("capec_ids", []) or []),
            )
        except ValueError as e:
            log.warning("attack-heatmap: skipping malformed finding: %s", e)
            continue
        if not f.attack_technique_ids:
            tids, caps = infer_attack_capec(f)
            f.attack_technique_ids = tids
            f.capec_ids = caps
        out.append(f)
    return out


def _heatmap_for_findings(findings: list[Finding]) -> list[dict]:
    """Build the canonical-ordered tactic rows the template renders."""
    rows: list[dict] = []
    for tactic in TACTIC_ORDER:
        bucket: list[Finding] = []
        techniques: set[str] = set()
        for f in findings:
            for tid in f.attack_technique_ids:
                if tactic_for_technique(tid) == tactic:
                    bucket.append(f)
                    techniques.add(tid)
                    break
        rows.append({
            "tactic": tactic,
            "slug": attack_tactic_slug(tactic),
            "style": style_for(attack_tactic_slug(tactic)),
            "count": len(bucket),
            "techniques": sorted(techniques),
            "findings": bucket,
        })
    return rows


@router.get("/attack-heatmap", name="attack_heatmap_index")
def attack_heatmap_index(
    request: Request, cfg: UIConfig = Depends(get_config),
):
    runs = list_runs(cfg.runs_dir)
    snapshots: list[dict] = []
    for r in runs[:25]:  # don't slow the index page if there are 100s of runs
        run_path = Path(cfg.runs_dir).expanduser() / r["filename"]
        try:
            data = json.loads(run_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        findings = _findings_from_dicts(data.get("findings", []) or [])
        rows = _heatmap_for_findings(findings)
        n_tactics = sum(1 for row in rows if row["count"] > 0)
        snapshots.append({
            "filename": r["filename"],
            "client": r.get("client", "—"),
            "engagement_id": r.get("engagement_id", "—"),
            "n_findings": len(findings),
            "n_tactics_covered": n_tactics,
        })
    return request.app.state.templates.TemplateResponse(
        request,
        "attack_heatmap.html",
        {
            "active_nav": "Findings",
            "cfg": cfg,
            "snapshots": snapshots,
            "selected": None,
            "rows": [],
        },
    )


@router.get("/attack-heatmap/{run_filename}", name="attack_heatmap_detail")
def attack_heatmap_detail(
    request: Request,
    run_filename: str,
    cfg: UIConfig = Depends(get_config),
):
    if "/" in run_filename or run_filename.startswith(".."):
        raise HTTPException(400, "invalid run filename")
    run_path = Path(cfg.runs_dir).expanduser() / run_filename
    if not run_path.is_file():
        raise HTTPException(404, f"no run at {run_path}")
    try:
        data = json.loads(run_path.read_text())
    except json.JSONDecodeError as e:
        raise HTTPException(500, f"corrupt run JSON: {e}")
    findings = _findings_from_dicts(data.get("findings", []) or [])
    rows = _heatmap_for_findings(findings)
    return request.app.state.templates.TemplateResponse(
        request,
        "attack_heatmap.html",
        {
            "active_nav": "Findings",
            "cfg": cfg,
            "snapshots": [],
            "selected": run_filename,
            "rows": rows,
            "n_findings": len(findings),
            "supported_classes": sorted(CLASS_TO_ATTACK_CAPEC.keys()),
        },
    )
