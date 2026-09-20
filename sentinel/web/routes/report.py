"""Report — pick a run, generate PDF + compliance overlay, optionally bundle as zip."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Optional

import yaml

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, Response

from sentinel.core.findings import Finding, Severity, Status
from sentinel.core.scope import Scope
from sentinel.core.orchestrator import RunReport
from sentinel.reporting.compliance import render_overlay_markdown
from sentinel.reporting.diff import diff_findings, render_diff_markdown
from sentinel.reporting.pdf import PDFReporter
from sentinel.ui.state import UIConfig, list_runs, list_engagements
from sentinel.web.deps import get_config

router = APIRouter()


def _findings_from_dicts(dicts: list[dict]) -> list[Finding]:
    """Reconstruct Finding objects from a run JSON for PDFReporter."""
    out: list[Finding] = []
    for d in dicts:
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
            impact=d.get("impact"),
            proof_of_concept=d.get("proof_of_concept"),
            expected_output=d.get("expected_output"),
            validation=d.get("validation"),
            triage_notes=d.get("triage_notes"),
            reproduces_in_lab=bool(d.get("reproduces_in_lab", False)),
            reproduces_under_operational=bool(d.get("reproduces_under_operational", False)),
            reproduces_complete=bool(d.get("reproduces_complete", False)),
            attack_technique_ids=list(d.get("attack_technique_ids", []) or []),
            capec_ids=list(d.get("capec_ids", []) or []),
        )
        out.append(f)
    return out


def _resolve_scope_for_run(cfg: UIConfig, run_data: dict) -> Optional[Scope]:
    """Try to find the engagement scope file matching this run."""
    scope_dict = run_data.get("scope") or {}
    eng_id = scope_dict.get("engagement_id")
    if not eng_id:
        return None
    for e in list_engagements(cfg.scopes_dir):
        if e["engagement_id"] == eng_id:
            try:
                return Scope.load(e["path"])
            except Exception:
                return None
    return None


@router.get("/report")
def report_index(request: Request, cfg: UIConfig = Depends(get_config), run: Optional[str] = None):
    runs = list_runs(cfg.runs_dir)
    selected = next((r for r in runs if r["filename"] == run), runs[0] if runs else None)
    return request.app.state.templates.TemplateResponse(
        request, "report.html",
        {"active_nav": "Report", "cfg": cfg, "runs": runs, "selected": selected},
    )


@router.post("/report/pdf")
def report_pdf(request: Request, cfg: UIConfig = Depends(get_config), run_filename: str = Form(...)):
    run_path = Path(cfg.runs_dir).expanduser() / run_filename
    if not run_path.is_file():
        raise HTTPException(404, "run not found")
    run_data = json.loads(run_path.read_text())
    scope = _resolve_scope_for_run(cfg, run_data)
    if scope is None:
        raise HTTPException(400, "could not resolve scope file for this run")
    findings = _findings_from_dicts(run_data.get("findings", []))
    report_obj = RunReport(scope=scope, findings=findings,
                           scanners_run=run_data.get("scanners_run", []), errors=[])
    out_dir = Path(cfg.project_dir) / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = PDFReporter(str(out_dir)).write(report_obj)
    return FileResponse(pdf_path, media_type="application/pdf", filename=pdf_path.name)


@router.post("/report/compliance")
def report_compliance(request: Request, cfg: UIConfig = Depends(get_config), run_filename: str = Form(...)):
    run_path = Path(cfg.runs_dir).expanduser() / run_filename
    if not run_path.is_file():
        raise HTTPException(404, "run not found")
    run_data = json.loads(run_path.read_text())
    findings = _findings_from_dicts(run_data.get("findings", []))
    md = render_overlay_markdown(findings)
    return Response(
        md, media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{run_filename.replace(".json", "-compliance.md")}"'},
    )


@router.post("/report/diff")
def report_diff(
    request: Request,
    cfg: UIConfig = Depends(get_config),
    run_filename: str = Form(...),
    prior_run: str = Form(...),
    download: bool = Form(False),
):
    """Compute the finding-level delta between two runs and either render
    the markdown inline (HTMX swap target) or download as `<run>.delta.md`."""
    if not prior_run:
        raise HTTPException(400, "prior_run is required")
    runs_dir = Path(cfg.runs_dir).expanduser()
    cur_path = runs_dir / run_filename
    pri_path = runs_dir / prior_run
    if not cur_path.is_file():
        raise HTTPException(404, f"current run not found: {cur_path}")
    if not pri_path.is_file():
        raise HTTPException(404, f"prior run not found: {pri_path}")
    cur_data = json.loads(cur_path.read_text())
    pri_data = json.loads(pri_path.read_text())
    cur_findings = _findings_from_dicts(cur_data.get("findings", []))
    pri_findings = _findings_from_dicts(pri_data.get("findings", []))
    delta = diff_findings(pri_findings, cur_findings)
    md = render_diff_markdown(
        delta,
        prior_label=Path(prior_run).stem,
        current_label=Path(run_filename).stem,
    )
    if download:
        return Response(
            md, media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{Path(run_filename).stem}.delta.md"'},
        )
    # HTMX inline swap — render the markdown via safe_markdown into a card.
    counts = delta.counts()
    from sentinel.web.helpers import safe_markdown
    html = (
        f'<div class="bg-bg-card border border-line rounded-lg shadow-card overflow-hidden">'
        f'<div class="px-5 py-3 border-b border-line text-sm font-semibold flex items-center gap-1.5">'
        f'<i data-lucide="git-compare-arrows" class="w-4 h-4 text-fg-muted"></i> Delta · '
        f'<code class="font-mono">{prior_run}</code> → <code class="font-mono">{run_filename}</code>'
        f' · <span class="chip chip-info">closed {counts["closed"]}</span>'
        f' · <span class="chip chip-critical">new {counts["new"]}</span>'
        f' · <span class="chip chip-medium">escalated {counts["escalated"]}</span>'
        f' · <span class="chip chip-ok">reduced {counts["reduced"]}</span>'
        f' · <span class="chip chip-low">persisted {counts["persisted"]}</span>'
        f'</div>'
        f'<div class="p-5 prose prose-invert prose-sm max-w-none">{safe_markdown(md)}</div>'
        f'</div>'
    )
    return HTMLResponse(html)


@router.post("/report/bundle")
def report_bundle(request: Request, cfg: UIConfig = Depends(get_config), run_filename: str = Form(...)):
    run_path = Path(cfg.runs_dir).expanduser() / run_filename
    if not run_path.is_file():
        raise HTTPException(404, "run not found")
    run_data = json.loads(run_path.read_text())
    scope = _resolve_scope_for_run(cfg, run_data)
    if scope is None:
        raise HTTPException(400, "could not resolve scope")
    findings = _findings_from_dicts(run_data.get("findings", []))
    out_dir = Path(cfg.project_dir) / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = PDFReporter(str(out_dir)).write(RunReport(
        scope=scope, findings=findings,
        scanners_run=run_data.get("scanners_run", []), errors=[]))
    md = render_overlay_markdown(findings)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(pdf_path, arcname=pdf_path.name)
        zf.writestr(run_filename.replace(".json", "-compliance.md"), md)
    buf.seek(0)
    zip_name = f"{scope.client}-{scope.engagement_id}-deliverable.zip"
    return Response(
        buf.getvalue(), media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{zip_name}"'},
    )
