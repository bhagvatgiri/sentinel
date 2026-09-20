"""Findings browser — GET /findings, GET /findings/{run_filename},
GET /findings/{run_filename}/{fingerprint}, GET /findings/{run_filename}/{fingerprint}/screenshot.png.

Server-rendered list with HTMX-driven filter chips. The filter form posts to
the same route with hx-target=#findings-list so we replace just the list.

Phase 10.5 added POST /findings/{run_filename}/suggest_fix — an HTMX endpoint
that calls a local Ollama model to propose a code-level remediation.

Plan 03-06 (VERIFY-07, 2026-XX-XX) adds two new GET routes that render the
per-finding PoC evidence bundle written by Plan 03-04's execute_poc sandbox:

  - GET /findings/{run_filename}/{fingerprint}
      Renders finding_poc_detail.html with the PoC command, stdout/stderr,
      exit_code, optional refusal text, and the matching audit-log
      rationale extracted from .audit-<engagement_id>.jsonl. The
      evidence_state chip is color-coded via the FROZEN mapping from
      Plan 03-06's <interfaces> table (VERIFIED -> chip-ok,
      UNREPRODUCIBLE -> chip-low, MANUAL_REQUIRED -> chip-medium,
      VERIFICATION_ERROR -> chip-critical, PENDING/RECON_INFERRED -> chip-info,
      REQUIRES_TEST_CREDENTIALS/REQUIRES_TWO_ACCOUNTS -> chip-info).

  - GET /findings/{run_filename}/{fingerprint}/screenshot.png
      Returns FileResponse(screenshot.png, media_type='image/png') when the
      file exists in the evidence bundle. HTTP 404 when absent. Screenshots
      are NOT base64-encoded into the detail HTML — Playwright PoCs can
      produce 1MB+ PNGs and base64 inflation bloats the page render path.

The findings_detail listing route is enhanced — each finding row now ships
with `bundle_exists: bool` (True when workspaces/<eng>/verification/<fp>/
exists) so the template can render a conditional "View PoC" link and an
evidence_state chip. The finding_card macro reads both fields.

Path-traversal safety: fingerprint must match `^[a-f0-9]{16}$`; run_filename
goes through the existing `_resolve_run_filename` helper which rejects `/`,
`..`, and leading `.`. The detail + screenshot routes also assert the
resolved bundle dir is under workspaces_dir (rejects symlink escape) via
`Path.resolve().relative_to(workspaces_dir.resolve())`.

All user-controlled content (stdout, stderr, command, rationale, refusal)
goes through Jinja's autoescape — XSS via hostile PoC stdout is prevented.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, Form, Query, Request, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse

from sentinel.core.findings import EvidenceState, Finding, Severity, Status
from sentinel.reporting import render_poc_section
from sentinel.ui.state import UIConfig, list_runs
from sentinel.web import helpers
from sentinel.web.deps import get_config


log = logging.getLogger(__name__)

router = APIRouter()


# ---- Plan 03-06: path-traversal regex + evidence-bundle helpers -----------

# Fingerprint = sha1(...)[:16] -> 16 lowercase hex chars. The route's regex
# rejects anything else (HTTP 400) before any filesystem access.
_FINGERPRINT_RE = re.compile(r"^[a-f0-9]{16}$")

# Truncation cap for log content rendered inline in the detail template.
# The full files stay on disk; the dashboard view is a quick-look. Plan
# 03-04 already caps stdout/stderr at 1MB at write time; this is a second
# guard so the rendered HTML response stays bounded.
_DETAIL_TRUNCATE_BYTES = 64 * 1024


def _resolve_run_filename(cfg: UIConfig, run_filename: str) -> Path:
    """Resolve `run_filename` under `cfg.runs_dir`, raising HTTPException
    400 on any traversal-shape input and 404 when the file is absent.

    Shared by findings_detail, findings_suggest_fix, finding_poc_detail,
    finding_poc_screenshot — single source of truth for run-JSON
    resolution.
    """
    if "/" in run_filename or "\\" in run_filename or run_filename.startswith(".."):
        raise HTTPException(400, "invalid run filename")
    if run_filename.startswith("."):
        raise HTTPException(400, "invalid run filename")
    run_path = Path(cfg.runs_dir).expanduser() / run_filename
    if not run_path.is_file():
        raise HTTPException(404, f"no run at {run_path}")
    return run_path


def _load_run_data(run_path: Path) -> dict:
    """Parse the run JSON; raise HTTPException 500 on corrupt JSON."""
    try:
        return json.loads(run_path.read_text())
    except json.JSONDecodeError as e:
        raise HTTPException(500, f"corrupt run JSON: {e}")


def _resolve_evidence_bundle(
    workspaces_dir: Path, engagement_id: str, fingerprint: str
) -> tuple[Path, dict]:
    """Resolve the bundle dir under workspaces_dir and read its contents.

    Returns (bundle_dir, bundle_data) where bundle_data has either:
      - {"bundle_missing": True}                   (dir doesn't exist on disk)
      - file-content dict (poc_sh / poc_py / stdout_log / stderr_log /
        exit_code / refusal_txt / has_screenshot / language)

    Raises HTTPException 400 when the resolved bundle_dir escapes the
    workspaces_dir (symlink-escape check via is_relative_to / .relative_to).
    """
    workspaces_dir = Path(workspaces_dir).expanduser()
    bundle_dir = workspaces_dir / engagement_id / "verification" / fingerprint

    # T-03-06-07 mitigation — symlink escape check. We resolve the bundle
    # dir AND the workspaces root and assert containment. If bundle_dir
    # doesn't exist yet, `.resolve(strict=False)` still gives an absolute
    # path; we compare against the resolved workspaces root anyway.
    try:
        resolved_bundle = bundle_dir.resolve()
        resolved_root = workspaces_dir.resolve()
        # Use Path.relative_to which raises ValueError on non-containment.
        # is_relative_to was added in 3.9 — we use the older idiom here.
        resolved_bundle.relative_to(resolved_root)
    except ValueError:
        raise HTTPException(400, "bundle path escapes workspaces dir")
    except OSError as e:
        # Filesystem couldn't resolve — treat as missing.
        log.warning("evidence bundle resolve OSError: %s", e)
        return bundle_dir, {"bundle_missing": True}

    if not bundle_dir.is_dir():
        return bundle_dir, {"bundle_missing": True}

    def _read(name: str) -> Optional[str]:
        p = bundle_dir / name
        if not p.is_file():
            return None
        try:
            text = p.read_text(errors="replace")
        except OSError as e:
            log.warning("evidence bundle file read failed: %s -> %s", p, e)
            return None
        if len(text) > _DETAIL_TRUNCATE_BYTES:
            text = text[:_DETAIL_TRUNCATE_BYTES] + "\n\n[... truncated ...]"
        return text

    poc_sh = _read("poc.sh")
    poc_py = _read("poc.py")

    # Detect language from which file is present + a content heuristic for
    # playwright vs plain python (Plan 03-04's ACCEPTED_LANGUAGES tuple
    # is ('shell', 'python', 'playwright', 'sqlmap')). The template uses
    # this to set the syntax-highlight class.
    language = None
    if poc_sh:
        # sqlmap PoCs are also written to poc.sh in some configurations;
        # the language=sqlmap variant is shell-equivalent for rendering.
        language = "shell"
    if poc_py:
        if "playwright" in poc_py:
            language = "playwright"
        else:
            language = "python"

    return bundle_dir, {
        "bundle_missing": False,
        "poc_sh": poc_sh,
        "poc_py": poc_py,
        "stdout_log": _read("stdout.log"),
        "stderr_log": _read("stderr.log"),
        "exit_code": _read("exit_code.txt"),
        "refusal_txt": _read("refusal.txt"),
        "has_screenshot": (bundle_dir / "screenshot.png").is_file(),
        "language": language,
    }


def _resolve_audit_rationale(
    workspaces_dir: Path, engagement_id: str, fingerprint: str
) -> Optional[dict]:
    """Scan the engagement's .audit-<id>.jsonl for the latest
    poc_run_completed event matching `fingerprint`. Returns the payload
    dict (with `rationale`, `duration_sec`, `expected_output_matched`,
    `destructive_pattern`, `out_of_scope_url`) or None if no entry found
    OR the audit log doesn't exist OR the file is corrupt.

    Looks in workspaces/<eng>/.audit-<id>.jsonl first, then cwd as
    fallback (CLAUDE.md notes the audit log can live in either spot
    depending on engagement setup).
    """
    workspaces_dir = Path(workspaces_dir).expanduser()
    candidates = [
        workspaces_dir / engagement_id / f".audit-{engagement_id}.jsonl",
        Path.cwd() / f".audit-{engagement_id}.jsonl",
    ]
    audit_path: Optional[Path] = None
    for p in candidates:
        if p.is_file():
            audit_path = p
            break
    if audit_path is None:
        return None

    latest: Optional[dict] = None
    latest_ts: str = ""
    try:
        with audit_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("event") != "poc_run_completed":
                    continue
                payload = entry.get("payload") or {}
                if payload.get("finding_fingerprint") != fingerprint:
                    continue
                # ISO timestamps are lexicographic-sortable.
                ts = entry.get("ts", "")
                if ts >= latest_ts:
                    latest = payload
                    latest_ts = ts
    except OSError as e:
        log.warning("audit log read failed: %s -> %s", audit_path, e)
        return None
    return latest


# Plan 03-06 FROZEN evidence_state -> chip-class mapping (matches the table
# in 03-06-PLAN.md <interfaces>). Values must match the EVENT_STYLES chip
# vocabulary (`ok`, `info`, `low`, `medium`, `high`, `critical`).
_CHIP_CLASS_BY_EVIDENCE_STATE: dict[str, str] = {
    "verified": "ok",
    "live_confirmed": "ok",
    "unreproducible": "low",
    "live_disproven": "low",
    "manual-required": "medium",
    "manual_required": "medium",   # snake_case alias (EvidenceState.from_string accepts both)
    "manual_verification_required": "medium",
    "requires_test_credentials": "info",
    "requires_two_accounts": "info",
    "verification_error": "critical",
    "pending": "info",
    "recon_inferred": "info",
}


def _chip_class_for(evidence_state: Optional[str]) -> str:
    """Lookup the chip-class for an evidence_state string. Unknown values
    fall back to `info` so the template never crashes when a future
    EvidenceState value is added without a mapping update."""
    if not evidence_state:
        return "info"
    return _CHIP_CLASS_BY_EVIDENCE_STATE.get(
        str(evidence_state).strip().lower(), "info"
    )


def _chip_class_for_novelty(novelty_score: Optional[float]) -> str:
    """Plan 05-05 (NOVEL-07): map novelty_score to chip class for the
    Novelty panel. Vocabulary extends the existing _chip_class_for taxonomy.

        score >= 0.75   -> 'novelty-high'    (escalation candidate)
        0.5 <= s < 0.75 -> 'novelty-medium'  (interesting but below threshold)
        score <  0.5    -> 'info'            (well within known-pattern territory)

    Returns 'info' on None / non-numeric / NaN input (defensive — the chip
    must never break the page render even if a future ingestion source
    smuggles a non-float into the novelty_score field).
    """
    try:
        s = float(novelty_score)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "info"
    # NaN guard — NaN != NaN is the canonical Python NaN test.
    if s != s:
        return "info"
    if s >= 0.75:
        return "novelty-high"
    if s >= 0.5:
        return "novelty-medium"
    return "info"


def _annotate_findings_with_bundle_exists(
    findings: list[dict], workspaces_dir: Path, engagement_id: Optional[str]
) -> None:
    """For each finding dict, set `bundle_exists: bool` based on whether
    workspaces/<engagement>/verification/<fingerprint>/ is on disk.

    Mutates the dicts in-place. Skips when engagement_id is missing or
    workspaces_dir doesn't exist (treats every finding as bundle_exists=False).
    """
    if not engagement_id:
        for f in findings:
            f["bundle_exists"] = False
        return
    workspaces_dir = Path(workspaces_dir).expanduser()
    verification_root = workspaces_dir / engagement_id / "verification"
    if not verification_root.is_dir():
        for f in findings:
            f["bundle_exists"] = False
        return
    for f in findings:
        fp = f.get("fingerprint")
        if not fp or not _FINGERPRINT_RE.match(fp):
            f["bundle_exists"] = False
            continue
        f["bundle_exists"] = (verification_root / fp).is_dir()


# ---- Plan 04-05 (POC-07): finding-dict -> Finding reconstitution ----------

# Pre-computed set of Finding's dataclass field names so we can filter the
# run JSON's per-finding dict (which carries transient extras like
# `fingerprint` (computed from to_dict, not a field) and `bundle_exists`
# (annotated by _annotate_findings_with_bundle_exists)) down to just the
# Finding constructor's accepted kwargs.
_FINDING_FIELDS: set[str] = set(Finding.__dataclass_fields__.keys())


def _reconstitute_finding(f_data: dict) -> Finding:
    """Filter run-JSON extras out of `f_data`, coerce enum-shaped strings,
    and return a Finding instance.

    Run JSON per-finding dicts carry fields outside Finding's constructor:
    - `fingerprint`: computed by Finding.to_dict, not stored as a field
    - `bundle_exists`: annotated by _annotate_findings_with_bundle_exists
    - Other future transient annotations added by callers

    They also carry enums as their string `.value` form (because to_dict
    serializes them that way). The Finding constructor expects enum
    instances OR strings that the field type accepts; we coerce known
    enum-typed fields explicitly so a stringly-typed `'high'` round-trips
    back into Severity.HIGH cleanly. Status / EvidenceState handled the
    same way.

    Used by the finding_poc_markdown route to round-trip a run JSON's
    finding back through a real Finding instance before handing it to
    render_poc_section (which expects the dataclass, not the dict).
    """
    payload = {k: v for k, v in f_data.items() if k in _FINDING_FIELDS}
    if isinstance(payload.get("severity"), str):
        payload["severity"] = Severity.from_string(payload["severity"])
    if isinstance(payload.get("status"), str):
        try:
            payload["status"] = Status(payload["status"])
        except ValueError:
            payload["status"] = Status.NEW
    if isinstance(payload.get("evidence_state"), str):
        payload["evidence_state"] = EvidenceState.from_string(payload["evidence_state"])
    return Finding(**payload)


# ---- Routes ---------------------------------------------------------------


@router.get("/findings", name="findings_index")
def findings_index(request: Request, cfg: UIConfig = Depends(get_config)):
    runs = list_runs(cfg.runs_dir)
    return request.app.state.templates.TemplateResponse(
        request,
        "findings_index.html",
        {"active_nav": "Findings", "runs": runs, "cfg": cfg},
    )


@router.get("/findings/{run_filename}", name="findings_detail")
def findings_detail(
    request: Request,
    run_filename: str,
    cfg: UIConfig = Depends(get_config),
    severity: list[str] = Query(default_factory=list),
    scanner: list[str] = Query(default_factory=list),
    status: list[str] = Query(default_factory=list),
    cwe: str = "",
    hide_fp: bool = True,
    sort: str = "severity",
    partial: bool = False,
):
    run_path = _resolve_run_filename(cfg, run_filename)
    data = _load_run_data(run_path)

    findings = data.get("findings", [])
    scope = data.get("scope") or {}
    errors = data.get("errors") or []
    scanners_run = data.get("scanners_run") or []

    # Plan 03-06 — annotate each finding with bundle_exists so the
    # template renders the "View PoC" link conditionally + the chip
    # class via the FROZEN evidence_state mapping. We do this BEFORE
    # filtering so the annotations are stable regardless of UI filters.
    engagement_id = data.get("engagement_id") or scope.get("engagement_id")
    _annotate_findings_with_bundle_exists(
        findings, Path(cfg.workspaces_dir), engagement_id
    )

    # Apply filters.
    filtered = helpers.filter_findings(
        findings,
        severities=severity or None,
        scanners=scanner or None,
        statuses=status or None,
        cwe_substr=cwe,
        hide_fp=hide_fp,
    )
    if sort == "severity":
        filtered = helpers.sort_by_severity(filtered)
    elif sort == "scanner":
        filtered = sorted(filtered, key=lambda f: f.get("scanner", "?"))
    elif sort == "location":
        filtered = sorted(filtered, key=lambda f: f.get("location", "?"))

    # For chips: list of unique scanners + statuses present in this run.
    sev_breakdown_all = helpers.severity_breakdown(findings)
    scanners_seen = sorted({f.get("scanner", "?") for f in findings if f.get("scanner")})
    statuses_seen = sorted({f.get("status", "new") for f in findings if f.get("status")})

    ctx = {
        "active_nav": "Findings",
        "cfg": cfg,
        "run_filename": run_filename,
        "run_path": str(run_path),
        "scope": scope,
        "errors": errors,
        "scanners_run": scanners_run,
        "findings_all": findings,
        "filtered": filtered,
        "sev_breakdown_all": sev_breakdown_all,
        "scanners_seen": scanners_seen,
        "statuses_seen": statuses_seen,
        "selected_severity": severity,
        "selected_scanner": scanner,
        "selected_status": status,
        "cwe_substr": cwe,
        "hide_fp": hide_fp,
        "sort": sort,
        # Plan 03-06 — expose the chip-class resolver to the template so
        # the same FROZEN mapping is used for both the listing row chip
        # and the detail-page header chip.
        "chip_class_for": _chip_class_for,
    }
    template = "_components/findings_list.html" if partial else "findings_detail.html"
    return request.app.state.templates.TemplateResponse(request, template, ctx)


# ---- Pre-submission gate (2026-XX-XX) -------------------------------------
# Scores a run's findings GO/REVIEW/HOLD so the operator never submits a finding
# that'll come back Informative/N-A/Duplicate. Mirrors the `triage-findings` CLI
# (UI parity). Declared BEFORE the /{fingerprint} catch-all so "gate" isn't
# captured as a fingerprint.

@router.get("/findings/{run_filename}/gate", name="findings_submission_gate")
def findings_submission_gate(
    request: Request,
    run_filename: str,
    cfg: UIConfig = Depends(get_config),
    program_maturity: str = "",
):
    from sentinel.agent.pentest.submission_gate import assess_run

    run_path = _resolve_run_filename(cfg, run_filename)
    data = _load_run_data(run_path)
    findings = data.get("findings") or data.get("vulnerabilities") or []
    pm = (program_maturity or "").strip().lower() or None
    result = assess_run(findings, program_maturity=pm)
    order = {"hold": 0, "review": 1, "go": 2}
    verdicts = sorted(result["verdicts"], key=lambda v: order.get(v["decision"], 3))
    return request.app.state.templates.TemplateResponse(
        request, "submission_gate.html",
        {
            "active_nav": "Findings",
            "run_filename": run_filename,
            "verdicts": verdicts,
            "counts": result["counts"],
            "program_maturity": program_maturity,
        },
    )


# ---- Plan 03-06 (VERIFY-07): PoC detail + screenshot routes ---------------


@router.get(
    "/findings/{run_filename}/{fingerprint}",
    name="finding_poc_detail",
)
def finding_poc_detail(
    request: Request,
    run_filename: str,
    fingerprint: str,
    cfg: UIConfig = Depends(get_config),
):
    """Render the per-finding PoC evidence bundle written by Plan 03-04's
    execute_poc sandbox. Operators see the command, stdout/stderr,
    exit_code, evidence_state chip, audit-log rationale, and an
    `<img>` reference to the dedicated screenshot route (when present).

    The bundle is read from
    `cfg.workspaces_dir/<engagement_id>/verification/<fingerprint>/`.
    Missing bundles render a 200 response with a "no PoC bundle" message
    so operators get context rather than a generic 404.
    """
    # Path-traversal safety (T-03-06-01).
    if not _FINGERPRINT_RE.match(fingerprint):
        raise HTTPException(
            status_code=400,
            detail=f"fingerprint must be 16 hex chars, got {fingerprint!r}",
        )
    # Path-traversal safety on run_filename (T-03-06-02) via shared helper.
    run_path = _resolve_run_filename(cfg, run_filename)
    run_data = _load_run_data(run_path)

    engagement_id = run_data.get("engagement_id") or (
        run_data.get("scope") or {}
    ).get("engagement_id")
    if not engagement_id:
        raise HTTPException(
            status_code=500, detail="run JSON missing engagement_id"
        )

    # Find the matching finding (by fingerprint) in the run's findings list.
    findings_list = run_data.get("findings", [])
    matching_finding = next(
        (f for f in findings_list if f.get("fingerprint") == fingerprint),
        None,
    )

    workspaces_dir = Path(cfg.workspaces_dir).expanduser()
    bundle_dir, bundle_data = _resolve_evidence_bundle(
        workspaces_dir, engagement_id, fingerprint
    )
    audit_payload = _resolve_audit_rationale(
        workspaces_dir, engagement_id, fingerprint
    )

    # Determine chip-class from the finding's evidence_state. If the
    # finding wasn't found in the run JSON (rare), fall back to the
    # audit-log payload's evidence_state field.
    evidence_state: Optional[str] = None
    if matching_finding:
        evidence_state = matching_finding.get("evidence_state")
    if not evidence_state and audit_payload:
        evidence_state = audit_payload.get("evidence_state")
    chip_class = _chip_class_for(evidence_state)

    # Plan 05-05 (NOVEL-07) — Novelty panel context. Load the matching
    # NovelFindingEvidence entry from RunReport.novel_findings (Plan 05-04
    # populates this) and compute the chip class for the finding's
    # novelty_score (Plan 05-01 default 0.0). Legacy run JSONs without the
    # `novel_findings` key render `.get(...) or []` -> no match, so the
    # template's empty-state branch renders. The score chip ALWAYS renders
    # so operators see WHERE on the novelty scale every finding lands.
    novel_findings_list = run_data.get("novel_findings") or []
    novel_evidence: Optional[dict] = next(
        (
            entry
            for entry in novel_findings_list
            if entry.get("finding_fingerprint") == fingerprint
        ),
        None,
    )
    novelty_score = (matching_finding or {}).get("novelty_score", 0.0)
    novelty_chip_class = _chip_class_for_novelty(novelty_score)

    return request.app.state.templates.TemplateResponse(
        request,
        "finding_poc_detail.html",
        {
            "active_nav": "Findings",
            "cfg": cfg,
            "run_filename": run_filename,
            "fingerprint": fingerprint,
            "engagement_id": engagement_id,
            "finding": matching_finding,
            "evidence_state": evidence_state,
            "chip_class": chip_class,
            "bundle_dir": str(bundle_dir),
            "bundle": bundle_data,
            "audit": audit_payload,
            # Plan 05-05 (NOVEL-07) Novelty panel context.
            "novel_evidence": novel_evidence,
            "novelty_score": novelty_score,
            "novelty_chip_class": novelty_chip_class,
        },
    )


@router.get(
    "/findings/{run_filename}/{fingerprint}/screenshot.png",
    name="finding_poc_screenshot",
)
def finding_poc_screenshot(
    request: Request,
    run_filename: str,
    fingerprint: str,
    cfg: UIConfig = Depends(get_config),
):
    """Serve the PoC screenshot.png from disk via FileResponse with the
    `image/png` Content-Type. The detail template references this URL via
    `url_for('finding_poc_screenshot', ...)` so the browser can cache the
    image independently from the HTML — base64 data URIs were rejected
    because Playwright PoCs can produce 1MB+ PNGs and base64 inflation
    bloats the page render path (~33% size increase + re-fetch per nav).

    HTTP 404 when the file is absent. HTTP 400 on traversal-shape input.
    """
    if not _FINGERPRINT_RE.match(fingerprint):
        raise HTTPException(
            status_code=400, detail="fingerprint must be 16 hex chars"
        )
    run_path = _resolve_run_filename(cfg, run_filename)
    run_data = _load_run_data(run_path)
    engagement_id = run_data.get("engagement_id") or (
        run_data.get("scope") or {}
    ).get("engagement_id")
    if not engagement_id:
        raise HTTPException(
            status_code=500, detail="run JSON missing engagement_id"
        )

    workspaces_dir = Path(cfg.workspaces_dir).expanduser()
    bundle_dir = workspaces_dir / engagement_id / "verification" / fingerprint
    # T-03-06-07 mitigation — symlink-escape check (same as the detail route).
    try:
        bundle_dir.resolve().relative_to(workspaces_dir.resolve())
    except ValueError:
        raise HTTPException(
            status_code=400, detail="bundle path escapes workspaces dir"
        )
    except OSError as e:
        log.warning("screenshot bundle resolve OSError: %s", e)
        raise HTTPException(status_code=404, detail="bundle path not found")

    screenshot = bundle_dir / "screenshot.png"
    if not screenshot.is_file():
        raise HTTPException(
            status_code=404, detail="screenshot not present in this bundle"
        )
    return FileResponse(screenshot, media_type="image/png")


# ---- Plan 04-05 (POC-07): H1-narrative markdown route ---------------------


@router.get(
    "/findings/{run_filename}/{fingerprint}/markdown",
    name="finding_poc_markdown",
)
def finding_poc_markdown(
    request: Request,
    run_filename: str,
    fingerprint: str,
    cfg: UIConfig = Depends(get_config),
):
    """Return the H1-narrative Markdown body for one finding as text/markdown.

    Reconstitutes the Finding object from the run JSON's findings list
    (via _reconstitute_finding) and hands it to render_poc_section
    (sentinel.reporting, established by Plan 04-02). The renderer's output
    flows back to the client verbatim with `Content-Type:
    text/markdown; charset=utf-8` — no transformation, no wrapping,
    no HTML escaping. This is the surface the dashboard's "Copy
    Reproduction Markdown" button fetches before calling
    navigator.clipboard.writeText.

    Empty poc_steps returns 200 + the renderer's fallback markdown
    ('No automated reproduction available — manual investigation
    required.') — NOT 404, because the finding exists; only the
    automated reproduction is absent. Operators get the context.

    Errors:
        400  fingerprint not 16 hex chars
        400  run_filename contains '/', '\\\\', '..' (via _resolve_run_filename)
        404  run file missing on disk
        404  fingerprint not found in run JSON's findings list
        500  run JSON corrupt (via _load_run_data)
        500  Finding reconstitution failed (caught + reraised with detail)
    """
    if not _FINGERPRINT_RE.match(fingerprint):
        raise HTTPException(
            status_code=400,
            detail=f"fingerprint must be 16 hex chars, got {fingerprint!r}",
        )
    run_path = _resolve_run_filename(cfg, run_filename)
    data = _load_run_data(run_path)

    f_data = next(
        (
            f
            for f in data.get("findings", [])
            if f.get("fingerprint") == fingerprint
        ),
        None,
    )
    if f_data is None:
        raise HTTPException(
            status_code=404, detail=f"finding {fingerprint} not in run"
        )

    try:
        finding = _reconstitute_finding(f_data)
    except Exception as e:
        log.warning("finding reconstitution failed: %s", e)
        raise HTTPException(
            status_code=500, detail=f"could not reconstitute finding: {e}"
        )

    body = render_poc_section(finding)
    return PlainTextResponse(body, media_type="text/markdown; charset=utf-8")


# ---- Phase 10.5: live remediation suggestions -----------------------------


@router.post("/findings/{run_filename}/suggest_fix",
             name="findings_suggest_fix",
             response_class=HTMLResponse)
async def findings_suggest_fix(
    request: Request,
    run_filename: str,
    fingerprint: str = Form(...),
    cfg: UIConfig = Depends(get_config),
):
    """HTMX endpoint that returns a code-level fix suggestion for one finding.

    Calls a local Ollama model (default: mistral-nemo:12b) — cheap and
    private. The operator copies the suggestion into the deliverable;
    Sentinel never auto-commits to client repos.
    """
    run_path = _resolve_run_filename(cfg, run_filename)
    data = _load_run_data(run_path)

    finding = next(
        (f for f in data.get("findings", []) if f.get("fingerprint") == fingerprint),
        None,
    )
    if finding is None:
        return HTMLResponse(
            f'<div class="text-sev-high text-sm">Finding {fingerprint} not '
            'found in this run (corrupt link?).</div>',
            status_code=404,
        )

    try:
        from sentinel.agent.remediation import suggest_fix as run_suggest_fix
    except Exception as e:
        return HTMLResponse(
            f'<div class="text-sev-high text-sm">Remediation module not '
            f'importable: {e}</div>', status_code=500,
        )

    try:
        suggestion = await run_suggest_fix(finding, ollama_host=cfg.ollama_host)
    except Exception as e:
        log.warning("suggest_fix: ollama call failed: %s", e)
        return HTMLResponse(
            f'<div class="text-sev-high text-sm">Ollama call failed: {e}'
            '<br><span class="text-fg-muted text-xs">Make sure Ollama is '
            'running and `mistral-nemo:12b` is pulled.</span></div>',
            status_code=502,
        )

    safe = suggestion or "_(empty response from model)_"
    return HTMLResponse(
        '<div class="rounded-md border border-accent/40 bg-accent/5 p-3 mt-2">'
        '<h4 class="text-xs font-semibold uppercase tracking-wider text-accent mb-2">'
        'Suggested fix (mistral-nemo:12b)</h4>'
        f'<pre class="text-xs whitespace-pre-wrap text-fg leading-relaxed">{_escape(safe)}</pre>'
        '<p class="text-xxs text-fg-muted mt-2">_Operator review required before committing to client repo._</p>'
        '</div>'
    )


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
