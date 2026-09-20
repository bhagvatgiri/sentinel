"""Scan launcher — GET /scan, POST /scan/run, GET /scan/status/{id}, POST /scan/stop/{id}.

Form posts an argv to subprocess.Popen and returns a partial that polls
/scan/status/{id} every 2s until the job exits.
"""

from __future__ import annotations

import sys
from pathlib import Path
import shlex
import subprocess
from typing import Optional


# Absolute path to the `sentinel` wrapper inside *this* venv. Avoids
# relying on the FastAPI server's PATH including .venv/bin/ (it usually
# doesn't when uvicorn is launched outside an activated shell).
_SENTINEL_BIN = str(Path(sys.executable).parent / "sentinel")

import yaml

from fastapi import APIRouter, Depends, Form, Request, HTTPException
from fastapi.responses import HTMLResponse

from sentinel.ui.state import UIConfig, list_engagements
from sentinel.web import jobs
from sentinel.web.deps import get_config


router = APIRouter()


# How many of the most-recent log lines to show in the live terminal pane.
# Shannon is the verbose case — its planning and tool-call traces flood the
# log. 200 lines fits a typical laptop screen and the deque keeps 10k for
# scrollback when we add a "show all" view later.
LIVE_LOG_TAIL_LINES = 200


def _form_error(message: str) -> HTMLResponse:
    """Return a visible error fragment HTMX can swap into #scan-result.

    HTMX 2.x by default drops 4xx responses silently — bad UX when the user
    submits an invalid form. Return 200 with an error chip so they can see
    what's wrong and fix it.
    """
    safe = (
        message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
    html = (
        '<div class="bg-bg-card border border-sev-critical/40 rounded-lg p-4 '
        'flex items-start gap-3">'
        '<i data-lucide="alert-circle" class="w-5 h-5 text-sev-critical flex-shrink-0 mt-0.5"></i>'
        '<div>'
        '<div class="text-sm font-semibold text-sev-critical mb-1">Form error</div>'
        f'<div class="text-xs text-fg">{safe}</div>'
        '</div></div>'
        '<script>if (window.lucide) lucide.createIcons();</script>'
    )
    return HTMLResponse(content=html)


SCAN_MODES = [
    ("scan-repo",        "SAST + secrets + deps on a local repo"),
    ("scan-config",      "IaC / config scan"),
    ("scan-deps",        "Dependency CVE scan"),
    ("scan-web",         "Passive web intake — TLS + headers + DNS + whatweb + testssl"),
    ("scan-live",        "Live URL scan with nuclei templates"),
    ("scan-recon",       "Recon — subdomains + nmap NSE + ffuf + kiterunner"),
    ("scan-active",      "Active web pentest — ZAP + wapiti + Shannon"),
    ("scan-full",        "Everything: passive + recon + nuclei + active"),
    ("scan-apk",         "Mobile pentest — MobSF + apkleaks against an APK file"),
    ("scan-cloud",       "Cloud enumeration — S3Scanner / cloud_enum / Prowler / CloudFox"),
    ("scan-dfir",        "DFIR agent — IOC extraction + timeline on a pcap or log file"),
    ("sbom",             "Generate SBOM (Syft)"),
    ("agent",            "Autonomous pentest agent — recon (Phase 1; scope-gated)"),
    ("scan-autonomous",  "Autonomous pentest pipeline — recon + 6 vuln + 6 exploit + correlation + report"),
    ("brain-grow",       "Brain-Growth Agent — research a topic and ingest into the corpus"),
]
DESTRUCTIVE_MODES = {"scan-active", "scan-full", "scan-autonomous"}
# Modes that take a `--topic` instead of a `target` URL.
TOPIC_MODES = {"brain-grow"}
# Modes built on the autonomous pentest pipeline (extra cost-cap fields shown in form).
AGENT_MODES = {"agent", "scan-autonomous"}
# Modes where the "target" form field is a local filesystem path
# (APK file, pcap / log file, etc.) — UI hint only; the backend still
# validates via Scope.authorize_artifact() in the CLI handler.
FILE_TARGET_MODES = {"scan-apk", "scan-dfir"}
# Modes that take no positional target at all — scope (+ optional flags)
# carries the targeting. Form's target field is hidden / ignored.
NO_TARGET_MODES = {"scan-cloud"}


def _load_scope(path: str) -> dict:
    try:
        return yaml.safe_load(Path(path).read_text()) or {}
    except Exception:
        return {}


def _derive_target(scope: dict, mode: str) -> str:
    targets = scope.get("targets") or {}
    repos = [r for r in (targets.get("repos") or []) if r]
    domains = [d for d in (targets.get("domains") or []) if d]
    ips = [i for i in (targets.get("ips") or []) if i]
    if mode in ("scan-repo", "scan-config", "scan-deps", "sbom"):
        for r in repos:
            if r.startswith(("/", "~")):
                return r
        return ""
    if mode in ("scan-web", "scan-live", "scan-active", "scan-full"):
        for d in domains:
            d_clean = d.lstrip("*.")
            if "*" not in d_clean:
                return f"https://{d_clean}"
        if ips:
            return f"https://{ips[0].split('/')[0]}"
        return ""
    if mode == "scan-recon":
        for d in domains:
            d_clean = d.lstrip("*.")
            if "*" not in d_clean:
                return d_clean
        return ""
    if mode in ("agent", "scan-autonomous"):
        for d in domains:
            d_clean = d.lstrip("*.")
            if "*" not in d_clean:
                return f"https://{d_clean}"
        if ips:
            return f"https://{ips[0].split('/')[0]}"
        return ""
    if mode in ("scan-apk", "scan-dfir"):
        # File-path modes — no scope-derivable default; operator must
        # paste a path into the target field.
        return ""
    if mode == "scan-cloud":
        # No positional target; the scope yaml itself bounds the run.
        return ""
    return ""


@router.get("/scan", name="scan")
def scan_form(
    request: Request,
    cfg: UIConfig = Depends(get_config),
    eng: Optional[str] = None,
    mode: str = "scan-web",
):
    engagements = list_engagements(cfg.scopes_dir)
    selected = next((e for e in engagements if e["filename"] == eng), engagements[0] if engagements else None)
    scope_data = _load_scope(selected["path"]) if selected else {}
    target = _derive_target(scope_data, mode)
    targets_summary = scope_data.get("targets") or {}

    return request.app.state.templates.TemplateResponse(
        request,
        "scan.html",
        {
            "active_nav": "Scan",
            "cfg": cfg,
            "engagements": engagements,
            "selected_engagement": selected,
            "scope_data": scope_data,
            "scope_summary": {
                "repos": len(targets_summary.get("repos") or []),
                "domains": len(targets_summary.get("domains") or []),
                "ips": len(targets_summary.get("ips") or []),
            },
            "modes": SCAN_MODES,
            "selected_mode": mode,
            "target": target,
            "destructive_modes": list(DESTRUCTIVE_MODES),
            "topic_modes": list(TOPIC_MODES),
            "agent_modes": list(AGENT_MODES),
            "file_target_modes": list(FILE_TARGET_MODES),
            "no_target_modes": list(NO_TARGET_MODES),
            "active_jobs": [j for j in jobs.all_jobs() if j.is_running],
            # All running runs (in-memory + orphan external runs whose subprocess
            # survived a FastAPI restart). Survives refresh + restart.
            "active_runs": jobs.list_active_runs(),
        },
    )


@router.post("/scan/run")
def scan_run(
    request: Request,
    cfg: UIConfig = Depends(get_config),
    engagement: str = Form(""),                 # optional for brain-grow
    mode: str = Form(...),
    target: str = Form(""),                     # blank for brain-grow
    topic: str = Form(""),                      # only used for brain-grow
    repo_url: str = Form(""),
    repo_path: str = Form(""),
    deep: bool = Form(False),
    use_vault: bool = Form(True),
    use_corpus: bool = Form(False),
    no_llm: bool = Form(False),
    auto_brain: bool = Form(False),
    max_budget_usd: float = Form(5.0),
    confirm_token: str = Form(""),
    # Phase 10 / 6 — scan-autonomous extras
    resume: bool = Form(False),
    all_scope_targets: bool = Form(False),
    max_concurrent: int = Form(2),
    # Phase A (2026-XX-XX) — deeper-diving knobs for scan-autonomous H1 scans.
    # Only consumed when mode == "scan-autonomous"; ignored otherwise.
    max_budget_per_scan_usd: float = Form(100.0),
    recon_max_pages: int = Form(40),
    recon_max_turns: int = Form(80),
    vuln_max_pages: int = Form(30),
    vuln_max_turns: int = Form(70),
    exploit_max_turns: int = Form(110),
):
    # brain-grow doesn't bind to an engagement (corpus growth isn't scope-bound).
    selected = None
    if mode not in TOPIC_MODES:
        engagements = list_engagements(cfg.scopes_dir)
        selected = next((e for e in engagements if e["filename"] == engagement), None)
        if not selected:
            return _form_error(
                f"Unknown engagement: '{engagement or '(blank)'}'. "
                f"Pick one from the engagement dropdown."
            )

    # Destructive-mode guard: must type the literal "confirm" in the box.
    # Case-insensitive — operator stress-typing-friendly. The earlier `selected`
    # check has already returned an error if no engagement matched.
    if mode in DESTRUCTIVE_MODES:
        if confirm_token.strip().lower() != "confirm":
            return _form_error(
                f"To run {mode}, type 'confirm' in the destructive-mode "
                f"confirmation field at the bottom of the form."
            )

    # Build argv per mode.
    if mode == "brain-grow":
        if not topic.strip():
            return _form_error("Topic is required for brain-grow.")
        argv = [
            _SENTINEL_BIN, "brain-grow",
            "--topic", topic.strip(),
            "--corpus-dir", cfg.corpus_dir,
            "--ollama-host", cfg.ollama_host,
            "--embed-model", cfg.embed_model,
            "--max-budget-usd", str(max_budget_usd),
        ]
        expected = None
    elif mode == "agent":
        if not target.strip():
            return _form_error("Target URL is required for agent mode.")
        argv = [
            _SENTINEL_BIN, "agent", target.strip(),
            "--scope", selected["path"],
            "--max-budget-usd", str(max_budget_usd),
        ]
        expected = None
    elif mode == "scan-autonomous":
        # When --all-scope-targets is set the target arg is dropped (the CLI
        # expands every concrete domain in scope.targets.domains).
        if not all_scope_targets and not target.strip():
            return _form_error(
                "Target URL is required for scan-autonomous "
                "(or check 'All scope targets' to fan out across the scope)."
            )
        argv = [_SENTINEL_BIN, "scan-autonomous"]
        if not all_scope_targets:
            argv.append(target.strip())
        argv += [
            "--scope", selected["path"],
            "--max-budget-per-phase-usd", str(max_budget_usd),
            "--max-budget-per-scan-usd", str(max_budget_per_scan_usd),
            "--recon-max-pages", str(recon_max_pages),
            "--recon-max-turns", str(recon_max_turns),
            "--vuln-max-pages", str(vuln_max_pages),
            "--vuln-max-turns", str(vuln_max_turns),
            "--exploit-max-turns", str(exploit_max_turns),
            "--ollama-host", cfg.ollama_host,
            "--embed-model", cfg.embed_model,
        ]
        if use_corpus:
            argv += ["--corpus-dir", cfg.corpus_dir]
        if repo_path.strip():
            argv += ["--repo-path", repo_path.strip()]
        if auto_brain:
            argv.append("--auto-brain")
        if use_vault:
            argv += ["--vault", cfg.vault_path]
        if resume:
            argv.append("--resume")
        if all_scope_targets:
            argv += ["--all-scope-targets", "--max-concurrent", str(max(1, max_concurrent))]
        expected = str(Path(cfg.project_dir) / "runs" /
                       f"{selected['client']}-{selected['engagement_id']}.json")
    elif mode == "scan-apk":
        # Mobile pentest entry — target field is the APK path; CLI validates
        # via Scope.authorize_artifact("apk", path).
        if not target.strip():
            return _form_error("APK file path is required for scan-apk.")
        argv = [
            _SENTINEL_BIN, "scan-apk", target.strip(),
            "--scope", selected["path"],
            "--ollama-host", cfg.ollama_host,
            "--ollama-model", cfg.ollama_model,
            "--embed-model", cfg.embed_model,
        ]
        if use_vault:
            argv += ["--vault", cfg.vault_path]
        if use_corpus:
            argv += ["--corpus-dir", cfg.corpus_dir]
        expected = None
    elif mode == "scan-cloud":
        # No positional target — scope yaml bounds the run. Provider and
        # bucket-keyword knobs default to sensible values for first-pass
        # discovery; operator can refine via CLI for advanced runs.
        argv = [
            _SENTINEL_BIN, "scan-cloud",
            "--scope", selected["path"],
            "--provider", "any",
            "--ollama-host", cfg.ollama_host,
            "--ollama-model", cfg.ollama_model,
            "--embed-model", cfg.embed_model,
        ]
        if use_vault:
            argv += ["--vault", cfg.vault_path]
        if use_corpus:
            argv += ["--corpus-dir", cfg.corpus_dir]
        expected = None
    elif mode == "scan-dfir":
        # DFIR agent — target field is a pcap or log file path.
        if not target.strip():
            return _form_error(
                "File path (pcap or log) is required for scan-dfir."
            )
        argv = [
            _SENTINEL_BIN, "scan-dfir", target.strip(),
            "--scope", selected["path"],
        ]
        expected = None
    else:
        # Existing scanner modes.
        if not target.strip():
            return _form_error("Target is required.")
        argv = [_SENTINEL_BIN, mode, target.strip(), "--scope", selected["path"]]
        if mode in ("scan-repo", "scan-deps", "scan-active", "scan-full") and repo_url.strip():
            argv += ["--repo-url", repo_url.strip()]
        if deep and mode in ("scan-live", "scan-web", "scan-recon", "scan-active", "scan-full"):
            argv.append("--deep")
        if use_vault:
            argv += ["--vault", cfg.vault_path]
        if use_corpus:
            argv += ["--corpus-dir", cfg.corpus_dir]
        if no_llm:
            argv.append("--no-llm")
        argv += ["--ollama-host", cfg.ollama_host,
                 "--ollama-model", cfg.ollama_model,
                 "--embed-model", cfg.embed_model]
        expected = str(Path(cfg.project_dir) / "runs" /
                       f"{selected['client']}-{selected['engagement_id']}.json")

    job = jobs.launch(argv, cwd=cfg.project_dir, expected_run_json=expected)

    # Return the live-status partial — HTMX swaps it into the results pane.
    return request.app.state.templates.TemplateResponse(
        request,
        "_components/scan_status.html",
        {"job": job, "argv_str": " ".join(shlex.quote(a) for a in argv), "tail_lines": LIVE_LOG_TAIL_LINES},
    )


@router.get("/scan/status/{job_id}")
def scan_status(request: Request, job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "no such job")
    return request.app.state.templates.TemplateResponse(
        request,
        "_components/scan_status.html",
        {"job": job, "argv_str": " ".join(shlex.quote(a) for a in job.argv), "tail_lines": LIVE_LOG_TAIL_LINES},
    )


@router.post("/scan/stop/{job_id}")
def scan_stop(request: Request, job_id: str):
    msg = jobs.stop(job_id)
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, msg)
    return request.app.state.templates.TemplateResponse(
        request,
        "_components/scan_status.html",
        {
            "job": job,
            "argv_str": " ".join(shlex.quote(a) for a in job.argv),
            "stop_msg": msg,
            "tail_lines": LIVE_LOG_TAIL_LINES,
        },
    )
