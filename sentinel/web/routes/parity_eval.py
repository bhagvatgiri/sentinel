"""BENCH-10: `/bench/parity-eval` FastAPI dashboard surface (Plan 02-04).

Routes:

  GET  /bench/parity-eval                    — render latest eval JSON +
                                                Markdown report + current
                                                default profile state.
                                                Accept: application/json
                                                returns the eval JSON.
  POST /bench/parity-eval/reset-default      — calls reset_default; 303.
  POST /bench/parity-eval/run                — kicks off run_parity_eval
                                                via BackgroundTasks;
                                                returns 202 + job_id.

This is the UI-parity surface for the CLI `sentinel bench parity-eval`,
`sentinel bench show-default`, `sentinel bench reset-default`. Every CLI
operator surface in Plan 02-04 has a matching dashboard surface — per
CLAUDE.md's UI-parity rule.

Markdown rendering: the `markdown` library is OPTIONAL — if absent, the
fallback renders the report inside an HTML-escaped `<pre>` block so the
content is still readable. (Plan 02-03's report_renderer produces clean
Markdown; even raw `<pre>` is operator-friendly.)
"""

from __future__ import annotations

import html
import json
import logging
import uuid
from pathlib import Path
from typing import Optional

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Form,
    HTTPException,
    Request,
)
from fastapi.responses import JSONResponse, RedirectResponse


log = logging.getLogger(__name__)


router = APIRouter()


# Module-level so tests can monkeypatch BEFORE the app is created.
_PROJECT_ROOT: Path = Path(__file__).resolve().parents[3]
_RUNS_DIR: Path = _PROJECT_ROOT / "runs"


# ---- Helpers -------------------------------------------------------------


def _latest_eval_files() -> tuple[Optional[Path], Optional[Path]]:
    """Return (latest eval JSON, latest Markdown report) by mtime.

    Both may be None when runs/ is empty (or doesn't exist yet). The
    JSON and Markdown are mtime-paired by glob convention — if you ran
    `sentinel bench parity-eval`, both files land within ~1s of each
    other under the same timestamp suffix.
    """
    if not _RUNS_DIR.exists():
        return (None, None)
    json_files = sorted(
        _RUNS_DIR.glob("bench-parity-*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    md_files = sorted(
        _RUNS_DIR.glob("qwen-parity-eval-*.md"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return (
        json_files[0] if json_files else None,
        md_files[0] if md_files else None,
    )


def _load_eval_history(limit: int = 10) -> list[dict]:
    """Lite metadata for the eval-history table."""
    if not _RUNS_DIR.exists():
        return []
    out: list[dict] = []
    for p in sorted(
        _RUNS_DIR.glob("bench-parity-*.json"),
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    )[:limit]:
        try:
            data = json.loads(p.read_text())
        except Exception:  # noqa: BLE001
            continue
        out.append({
            "filename": p.name,
            "completed_at": data.get("completed_at") or "",
            "verdict_overall": data.get("verdict_overall", "unknown"),
            "suites_count": len(data.get("suites", {}) or {}),
            "suite": data.get("suite", ""),
            "schema_version": data.get("schema_version", ""),
        })
    return out


def _markdown_to_html(md_text: str) -> str:
    """Render Markdown → HTML. Falls back to escaped <pre> if the
    `markdown` package isn't installed (no new runtime dep required)."""
    try:
        import markdown  # type: ignore
        return markdown.markdown(
            md_text, extensions=["tables", "fenced_code"]
        )
    except ImportError:
        # Defensive fallback — escape + <pre>. Operators still read fine.
        return (
            '<pre style="white-space: pre-wrap; word-wrap: break-word;">'
            + html.escape(md_text)
            + "</pre>"
        )


def _load_latest_eval_and_report() -> tuple[Optional[dict], Optional[str]]:
    """Return (latest eval JSON dict, latest Markdown rendered to HTML)."""
    eval_path, md_path = _latest_eval_files()
    eval_json: Optional[dict] = None
    report_html: Optional[str] = None
    if eval_path is not None:
        try:
            eval_json = json.loads(eval_path.read_text())
        except Exception as e:  # noqa: BLE001
            log.warning(
                "parity_eval route: failed to load %s: %s", eval_path, e
            )
    if md_path is not None:
        try:
            report_html = _markdown_to_html(md_path.read_text())
        except Exception as e:  # noqa: BLE001
            log.warning(
                "parity_eval route: failed to render %s: %s", md_path, e
            )
    return eval_json, report_html


def _bench_suite_scope_path(suite_name: str) -> Path:
    """Resolve a suite name to its bench/<suite>/scope.yaml path.

    Used by POST /run to validate suite names BEFORE kicking off the
    BackgroundTasks run. Returns the path; caller checks `.exists()`.
    """
    # Relative path so the POST /run validation respects monkeypatched cwd
    # in hermetic tests (the test fixture chdir's into tmp_path).
    return Path("bench") / suite_name / "scope.yaml"


def _wants_json(request: Request) -> bool:
    """Return True if the client prefers JSON over HTML.

    Looks at the Accept header; if `application/json` precedes `text/html`
    (or text/html is absent), returns True.
    """
    accept = request.headers.get("accept", "").lower()
    if "application/json" not in accept:
        return False
    # If both are present, JSON wins only if it's listed (we don't bother
    # with q-value parsing — keep it simple, accept JSON whenever the
    # caller asks for it explicitly).
    if "text/html" in accept:
        # Both present — let JSON win when the caller listed it (typical
        # for `curl -H 'Accept: application/json'` or fetch() with explicit
        # JSON ask).
        return accept.find("application/json") <= accept.find("text/html")
    return True


# ---- Routes --------------------------------------------------------------


@router.get("/bench/parity-eval", name="parity_eval_index")
def parity_eval_index(request: Request):
    """Render the latest parity-eval state.

    Content negotiation:
      - Accept: application/json → returns the latest eval JSON dict
        (or 404 if no eval has been written yet).
      - Anything else → HTML page (parity_eval.html).
    """
    eval_json, report_html = _load_latest_eval_and_report()

    if _wants_json(request):
        if eval_json is None:
            raise HTTPException(
                status_code=404,
                detail="No parity-eval runs yet. Run `sentinel bench "
                "parity-eval --suite juice-shop,dvwa,ctf-box` first.",
            )
        return JSONResponse(content=eval_json)

    # Current default profile — read lazily so monkeypatched state path
    # in tests is honored.
    from sentinel.benchmark.default_switch import read_current_default
    current_default = read_current_default()

    history = _load_eval_history(limit=10)

    return request.app.state.templates.TemplateResponse(
        request, "parity_eval.html",
        {
            "active_nav": "Benchmarks",
            "latest_eval": eval_json,
            "latest_report_html": report_html,
            "current_default_profile": current_default,
            "eval_history": history,
        },
    )


@router.post(
    "/bench/parity-eval/reset-default",
    name="parity_eval_reset_default",
)
def parity_eval_reset_default():
    """Reset the persisted ModelRouter default to anthropic-baseline."""
    from sentinel.benchmark.default_switch import reset_default
    reset_default()
    return RedirectResponse(
        url="/bench/parity-eval",
        status_code=303,
    )


def _kickoff_parity_eval(
    *,
    suite: str,
    baseline: str,
    candidate: str,
    output_dir: Path,
    job_id: str,
) -> None:
    """BackgroundTasks worker — runs the parity-eval harness off the
    request thread. Tests monkeypatch `run_parity_eval` so this never
    fires a real benchmark.

    Errors land in the application log; the dashboard polls
    /bench/parity-eval to see new evals appear in runs/.
    """
    try:
        from sentinel.benchmark.parity_eval import run_parity_eval
        log.info(
            "parity_eval route: starting background job %s "
            "(suite=%s, baseline=%s, candidate=%s)",
            job_id, suite, baseline, candidate,
        )
        run_parity_eval(
            suite=suite,
            baseline_profile=baseline,
            candidate_profile=candidate,
            output_dir=output_dir,
        )
        log.info(
            "parity_eval route: background job %s complete", job_id
        )
    except Exception as e:  # noqa: BLE001
        log.exception(
            "parity_eval route: background job %s failed: %s", job_id, e
        )


@router.post("/bench/parity-eval/run", name="parity_eval_run")
def parity_eval_run(
    background_tasks: BackgroundTasks,
    suite: str = Form(...),
    baseline: str = Form("anthropic-baseline"),
    candidate: str = Form("siliconflow-qwen-235b"),
):
    """Kick off a parity-eval as a BackgroundTasks job.

    Validates every suite name has a `bench/<name>/scope.yaml` BEFORE
    enqueueing. Returns 202 + a job_id (uuid). The dashboard polls
    /bench/parity-eval to see when the new eval lands.

    NOTE: this is a fire-and-forget surface. Long-running parity evals
    can take 30+ minutes on the real harness; the dashboard reflects
    the new run only after run_parity_eval writes its JSON. For a
    blocking + observable run, use the CLI subcommand instead.
    """
    # Suite list comes in as a comma-separated string.
    suite_names = [s.strip() for s in suite.split(",") if s.strip()]
    if not suite_names:
        raise HTTPException(
            status_code=400,
            detail="suite is required (comma-separated, e.g. "
            "'juice-shop,dvwa,ctf-box')",
        )

    missing: list[str] = []
    for name in suite_names:
        scope_p = _bench_suite_scope_path(name)
        if not scope_p.exists():
            missing.append(name)
    if missing:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown suite(s): {missing}. Each suite must have a "
                f"bench/<name>/scope.yaml file in the project root."
            ),
        )

    if baseline not in {"anthropic-baseline", "siliconflow-qwen-235b"}:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown baseline profile: {baseline!r}",
        )
    if candidate not in {"anthropic-baseline", "siliconflow-qwen-235b"}:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown candidate profile: {candidate!r}",
        )

    job_id = str(uuid.uuid4())
    background_tasks.add_task(
        _kickoff_parity_eval,
        suite=suite,
        baseline=baseline,
        candidate=candidate,
        output_dir=_RUNS_DIR,
        job_id=job_id,
    )
    return JSONResponse(
        content={"job_id": job_id, "status": "queued"},
        status_code=202,
    )
