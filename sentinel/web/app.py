"""FastAPI application factory.

Mounts static files, registers Jinja2 with autoescape, wires the route
modules. All Sentinel backend modules (orchestrator, scope, scanners,
corpus, llm, reporting) are imported into the route handlers as-is.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


_HERE = Path(__file__).parent
TEMPLATES_DIR = _HERE / "templates"
STATIC_DIR = _HERE / "static"


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sentinel",
        description="Full-spectrum pentest platform — web UI",
        version="0.1.0",
        docs_url="/api/docs",     # OpenAPI under /api/docs (avoids clash with /report etc)
        redoc_url=None,
    )

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Templates instance lives on app.state so route modules can reach it.
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    # Expose helpers + constants to every template by injecting them on the
    # underlying Jinja2 Environment. (Use update() not item-assign — newer
    # starlette wraps env.globals in a TemplateContext that errors on direct
    # __setitem__ for some keys.)
    from sentinel.web import helpers as _helpers
    from sentinel.web import event_styles as _event_styles
    templates.env.globals.update({
        "safe_html": _helpers.safe_html,
        "safe_markdown": _helpers.safe_markdown,
        "SEVERITY_ORDER": _helpers.SEVERITY_ORDER,
        # Shared event-kind styling — used by agent_run_body.html and any
        # other template that renders structured events.
        "event_style": _event_styles.style_for,
        "EVENT_STYLES": _event_styles.EVENT_STYLES,
    })
    app.state.templates = templates

    # Register route modules.
    from sentinel.web.routes import (
        agent_chat, agent_login, agent_runs, agent_signup, ask,
        attack_heatmap, audit, benchmark, brain, chat, chrome, dashboard,
        engagements, findings, h1, library, parity_eval, payloads, report,
        scan, state, tools, traces, workspaces,
    )
    app.include_router(dashboard.router)
    app.include_router(scan.router)
    app.include_router(findings.router)
    app.include_router(engagements.router)
    app.include_router(audit.router)
    app.include_router(report.router)
    app.include_router(ask.router)
    app.include_router(chat.router)
    app.include_router(brain.router)
    app.include_router(tools.router)
    app.include_router(agent_runs.router)
    app.include_router(agent_chat.router)
    app.include_router(workspaces.router)
    app.include_router(payloads.router)
    app.include_router(library.router)
    app.include_router(state.router)
    # Plan 02-01 ENG-04 — H1 submission ledger dashboard (UI parity for
    # `sentinel h1 record-submission` CLI).
    app.include_router(h1.router)
    # Wave 2 / A4 — flame-graph trace view of historical pipeline runs.
    app.include_router(traces.router)
    # Wave 4 / A6 — per-engagement ATT&CK kill-chain coverage matrix.
    app.include_router(attack_heatmap.router)
    # Wave 8 / D5-D9 — benchmark dashboard.
    app.include_router(benchmark.router)
    # Phase 02 Plan 02-04 (BENCH-10) — parity-eval dashboard surface
    # (`/bench/parity-eval`). Lives alongside the Wave 8 registry view at
    # `/benchmarks` (plural) — paths don't collide because the parity-eval
    # routes are under /bench/ (singular).
    app.include_router(parity_eval.router)
    # Real-Chrome-via-CDP DataDome bypass profile management (2026-XX-XX).
    app.include_router(chrome.router)
    # Human-in-the-loop login widget on /agent-runs/<job_id> (2026-XX-XX).
    app.include_router(agent_login.router)
    # Human-in-the-loop signup widget + cross-job operator console + per-job
    # captcha-solves counter fragment (Quick 260517-f7a, 2026-XX-XX).
    app.include_router(agent_signup.router)

    return app


app = create_app()
