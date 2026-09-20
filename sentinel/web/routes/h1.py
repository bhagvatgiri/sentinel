"""H1 submission-ledger dashboard route.

Mirrors the `sentinel h1 record-submission` CLI surface so an operator
can read every recorded H1 submission from the dashboard without
dropping to a terminal. Same business-logic import (`load_ledger`) the
CLI uses — no shape drift between surfaces (UI parity rule).

Two surfaces, parallel to /state and /state.json:

  GET /h1/submissions          HTML by default; JSON when
                                Accept: application/json
  GET /h1/submissions.json     always JSON, Accept-agnostic
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from sentinel.h1.tracker import load_ledger
from sentinel.ui.state import UIConfig
from sentinel.web.deps import get_config


log = logging.getLogger(__name__)
router = APIRouter()


def _ledger_path() -> Path:
    """Canonical ledger location. Lives under operator-only ~/.sentinel/."""
    return Path.home() / ".sentinel" / "h1-submissions.jsonl"


def _wants_json(request: Request) -> bool:
    """Substring-match `application/json` in the Accept header.

    Same pattern as sentinel/web/routes/state.py — strict equality would
    miss `application/json, text/plain;q=0.5` style headers.
    """
    accept = request.headers.get("accept", "") or ""
    return "application/json" in accept.lower()


@router.get("/h1/submissions", name="h1_submissions")
def h1_submissions(request: Request, cfg: UIConfig = Depends(get_config)):
    """Render the H1 submission ledger.

    Content-negotiated:
      * `Accept: application/json` → `{"rows": [...]}` JSON body.
      * Otherwise → HTML table with the data-testid anchor.
    """
    rows = load_ledger(_ledger_path())
    if _wants_json(request):
        return JSONResponse({"rows": rows})
    return request.app.state.templates.TemplateResponse(
        request,
        "h1_submissions.html",
        {
            "active_nav": "H1",
            "cfg": cfg,
            "rows": rows,
        },
    )


@router.get("/h1/submissions.json", name="h1_submissions_json")
def h1_submissions_json(cfg: UIConfig = Depends(get_config)):
    """Always-JSON sibling. Accept-header-agnostic so scripts that don't
    set Accept still get JSON."""
    return JSONResponse({"rows": load_ledger(_ledger_path())})
