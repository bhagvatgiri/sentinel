"""Operator chat panel for running pentest agents (Phase B / Task #64).

The dashboard's per-job detail page renders a sidebar chat. The operator
types directives there; this route enqueues them on the per-job control
channel. The pipeline (when launched with --enable-operator-chat)
drains the channel between phases and prepends the messages to the
next phase's prompt as priority directives.

History is the audit-trail view — every message ever sent, plus its
consumed_at timestamp. Used both by the chat panel UI and (eventually)
by the audit verification flow.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Form, Request

from sentinel.agent.pentest.control_channel import ControlChannel


router = APIRouter()


@router.post("/agent-runs/{job_id}/chat/message")
def post_message(
    request: Request,
    job_id: str,
    content: str = Form(...),
):
    if not content.strip():
        return request.app.state.templates.TemplateResponse(
            request, "_components/agent_chat_panel.html",
            {"job_id": job_id, "messages": [], "error": "Message is empty."},
            status_code=400,
        )
    chan = ControlChannel(job_id)
    chan.enqueue(content.strip())
    messages = chan.history()
    return request.app.state.templates.TemplateResponse(
        request, "_components/agent_chat_panel.html",
        {
            "job_id": job_id,
            "messages": messages,
            "error": None,
            "fmt_ts": _fmt_ts,
        },
    )


@router.get("/agent-runs/{job_id}/chat/history")
def get_history(request: Request, job_id: str):
    chan = ControlChannel(job_id)
    messages = chan.history()
    return request.app.state.templates.TemplateResponse(
        request, "_components/agent_chat_panel.html",
        {
            "job_id": job_id,
            "messages": messages,
            "error": None,
            "fmt_ts": _fmt_ts,
        },
    )


def _fmt_ts(ts: float) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
