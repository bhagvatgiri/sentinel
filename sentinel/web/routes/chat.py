"""Chat — multi-turn conversational interface over the brain corpus.

Replaces (eventually, post-Phase-A.5) the single-shot /ask page. Adds:
- Session persistence at ~/.sentinel/chat_sessions/<sid>.jsonl
- Conversation-aware retrieval (last N user turns inform the embedding query)
- Smart engagement-scope default (auto-pick past-engagements chip on
  "our"/"my"/"this engagement" — closes Task #60)
- Source-filter chips driven from live Chroma introspection (NOT
  hardcoded — avoids the past-engagements-missing bug that motivated
  this whole rewrite)

Phase A ships non-streamed (full response after model finishes). Phase
A.1 will add SSE streaming. Backend is Ollama for now (mirrors /ask);
Claude routing follows once the dashboard's auth picks that up.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse

from sentinel.corpus.embedder import OllamaEmbedder
from sentinel.corpus.store import CorpusStore
from sentinel.llm.ollama_client import OllamaClient
from sentinel.rag.ask import SYSTEM_PROMPT
from sentinel.rag.conversation import (
    ConversationSession,
    Turn,
    detect_engagement_scope,
)
from sentinel.rag.conversation_retriever import ConversationRetriever
from sentinel.rag.retriever import Retriever, format_context
from sentinel.ui.state import UIConfig, corpus_chroma_stats
from sentinel.web.deps import get_config


router = APIRouter()
log = logging.getLogger(__name__)


def _engagement_extra_sources(engagements_dir: Path) -> list[str]:
    """Return past-engagement-* source labels derived from the engagements dir.

    Matches the convention used by the past-engagement ingester:
    `past-engagement-<client>-<engagement_id>`. The ingester reads the
    scope yaml as authoritative, so we don't need to parse — we just
    need to ENUMERATE possible labels for chip introspection.
    """
    if not engagements_dir.exists():
        return []
    labels: set[str] = set()
    # Best-effort: the dashboard's existing label-derivation logic lives
    # in dashboard.py / engagements.py. For chip introspection we just
    # need a single "past-engagements" umbrella plus per-engagement
    # entries. We let corpus_chroma_stats's extra_sources query each
    # one and only return the chips that have at least one chunk.
    labels.add("past-engagements")  # generic catch-all
    for path in engagements_dir.glob("*.yaml"):
        # Convention: past-engagement-<stem>. Stem already includes the
        # client + id (e.g., 2026-XX-XX-AcmeProgram-bbp). The ingester strips
        # spaces and lowercases.
        labels.add(f"past-engagement-{path.stem}")
    return sorted(labels)


def _resolve_chip_set(cfg: UIConfig) -> tuple[list[dict], int]:
    """Return ([{name, count}], total_chunks) — chip set for the chat UI.

    Driven from live Chroma introspection. Past-engagement chips only
    appear if they have chunks. Avoids the hardcoded-allowlist bug that
    motivated rewriting /ask.
    """
    engagements = _engagement_extra_sources(Path("./engagements"))
    stats = corpus_chroma_stats(
        cfg.corpus_dir, cfg.ollama_host, cfg.embed_model,
        extra_sources=engagements,
    )
    if not stats.get("available"):
        return [], 0
    per_source = stats.get("per_source") or {}
    # Always show the "hackerone" chip — corpus_chroma_stats's known list
    # was missing it as of 2026-XX-XX; if a `hackerone` source exists
    # but its count came back 0, force a direct query as a fallback.
    if "hackerone" not in per_source:
        try:
            embedder = OllamaEmbedder(host=cfg.ollama_host, model=cfg.embed_model)
            store = CorpusStore(cfg.corpus_dir, embedder)
            ids = store._collection.get(where={"source": "hackerone"}, include=[])
            n = len(ids.get("ids") or [])
            if n > 0:
                per_source["hackerone"] = n
        except Exception:
            pass
    chips = [{"name": k, "count": v} for k, v in per_source.items() if v > 0]
    chips.sort(key=lambda c: -c["count"])
    return chips, stats.get("total_chunks", 0)


def _form_error(message: str) -> HTMLResponse:
    safe = (message or "").replace("<", "&lt;")
    return HTMLResponse(
        f'<div class="bg-bg-card border border-sev-critical/40 rounded-lg p-4 text-sm text-sev-critical">{safe}</div>',
        status_code=400,
    )


# ----- routes -------------------------------------------------------------


@router.get("/chat")
def chat_index(request: Request, cfg: UIConfig = Depends(get_config)):
    """List existing sessions + new-session form."""
    chips, total_chunks = _resolve_chip_set(cfg)
    sessions = ConversationSession.list_all()
    return request.app.state.templates.TemplateResponse(
        request, "chat.html",
        {
            "active_nav": "Chat",
            "cfg": cfg,
            "chips": chips,
            "total_chunks": total_chunks,
            "sessions": sessions,
            "active_session": None,
        },
    )


@router.post("/chat/new")
def chat_new(
    request: Request,
    cfg: UIConfig = Depends(get_config),
    model: str = Form(""),
    source_filter: list[str] = Form(default_factory=list),
):
    """Create a new session and redirect to it. Form-driven, no JS required."""
    chosen_model = (model or cfg.ollama_model or "llama3.1:8b").strip()
    session = ConversationSession.new(
        model=chosen_model,
        source_filters=list(source_filter or []),
    )
    # Persist the empty session (header line) so /chat/<id> can find it.
    CHAT_DIR = ConversationSession.new("noop").path.parent
    CHAT_DIR.mkdir(parents=True, exist_ok=True)
    with session.path.open("a", encoding="utf-8") as f:
        f.write(session._header_line() + "\n")
    return RedirectResponse(f"/chat/{session.id}", status_code=303)


@router.get("/chat/{sid}")
def chat_show(
    request: Request,
    sid: str,
    cfg: UIConfig = Depends(get_config),
):
    """Render a single session's conversation."""
    session = ConversationSession.load(sid)
    if session is None:
        return _form_error(f"Session not found: {sid}")
    chips, total_chunks = _resolve_chip_set(cfg)
    sessions = ConversationSession.list_all()
    return request.app.state.templates.TemplateResponse(
        request, "chat.html",
        {
            "active_nav": "Chat",
            "cfg": cfg,
            "chips": chips,
            "total_chunks": total_chunks,
            "sessions": sessions,
            "active_session": session,
        },
    )


@router.post("/chat/{sid}/message")
def chat_message(
    request: Request,
    sid: str,
    cfg: UIConfig = Depends(get_config),
    message: str = Form(...),
    top_k: int = Form(5),
):
    """Add a user turn → run RAG → generate assistant reply → persist both.

    Returns the rendered conversation pane so HTMX can replace the whole
    thread (avoids out-of-order issues with append-only fragments).
    """
    if not message.strip():
        return _form_error("Message is empty.")
    session = ConversationSession.load(sid)
    if session is None:
        return _form_error(f"Session not found: {sid}")

    # Smart engagement-scope default: if the user typed an engagement-scoped
    # phrase AND no source filters are pinned to the session yet, add the
    # umbrella `past-engagements` chip for THIS turn. We don't mutate the
    # session's persistent filter set — the user may want to revert next
    # turn. Closes Task #60.
    auto_filter: Optional[list[str]] = None
    auto_filter_reason = ""
    if not session.source_filters and detect_engagement_scope(message):
        auto_filter = ["past-engagements"]
        auto_filter_reason = "Detected engagement-scoped phrasing — searching past engagements only."

    try:
        embedder = OllamaEmbedder(host=cfg.ollama_host, model=cfg.embed_model)
        store = CorpusStore(cfg.corpus_dir, embedder)
        retriever = Retriever(store)
        conv_retriever = ConversationRetriever(retriever)
        ollama = OllamaClient(host=cfg.ollama_host, model=session.model or cfg.ollama_model)

        # Build conversation-aware retrieval
        query_used, chunks = conv_retriever.retrieve_for_turn(
            session, message, top_k=top_k, source_filter=auto_filter,
        )
        context = format_context(chunks)

        # Build conversation-aware prompt: include prior turns so the model
        # has context for follow-ups, AND the freshly retrieved corpus chunks.
        history_lines: list[str] = []
        # Cap to last 6 turns (3 user + 3 assistant) to fit in 8K-32K models
        for turn in session.history[-6:]:
            label = "User" if turn.role == "user" else "Assistant"
            history_lines.append(f"{label}: {turn.content}")
        history_block = "\n\n".join(history_lines)

        prompt_parts = []
        if history_block:
            prompt_parts.append(f"Previous conversation:\n{history_block}\n")
        prompt_parts.append(f"New question: {message}\n")
        prompt_parts.append(
            context if context
            else "(no context retrieved — answer cautiously and say so)"
        )
        prompt_parts.append("Answer:")
        prompt = "\n\n".join(prompt_parts)

        ans_text = ollama.generate(prompt, system=SYSTEM_PROMPT) or "(model unavailable)"
    except Exception as e:
        log.exception("chat message failed")
        return _form_error(f"Chat failed: {e}")

    # Persist both turns (user first, then assistant) — append-only to disk.
    user_turn = Turn(role="user", content=message)
    session.append_turn(user_turn)
    assistant_turn = Turn(
        role="assistant",
        content=ans_text.strip(),
        citations=[
            {
                "title": c.title, "source": c.source,
                "url": c.url, "distance": c.distance,
            } for c in chunks
        ],
        retrieval_query=query_used,
        model=session.model,
    )
    session.append_turn(assistant_turn)

    # Auto-set a session title from the first user turn if not yet set.
    if not session.title:
        title = message.strip().split("\n")[0][:80]
        session.update_title(title)

    chips, total_chunks = _resolve_chip_set(cfg)
    return request.app.state.templates.TemplateResponse(
        request, "_components/chat_thread.html",
        {
            "session": session,
            "auto_filter_reason": auto_filter_reason,
            "chips": chips,
            "total_chunks": total_chunks,
        },
    )


# ----- streaming -----------------------------------------------------------
#
# Phase A.1: token-by-token streaming via SSE. The non-streaming POST
# /chat/<sid>/message above stays as a fallback for any client that
# can't consume text/event-stream (or as the test path).
#
# Flow:
#   1. POST /chat/<sid>/stream    — kicks off the stream; persists the user
#      turn IMMEDIATELY (so a dropped stream still records intent), then
#      yields SSE `event: token` lines as the model emits chunks, then
#      one final `event: done` with the renderable thread URL.
#   2. GET /chat/<sid>/refresh    — thin re-render of the chat_thread
#      component so the frontend can swap in the final HTML (with
#      citations) once streaming completes.


def _sse(event: str, data: str) -> bytes:
    """Format a single SSE message. Escapes newlines per spec."""
    safe = data.replace("\r\n", "\n").replace("\r", "\n")
    lines = safe.split("\n")
    out = [f"event: {event}"]
    for line in lines:
        out.append(f"data: {line}")
    out.append("")  # blank line terminates the event
    out.append("")
    return ("\n".join(out)).encode("utf-8")


@router.post("/chat/{sid}/stream")
def chat_stream(
    request: Request,
    sid: str,
    cfg: UIConfig = Depends(get_config),
    message: str = Form(...),
    top_k: int = Form(5),
):
    """SSE token stream for a single chat turn."""
    if not message.strip():
        return _form_error("Message is empty.")
    session = ConversationSession.load(sid)
    if session is None:
        return _form_error(f"Session not found: {sid}")

    auto_filter: Optional[list[str]] = None
    if not session.source_filters and detect_engagement_scope(message):
        auto_filter = ["past-engagements"]

    # Persist the user turn IMMEDIATELY — even if the stream drops, the
    # operator's question is captured in the session JSONL.
    user_turn = Turn(role="user", content=message)
    session.append_turn(user_turn)

    # Auto-set title from first user turn.
    if not session.title:
        session.update_title(message.strip().split("\n")[0][:80])

    # Build the prompt (same shape as POST /message — see that handler
    # for the rationale).
    try:
        embedder = OllamaEmbedder(host=cfg.ollama_host, model=cfg.embed_model)
        store = CorpusStore(cfg.corpus_dir, embedder)
        retriever = Retriever(store)
        conv_retriever = ConversationRetriever(retriever)
        ollama = OllamaClient(host=cfg.ollama_host, model=session.model or cfg.ollama_model)

        query_used, chunks = conv_retriever.retrieve_for_turn(
            session, message, top_k=top_k, source_filter=auto_filter,
        )
        context = format_context(chunks)
    except Exception as e:
        log.exception("chat stream setup failed")
        return _form_error(f"Stream setup failed: {e}")

    # Build conversation prompt — include prior turns AND the just-appended
    # user turn (its content is `message`).
    history_lines: list[str] = []
    for turn in session.history[-6:-1]:  # exclude the just-appended user turn
        label = "User" if turn.role == "user" else "Assistant"
        history_lines.append(f"{label}: {turn.content}")
    history_block = "\n\n".join(history_lines)

    prompt_parts: list[str] = []
    if history_block:
        prompt_parts.append(f"Previous conversation:\n{history_block}\n")
    prompt_parts.append(f"New question: {message}\n")
    prompt_parts.append(
        context if context
        else "(no context retrieved — answer cautiously and say so)"
    )
    prompt_parts.append("Answer:")
    prompt = "\n\n".join(prompt_parts)

    chunks_for_persist = list(chunks)

    def event_gen():
        accumulated: list[str] = []
        try:
            for chunk_text in ollama.generate_stream(prompt, system=SYSTEM_PROMPT):
                accumulated.append(chunk_text)
                yield _sse("token", chunk_text)
        except Exception as e:
            log.exception("chat stream generation failed")
            yield _sse("error", f"stream failed: {e}")
        finally:
            # ALWAYS persist the assistant turn — even if generation crashed
            # mid-stream the operator should see what was emitted.
            content = "".join(accumulated) or "(model unavailable)"
            assistant_turn = Turn(
                role="assistant",
                content=content.strip(),
                citations=[
                    {
                        "title": c.title, "source": c.source,
                        "url": c.url, "distance": c.distance,
                    } for c in chunks_for_persist
                ],
                retrieval_query=query_used,
                model=session.model,
            )
            session.append_turn(assistant_turn)
            yield _sse("done", f"/chat/{sid}/refresh")

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering if proxied
        },
    )


@router.get("/chat/{sid}/refresh")
def chat_refresh(
    request: Request,
    sid: str,
    cfg: UIConfig = Depends(get_config),
):
    """Re-render the chat_thread component for post-stream swap."""
    session = ConversationSession.load(sid)
    if session is None:
        return _form_error(f"Session not found: {sid}")
    chips, total_chunks = _resolve_chip_set(cfg)
    return request.app.state.templates.TemplateResponse(
        request, "_components/chat_thread.html",
        {
            "session": session,
            "auto_filter_reason": "",
            "chips": chips,
            "total_chunks": total_chunks,
        },
    )
