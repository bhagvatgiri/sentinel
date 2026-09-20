"""Ask — RAG Q&A grounded in the local corpus."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Form, Request

from sentinel.corpus.embedder import OllamaEmbedder
from sentinel.corpus.store import CorpusStore
from sentinel.llm.ollama_client import OllamaClient
from sentinel.rag.ask import ask as rag_ask
from sentinel.rag.retriever import Retriever
from sentinel.ui.state import UIConfig
from sentinel.web.deps import get_config

router = APIRouter()


SOURCES = ["owasp", "mitre-cwe", "mitre-attack", "nist", "nvd", "writeups", "hackerone", "books"]


@router.get("/ask")
def ask_form(request: Request, cfg: UIConfig = Depends(get_config)):
    return request.app.state.templates.TemplateResponse(
        request, "ask.html",
        {"active_nav": "Ask", "cfg": cfg, "sources": SOURCES},
    )


@router.post("/ask/query")
def ask_query(
    request: Request,
    cfg: UIConfig = Depends(get_config),
    question: str = Form(...),
    top_k: int = Form(5),
    source_filter: list[str] = Form(default_factory=list),
):
    if not question.strip():
        return request.app.state.templates.TemplateResponse(
            request, "_components/ask_answer.html",
            {"error": "Question is required.", "answer": None},
        )
    try:
        embedder = OllamaEmbedder(host=cfg.ollama_host, model=cfg.embed_model)
        store = CorpusStore(cfg.corpus_dir, embedder)
        retriever = Retriever(store)
        ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
        # Apply per-source filter if any chips were checked.
        sf = source_filter or None
        chunks = retriever.retrieve(question, top_k=top_k, source_filter=sf)
        # Build a stripped answer manually (rag_ask ignores source_filter)
        from sentinel.rag.retriever import format_context
        from sentinel.rag.ask import SYSTEM_PROMPT
        context = format_context(chunks)
        prompt = (
            f"Question: {question}\n\n"
            f"{context if context else '(no context retrieved — answer cautiously and say so)'}\n\n"
            f"Answer:"
        )
        ans_text = ollama.generate(prompt, system=SYSTEM_PROMPT) or "(model unavailable)"
        from sentinel.rag.ask import Answer
        ans = Answer(question=question, answer=ans_text.strip(), chunks=chunks)
    except Exception as e:
        return request.app.state.templates.TemplateResponse(
            request, "_components/ask_answer.html",
            {"error": f"Ask failed: {e}", "answer": None},
        )
    return request.app.state.templates.TemplateResponse(
        request, "_components/ask_answer.html",
        {"answer": ans, "error": None},
    )
