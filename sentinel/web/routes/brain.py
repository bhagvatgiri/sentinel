"""Brain — corpus inspector. Per-source chunk counts + semantic search."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request

from sentinel.ui.state import UIConfig, vault_knowledge_stats, corpus_chroma_stats
from sentinel.web.deps import get_config

router = APIRouter()


@router.get("/brain")
def brain(request: Request, cfg: UIConfig = Depends(get_config)):
    vault = vault_knowledge_stats(cfg.vault_path)
    corpus = corpus_chroma_stats(cfg.corpus_dir, cfg.ollama_host, cfg.embed_model)
    return request.app.state.templates.TemplateResponse(
        request, "brain.html",
        {"active_nav": "Brain", "cfg": cfg, "vault": vault, "corpus": corpus},
    )


@router.post("/brain/search")
def brain_search(
    request: Request,
    cfg: UIConfig = Depends(get_config),
    query: str = Form(...),
    top_k: int = Form(8),
):
    if not query.strip():
        return request.app.state.templates.TemplateResponse(
            request, "_components/brain_results.html",
            {"results": [], "error": "Query is required.", "query": ""},
        )
    try:
        from sentinel.corpus.embedder import OllamaEmbedder
        from sentinel.corpus.store import CorpusStore
        from sentinel.rag.retriever import Retriever
        embedder = OllamaEmbedder(host=cfg.ollama_host, model=cfg.embed_model)
        store = CorpusStore(cfg.corpus_dir, embedder)
        results = Retriever(store).retrieve(query, top_k=top_k)
    except Exception as e:
        return request.app.state.templates.TemplateResponse(
            request, "_components/brain_results.html",
            {"results": [], "error": f"Search failed: {e}", "query": query},
        )
    return request.app.state.templates.TemplateResponse(
        request, "_components/brain_results.html",
        {"results": results, "error": None, "query": query},
    )
