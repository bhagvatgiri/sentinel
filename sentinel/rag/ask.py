"""Standalone Q&A — `sentinel ask 'how do I prevent CSRF?'`.

Retrieves top-k from Chroma, builds a citation-aware prompt, calls Ollama.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sentinel.llm.ollama_client import OllamaClient
from sentinel.rag.retriever import RetrievedChunk, Retriever, format_context


SYSTEM_PROMPT = """You are a senior application/infrastructure security engineer.
Answer the user's question using ONLY the context provided. Cite sources by their
[number] from the context block. If the context does not contain enough information
to answer confidently, say so and explain what additional information would be needed.
Do not fabricate citations or invent details that are not present in the context.
Use plain professional English."""


@dataclass
class Answer:
    question: str
    answer: str
    chunks: list[RetrievedChunk]


def ask(question: str, retriever: Retriever, ollama: OllamaClient, top_k: int = 5) -> Answer:
    chunks = retriever.retrieve(question, top_k=top_k)
    context = format_context(chunks)
    prompt = (
        f"Question: {question}\n\n"
        f"{context if context else '(no context retrieved — answer cautiously and say so)'}\n\n"
        f"Answer:"
    )
    response = ollama.generate(prompt, system=SYSTEM_PROMPT) or "(model unavailable)"
    return Answer(question=question, answer=response.strip(), chunks=chunks)


def render_answer_text(ans: Answer) -> str:
    out = [ans.answer, "", "Sources:"]
    if not ans.chunks:
        out.append("  (none retrieved)")
    for i, c in enumerate(ans.chunks, 1):
        out.append(f"  [{i}] {c.short_citation()}")
    return "\n".join(out)
