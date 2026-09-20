"""RAG retriever — pulls top-k chunks from Chroma, formats them as context.

Two retrieval modes:
  - retrieve(query)            : open-ended Q&A
  - retrieve_for_finding(f)    : injects scanner/CWE/CVE into the query for triage
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from sentinel.core.findings import Finding
from sentinel.corpus.store import CorpusStore


log = logging.getLogger(__name__)


@dataclass
class RetrievedChunk:
    text: str
    title: str
    source: str
    url: Optional[str]
    distance: float

    def short_citation(self) -> str:
        if self.url:
            return f"{self.source}: {self.title} <{self.url}>"
        return f"{self.source}: {self.title}"


class Retriever:
    def __init__(self, store: CorpusStore):
        self.store = store

    def retrieve(self, query: str, top_k: int = 5, source_filter: Optional[list[str]] = None) -> list[RetrievedChunk]:
        where = {"source": {"$in": source_filter}} if source_filter else None
        raw = self.store.query(query, top_k=top_k, where=where)
        return [
            RetrievedChunk(
                text=r["text"],
                title=r["title"],
                source=r["source"],
                url=r["url"],
                distance=r["distance"],
            )
            for r in raw
        ]

    def retrieve_for_finding(self, finding: Finding, top_k: int = 4) -> list[RetrievedChunk]:
        # Build a query that prioritizes specific identifiers when present.
        parts: list[str] = []
        if finding.cwe:
            parts.append(finding.cwe)
        if finding.cve:
            parts.append(finding.cve)
        parts.append(finding.title)
        if finding.description:
            parts.append(finding.description[:300])
        query = " ".join(parts)
        return self.retrieve(query, top_k=top_k)


def format_context(chunks: list[RetrievedChunk]) -> str:
    """Render chunks as a numbered context block to inject into a prompt."""
    if not chunks:
        return ""
    blocks: list[str] = ["<context>"]
    for i, c in enumerate(chunks, 1):
        blocks.append(f"[{i}] {c.short_citation()}\n{c.text.strip()}")
    blocks.append("</context>")
    return "\n\n".join(blocks)
