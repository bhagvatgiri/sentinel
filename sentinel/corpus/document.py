"""Document — the unit passed from sources to chunker/embedder/store."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Document:
    """A single source document.

    `id` should be stable across re-ingestion so updates are idempotent.
    `metadata` is searchable in the vector store (Chroma supports `where=`
    filters on it). Keep it small — the full text lives in `text`.
    """

    id: str
    text: str
    title: str
    source: str  # e.g. "owasp", "mitre-cwe", "nvd", "books"
    url: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @staticmethod
    def make_id(source: str, key: str) -> str:
        return f"{source}:{hashlib.sha1(key.encode('utf-8')).hexdigest()[:16]}"


@dataclass
class Chunk:
    """A chunk derived from a Document — what actually gets embedded."""

    id: str  # f"{doc_id}#chunk-{n}"
    doc_id: str
    text: str
    title: str
    source: str
    url: Optional[str]
    chunk_index: int
    metadata: dict = field(default_factory=dict)

    def chroma_metadata(self) -> dict:
        """Chroma metadata can't store None or lists. Flatten."""
        m: dict = {
            "doc_id": self.doc_id,
            "title": self.title or "",
            "source": self.source,
            "url": self.url or "",
            "chunk_index": self.chunk_index,
        }
        for k, v in self.metadata.items():
            if v is None:
                continue
            if isinstance(v, (str, int, float, bool)):
                m[k] = v
            elif isinstance(v, list):
                m[k] = ", ".join(str(x) for x in v)[:500]
        return m
