"""Recursive character-based chunker with overlap.

We don't use tiktoken or model-specific tokenizers because we want this to be
embedder-agnostic. Empirically, ~1500 chars (~400 tokens) per chunk with 200
chars overlap works well for technical security text.
"""

from __future__ import annotations

import re
from typing import Iterable

from sentinel.corpus.document import Chunk, Document


# Try splits in this order; the first that produces small-enough pieces wins.
DEFAULT_SEPARATORS = [
    "\n## ",   # markdown H2
    "\n### ",  # markdown H3
    "\n\n",    # paragraph
    "\n",      # line
    ". ",      # sentence
    " ",       # word
    "",        # char (last resort)
]


def chunk_document(
    doc: Document,
    chunk_size: int = 1500,
    chunk_overlap: int = 200,
) -> list[Chunk]:
    """Split a Document into overlapping chunks."""
    if chunk_overlap >= chunk_size:
        raise ValueError("chunk_overlap must be smaller than chunk_size")
    if not doc.text.strip():
        return []

    pieces = _recursive_split(doc.text, chunk_size, DEFAULT_SEPARATORS)
    pieces = _merge_with_overlap(pieces, chunk_size, chunk_overlap)

    chunks: list[Chunk] = []
    for i, text in enumerate(pieces):
        text = text.strip()
        if not text:
            continue
        chunks.append(
            Chunk(
                id=f"{doc.id}#chunk-{i}",
                doc_id=doc.id,
                text=text,
                title=doc.title,
                source=doc.source,
                url=doc.url,
                chunk_index=i,
                metadata={**doc.metadata, "tags": doc.tags},
            )
        )
    return chunks


# ---- internals ------------------------------------------------------------


def _recursive_split(text: str, max_size: int, separators: list[str]) -> list[str]:
    if len(text) <= max_size:
        return [text]
    if not separators:
        # Hard slice as fallback.
        return [text[i : i + max_size] for i in range(0, len(text), max_size)]

    sep, *rest = separators
    if sep == "":
        return [text[i : i + max_size] for i in range(0, len(text), max_size)]

    parts = text.split(sep)
    out: list[str] = []
    for p in parts:
        if not p:
            continue
        # Re-prepend the separator (except for the first piece) so we keep the
        # heading marker that triggered the split.
        candidate = (sep if out else "") + p if sep != "\n\n" else p
        if len(candidate) > max_size:
            out.extend(_recursive_split(candidate, max_size, rest))
        else:
            out.append(candidate)
    return out


def _merge_with_overlap(pieces: list[str], chunk_size: int, overlap: int) -> list[str]:
    """Greedy merge of small adjacent pieces, then add tail-overlap between chunks."""
    if not pieces:
        return []

    merged: list[str] = []
    buf = ""
    for p in pieces:
        if not buf:
            buf = p
            continue
        if len(buf) + len(p) <= chunk_size:
            buf = buf + p
        else:
            merged.append(buf)
            buf = p
    if buf:
        merged.append(buf)

    if overlap <= 0 or len(merged) <= 1:
        return merged

    out = [merged[0]]
    for prev, cur in zip(merged, merged[1:]):
        tail = prev[-overlap:]
        out.append(tail + cur if not cur.startswith(tail) else cur)
    return out
