"""Semantic duplicate-probability check for drafted H1 reports.

Before the operator burns hours on submission ceremony, run the report's title
+ first 500 chars through the local Chroma corpus and surface the top-K
nearest writeups by cosine distance. A distance < 0.25 flags the row
as high-duplicate-risk (empirical threshold for nomic-embed-text on the
writeups corpus).

Graceful degradation: if Chroma isn't installed OR the corpus dir is
empty / unreachable, returns `[]` so the caller can render "corpus
unavailable" rather than crashing. The corpus is opt-in for now
(operator may not have ingested writeups yet on a fresh machine).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

# Module-level so tests can monkeypatch the symbols without importing
# chromadb at test-collection time.
try:
    from sentinel.corpus.store import CorpusStore  # noqa: F401
except Exception:  # pragma: no cover — chromadb optional at runtime
    CorpusStore = None  # type: ignore[assignment,misc]

try:
    from sentinel.corpus.embedder import OllamaEmbedder  # noqa: F401
except Exception:  # pragma: no cover
    OllamaEmbedder = None  # type: ignore[assignment,misc]


# Empirical "this is the same finding" line for cosine distance on
# nomic-embed-text against the writeups corpus. Below = high probability
# the operator is about to file a duplicate.
HIGH_DUP_DISTANCE = 0.25


_TITLE_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
_FENCE_RE = re.compile(r"^```", re.MULTILINE)


def _build_query_text(report_path: Path) -> str:
    """Extract the title + first 500 chars of body (sans code fences) to
    use as the semantic search query."""
    try:
        text = report_path.read_text(errors="replace")
    except OSError:
        return ""
    m = _TITLE_RE.search(text)
    title = m.group(1).strip() if m else report_path.stem
    # Strip everything inside fenced code blocks before extracting body.
    body_parts: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        body_parts.append(line)
    body = "\n".join(body_parts).strip()
    # Drop the title line (already separately included) and any leading
    # whitespace.
    body_short = body[:500]
    return f"{title}\n\n{body_short}"


def dup_check(
    report_path: Path | str,
    *,
    corpus_dir: Path | str,
    top_k: int = 5,
    source_filter: Optional[str] = None,
) -> list[dict]:
    """Return the top-K nearest writeups for `report_path`.

    Each row: `{distance, source, doc_id, title, url, high_duplicate_risk}`,
    ordered ascending by distance (closest first). Empty list when the
    corpus is unavailable (chromadb missing, dir empty, query fails).

    `source_filter` (e.g. "writeups", "hackerone-full") is passed
    through to Chroma as `where={"source": <filter>}`.
    """
    report_path = Path(report_path)
    corpus_dir = Path(corpus_dir)

    if CorpusStore is None:
        return []

    query_text = _build_query_text(report_path)
    if not query_text:
        return []

    try:
        # OllamaEmbedder needed by CorpusStore — None when monkeypatched
        # to a stub in tests, which the stub ignores.
        embedder = OllamaEmbedder() if OllamaEmbedder is not None else None
        store = CorpusStore(corpus_dir, embedder)
    except Exception:
        # chromadb-not-installed, corpus-dir-empty, embedder-host-down —
        # all degrade gracefully.
        return []

    where = {"source": source_filter} if source_filter else None
    try:
        raw = store.query(query_text, top_k=top_k, where=where)
    except Exception:
        return []

    rows: list[dict] = []
    for r in raw or []:
        dist = float(r.get("distance", 1.0))
        rows.append(
            {
                "distance": dist,
                "source": r.get("source", "") or "",
                "doc_id": r.get("id", "") or "",
                "title": r.get("title", "") or "",
                "url": r.get("url") or "",
                "high_duplicate_risk": dist < HIGH_DUP_DISTANCE,
            }
        )
    rows.sort(key=lambda r: r["distance"])
    return rows
