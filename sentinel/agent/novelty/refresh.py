"""refresh_index — CLI entry point for `sentinel novelty refresh-index` (Plan 05-02, NOVEL-03).

Walks the Chroma corpus, partitions chunks by source (NVD chunks go through
NvdLoader's --since-year filter; non-NVD chunks build IndexEntry directly from
metadata), assembles a CorpusIndex, persists under
`<corpus_dir>/novelty-index/`, and returns a stats dict for the CLI to print.

Pagination via Chroma's `_collection.get(limit=batch_size, offset=N)` keeps
memory bounded regardless of corpus size (T-05-02-02 mitigation — the ~14k
seed-corpus + NVD entries fit comfortably under 100MB RAM at fp32 768-dim).

Idempotent: re-running overwrites the prior novelty-index files. No --force
flag (T-05-02-04 disposition — the operator's intent is always "rebuild").

This module is the orchestration shell; the heavy logic lives in:
  * sentinel.agent.novelty.corpus_index.CorpusIndex (persist/load/nearest)
  * sentinel.agent.novelty.nvd_loader.NvdLoader (NVD entry extraction)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator, Optional, Tuple

import numpy as np

from sentinel.agent.novelty.corpus_index import CorpusIndex, IndexEntry
from sentinel.agent.novelty.nvd_loader import NvdLoader


log = logging.getLogger(__name__)


def _iter_chroma_chunks(
    store,
    source_filter: Optional[str] = None,
    batch_size: int = 1000,
) -> Iterator[Tuple[str, list[float], dict, str]]:
    """Walk every chunk in the Chroma collection via paginated `_collection.get`.

    Yields (chunk_id, embedding, metadata, document) tuples. `source_filter`
    is an optional source name (e.g. "nvd") that becomes a Chroma `where=`
    clause; pass None to walk the entire collection.

    Implemented as a private helper (not as a CorpusStore method) because the
    novelty-index subsystem owns this iteration shape — extending CorpusStore
    would couple the corpus subsystem to a Plan 05-02-specific access pattern.
    """
    where = {"source": source_filter} if source_filter else None
    offset = 0
    while True:
        kwargs = dict(
            include=["embeddings", "metadatas", "documents"],
            limit=batch_size,
            offset=offset,
        )
        if where is not None:
            kwargs["where"] = where
        result = store._collection.get(**kwargs)
        ids = result.get("ids") or []
        if not ids:
            return
        embeddings = result.get("embeddings") or []
        metadatas = result.get("metadatas") or []
        documents = result.get("documents") or []
        for i, cid in enumerate(ids):
            emb = embeddings[i] if i < len(embeddings) else None
            meta = metadatas[i] if i < len(metadatas) else {}
            doc = documents[i] if i < len(documents) else ""
            if emb is None:
                # Chunk in Chroma with no embedding is degenerate — skip.
                continue
            yield (cid, emb, dict(meta or {}), doc or "")
        offset += len(ids)
        if len(ids) < batch_size:
            return


def _entry_from_chunk(
    chunk_id: str,
    metadata: dict,
    document: str,
) -> IndexEntry:
    """Build an IndexEntry from a non-NVD Chroma chunk."""
    preview = (document or "")[:240]
    return IndexEntry(
        chunk_id=str(chunk_id),
        source=str(metadata.get("source", "")),
        title=str(metadata.get("title", "")),
        text_preview=preview,
        url=metadata.get("url") or None,
        cve_id=None,
    )


def refresh_index(
    corpus_dir: str,
    since_year: int = 2020,
    ollama_host: str = "http://localhost:11434",
    ollama_model: str = "nomic-embed-text",
) -> dict:
    """Build + persist the novelty-index from the Chroma corpus.

    Returns a stats dict:

        {
            "sources": {source_name: count, ...},
            "total_entries": int,
            "nvd_entries": int,
            "nvd_filtered_out": int,
            "dim": int,
            "persist_dir": str,
        }

    The CLI prints this dict as pretty-JSON for the operator. Not part of the
    legal audit-log chain — refresh-index is dev tooling, not an engagement
    event (T-05-02-06 disposition).
    """
    # Lazy imports — keep `from sentinel.agent.novelty import refresh_index`
    # cheap and free of chromadb / Ollama setup cost.
    from sentinel.corpus.embedder import OllamaEmbedder
    from sentinel.corpus.store import CorpusStore

    persist_dir = Path(corpus_dir).expanduser() / "novelty-index"

    embedder = OllamaEmbedder(host=ollama_host, model=ollama_model)
    store = CorpusStore(persist_dir=corpus_dir, embedder=embedder)

    nvd_loader = NvdLoader(since_year=since_year)

    vectors: list[np.ndarray] = []
    entries: list[IndexEntry] = []
    source_counts: dict[str, int] = {}
    nvd_count = 0
    nvd_filtered = 0

    for chunk_id, embedding, metadata, document in _iter_chroma_chunks(store):
        source = metadata.get("source", "") or ""
        source_counts[source] = source_counts.get(source, 0) + 1
        if source == "nvd":
            # Route the single chunk through NvdLoader so since_year + cve_id
            # validation stay centralized.
            singleton = [(chunk_id, embedding, metadata, document)]
            yielded = list(nvd_loader.iter_entries(singleton))
            if not yielded:
                nvd_filtered += 1
                continue
            for vec, entry in yielded:
                vectors.append(vec)
                entries.append(entry)
                nvd_count += 1
        else:
            vec = np.asarray(embedding, dtype=np.float32).ravel()
            vectors.append(vec)
            entries.append(_entry_from_chunk(chunk_id, metadata, document))

    if vectors:
        matrix = np.stack(vectors).astype(np.float32, copy=False)
    else:
        # Empty corpus — still persist a valid (0, D) shape. Default to D=768
        # for nomic-embed-text; the scorer's load() tolerates an empty index.
        matrix = np.zeros((0, 768), dtype=np.float32)

    index = CorpusIndex(vectors=matrix, entries=entries)
    index.persist(persist_dir)

    stats = {
        "sources": source_counts,
        "total_entries": int(index.size),
        "nvd_entries": nvd_count,
        "nvd_filtered_out": nvd_filtered,
        "dim": int(index.dim),
        "persist_dir": str(persist_dir),
    }
    log.info("novelty-index refreshed: %s", stats)
    return stats
