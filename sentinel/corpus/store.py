"""Chroma vector store wrapper.

One persistent client, one collection named 'cybersec_corpus'. Upserts are
keyed on chunk.id, so re-running ingest on the same source updates rather
than duplicates. Filtering is done via Chroma `where=` on metadata.

We embed externally (via OllamaEmbedder) and pass embeddings in directly,
so Chroma never tries to download its default embedder.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from sentinel.corpus.document import Chunk
from sentinel.corpus.embedder import OllamaEmbedder


log = logging.getLogger(__name__)


COLLECTION_NAME = "cybersec_corpus"


class CorpusStore:
    def __init__(self, persist_dir: str | Path, embedder: OllamaEmbedder):
        try:
            import chromadb  # noqa: F401
        except ImportError as e:
            raise RuntimeError(
                "chromadb is required. Install with: pip install chromadb"
            ) from e
        import chromadb

        self.persist_dir = Path(persist_dir).expanduser().resolve()
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.embedder = embedder
        self._client = chromadb.PersistentClient(path=str(self.persist_dir))
        self._collection = self._client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )

    def upsert_chunks(self, chunks: list[Chunk], batch_size: int = 32) -> int:
        """Embed and upsert in batches. Returns count of successfully stored chunks."""
        stored = 0
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i : i + batch_size]
            embeddings = self.embedder.embed_batch([c.text for c in batch])

            # Drop any chunks whose embedding failed.
            ids: list[str] = []
            docs: list[str] = []
            metas: list[dict] = []
            embs: list[list[float]] = []
            for chunk, emb in zip(batch, embeddings):
                if emb is None:
                    log.warning("dropping chunk %s: embedding failed", chunk.id)
                    continue
                ids.append(chunk.id)
                docs.append(chunk.text)
                metas.append(chunk.chroma_metadata())
                embs.append(emb)

            if ids:
                self._collection.upsert(ids=ids, documents=docs, metadatas=metas, embeddings=embs)
                stored += len(ids)
                log.info("upserted batch: %d chunks (running total: %d)", len(ids), stored)
        return stored

    def query(
        self,
        query_text: str,
        top_k: int = 5,
        where: Optional[dict] = None,
    ) -> list[dict]:
        """Return list of dicts: {id, text, title, source, url, distance, metadata}."""
        emb = self.embedder.embed_one(query_text)
        if emb is None:
            return []
        result = self._collection.query(
            query_embeddings=[emb],
            n_results=top_k,
            where=where,
        )
        out: list[dict] = []
        ids = (result.get("ids") or [[]])[0]
        docs = (result.get("documents") or [[]])[0]
        metas = (result.get("metadatas") or [[]])[0]
        dists = (result.get("distances") or [[]])[0]
        for cid, doc, meta, dist in zip(ids, docs, metas, dists):
            out.append(
                {
                    "id": cid,
                    "text": doc,
                    "title": meta.get("title", ""),
                    "source": meta.get("source", ""),
                    "url": meta.get("url") or None,
                    "distance": float(dist),
                    "metadata": dict(meta),
                }
            )
        return out

    def stats(self) -> dict:
        try:
            count = self._collection.count()
        except Exception:  # pragma: no cover
            count = -1
        return {"collection": COLLECTION_NAME, "chunks": count, "persist_dir": str(self.persist_dir)}

    def has_url(self, url: str) -> bool:
        """True if any chunk in the collection has this URL in metadata.
        Used by brain-grow's URL-novelty override (tools.py:ingest_text)."""
        if not url:
            return False
        try:
            res = self._collection.get(where={"url": url}, limit=1, include=[])
        except Exception:  # pragma: no cover
            return False
        return bool(res.get("ids"))

    def delete_source(self, source: str) -> int:
        """Delete all chunks belonging to a given source. Returns count deleted (best-effort)."""
        before = self._collection.count()
        self._collection.delete(where={"source": source})
        after = self._collection.count()
        return max(0, before - after)
