"""Ingestion pipeline — chains source -> chunker -> embedder -> store -> obsidian."""

from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.corpus.chunker import chunk_document
from sentinel.corpus.document import Chunk, Document
from sentinel.corpus.embedder import OllamaEmbedder
from sentinel.corpus.obsidian_writer import ObsidianCorpusWriter
from sentinel.corpus.sources.base import Source
from sentinel.corpus.store import CorpusStore


log = logging.getLogger(__name__)


@dataclass
class IngestReport:
    source: str
    documents: int = 0
    chunks_stored: int = 0
    obsidian_notes: int = 0
    errors: list[str] = field(default_factory=list)


class CorpusIngester:
    def __init__(
        self,
        store: CorpusStore,
        obsidian_writer: Optional[ObsidianCorpusWriter] = None,
        chunk_size: int = 1500,
        chunk_overlap: int = 200,
    ):
        self.store = store
        self.obsidian_writer = obsidian_writer
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def ingest(self, source: Source, work_dir: Optional[Path] = None) -> IngestReport:
        report = IngestReport(source=source.name)
        own_tmp = work_dir is None
        wd = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix=f"sentinel-{source.name}-"))
        try:
            log.info("[%s] fetching", source.name)
            try:
                source.fetch(wd)
            except Exception as e:
                report.errors.append(f"fetch failed: {e}")
                log.exception("fetch failed for %s", source.name)
                return report

            log.info("[%s] parsing + chunking + embedding", source.name)
            docs: list[Document] = []
            chunks: list[Chunk] = []
            for doc in source.parse(wd):
                docs.append(doc)
                chunks.extend(chunk_document(doc, self.chunk_size, self.chunk_overlap))
            report.documents = len(docs)
            log.info("[%s] %d documents -> %d chunks", source.name, len(docs), len(chunks))

            if chunks:
                report.chunks_stored = self.store.upsert_chunks(chunks)

            if self.obsidian_writer and docs:
                report.obsidian_notes = self.obsidian_writer.write_documents(source.name, docs)

        finally:
            if own_tmp:
                import shutil
                shutil.rmtree(wd, ignore_errors=True)
        return report
