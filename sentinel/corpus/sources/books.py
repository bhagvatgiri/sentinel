"""Local books source — ingests PDFs and EPUBs from a folder you point it at.

USE ONLY WITH BOOKS YOU LEGALLY OWN. This module makes no attempt to verify
ownership; it is your responsibility. The corpus stays local — nothing is
uploaded anywhere — but redistributing copyrighted text (even via embeddings
backed by stored full text) is still a copyright issue.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from sentinel.corpus.document import Document
from sentinel.corpus.sources.base import Source


log = logging.getLogger(__name__)


class BooksSource(Source):
    name = "books"

    def __init__(self, books_dir: str | Path):
        self.books_dir = Path(books_dir).expanduser().resolve()

    def fetch(self, work_dir: Path) -> None:
        # Nothing to download — books are local already.
        if not self.books_dir.exists():
            raise RuntimeError(f"Books directory does not exist: {self.books_dir}")

    def parse(self, work_dir: Path) -> Iterable[Document]:
        for path in self.books_dir.rglob("*"):
            if path.is_dir():
                continue
            ext = path.suffix.lower()
            if ext == ".pdf":
                yield from self._parse_pdf(path)
            elif ext == ".epub":
                yield from self._parse_epub(path)
            elif ext in (".txt", ".md"):
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                if len(text.strip()) < 500:
                    continue
                yield Document(
                    id=Document.make_id(self.name, str(path.relative_to(self.books_dir))),
                    text=text,
                    title=path.stem,
                    source=self.name,
                    url=None,
                    tags=["book", path.parent.name.lower() or "uncategorized"],
                    metadata={"path": str(path.relative_to(self.books_dir)), "format": ext.lstrip(".")},
                )

    def _parse_pdf(self, path: Path) -> Iterable[Document]:
        try:
            from pypdf import PdfReader
        except ImportError as e:
            raise RuntimeError("pypdf required: pip install pypdf") from e
        try:
            reader = PdfReader(str(path))
        except Exception as e:
            log.warning("could not read pdf %s: %s", path, e)
            return
        text_parts = []
        for page in reader.pages:
            try:
                text_parts.append(page.extract_text() or "")
            except Exception:
                continue
        text = "\n".join(t for t in text_parts if t.strip())
        if len(text) < 500:
            return
        rel = path.relative_to(self.books_dir)
        yield Document(
            id=Document.make_id(self.name, str(rel)),
            text=text,
            title=path.stem,
            source=self.name,
            url=None,
            tags=["book", "pdf", path.parent.name.lower() or "uncategorized"],
            metadata={"path": str(rel), "format": "pdf"},
        )

    def _parse_epub(self, path: Path) -> Iterable[Document]:
        try:
            from ebooklib import epub
            from bs4 import BeautifulSoup
        except ImportError as e:
            raise RuntimeError(
                "EPUB parsing requires: pip install ebooklib beautifulsoup4"
            ) from e
        try:
            book = epub.read_epub(str(path))
        except Exception as e:
            log.warning("could not read epub %s: %s", path, e)
            return
        text_parts = []
        for item in book.get_items():
            if hasattr(item, "get_content"):
                try:
                    soup = BeautifulSoup(item.get_content(), "html.parser")
                    text_parts.append(soup.get_text(separator="\n"))
                except Exception:
                    continue
        text = "\n".join(t for t in text_parts if t.strip())
        if len(text) < 500:
            return
        rel = path.relative_to(self.books_dir)
        yield Document(
            id=Document.make_id(self.name, str(rel)),
            text=text,
            title=path.stem,
            source=self.name,
            url=None,
            tags=["book", "epub", path.parent.name.lower() or "uncategorized"],
            metadata={"path": str(rel), "format": "epub"},
        )
