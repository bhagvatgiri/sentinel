"""Library — operator view of the local book corpus.

Reads `library/security-books-catalog.json` (produced by
`tools/extract-security-books-catalog.py`) and joins it against
`library/download-progress.json` so the operator can see at a glance which
books are present, which are missing, and how each maps to corpus chunks.

Read-only. No way to trigger downloads from the UI on purpose — the
authorization grant lives in `library/PERMISSION.txt`, the downloader is a
one-shot tool the operator runs from the shell, and re-running it should
be a deliberate act, not a button click.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Request

from sentinel.ui.state import UIConfig
from sentinel.web.deps import get_config


router = APIRouter()


def _project_root(cfg: UIConfig) -> Path:
    return Path(cfg.project_dir).expanduser()


def _load_catalog(root: Path) -> Optional[dict]:
    p = root / "library" / "security-books-catalog.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None


def _load_progress(root: Path) -> dict:
    p = root / "library" / "download-progress.json"
    if not p.is_file():
        return {"books": {}, "runs": []}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return {"books": {}, "runs": []}


def _permission_text(root: Path) -> str:
    p = root / "library" / "PERMISSION.txt"
    if not p.is_file():
        return ""
    try:
        return p.read_text()
    except OSError:
        return ""


@router.get("/library", name="library_index")
def library_index(request: Request, cfg: UIConfig = Depends(get_config)):
    root = _project_root(cfg)
    catalog = _load_catalog(root)
    progress = _load_progress(root)
    permission = _permission_text(root)

    rows: list[dict] = []
    by_category: dict[str, list[dict]] = {}
    n_present = 0
    n_missing = 0
    total_bytes = 0

    if catalog:
        prog_books = progress.get("books", {})
        for book in catalog.get("books", []):
            key = f"{book['category']}/{book['expected_filename']}"
            entry = prog_books.get(key, {})
            status = entry.get("status") or "missing"
            size = int(entry.get("size") or 0)
            if status in ("downloaded", "skipped_existing"):
                n_present += 1
                total_bytes += size
            else:
                n_missing += 1
            row = {
                "title": book["title"],
                "author": book["author"],
                "category": book["category"],
                "filename": book["expected_filename"],
                "notion_url": book.get("notion_url", ""),
                "status": status,
                "size": size,
                "path": entry.get("path", ""),
                "sha256": entry.get("sha256", ""),
            }
            rows.append(row)
            by_category.setdefault(book["category"], []).append(row)

    # Latest run summary, if any.
    last_run = (progress.get("runs") or [{}])[-1] if progress.get("runs") else {}

    # Try to compute corpus chunk count for source=books (best-effort; falls
    # back to 0 if Chroma isn't reachable).
    book_chunks = 0
    try:
        from sentinel.ui.state import corpus_chroma_stats
        cstats = corpus_chroma_stats(cfg.corpus_dir, cfg.ollama_host, cfg.embed_model)
        per_source = cstats.get("per_source") or {}
        book_chunks = int(per_source.get("books") or 0)
    except Exception:
        book_chunks = 0

    return request.app.state.templates.TemplateResponse(
        request, "library.html",
        {
            "active_nav": "Library",
            "cfg": cfg,
            "catalog_present": catalog is not None,
            "catalog": catalog or {},
            "rows": rows,
            "by_category": by_category,
            "n_total": len(rows),
            "n_present": n_present,
            "n_missing": n_missing,
            "total_bytes": total_bytes,
            "last_run": last_run,
            "book_chunks": book_chunks,
            "permission_present": bool(permission),
            "permission_excerpt": permission[:1000] if permission else "",
        },
    )
