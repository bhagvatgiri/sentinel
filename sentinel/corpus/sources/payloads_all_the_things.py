"""Payloads-All-The-Things corpus ingester.

Wraps the local clone of github.com/swisskyrepo/PayloadsAllTheThings
(~66 vuln-class categories, ~140+ READMEs, plus per-category Files/
sub-directories with raw payload lists) and ingests every markdown +
text file into Chroma under `source="payloads-all-the-things"`.

Each document carries `metadata.category` set to the top-level folder
name (e.g. "SQL Injection", "JSON Web Token", "GraphQL Injection") so
operators can filter retrievals by class. Tags echo the category
slugified to lowercase-hyphen form so RAG keyword queries hit them.

This source is local-only: it does NOT git-clone on demand. The
operator runs `git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
library/PayloadsAllTheThings` once; the ingester walks whatever's there.
That keeps the clone under operator control (license attribution, update
cadence, fork-able) and avoids surprise network calls during ingest.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterable

from sentinel.corpus.document import Document
from sentinel.corpus.sources.base import Source


log = logging.getLogger(__name__)


# Files we ingest verbatim. README.md is the curated content; .txt files
# are usually raw-payload lists in Files/ subdirs (also valuable for the
# agent). .py / .yaml / .json files in Files/ are skipped — they're
# operator scripts, not payload knowledge.
_INGEST_EXTENSIONS = (".md", ".txt")

# Files we skip even when extension matches.
_SKIP_FILENAMES = {
    "CONTRIBUTING.md", "LICENSE", "LICENSE.md", "_template_vuln.md",
}

# Top-level dirs we skip — they're scaffolding, not payload knowledge.
_SKIP_TOPLEVEL = {
    "_LEARNING_AND_SOCIALS", "_template_vuln", ".github",
    "Methodology and Resources",  # huge, mostly meta-process docs;
                                  # operator can re-include via flag if wanted
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(s: str) -> str:
    return _SLUG_RE.sub("-", s.lower()).strip("-")


def _category_from_path(repo_root: Path, file_path: Path) -> str:
    """The first directory under repo_root is the category."""
    rel = file_path.relative_to(repo_root)
    parts = rel.parts
    if len(parts) >= 2:
        return parts[0]
    return "_root"  # README.md at repo root, etc.


class PayloadsAllTheThingsSource(Source):
    """Reads a local PayloadsAllTheThings clone. Set `repo_dir` to wherever
    you cloned it; default `library/PayloadsAllTheThings`."""

    name = "payloads-all-the-things"

    def __init__(self, repo_dir: Path | str = "library/PayloadsAllTheThings",
                 only_categories: list[str] | None = None,
                 min_chars: int = 200):
        self.repo_dir = Path(repo_dir).expanduser().resolve()
        self.only_categories = set(only_categories or [])
        self.min_chars = min_chars

    def fetch(self, work_dir: Path) -> None:
        # Local-only source. We refuse to silently auto-clone — the
        # operator is responsible for `git clone` so license + update
        # cadence stays explicit.
        if not self.repo_dir.exists():
            raise FileNotFoundError(
                f"PayloadsAllTheThings not found at {self.repo_dir}. "
                f"Clone first: git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git "
                f"{self.repo_dir}"
            )
        if not (self.repo_dir / "README.md").is_file():
            log.warning(
                "payloads-all-the-things: %s exists but doesn't look like the repo "
                "(no top-level README.md). Continuing anyway.", self.repo_dir,
            )

    def parse(self, work_dir: Path) -> Iterable[Document]:
        repo = self.repo_dir
        if not repo.exists():
            return

        for path in sorted(repo.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _INGEST_EXTENSIONS:
                continue
            if path.name in _SKIP_FILENAMES:
                continue

            category = _category_from_path(repo, path)
            if category in _SKIP_TOPLEVEL:
                continue
            if self.only_categories and category not in self.only_categories:
                continue

            try:
                text = path.read_text(errors="ignore")
            except OSError as e:
                log.warning("PATT: failed to read %s: %s", path, e)
                continue

            if len(text.strip()) < self.min_chars:
                continue

            rel = str(path.relative_to(repo))
            # Title format: "<Category>: <filename without ext>"
            stem = path.stem.replace("_", " ")
            title = f"PayloadsAllTheThings — {category}: {stem}" if category != "_root" else f"PayloadsAllTheThings: {stem}"

            tags = ["payloads-all-the-things", _slugify(category)]
            # Add the filename slug as a tag too for fine-grained retrieval.
            stem_slug = _slugify(stem)
            if stem_slug and stem_slug not in tags:
                tags.append(stem_slug)

            yield Document(
                id=Document.make_id(self.name, rel),
                text=text,
                title=title,
                source=self.name,
                url=f"https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/{rel}",
                tags=tags,
                metadata={
                    "category": category,
                    "filename": path.name,
                    "rel_path": rel,
                },
            )
