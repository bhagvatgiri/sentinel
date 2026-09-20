"""OWASP source — clones the public OWASP repos and parses their markdown.

Repos:
  CheatSheetSeries  — https://github.com/OWASP/CheatSheetSeries  (CC-BY-SA)
  ASVS              — https://github.com/OWASP/ASVS              (CC-BY-SA)
  Top10             — https://github.com/OWASP/Top10             (CC-BY-SA)
  WSTG              — https://github.com/OWASP/wstg              (CC-BY-SA)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from sentinel.corpus.document import Document
from sentinel.corpus.sources.base import Source


REPOS = {
    "cheatsheets": "https://github.com/OWASP/CheatSheetSeries.git",
    "asvs": "https://github.com/OWASP/ASVS.git",
    "top10": "https://github.com/OWASP/Top10.git",
    "wstg": "https://github.com/OWASP/wstg.git",
}


class OwaspSource(Source):
    name = "owasp"

    def fetch(self, work_dir: Path) -> None:
        for sub, url in REPOS.items():
            self.git_clone(url, work_dir / sub)

    def parse(self, work_dir: Path) -> Iterable[Document]:
        for sub in REPOS:
            root = work_dir / sub
            if not root.exists():
                continue
            for md in root.rglob("*.md"):
                rel = md.relative_to(root)
                # Skip obvious noise.
                low = str(rel).lower()
                if low.startswith(("readme", "license", "contributing", ".github")):
                    continue
                if any(p in low for p in ("/.github/", "/scripts/", "/assets/")):
                    continue
                try:
                    text = md.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                if len(text.strip()) < 200:  # skip stubs
                    continue
                title = _extract_title(text) or md.stem.replace("_", " ").replace("-", " ").title()
                doc_id = Document.make_id(self.name, f"{sub}/{rel}")
                yield Document(
                    id=doc_id,
                    text=text,
                    title=title,
                    source=self.name,
                    url=f"https://github.com/OWASP/{_repo_basename(sub)}/blob/main/{rel}".replace("\\", "/"),
                    tags=["owasp", sub],
                    metadata={"subproject": sub, "path": str(rel)},
                )


_TITLE_RE = re.compile(r"^\s*#\s+(.+?)\s*$", re.MULTILINE)


def _extract_title(text: str) -> str | None:
    m = _TITLE_RE.search(text)
    return m.group(1) if m else None


def _repo_basename(sub: str) -> str:
    return {
        "cheatsheets": "CheatSheetSeries",
        "asvs": "ASVS",
        "top10": "Top10",
        "wstg": "wstg",
    }[sub]
