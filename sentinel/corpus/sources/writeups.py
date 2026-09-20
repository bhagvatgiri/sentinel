"""Bug bounty writeups source — pulls a curated index from public GitHub repos.

We do NOT scrape arbitrary blogs (legal grey, often paywalled). Instead, we
read a curated machine-readable list and pull the title + URL + summary into
the corpus. Embedding the URL+summary is enough for retrieval to surface the
right writeup; the user clicks through to read the full article on the
original site, respecting the author's hosting and any rate limits.

Two index sources we trust:
  - https://github.com/devanshbatham/Awesome-Bugbounty-Writeups (markdown index)
  - https://github.com/ngalongc/bug-bounty-reference  (markdown index)

You can extend INDEX_REPOS with your own private list of curated reading.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from sentinel.corpus.document import Document
from sentinel.corpus.sources.base import Source


INDEX_REPOS = {
    "awesome-bugbounty-writeups": "https://github.com/devanshbatham/Awesome-Bugbounty-Writeups.git",
    "bug-bounty-reference": "https://github.com/ngalongc/bug-bounty-reference.git",
}


# `[Title](https://...)` patterns inside markdown.
LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")


class WriteupsSource(Source):
    name = "writeups"

    def fetch(self, work_dir: Path) -> None:
        for sub, url in INDEX_REPOS.items():
            self.git_clone(url, work_dir / sub)

    def parse(self, work_dir: Path) -> Iterable[Document]:
        seen: set[str] = set()
        for sub in INDEX_REPOS:
            root = work_dir / sub
            if not root.exists():
                continue
            for md in root.rglob("*.md"):
                try:
                    content = md.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                # Walk the file line-by-line so each link gets its surrounding
                # bullet/heading context as the document body.
                lines = content.splitlines()
                current_section = ""
                for i, line in enumerate(lines):
                    if line.startswith("#"):
                        current_section = line.strip(" #")
                        continue
                    for m in LINK_RE.finditer(line):
                        title, url = m.group(1).strip(), m.group(2).strip()
                        if not title or url in seen:
                            continue
                        seen.add(url)
                        # Build a small "body": surrounding lines for context.
                        ctx_start = max(0, i - 1)
                        ctx_end = min(len(lines), i + 2)
                        ctx = "\n".join(lines[ctx_start:ctx_end])
                        text = (
                            f"# {title}\n\n"
                            f"**Section:** {current_section or sub}\n"
                            f"**URL:** {url}\n\n"
                            f"## Context\n\n{ctx}\n"
                        )
                        yield Document(
                            id=Document.make_id(self.name, url),
                            text=text,
                            title=title,
                            source=self.name,
                            url=url,
                            tags=["writeup", "bug-bounty", _slug(current_section) if current_section else sub],
                            metadata={"index_repo": sub, "section": current_section},
                        )


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-") or "general"
