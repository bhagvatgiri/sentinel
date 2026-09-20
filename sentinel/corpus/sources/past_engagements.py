"""Past-engagement memory source.

Walks `workspaces/*/deliverables/` and ingests every markdown deliverable
the autonomous pentest pipeline produced as a corpus document. Future
runs can then RAG-query precedent: "have we seen this Vercel SSRF
pattern before?" returns the engagement where it was confirmed.

Each engagement gets its own logical source name
(`past-engagement-<client>-<engagement_id>`) so operators can include or
exclude specific engagements via `corpus_search(source_filter=...)`.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterable, Optional

from sentinel.corpus.document import Document
from sentinel.corpus.sources.base import Source


log = logging.getLogger(__name__)


# Recognise the deliverables we care about. Anything else in deliverables/
# (queue JSONs, raw evidence dumps, etc.) is skipped — we want narrative
# documents the LLM can reason over, not raw structured output.
_INTERESTING_FILES = re.compile(
    r"(recon|.+_analysis|.+_exploitation_evidence|chain_analysis|"
    r"comprehensive_security_assessment_report)_deliverable\.md$|"
    r"comprehensive_security_assessment_report\.md$",
    re.IGNORECASE,
)


class PastEngagementsSource(Source):
    """Reads past-engagement deliverables. Doesn't fetch anything; assumes
    the workspaces directory already exists locally on the operator's box.
    """

    name = "past-engagements"

    def __init__(self, workspaces_dir: Path,
                 only_engagements: Optional[list[str]] = None,
                 scopes_dir: Optional[Path] = None):
        self.workspaces_dir = Path(workspaces_dir).expanduser()
        self.only_engagements = set(only_engagements or [])
        # Optional path to the operator's engagements/ dir. When provided,
        # `_infer_client` reads the scope yaml as authoritative (so a
        # client like "Radiant Global" lands as "Radiant Global", not
        # the wrong-segment heuristic guess of "global").
        self.scopes_dir = Path(scopes_dir).expanduser() if scopes_dir else None
        self._client_by_eng_id = self._build_client_index() if self.scopes_dir else {}

    def _build_client_index(self) -> dict[str, str]:
        """Walk scopes_dir/*.yaml and map engagement_id → client. Only
        called once at construction; tolerant of missing files / bad yaml."""
        out: dict[str, str] = {}
        if self.scopes_dir is None or not self.scopes_dir.is_dir():
            return out
        try:
            import yaml
        except ImportError:
            log.warning("past-engagements: PyYAML missing; falling back to heuristic")
            return out
        for p in self.scopes_dir.glob("*.yaml"):
            try:
                doc = yaml.safe_load(p.read_text()) or {}
            except Exception as e:
                log.debug("past-engagements: skipping unreadable %s: %s", p, e)
                continue
            if not isinstance(doc, dict):
                continue
            eid = doc.get("engagement_id")
            client = doc.get("client")
            if eid and client:
                out[str(eid)] = str(client)
        return out

    def fetch(self, work_dir: Path) -> None:
        # Source is local — nothing to download. Validate dir exists.
        if not self.workspaces_dir.exists():
            log.warning("past-engagements: %s does not exist; nothing to ingest",
                        self.workspaces_dir)

    def parse(self, work_dir: Path) -> Iterable[Document]:
        if not self.workspaces_dir.exists():
            return

        for engagement_dir in sorted(self.workspaces_dir.iterdir()):
            if not engagement_dir.is_dir():
                continue
            engagement_id = engagement_dir.name
            if self.only_engagements and engagement_id not in self.only_engagements:
                continue

            deliv_dir = engagement_dir / "deliverables"
            if not deliv_dir.is_dir():
                continue

            client = self._infer_client(engagement_dir)
            logical_source = (
                f"past-engagement-{client}-{engagement_id}"
                if client else f"past-engagement-{engagement_id}"
            )

            for md in sorted(deliv_dir.glob("*.md")):
                if not _INTERESTING_FILES.search(md.name):
                    continue
                try:
                    text = md.read_text()
                except OSError as e:
                    log.warning("past-engagements: skipping %s: %s", md, e)
                    continue
                if len(text.strip()) < 200:
                    continue  # nothing useful to embed

                title = f"[{engagement_id}] {md.stem}"
                yield Document(
                    id=Document.make_id(logical_source, str(md)),
                    text=text,
                    title=title,
                    source=logical_source,
                    url=None,
                    tags=["past-engagement", engagement_id, md.stem],
                    metadata={
                        "engagement_id": engagement_id,
                        "client": client or "",
                        "deliverable_kind": md.stem,
                        "workspace_path": str(engagement_dir),
                    },
                )

    def _infer_client(self, engagement_dir: Path) -> str:
        """Authoritative source: the scope yaml's `client:` field, looked
        up by engagement_id == workspace dir name. Falls back to a
        dir-name heuristic only when no scope yaml maps to this engagement
        (e.g. workspaces created without a scope yaml on disk).
        """
        eid = engagement_dir.name
        canonical = self._client_by_eng_id.get(eid)
        if canonical:
            return canonical
        # Heuristic fallback: split on `-` and grab the first non-numeric,
        # non-quarter token after the year. Captures the original
        # behavior so old workspaces without scope yamls still get a label.
        parts = eid.split("-")
        if len(parts) >= 3:
            for p in parts[2:]:
                if p and not p.isdigit() and p.lower() not in ("q1", "q2", "q3", "q4"):
                    return p.lower()
        return ""
