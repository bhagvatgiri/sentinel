"""NVD / CVE source — clones the CVE Program's official cvelistV5 git repo.

This is the canonical source: https://github.com/CVEProject/cvelistV5
~250k CVEs as JSON files. The clone is large (several GB).

We index a configurable number of the most recent N years to keep the corpus
manageable. For lookups of older CVEs the repo can still be queried directly,
but indexing all of it isn't usually worth the embedding cost.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterable, Optional

from sentinel.corpus.document import Document
from sentinel.corpus.sources.base import Source


log = logging.getLogger(__name__)


CVE_REPO = "https://github.com/CVEProject/cvelistV5.git"


class NvdSource(Source):
    name = "nvd"

    def __init__(self, since_year: int = 2020, max_records: Optional[int] = None):
        self.since_year = since_year
        self.max_records = max_records  # for testing / smoke runs

    def fetch(self, work_dir: Path) -> None:
        # Use a shallow clone — big repo, we only want current state.
        self.git_clone(CVE_REPO, work_dir / "cvelist", depth=1)

    def parse(self, work_dir: Path) -> Iterable[Document]:
        cves_dir = work_dir / "cvelist" / "cves"
        if not cves_dir.exists():
            return

        # cves/<year>/<bucket>/<CVE-...json>
        count = 0
        for year_dir in sorted(cves_dir.iterdir()):
            if not year_dir.is_dir():
                continue
            try:
                year = int(year_dir.name)
            except ValueError:
                continue
            if year < self.since_year:
                continue
            for path in year_dir.rglob("CVE-*.json"):
                if self.max_records is not None and count >= self.max_records:
                    return
                try:
                    data = json.loads(path.read_text())
                except json.JSONDecodeError:
                    continue
                doc = self._cve_to_doc(data)
                if doc is None:
                    continue
                count += 1
                yield doc

    def _cve_to_doc(self, data: dict) -> Optional[Document]:
        meta = data.get("cveMetadata") or {}
        cve_id = meta.get("cveId")
        state = meta.get("state", "")
        if not cve_id or state == "REJECTED":
            return None
        containers = data.get("containers") or {}
        cna = containers.get("cna") or {}
        title = cna.get("title") or cve_id
        descs = cna.get("descriptions") or []
        description = next((d.get("value", "") for d in descs if d.get("lang", "").startswith("en")), "")
        if not description.strip():
            return None

        # Affected products.
        affected = cna.get("affected") or []
        affected_lines = []
        for a in affected[:20]:
            vendor = a.get("vendor", "")
            product = a.get("product", "")
            versions = ", ".join(v.get("version", "") for v in (a.get("versions") or [])[:5])
            line = f"- {vendor} {product}".strip()
            if versions:
                line += f" — versions: {versions}"
            affected_lines.append(line)

        # CVSS.
        cvss_score = None
        cvss_severity = ""
        for m in cna.get("metrics") or []:
            for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
                if key in m:
                    cvss_score = m[key].get("baseScore")
                    cvss_severity = m[key].get("baseSeverity") or m[key].get("severity") or ""
                    break

        refs = []
        for r in (cna.get("references") or [])[:15]:
            if r.get("url"):
                refs.append(r["url"])

        text = (
            f"# {cve_id}: {title}\n\n"
            f"**State:** {state}  "
            + (f"**CVSS:** {cvss_score} ({cvss_severity})\n\n" if cvss_score else "\n\n")
            + f"## Description\n\n{description}\n"
        )
        if affected_lines:
            text += "\n## Affected\n\n" + "\n".join(affected_lines) + "\n"
        if refs:
            text += "\n## References\n\n" + "\n".join(f"- {r}" for r in refs) + "\n"

        return Document(
            id=Document.make_id(self.name, cve_id),
            text=text,
            title=f"{cve_id}: {title}",
            source=self.name,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            tags=["nvd", "cve", cvss_severity.lower() if cvss_severity else "unscored"],
            metadata={
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "state": state,
            },
        )
