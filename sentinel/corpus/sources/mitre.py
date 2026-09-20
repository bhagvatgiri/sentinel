"""MITRE sources — CWE (XML) and ATT&CK (STIX JSON via git).

CWE:    https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
ATT&CK: https://github.com/mitre-attack/attack-stix-data
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Iterable

from sentinel.corpus.document import Document
from sentinel.corpus.sources.base import Source


CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
ATTACK_REPO = "https://github.com/mitre-attack/attack-stix-data.git"


# CWE XML uses these namespaces.
NS = {"cwe": "http://cwe.mitre.org/cwe-7"}


class MitreCweSource(Source):
    name = "mitre-cwe"

    def fetch(self, work_dir: Path) -> None:
        zip_path = work_dir / "cwec.zip"
        self.http_get(CWE_ZIP_URL, zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(work_dir)

    def parse(self, work_dir: Path) -> Iterable[Document]:
        xml_files = sorted(work_dir.glob("cwec_v*.xml"))
        if not xml_files:
            return
        tree = ET.parse(xml_files[-1])
        root = tree.getroot()
        # Namespace varies by CWE version; auto-detect.
        ns_uri = root.tag.split("}")[0].lstrip("{") if "}" in root.tag else ""
        ns = {"c": ns_uri} if ns_uri else {}
        prefix = "c:" if ns_uri else ""

        for weak in root.findall(f".//{prefix}Weakness", ns):
            cwe_id = weak.get("ID")
            name = weak.get("Name") or "CWE"
            abstraction = weak.get("Abstraction") or ""
            status = weak.get("Status") or ""
            description = (weak.findtext(f"{prefix}Description", default="", namespaces=ns) or "").strip()
            extended = (weak.findtext(f"{prefix}Extended_Description", default="", namespaces=ns) or "").strip()
            text_parts = [f"# CWE-{cwe_id}: {name}"]
            if abstraction:
                text_parts.append(f"**Abstraction:** {abstraction}  **Status:** {status}")
            if description:
                text_parts.append("\n## Description\n\n" + description)
            if extended:
                text_parts.append("\n## Extended description\n\n" + extended)

            consequences = []
            for cons in weak.findall(f".//{prefix}Common_Consequences/{prefix}Consequence", ns):
                scope = ", ".join(s.text or "" for s in cons.findall(f"{prefix}Scope", ns))
                impact = ", ".join(i.text or "" for i in cons.findall(f"{prefix}Impact", ns))
                if scope or impact:
                    consequences.append(f"- Scope: {scope} — Impact: {impact}")
            if consequences:
                text_parts.append("\n## Common consequences\n\n" + "\n".join(consequences))

            mitigations = []
            for mit in weak.findall(f".//{prefix}Potential_Mitigations/{prefix}Mitigation", ns):
                phase = ", ".join(p.text or "" for p in mit.findall(f"{prefix}Phase", ns))
                desc = (mit.findtext(f"{prefix}Description", default="", namespaces=ns) or "").strip()
                if desc:
                    mitigations.append(f"- **Phase:** {phase}\n  {desc}")
            if mitigations:
                text_parts.append("\n## Mitigations\n\n" + "\n".join(mitigations))

            full = "\n\n".join(text_parts)
            yield Document(
                id=Document.make_id(self.name, f"CWE-{cwe_id}"),
                text=full,
                title=f"CWE-{cwe_id}: {name}",
                source=self.name,
                url=f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
                tags=["mitre", "cwe", abstraction.lower() if abstraction else "weakness"],
                metadata={"cwe_id": cwe_id, "abstraction": abstraction, "status": status},
            )


class MitreAttackSource(Source):
    name = "mitre-attack"

    def fetch(self, work_dir: Path) -> None:
        self.git_clone(ATTACK_REPO, work_dir / "attack-stix-data")

    def parse(self, work_dir: Path) -> Iterable[Document]:
        repo = work_dir / "attack-stix-data"
        # We use the enterprise-attack bundle (the most useful one for defenders).
        for matrix in ("enterprise-attack", "mobile-attack", "ics-attack"):
            files = sorted((repo / matrix).glob(f"{matrix}-*.json"))
            if not files:
                continue
            data = json.loads(files[-1].read_text())
            for obj in data.get("objects", []):
                t = obj.get("type")
                if t not in ("attack-pattern", "x-mitre-tactic", "course-of-action", "intrusion-set", "malware", "tool"):
                    continue
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue
                name = obj.get("name") or "(unnamed)"
                desc = obj.get("description") or ""
                if not desc.strip():
                    continue
                ext_id = ""
                refs = obj.get("external_references") or []
                url = ""
                for r in refs:
                    if r.get("source_name", "").startswith("mitre-attack"):
                        ext_id = r.get("external_id", "") or ext_id
                        url = r.get("url", "") or url
                title = f"{ext_id} {name}".strip() if ext_id else name
                yield Document(
                    id=Document.make_id(self.name, obj.get("id", title)),
                    text=f"# {title}\n\n**Type:** {t} ({matrix})\n\n{desc}",
                    title=title,
                    source=self.name,
                    url=url or None,
                    tags=["mitre", "attack", matrix, t],
                    metadata={"matrix": matrix, "stix_type": t, "attack_id": ext_id},
                )
