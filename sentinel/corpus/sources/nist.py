"""NIST Special Publications — selected SP 800 series PDFs.

These are public-domain US government documents. We download a curated set of
the most-relevant ones for security work; the full SP 800 series is hundreds
of documents and most aren't useful for app/infra sec.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from sentinel.corpus.document import Document
from sentinel.corpus.sources.base import Source


log = logging.getLogger(__name__)


# Curated NIST SPs that pay rent for app/infra security work.
NIST_SPS = [
    ("SP 800-53 Rev 5", "Security and Privacy Controls", "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"),
    ("SP 800-61 Rev 2", "Computer Security Incident Handling Guide", "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf"),
    ("SP 800-115", "Technical Guide to Information Security Testing and Assessment", "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf"),
    ("SP 800-171 Rev 2", "Protecting Controlled Unclassified Information", "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r2.pdf"),
    ("SP 800-218", "Secure Software Development Framework (SSDF)", "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf"),
    ("SP 800-63B", "Digital Identity Guidelines: Authentication", "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf"),
    ("SP 800-190", "Application Container Security Guide", "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf"),
    ("SP 800-207", "Zero Trust Architecture", "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf"),
]


class NistSource(Source):
    name = "nist"

    def fetch(self, work_dir: Path) -> None:
        for ident, _title, url in NIST_SPS:
            dest = work_dir / f"{_slug(ident)}.pdf"
            try:
                self.http_get(url, dest)
            except Exception as e:
                log.warning("failed to download %s: %s", ident, e)

    def parse(self, work_dir: Path) -> Iterable[Document]:
        try:
            from pypdf import PdfReader
        except ImportError as e:
            raise RuntimeError("pypdf required: pip install pypdf") from e

        for ident, title, url in NIST_SPS:
            pdf_path = work_dir / f"{_slug(ident)}.pdf"
            if not pdf_path.exists():
                continue
            try:
                reader = PdfReader(str(pdf_path))
            except Exception as e:
                log.warning("could not read %s: %s", pdf_path, e)
                continue
            text_parts = []
            for page in reader.pages:
                try:
                    text_parts.append(page.extract_text() or "")
                except Exception:
                    continue
            text = "\n".join(t for t in text_parts if t.strip())
            if len(text) < 1000:
                continue
            yield Document(
                id=Document.make_id(self.name, ident),
                text=f"# {ident}: {title}\n\n{text}",
                title=f"{ident}: {title}",
                source=self.name,
                url=url,
                tags=["nist", "sp-800", _slug(ident)],
                metadata={"identifier": ident},
            )


def _slug(s: str) -> str:
    return s.lower().replace(" ", "-").replace(".", "-")
