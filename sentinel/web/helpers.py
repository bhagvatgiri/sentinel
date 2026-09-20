"""Render-side helpers used in route handlers.

XSS-safe wrappers + small utility functions. Templates handle most escaping
via Jinja2 autoescape; these helpers cover edge cases (markdown bodies that
need image-stripping, severity → label, etc.).
"""

from __future__ import annotations

import html
import re
from typing import Iterable


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


_MARKDOWN_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^\)]*\)")
_MARKDOWN_LINK_DANGEROUS = re.compile(
    r"(\[[^\]]*\]\()\s*(javascript:|data:|vbscript:|file:)([^\)]*\))",
    re.IGNORECASE,
)
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def safe_markdown(text: str) -> str:
    """Strip ![images], disarm javascript:/data:/vbscript:/file: URL schemes,
    strip raw HTML tags. Pair with a markdown-to-HTML renderer in the template
    OR display the cleaned text inside <p> with line-break preservation."""
    if not text:
        return ""
    text = _MARKDOWN_IMAGE_RE.sub("[image removed]", text)
    text = _MARKDOWN_LINK_DANGEROUS.sub(r"\1[blocked-scheme] removed\3", text)
    text = _HTML_TAG_RE.sub("", text)
    return text


def safe_html(text) -> str:
    return html.escape(str(text or ""), quote=True)


def severity_breakdown(findings: list[dict]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        out[sev] = out.get(sev, 0) + 1
    return out


def sort_by_severity(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: SEVERITY_RANK.get((f.get("severity") or "info").lower(), 99))


def filter_findings(
    findings: list[dict],
    severities: Iterable[str] | None = None,
    scanners: Iterable[str] | None = None,
    statuses: Iterable[str] | None = None,
    cwe_substr: str = "",
    hide_fp: bool = True,
) -> list[dict]:
    """Apply UI filters. Empty iterables (None or empty list) = no filter on that dim."""
    sev_set = {s.lower() for s in severities} if severities else None
    sca_set = {s for s in scanners} if scanners else None
    sta_set = {s for s in statuses} if statuses else None

    out = []
    for f in findings:
        if sev_set and (f.get("severity") or "info").lower() not in sev_set:
            continue
        if sca_set and (f.get("scanner") or "?") not in sca_set:
            continue
        if sta_set and (f.get("status") or "new") not in sta_set:
            continue
        if hide_fp and (f.get("status") == "false_positive"):
            continue
        if cwe_substr and cwe_substr.lower() not in (f.get("cwe") or "").lower():
            continue
        out.append(f)
    return out
