"""Differential reports — finding-level delta between two engagement runs.

Used for re-tests: load `runs/<prior>.json` and `runs/<current>.json`,
fingerprint every finding in each, and produce a markdown delta:

* **Closed** — fingerprints in prior, missing in current. Likely remediated.
* **New** — fingerprints in current, missing in prior. Likely regression
  or newly discovered surface.
* **Severity escalated** — same fingerprint, severity moved up.
* **Severity reduced** — same fingerprint, severity moved down.
* **Persisted** — same fingerprint, same severity.

The PDF reporter consumes the markdown verbatim as a "Delta from prior
engagement" section.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from sentinel.core.findings import Finding, Severity, Status


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class FindingDiff:
    closed: list[Finding] = field(default_factory=list)
    new: list[Finding] = field(default_factory=list)
    escalated: list[tuple[Finding, Severity, Severity]] = field(default_factory=list)
    reduced: list[tuple[Finding, Severity, Severity]] = field(default_factory=list)
    persisted: list[Finding] = field(default_factory=list)

    def is_clean(self) -> bool:
        """True iff the current run has no new or escalated findings."""
        return not self.new and not self.escalated

    def counts(self) -> dict:
        return {
            "closed": len(self.closed),
            "new": len(self.new),
            "escalated": len(self.escalated),
            "reduced": len(self.reduced),
            "persisted": len(self.persisted),
        }


def load_findings(path: Path) -> list[Finding]:
    """Load a runs/<id>.json file into a list of Findings.

    Tolerates both top-level `{findings: [...]}` (current shape) and a
    bare list (older runs) so re-tests across schema changes still work.
    """
    raw = json.loads(Path(path).read_text())
    items = raw.get("findings", raw) if isinstance(raw, dict) else raw
    out: list[Finding] = []
    for d in items:
        out.append(Finding(
            title=d["title"],
            description=d.get("description", ""),
            severity=Severity(d["severity"]),
            scanner=d["scanner"],
            target=d["target"],
            location=d.get("location"),
            cwe=d.get("cwe"),
            cve=d.get("cve"),
            cvss=d.get("cvss"),
            references=d.get("references", []),
            raw=d.get("raw", {}),
            status=Status(d.get("status", "new")),
            remediation=d.get("remediation"),
        ))
    return out


def diff_findings(prior: Iterable[Finding], current: Iterable[Finding]) -> FindingDiff:
    """Compute the delta between two finding sets, keyed by fingerprint."""
    prior_by_fp = {f.fingerprint(): f for f in prior}
    current_by_fp = {f.fingerprint(): f for f in current}

    out = FindingDiff()
    for fp, f in prior_by_fp.items():
        if fp not in current_by_fp:
            out.closed.append(f)
            continue
        cur = current_by_fp[fp]
        if cur.severity == f.severity:
            out.persisted.append(cur)
        elif _SEVERITY_ORDER[cur.severity] < _SEVERITY_ORDER[f.severity]:
            out.escalated.append((cur, f.severity, cur.severity))
        else:
            out.reduced.append((cur, f.severity, cur.severity))

    for fp, f in current_by_fp.items():
        if fp not in prior_by_fp:
            out.new.append(f)

    return out


def render_diff_markdown(diff: FindingDiff, *, prior_label: str = "prior",
                         current_label: str = "current") -> str:
    """Render the diff as a markdown section suitable for inclusion in the PDF."""
    counts = diff.counts()
    lines = [
        f"# Delta from prior engagement",
        "",
        f"_Comparison: **{prior_label}** → **{current_label}**_",
        "",
        f"| Change | Count |",
        f"|---|---|",
        f"| Closed | {counts['closed']} |",
        f"| New | {counts['new']} |",
        f"| Escalated | {counts['escalated']} |",
        f"| Reduced | {counts['reduced']} |",
        f"| Persisted | {counts['persisted']} |",
        "",
    ]

    if diff.is_clean():
        lines.append(
            "**No new or escalated findings.** The engagement is regression-free "
            "relative to the prior run."
        )
        lines.append("")

    if diff.new:
        lines.append("## New findings")
        lines.append("")
        for f in sorted(diff.new, key=lambda x: _SEVERITY_ORDER[x.severity]):
            lines.append(_finding_bullet(f))
        lines.append("")

    if diff.escalated:
        lines.append("## Severity escalated")
        lines.append("")
        for f, old, new in sorted(diff.escalated, key=lambda x: _SEVERITY_ORDER[x[2]]):
            lines.append(
                f"- **{f.title}** — {old.value} → **{new.value}**\n"
                f"    Affected: `{f.target}` ({f.location or 'no location'})\n"
                f"    Scanner: {f.scanner}, CWE: {f.cwe or '-'}, CVE: {f.cve or '-'}"
            )
        lines.append("")

    if diff.reduced:
        lines.append("## Severity reduced")
        lines.append("")
        for f, old, new in sorted(diff.reduced, key=lambda x: _SEVERITY_ORDER[x[2]]):
            lines.append(f"- **{f.title}** — {old.value} → {new.value}")
        lines.append("")

    if diff.closed:
        lines.append("## Closed (likely remediated)")
        lines.append("")
        for f in sorted(diff.closed, key=lambda x: _SEVERITY_ORDER[x.severity]):
            lines.append(_finding_bullet(f))
        lines.append("")

    if diff.persisted and (diff.new or diff.escalated):
        lines.append(f"## Persisted ({len(diff.persisted)} findings unchanged)")
        lines.append("")
        lines.append(
            "_Listed below for completeness — same fingerprint, same severity as the prior run._"
        )
        lines.append("")
        for f in sorted(diff.persisted, key=lambda x: _SEVERITY_ORDER[x.severity])[:20]:
            lines.append(f"- {f.severity.value}: {f.title}")
        if len(diff.persisted) > 20:
            lines.append(f"- … and {len(diff.persisted) - 20} more")
        lines.append("")

    return "\n".join(lines)


def _finding_bullet(f: Finding) -> str:
    return (
        f"- **[{f.severity.value}]** {f.title}\n"
        f"    Affected: `{f.target}` ({f.location or 'no location'})\n"
        f"    Scanner: {f.scanner}, CWE: {f.cwe or '-'}, CVE: {f.cve or '-'}"
    )
