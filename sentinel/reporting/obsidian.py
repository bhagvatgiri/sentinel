"""Obsidian reporter — write per-finding markdown notes into a vault.

Vault layout:
  vault/
    Engagements/
      <client>/
        <engagement_id>/
          README.md                   <- engagement overview, scope summary
          Findings/
            <severity>-<fingerprint>-<slug>.md   <- one per finding
          Scope/
            scope.yaml.snapshot       <- copy of scope file (for audit)
            audit.jsonl.snapshot      <- copy of audit log

Each finding note has YAML frontmatter (severity, status, scanner, etc.) so
Obsidian's Dataview / Tag plugins can roll them up.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Iterable

from sentinel.core.findings import Finding, Severity
from sentinel.core.orchestrator import RunReport
from sentinel.core.scope import Scope
from sentinel.reporting.poc_markdown import render_poc_section


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(s: str, max_len: int = 60) -> str:
    s = _SLUG_RE.sub("-", s.lower()).strip("-")
    return s[:max_len] or "finding"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class ObsidianReporter:
    def __init__(self, vault_path: str | Path):
        self.vault_path = Path(vault_path).expanduser().resolve()

    def engagement_dir(self, scope: Scope) -> Path:
        # Wave 3 — CTF / LAB engagements get redirected to
        # `scope.ctf_box_writeup_dir` (when set) so CTF write-ups never
        # mingle with paid-engagement vault content. Falls back to a
        # `CTF/<client>/<id>` subtree under the same vault if the scope
        # has not declared a separate dir, which still keeps CTF runs
        # visually separated from real engagements.
        from sentinel.core.engagement_mode import EngagementMode
        mode = getattr(scope, "engagement_mode", EngagementMode.PRODUCTION)
        if mode in (EngagementMode.CTF, EngagementMode.LAB):
            override = getattr(scope, "ctf_box_writeup_dir", None)
            if override:
                d = Path(override).expanduser().resolve() / scope.engagement_id
            else:
                d = (
                    self.vault_path / "CTF" / mode.value
                    / slugify(scope.client) / scope.engagement_id
                )
        else:
            d = self.vault_path / "Engagements" / slugify(scope.client) / scope.engagement_id
        (d / "Findings").mkdir(parents=True, exist_ok=True)
        (d / "Scope").mkdir(parents=True, exist_ok=True)
        return d

    def write_report(self, report: RunReport) -> Path:
        scope = report.scope
        # D1 (Wave 8) — pre-deliverable PII gate. Same hook as the PDF
        # reporter; redacts undeclared PII from finding fields BEFORE
        # the markdown notes are persisted into the vault. See
        # `sentinel/agent/pentest/pii_gate.py`.
        try:
            self._apply_pii_gate(report)
        except Exception as e:                          # noqa: BLE001
            import logging as _log
            _log.getLogger(__name__).warning(
                "pii_gate failed during Obsidian write: %s", e
            )
        engagement = self.engagement_dir(scope)

        # Copy scope file + audit log so the vault has the audit artifacts.
        if scope.source_path and scope.source_path.exists():
            shutil.copy2(scope.source_path, engagement / "Scope" / "scope.yaml.snapshot")
        if scope.audit_log and scope.audit_log.path.exists():
            shutil.copy2(scope.audit_log.path, engagement / "Scope" / "audit.jsonl.snapshot")

        # Write per-finding notes.
        findings_dir = engagement / "Findings"
        # Clear stale finding notes from prior runs of this engagement.
        for old in findings_dir.glob("*.md"):
            old.unlink()

        sorted_findings = sorted(
            report.findings,
            key=lambda f: (SEVERITY_ORDER[f.severity], f.scanner, f.title),
        )
        for f in sorted_findings:
            (findings_dir / self._finding_filename(f)).write_text(self._finding_md(f, scope))
            # POC-05 — emit per-finding reproduction note when poc_steps is
            # non-empty. The body is render_poc_section(f) verbatim so what
            # the vault stores is exactly what the H1-paste markdown renderer
            # produces (POC-08 byte-identity invariant; pinned by
            # tests/test_poc_obsidian.py Tests 3 + 10).
            if f.poc_steps:
                (findings_dir / self._reproduction_filename(f)).write_text(
                    self._reproduction_md(f, scope)
                )

        # Write engagement README (table of contents).
        (engagement / "README.md").write_text(self._readme_md(report))
        return engagement

    def _apply_pii_gate(self, report: RunReport) -> None:
        """Redact undeclared PII from finding free-text fields IN-PLACE
        before vault notes are written. Mirrors PDFReporter._apply_pii_gate.
        """
        import os as _os
        from sentinel.agent.pentest import pii_gate

        policy = (_os.getenv("SENTINEL_PII_GATE_POLICY") or "redact").lower()
        if policy not in {"redact", "warn", "block"}:
            policy = "redact"

        scope = report.scope
        audit = getattr(scope, "audit_log", None)
        for f in report.findings or []:
            for attr in ("description", "remediation", "triage_notes"):
                cur = getattr(f, attr, None)
                if not isinstance(cur, str) or not cur.strip():
                    continue
                dec = pii_gate.apply_gate(
                    cur, scope=scope, policy=policy,
                    audit=audit, artifact_name=f"finding:{attr}",
                )
                if not dec.allowed:
                    setattr(f, attr, f"[PII gate blocked: {dec.refused_reason}]")
                elif dec.findings:
                    setattr(f, attr, dec.redacted_text)

    # ---- markdown rendering -------------------------------------------

    def _finding_filename(self, f: Finding) -> str:
        return f"{f.severity.value}-{f.fingerprint()}-{slugify(f.title, 40)}.md"

    def _finding_md(self, f: Finding, scope: Scope) -> str:
        refs = "\n".join(f"  - {r}" for r in (f.references or [])) if f.references else "  - (none)"
        fm = (
            "---\n"
            f"client: {scope.client}\n"
            f"engagement: {scope.engagement_id}\n"
            f"scanner: {f.scanner}\n"
            f"severity: {f.severity.value}\n"
            f"status: {f.status.value}\n"
            f"cwe: {f.cwe or 'null'}\n"
            f"cve: {f.cve or 'null'}\n"
            f"cvss: {f.cvss if f.cvss is not None else 'null'}\n"
            f"fingerprint: {f.fingerprint()}\n"
            f"discovered_at: {f.discovered_at}\n"
            f"tags: [security, finding, severity/{f.severity.value}, scanner/{f.scanner}]\n"
            "---\n\n"
        )
        body = (
            f"# {f.title}\n\n"
            f"**Severity:** {f.severity.value} **Scanner:** {f.scanner} **Status:** {f.status.value}\n\n"
            f"**Target:** `{f.target}`  \n"
            f"**Location:** `{f.location or '(n/a)'}`\n\n"
            f"## Description\n\n{f.description or '(no description provided by scanner)'}\n\n"
            f"## Remediation\n\n{f.remediation or 'Manual review required.'}\n\n"
            f"## Triage notes\n\n{f.triage_notes or '(none)'}\n\n"
            f"## References\n\n{refs}\n"
        )
        # POC-05 — splice a Reproduction section + wikilink BEFORE the
        # References section when poc_steps is non-empty. Assumes
        # `## References` appears exactly once in `body` (verified by
        # reading this method — References is the final section, emitted
        # once). If a future refactor adds a second References block,
        # the `.replace(..., 1)` splice will land in the wrong spot;
        # future-proofing via a sentinel-comment marker is a Phase 5+
        # concern (documented in plan truths).
        if f.poc_steps:
            repro_link = (
                "## Reproduction\n\n"
                f"See [[{f.fingerprint()}-reproduction|reproduction steps]] for "
                "the H1-template Steps to Reproduce block (paste-ready).\n\n"
            )
            body = body.replace("## References\n\n", repro_link + "## References\n\n", 1)
        return fm + body

    # ---- POC-05 — per-finding reproduction notes ----------------------

    def _reproduction_filename(self, f: Finding) -> str:
        """Filename contract: exactly `<fingerprint>-reproduction.md`.

        Used by the main finding note's `[[<fp>-reproduction]]` wikilink;
        any change here must keep that wikilink in sync.
        """
        return f"{f.fingerprint()}-reproduction.md"

    def _reproduction_md(self, f: Finding, scope: Scope) -> str:
        """Return the markdown body for the per-finding reproduction note.

        Layout: YAML frontmatter (client / engagement / severity /
        fingerprint / finding_note / tags) followed by the exact output of
        `render_poc_section(f)` — byte-for-byte identical so the vault
        note and the HackerOne paste match. This is the load-bearing
        POC-08 cross-renderer invariant; pinned by Tests 3 + 10 in
        tests/test_poc_obsidian.py.
        """
        fm = (
            "---\n"
            f"client: {scope.client}\n"
            f"engagement: {scope.engagement_id}\n"
            f"severity: {f.severity.value}\n"
            f"fingerprint: {f.fingerprint()}\n"
            f"finding_note: {self._finding_filename(f)}\n"
            f"tags: [security, reproduction, severity/{f.severity.value}]\n"
            "---\n\n"
        )
        return fm + render_poc_section(f)

    def _readme_md(self, report: RunReport) -> str:
        scope = report.scope
        by_sev: dict[str, list[Finding]] = {}
        for f in report.findings:
            by_sev.setdefault(f.severity.value, []).append(f)

        lines = [
            f"# Engagement: {scope.client} / {scope.engagement_id}",
            "",
            f"- **Authorized by:** {scope.authorized_by}",
            f"- **Validity:** {scope.valid_from} → {scope.valid_until}",
            f"- **Scope file SHA-256:** `{scope.source_hash}`",
            f"- **Scanners run:** {', '.join(report.scanners_run) or '(none)'}",
            f"- **Total findings:** {len(report.findings)}",
            "",
            "## Findings by severity",
            "",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            items = by_sev.get(sev, [])
            if not items:
                continue
            lines.append(f"### {sev.upper()} ({len(items)})")
            lines.append("")
            for f in items:
                fname = self._finding_filename(f)
                lines.append(f"- [[Findings/{fname[:-3]}|{f.title}]] — `{f.scanner}` — `{f.location or f.target}`")
            lines.append("")

        if report.errors:
            lines.append("## Errors / skipped scanners")
            lines.append("")
            for e in report.errors:
                lines.append(f"- {e}")
            lines.append("")

        lines.append("## Audit")
        lines.append("")
        lines.append("- Scope snapshot: `Scope/scope.yaml.snapshot`")
        lines.append("- Audit log: `Scope/audit.jsonl.snapshot` (verifiable via `sentinel verify-audit`)")

        return "\n".join(lines) + "\n"
