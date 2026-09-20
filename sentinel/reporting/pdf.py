"""Compile a client-facing PDF deliverable from an Obsidian engagement folder.

Pure Python (no Pandoc required) using reportlab. Section structure:
  1. Cover (client, engagement, dates, scope hash)
  2. Executive summary (Ollama-generated if available, else stats-only)
  3. Scope summary
  4. Findings (grouped by severity)
  5. Audit log statement (hash + verification command)
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from sentinel.core.findings import Finding, Severity
from sentinel.core.orchestrator import RunReport
from sentinel.core.scope import Scope
from sentinel.llm.ollama_client import OllamaClient


SEVERITY_COLORS = {
    Severity.CRITICAL: colors.HexColor("#7f1d1d"),
    Severity.HIGH: colors.HexColor("#b91c1c"),
    Severity.MEDIUM: colors.HexColor("#b45309"),
    Severity.LOW: colors.HexColor("#1e40af"),
    Severity.INFO: colors.HexColor("#374151"),
}


class PDFReporter:
    def __init__(self, output_dir: str | Path, ollama: Optional[OllamaClient] = None):
        self.output_dir = Path(output_dir).expanduser().resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.ollama = ollama

    def write(self, report: RunReport) -> Path:
        scope = report.scope
        # D1 (Wave 8) — pre-deliverable PII gate. Every finding's free-text
        # fields (description / remediation / triage_notes) gets passed
        # through `pii_gate.apply_gate` so a non-target IP / personal email
        # accidentally pasted in by an agent gets redacted (or the write
        # gets blocked, depending on policy). Defaults to redact + audit.
        # See `sentinel/agent/pentest/pii_gate.py`.
        try:
            self._apply_pii_gate(report)
        except Exception as e:                          # noqa: BLE001
            # Gate failures must not crash report generation; log + carry
            # on. The gate writes its own audit trail so an operator can
            # see what happened.
            import logging as _log
            _log.getLogger(__name__).warning(
                "pii_gate failed during PDF write: %s", e
            )
        path = self.output_dir / f"{scope.client}-{scope.engagement_id}.pdf"
        doc = SimpleDocTemplate(
            str(path),
            pagesize=LETTER,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            title=f"Security Assessment — {scope.client}",
            author="Sentinel",
        )
        styles = self._styles()
        story: list = []

        # Wave 3 — non-production engagements get a giant red banner
        # PREPENDED before the cover. This makes accidental hand-off of a
        # CTF / LAB / BBP-research deliverable to a paying client
        # structurally impossible: the banner is the first thing the
        # reader sees + the document is otherwise visually unchanged.
        story += self._mode_banner(scope, styles)
        story += self._cover(scope, styles)
        story.append(PageBreak())
        story += self._exec_summary(report, styles)
        story.append(PageBreak())
        story += self._scope_summary(scope, styles)
        story.append(PageBreak())
        story += self._findings_section(report, styles)
        story.append(PageBreak())
        # Wave 4 / A6 — ATT&CK heatmap section
        story += self._attack_heatmap_section(report, styles)
        story.append(PageBreak())
        story += self._audit_section(scope, styles)

        doc.build(story)
        return path

    def _apply_pii_gate(self, report: RunReport) -> None:
        """D1 — redact undeclared PII from finding free-text fields
        IN-PLACE before the PDF gets rendered.

        Policy is "redact" (not "block") — Sentinel deliberately does
        NOT refuse to write a PDF; it rewrites and audit-logs. An
        operator who wants strict-block can override per-engagement
        via env var SENTINEL_PII_GATE_POLICY=block.
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
                    # Block policy — bake the refusal into the field so
                    # the operator can see it in the rendered PDF.
                    setattr(f, attr, f"[PII gate blocked: {dec.refused_reason}]")
                elif dec.findings:
                    setattr(f, attr, dec.redacted_text)

    def _mode_banner(self, scope: Scope, styles: dict) -> list:
        """Wave 3 — return a red-on-white banner block when the
        engagement mode is anything other than production. Empty list
        for production runs (the default). Banner is large and
        first-on-page so the reader cannot miss it."""
        # Lazy import — keeps PDF reporter importable in environments
        # where the engagement_mode module may not have been touched yet.
        from sentinel.core.engagement_mode import EngagementMode
        mode = getattr(scope, "engagement_mode", EngagementMode.PRODUCTION)
        if mode == EngagementMode.PRODUCTION:
            return []
        banner_style = ParagraphStyle(
            "ModeBanner", parent=styles["Title"],
            fontSize=20, leading=24,
            textColor=colors.HexColor("#ffffff"),
            backColor=colors.HexColor("#7f1d1d"),
            alignment=1,  # center
            spaceAfter=12, spaceBefore=12,
            borderPadding=12,
        )
        sub_style = ParagraphStyle(
            "ModeBannerSub", parent=styles["Body"],
            fontSize=12, leading=16,
            textColor=colors.HexColor("#7f1d1d"),
            alignment=1,
            spaceAfter=18,
        )
        return [
            Paragraph(
                f"{mode.value.upper()} ENGAGEMENT — NOT A CLIENT DELIVERABLE",
                banner_style,
            ),
            Paragraph(
                f"This document was produced from a Sentinel run in "
                f"<b>{mode.value}</b> mode. {mode.value.upper()} runs unlock "
                "tactics that are forbidden in paid engagements (webshells, "
                "reverse shells, code execution). Do NOT forward this PDF to "
                "a client; the audit log will reflect the mode mismatch and "
                "the laundering attempt is detectable post-hoc.",
                sub_style,
            ),
        ]

    # ---- sections ------------------------------------------------------

    def _styles(self) -> dict:
        base = getSampleStyleSheet()
        return {
            "Title": ParagraphStyle("Title", parent=base["Title"], fontSize=22, leading=26, spaceAfter=18),
            "H1": ParagraphStyle("H1", parent=base["Heading1"], fontSize=16, leading=20, spaceBefore=12, spaceAfter=8),
            "H2": ParagraphStyle("H2", parent=base["Heading2"], fontSize=13, leading=16, spaceBefore=10, spaceAfter=6),
            "Body": ParagraphStyle("Body", parent=base["BodyText"], fontSize=10, leading=14),
            "Mono": ParagraphStyle("Mono", parent=base["Code"], fontSize=8, leading=10),
            "Meta": ParagraphStyle("Meta", parent=base["BodyText"], fontSize=9, leading=12, textColor=colors.HexColor("#6b7280")),
        }

    def _cover(self, scope: Scope, styles: dict) -> list:
        return [
            Paragraph("Security Assessment Report", styles["Title"]),
            Paragraph(f"<b>Client:</b> {scope.client}", styles["Body"]),
            Paragraph(f"<b>Engagement ID:</b> {scope.engagement_id}", styles["Body"]),
            Paragraph(f"<b>Authorized by:</b> {scope.authorized_by}", styles["Body"]),
            Paragraph(f"<b>Validity:</b> {scope.valid_from} to {scope.valid_until}", styles["Body"]),
            Paragraph(f"<b>Report generated:</b> {datetime.utcnow().isoformat()}Z", styles["Body"]),
            Spacer(1, 0.3 * inch),
            Paragraph(
                "This report covers only the assets explicitly listed in the engagement scope. "
                "All scanning activity is logged in a hash-chained audit trail; see appendix.",
                styles["Meta"],
            ),
        ]

    def _exec_summary(self, report: RunReport, styles: dict) -> list:
        scope = report.scope
        story = [Paragraph("Executive Summary", styles["H1"])]
        summary = None
        if self.ollama and self.ollama.is_available():
            summary = self.ollama.summarize_engagement(report.findings, scope.client)
        if not summary:
            counts = self._severity_counts(report.findings)
            total = sum(counts.values())
            summary = (
                f"This engagement identified {total} security finding(s) for {scope.client}. "
                f"Severity breakdown: critical={counts.get('critical', 0)}, high={counts.get('high', 0)}, "
                f"medium={counts.get('medium', 0)}, low={counts.get('low', 0)}, info={counts.get('info', 0)}. "
                "Findings are detailed in the section that follows along with recommended remediation."
            )
        story.append(Paragraph(summary, styles["Body"]))
        return story

    def _scope_summary(self, scope: Scope, styles: dict) -> list:
        story = [Paragraph("Scope", styles["H1"])]
        rows = [
            ["Client", scope.client],
            ["Engagement ID", scope.engagement_id],
            ["Authorized by", scope.authorized_by],
            ["Authorization doc", scope.authorization_doc or "(not provided)"],
            ["Validity", f"{scope.valid_from} to {scope.valid_until}"],
            ["Scope file SHA-256", scope.source_hash],
            ["Repos in scope", ", ".join(scope.repos) or "(none)"],
            ["Domains in scope", ", ".join(scope.domains) or "(none)"],
            ["IPs in scope", ", ".join(scope.ips) or "(none)"],
            ["Out of scope", ", ".join(scope.out_of_scope) or "(none)"],
            ["Rate limit (rps)", str(scope.rate_limit_rps)],
        ]
        table = Table(rows, colWidths=[1.6 * inch, 5.0 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(table)
        return story

    def _findings_section(self, report: RunReport, styles: dict) -> list:
        story = [Paragraph("Findings", styles["H1"])]
        findings = sorted(
            report.findings,
            key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[f.severity.value], f.scanner),
        )
        if not findings:
            story.append(Paragraph("No findings.", styles["Body"]))
            return story

        # Wave 4 / A5 — Constraint gradation table immediately after the
        # heading. Honest snapshot of which findings clear Lab / Operational
        # / Complete conditions before the per-finding detail dump.
        story += self._gradation_table(findings, styles)

        for f in findings:
            color = SEVERITY_COLORS.get(f.severity, colors.black)
            story.append(
                Paragraph(
                    f"<b><font color='{color.hexval()}'>[{f.severity.value.upper()}]</font></b> {_esc(f.title)}",
                    styles["H2"],
                )
            )
            story.append(
                Paragraph(
                    f"<b>Scanner:</b> {f.scanner} &nbsp; <b>Status:</b> {f.status.value} &nbsp; "
                    f"<b>CWE:</b> {f.cwe or '-'} &nbsp; <b>CVE:</b> {f.cve or '-'} &nbsp; "
                    f"<b>CVSS:</b> {f.cvss if f.cvss is not None else '-'}",
                    styles["Meta"],
                )
            )
            # Wave 4 / A5+A6 — gradation + ATT&CK/CAPEC line on every finding.
            grad = (
                f"<b>Lab:</b> {_check(f.reproduces_in_lab)} &nbsp; "
                f"<b>Operational:</b> {_check(f.reproduces_under_operational)} &nbsp; "
                f"<b>Complete:</b> {_check(f.reproduces_complete)}"
            )
            story.append(Paragraph(grad, styles["Meta"]))
            tags = (
                f"<b>ATT&amp;CK:</b> {', '.join(f.attack_technique_ids) or '—'} &nbsp; "
                f"<b>CAPEC:</b> {', '.join(f.capec_ids) or '—'}"
            )
            story.append(Paragraph(tags, styles["Meta"]))
            story.append(Paragraph(f"<b>Target:</b> {_esc(f.target)}", styles["Body"]))
            if f.location:
                story.append(Paragraph(f"<b>Location:</b> <font face='Courier'>{_esc(f.location)}</font>", styles["Body"]))
            if f.description:
                story.append(Paragraph(f"<b>Description:</b> {_esc(f.description)}", styles["Body"]))
            if f.remediation:
                story.append(Paragraph(f"<b>Remediation:</b> {_esc(f.remediation)}", styles["Body"]))
            if f.triage_notes:
                story.append(Paragraph(f"<b>Notes:</b> {_esc(f.triage_notes)}", styles["Meta"]))
            # Phase 4 / POC-04 — Reproduction tab per finding. Additive: legacy
            # findings without poc_steps get an explicit "No automated
            # reproduction available" fallback line under the heading rather
            # than skipping the section entirely (so operators notice that the
            # finding wasn't autoexploited and needs manual investigation).
            story.extend(self._render_poc_section(f, styles))
            story.append(Spacer(1, 0.12 * inch))
        return story

    def _render_poc_section(self, finding: Finding, styles: dict) -> list:
        """Phase 4 / POC-04 — Reproduction tab for a single finding.

        Returns a list of reportlab flowables that compose the per-finding
        Reproduction section. Always emits the H2 'Reproduction' heading.

        - Empty `finding.poc_steps`: heading + explicit
          "No automated reproduction available — manual investigation required"
          fallback paragraph.
        - Non-empty: heading + per-step block (Step N: description,
          monospace command, Expected output:, monospace expected_output,
          optional embedded screenshot, small Spacer).

        Screenshot handling:
          - `step.screenshot_path` is Optional[str]. When set + the file
            exists, embed via `Image(path, width=5.5*inch, kind='proportional')`.
          - When set but missing/unreadable, emit a Meta paragraph
            "(screenshot unavailable: <path>)" so the operator notices.
          - When unset, skip the screenshot slot entirely.

        Hermetic: no network, no subprocess, no LLM. Pure reportlab
        flowables built from in-memory PocStep data + local file reads.
        """
        out: list = [Paragraph("Reproduction", styles["H2"])]

        if not finding.poc_steps:
            out.append(
                Paragraph(
                    "No automated reproduction available — "
                    "manual investigation required.",
                    styles["Body"],
                )
            )
            return out

        for step in finding.poc_steps:
            out.append(
                Paragraph(
                    f"<b>Step {step.step_number}:</b> {_esc(step.description)}",
                    styles["Body"],
                )
            )
            # Preserve embedded newlines in monospace command + expected_output
            # by translating to <br/> (reportlab Paragraph honors <br/>).
            cmd_html = _esc(step.command).replace("\n", "<br/>")
            out.append(
                Paragraph(
                    f"<font face='Courier'>{cmd_html}</font>",
                    styles["Mono"],
                )
            )
            out.append(Paragraph("<b>Expected output:</b>", styles["Body"]))
            expected = step.expected_output if step.expected_output else "(no output captured)"
            exp_html = _esc(expected).replace("\n", "<br/>")
            out.append(
                Paragraph(
                    f"<font face='Courier'>{exp_html}</font>",
                    styles["Mono"],
                )
            )
            if step.screenshot_path:
                p = Path(step.screenshot_path)
                if p.is_file():
                    try:
                        # Compute proportional dimensions ourselves so the
                        # image fits the printable page width while
                        # preserving its aspect ratio. reportlab's
                        # kind='proportional' requires both width AND
                        # height; computing via Pillow keeps the call
                        # simple (Pillow is already a reportlab dep).
                        from PIL import Image as PILImage
                        with PILImage.open(str(p)) as _im:
                            iw, ih = _im.size
                        target_w = 5.5 * inch
                        if iw and ih:
                            scale = target_w / iw
                            target_h = ih * scale
                        else:  # pragma: no cover - defensive
                            target_h = target_w
                        out.append(
                            Image(
                                str(p),
                                width=target_w,
                                height=target_h,
                            )
                        )
                    except Exception:
                        # Corrupt PNG / unreadable format / pillow rejected
                        # the file -> graceful fallback. Catching broad
                        # Exception per existing PDFReporter pattern.
                        out.append(
                            Paragraph(
                                f"(screenshot unavailable: {p})",
                                styles["Meta"],
                            )
                        )
                else:
                    out.append(
                        Paragraph(
                            f"(screenshot unavailable: {p})",
                            styles["Meta"],
                        )
                    )
            out.append(Spacer(1, 0.08 * inch))
        return out

    def _gradation_table(self, findings: list[Finding], styles: dict) -> list:
        """Wave 4 / A5 — per-finding Lab / Operational / Complete table."""
        rows = [["ID", "Severity", "Lab", "Operational", "Complete", "Title"]]
        for f in findings:
            fid = (f.raw or {}).get("entry_id") if isinstance(f.raw, dict) else None
            fid = fid or f.fingerprint()
            rows.append([
                str(fid),
                f.severity.value.upper(),
                _check(f.reproduces_in_lab),
                _check(f.reproduces_under_operational),
                _check(f.reproduces_complete),
                (f.title or "")[:60],
            ])
        table = Table(rows, colWidths=[1.0 * inch, 0.7 * inch, 0.5 * inch,
                                          0.9 * inch, 0.7 * inch, 2.8 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR",  (0, 0), (-1, 0), colors.HexColor("#ffffff")),
                    ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        return [
            Paragraph("Constraint Gradation (Lab / Operational / Complete)", styles["H2"]),
            Paragraph(
                "Per the constraint-aware methodology in the 2510.17521 paper: a finding "
                "may pass the weak Lab condition yet fail Operational (probe pushes >5% "
                "error rate / requires destructive testing) or Complete (a synthesised "
                "remediation patch blocks the same probe on a fixture). Honest reporting.",
                styles["Meta"],
            ),
            table,
            Spacer(1, 0.12 * inch),
        ]

    def _attack_heatmap_section(self, report: RunReport, styles: dict) -> list:
        """Wave 4 / A6 — kill-chain coverage matrix grouped by ATT&CK tactic."""
        from sentinel.core.attack_mapper import (
            TACTIC_ORDER, group_by_tactic, tactic_for_technique,
        )

        story = [Paragraph("ATT&CK Coverage Heatmap", styles["H1"])]
        if not report.findings:
            story.append(Paragraph("No findings — no coverage to plot.", styles["Body"]))
            return story

        groups = group_by_tactic(report.findings)
        rows = [["Tactic", "Findings exercising", "Technique IDs"]]
        for tactic in TACTIC_ORDER:
            buc = groups.get(tactic, [])
            tids: list[str] = []
            for f in buc:
                for tid in f.attack_technique_ids:
                    if tactic_for_technique(tid) == tactic and tid not in tids:
                        tids.append(tid)
            rows.append([tactic, str(len(buc)), ", ".join(tids) or "—"])

        table = Table(rows, colWidths=[2.2 * inch, 1.6 * inch, 2.8 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR",  (0, 0), (-1, 0), colors.HexColor("#ffffff")),
                    ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(
            Paragraph(
                "Per-finding ATT&amp;CK technique IDs grouped by kill-chain tactic. "
                "Tactics with zero coverage are explicit '—' rows so the operator can see "
                "what the engagement <i>did not</i> exercise.",
                styles["Meta"],
            )
        )
        story.append(table)
        return story

    def _audit_section(self, scope: Scope, styles: dict) -> list:
        log_path = scope.audit_log.path if scope.audit_log else None
        return [
            Paragraph("Appendix: Audit", styles["H1"]),
            Paragraph(
                "Every authorization decision made during this engagement was recorded in a "
                "hash-chained append-only log. Tampering with any record invalidates the chain "
                "and is detectable.",
                styles["Body"],
            ),
            Spacer(1, 0.1 * inch),
            Paragraph(f"Scope file SHA-256: <font face='Courier'>{scope.source_hash}</font>", styles["Body"]),
            Paragraph(f"Audit log path: <font face='Courier'>{log_path}</font>", styles["Body"]),
            Paragraph(
                "Verification: <font face='Courier'>sentinel verify-audit &lt;path&gt;</font>",
                styles["Body"],
            ),
        ]

    @staticmethod
    def _severity_counts(findings: list[Finding]) -> dict:
        out: dict = {}
        for f in findings:
            out[f.severity.value] = out.get(f.severity.value, 0) + 1
        return out


def _esc(s: str | None) -> str:
    if s is None:
        return ""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _check(b: bool) -> str:
    """Wave 4 / A5 — render a boolean as a check / cross glyph for the
    gradation table. Kept as a module-level helper so tests can import it."""
    return "" if b else ""
