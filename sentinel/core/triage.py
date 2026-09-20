"""Finding triage — dedupe across scanners, FP filtering, remediation enrichment.

Two-pass design:
  1. Rule-based dedup by fingerprint (always runs).
  2. Optional LLM pass (Ollama) for FP scoring + remediation text. If the LLM
     is unavailable, we fall back to scanner-provided text and mark the
     finding as triaged with a note.
"""

from __future__ import annotations

import logging
from typing import Optional

from sentinel.core.attack_mapper import tag_finding
from sentinel.core.findings import Finding, Severity, Status
from sentinel.llm.ollama_client import OllamaClient


log = logging.getLogger(__name__)


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicates across scanners by fingerprint, keeping highest severity."""
    by_fp: dict[str, Finding] = {}
    severity_rank = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    for f in findings:
        fp = f.fingerprint()
        existing = by_fp.get(fp)
        if existing is None or severity_rank[f.severity] > severity_rank[existing.severity]:
            by_fp[fp] = f
    return list(by_fp.values())


def triage_all(
    findings: list[Finding],
    ollama: Optional[OllamaClient] = None,
    fp_threshold: float = 0.85,
    retriever=None,  # Optional[sentinel.rag.retriever.Retriever]; loose typing avoids hard import
) -> list[Finding]:
    """Triage findings in place. Returns the same list (mutated).

    If `retriever` is provided, RAG context is fetched per-finding and passed
    to the LLM so remediation is grounded in the corpus.
    """
    use_llm = ollama is not None and ollama.is_available()
    if not use_llm and ollama is not None:
        log.warning("Ollama not available; falling back to rule-based triage only.")

    for finding in findings:
        # Wave 4 / A6 — auto-tag every finding with ATT&CK + CAPEC IDs.
        # Idempotent; runs whether or not the LLM is available.
        tag_finding(finding)
        if use_llm:
            rag_context = None
            if retriever is not None:
                try:
                    from sentinel.rag.retriever import format_context
                    chunks = retriever.retrieve_for_finding(finding)
                    rag_context = format_context(chunks) if chunks else None
                except Exception as e:  # never fail triage because of RAG
                    log.warning("RAG retrieval failed for %s: %s", finding.fingerprint(), e)
            result = ollama.triage_finding(finding, rag_context=rag_context)
            fp_score = float(result.get("false_positive_likelihood", 0.0) or 0.0)
            remediation = _coerce_text(result.get("remediation"))
            notes = _coerce_text(result.get("confidence_notes"))
            if remediation:
                finding.remediation = remediation
            if notes:
                finding.triage_notes = notes
            if fp_score >= fp_threshold:
                finding.status = Status.FALSE_POSITIVE
                finding.triage_notes = (notes or "") + f" [auto-FP score={fp_score:.2f}]"
            else:
                finding.status = Status.TRIAGED
        else:
            finding.status = Status.TRIAGED
            if not finding.remediation:
                finding.remediation = _heuristic_remediation(finding)

    return findings


def _coerce_text(value) -> str | None:
    """LLM may return remediation/notes as a string, list, or dict; normalize to string."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(f"- {item}" if isinstance(item, str) else f"- {item!r}" for item in value)
    return str(value)


def _heuristic_remediation(f: Finding) -> str:
    """Best-effort remediation when no LLM is available."""
    s = f.scanner
    if s == "gitleaks":
        return (
            "Rotate the exposed credential immediately. Revoke the leaked value, scrub "
            "from git history with git-filter-repo or BFG, and route future secrets "
            "through a secret manager (Vault, AWS Secrets Manager, etc.)."
        )
    if s == "osv-scanner" or s == "trivy":
        if f.cve:
            return f"Upgrade the affected package to a version that addresses {f.cve}. Verify with the project's security advisory."
        return "Upgrade the affected package to the latest patched version."
    if s == "semgrep":
        return "Review the flagged code path against the rule's guidance. Consult linked references for safe coding patterns."
    if s == "checkov":
        return "Apply the misconfiguration's documented remediation; consult the Checkov guideline link in references."
    if s == "nuclei":
        return "Validate the finding manually, then patch the underlying service or remove the exposure per the linked references."
    return "Manual review required."
