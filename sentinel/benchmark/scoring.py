"""Canonical-vuln scoring for the parity benchmark (BENCH-06).

This module turns the parity-eval harness's emitted findings + a target's
`canonical-vulns.yaml` "must-find" list into a per-phase precision /
recall / F1 + verdict ('pass' / 'partial' / 'fail'). Plan 02-02's
`run_parity_eval` calls these functions per (target, profile, phase)
triple; the verdict feeds Plan 02-03's cost-delta Markdown report.

Matching rule (fingerprint-based — NOT fuzzy string match):

    A finding `f` matches a canonical `c` when:
      1. CWE matches exactly (normalized — strip "CWE-" prefix on both
         sides, case-insensitive), OR canonical.cwe is missing.
      2. AND at least one of:
         a) c.detect_hint substring appears in f.location|title
            (case-insensitive).
         b) Any string in c.match_keywords list (default []) appears in
            f.title|description|location (case-insensitive).
         c) c.dvwa_module (default '') substring appears in f.location
            (case-insensitive) — DVWA-specific module-name match.
      3. Tie-break: if multiple canonicals match, pick the
         highest-severity one (critical > high > medium > low > info).
         Emit a DEBUG log listing all candidate ids so the operator can
         refine canonical-vulns.yaml.

Verdict thresholds (BENCH-06):

    F1 >= 0.95 (agentic phases)   → 'pass'
    F1 >= 0.85 (analytical only)  → 'pass'
    F1 >= 0.50 (any phase)        → 'partial'
    otherwise                     → 'fail'

The thresholds are exposed as `F1_THRESHOLDS` so Plan 02-03's report
generator can render the percentage bands without re-importing the
arithmetic.

Hermetic: this module does no I/O. Tests pass synthetic dicts; production
calls feed YAML-loaded dicts. The single source of truth for the F1
math AND the threshold constants is right here.
"""

from __future__ import annotations

import logging
from typing import Optional


log = logging.getLogger(__name__)


# ---- Public constants ---------------------------------------------------

# Agentic phases — the agent loop phases that DO things in the target.
# F1 threshold is tight (0.95) because the pipeline's purpose is to
# identify the canonical vulns; lower coverage means the agent missed
# something the canonical-vulns.yaml says it must find.
AGENTIC_PHASES: list[str] = [
    "recon",
    "vuln:auth",
    "vuln:authz",
    "vuln:idor",
    "vuln:injection",
    "vuln:xss",
    "vuln:ssrf",
    "vuln:csrf",
    "vuln:file_upload",
    "vuln:jwt_oauth",
    "exploit:auth",
    "exploit:authz",
    "exploit:idor",
    "exploit:injection",
    "exploit:xss",
    "exploit:ssrf",
    "exploit:csrf",
    "exploit:file_upload",
    "exploit:jwt_oauth",
    "chain_execute",
]

# Analytical phases — the agent loop phases that REASON OVER findings
# (correlation, deliverable generation). F1 threshold relaxes to 0.85
# because these are inherently fuzzier outputs (narrative + chain
# inference) where the agent's wording need not match the canonical
# entry's wording verbatim.
ANALYTICAL_PHASES: list[str] = ["correlation", "report"]

F1_THRESHOLDS: dict[str, float] = {
    "agentic_pass": 0.95,
    "analytical_pass": 0.85,
    "partial": 0.5,
}

# Severity order — higher index = higher severity. Used for tie-break
# when multiple canonicals match the same finding.
_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ---- Helpers ------------------------------------------------------------


def _normalize_cwe(cwe: Optional[str]) -> Optional[str]:
    """Strip 'CWE-' prefix and uppercase, so 'cwe-89' / 'CWE-89' / '89'
    all compare equal. Returns None if input is falsy.
    """
    if not cwe:
        return None
    s = str(cwe).strip().upper()
    if s.startswith("CWE-"):
        s = s[4:]
    return s


def _contains_ci(haystack: Optional[str], needle: Optional[str]) -> bool:
    """Case-insensitive substring containment. Returns False if either
    side is empty/None.
    """
    if not haystack or not needle:
        return False
    return needle.lower() in haystack.lower()


def _severity_rank(sev: Optional[str]) -> int:
    """Return 0..4 for known severity strings, -1 for unknown."""
    if not sev:
        return -1
    return _SEVERITY_ORDER.get(str(sev).strip().lower(), -1)


# ---- Matching -----------------------------------------------------------


def match_finding_to_canonical(
    finding: dict,
    canonical_vulns: list[dict],
) -> Optional[str]:
    """Return the canonical id that best matches `finding`, or None.

    See module docstring for the full matching rule. On tie-break,
    picks the highest-severity canonical and logs a DEBUG line listing
    all candidates.

    Args:
        finding: One emitted-finding dict. Expected keys: 'cwe',
            'location', 'title', optionally 'description'.
        canonical_vulns: List of canonical-vuln dicts (from one target's
            canonical-vulns.yaml). Each entry's matchable fields: 'cwe',
            'detect_hint', 'match_keywords' (list), 'dvwa_module',
            'severity'.

    Returns:
        Matching canonical's 'id', or None if no canonical matches.
    """
    finding_cwe = _normalize_cwe(finding.get("cwe"))
    finding_loc = finding.get("location") or ""
    finding_title = finding.get("title") or ""
    finding_desc = finding.get("description") or ""

    candidates: list[dict] = []

    for c in canonical_vulns:
        c_cwe = _normalize_cwe(c.get("cwe"))
        # Rule 1: CWE must match (case-insensitive, normalized) OR
        # canonical.cwe is None/missing.
        if c_cwe is not None and c_cwe != finding_cwe:
            continue

        # Rule 2: at least one of detect_hint / match_keywords /
        # dvwa_module substring matches finding fields.
        detect_hint = c.get("detect_hint") or ""
        match_keywords = c.get("match_keywords") or []
        dvwa_module = c.get("dvwa_module") or ""

        hit_via_hint = (
            _contains_ci(finding_loc, detect_hint)
            or _contains_ci(finding_title, detect_hint)
        )
        hit_via_keyword = any(
            _contains_ci(finding_title, kw)
            or _contains_ci(finding_desc, kw)
            or _contains_ci(finding_loc, kw)
            for kw in match_keywords
        )
        hit_via_dvwa_module = bool(dvwa_module) and _contains_ci(
            finding_loc, dvwa_module
        )

        if hit_via_hint or hit_via_keyword or hit_via_dvwa_module:
            candidates.append(c)

    if not candidates:
        return None

    if len(candidates) == 1:
        return candidates[0].get("id")

    # Tie-break: pick highest severity. Log all candidates so the operator
    # sees the ambiguity and can refine canonical-vulns.yaml.
    candidates.sort(
        key=lambda c: _severity_rank(c.get("severity")),
        reverse=True,
    )
    candidate_ids = [c.get("id") for c in candidates]
    log.debug(
        "match_finding_to_canonical: tie-break for finding %r — candidates=%s "
        "(picked highest severity: %s)",
        finding.get("title") or finding.get("location"),
        candidate_ids,
        candidates[0].get("id"),
    )
    return candidates[0].get("id")


# ---- Scoring ------------------------------------------------------------


def score_phase(
    emitted_findings: list[dict],
    expected_canonicals: list[dict],
) -> dict:
    """Score one phase's emitted findings against the canonical "must-find" list.

    Args:
        emitted_findings: Findings the agent emitted during this phase.
        expected_canonicals: Subset of canonical_vulns where expected_phase
            equals this phase's name.

    Returns:
        Dict with:
          precision (float), recall (float), f1 (float),
          tp (int), fp (int), fn (int),
          matched_canonical_ids (list[str]) — each id appears at most once,
          unmatched_canonical_ids (list[str]) — canonicals with no
              successful match (the FN set).

    Math:
        tp: emitted finding matches a canonical AND that canonical hasn't
            yet been claimed by a prior tp this phase (duplicate emitted
            matches count as FP).
        fp: emitted finding matched nothing OR matched a canonical already
            claimed by a prior tp.
        fn: canonical entries with no successful emitted match.
        precision = tp / (tp + fp)   (0 if denom is 0)
        recall    = tp / (tp + fn)   (0 if denom is 0)
        f1        = 2 * P * R / (P + R)   (0 if denom is 0)
    """
    matched_canonical_ids: list[str] = []
    matched_set: set[str] = set()
    tp = 0
    fp = 0

    for finding in emitted_findings:
        cid = match_finding_to_canonical(finding, expected_canonicals)
        if cid is None:
            fp += 1
            continue
        if cid in matched_set:
            # Duplicate match to a canonical we already counted as TP.
            fp += 1
            continue
        matched_set.add(cid)
        matched_canonical_ids.append(cid)
        tp += 1

    fn = len(expected_canonicals) - tp
    unmatched_canonical_ids = [
        c.get("id") for c in expected_canonicals
        if c.get("id") not in matched_set
    ]

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (
        (2 * precision * recall / (precision + recall))
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "matched_canonical_ids": matched_canonical_ids,
        "unmatched_canonical_ids": unmatched_canonical_ids,
    }


# ---- Verdict tagging ----------------------------------------------------


def verdict_for_phase(phase: str, f1: float) -> str:
    """Map (phase name, F1 score) → 'pass' / 'partial' / 'fail'.

    Agentic phases (recon / vuln:* / exploit:* / chain_execute) gate
    `pass` at F1 >= 0.95. Analytical phases (correlation / report) gate
    `pass` at F1 >= 0.85. Below 0.5 is 'fail' regardless. Between the
    relaxed threshold and 0.5 is 'partial'.

    Unknown phase names fall back to the agentic threshold (the safer,
    stricter default) and emit a warning log so the operator sees that
    canonical-vulns.yaml referenced a phase the scorer doesn't track.
    """
    if phase in AGENTIC_PHASES:
        pass_threshold = F1_THRESHOLDS["agentic_pass"]
    elif phase in ANALYTICAL_PHASES:
        pass_threshold = F1_THRESHOLDS["analytical_pass"]
    else:
        log.warning(
            "verdict_for_phase: unknown phase %r — falling back to agentic "
            "threshold (F1 >= %s for pass). Add %r to AGENTIC_PHASES or "
            "ANALYTICAL_PHASES if this is intentional.",
            phase, F1_THRESHOLDS["agentic_pass"], phase,
        )
        pass_threshold = F1_THRESHOLDS["agentic_pass"]

    if f1 >= pass_threshold:
        return "pass"
    if f1 >= F1_THRESHOLDS["partial"]:
        return "partial"
    return "fail"


__all__ = [
    "AGENTIC_PHASES",
    "ANALYTICAL_PHASES",
    "F1_THRESHOLDS",
    "match_finding_to_canonical",
    "score_phase",
    "verdict_for_phase",
]
