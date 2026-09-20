"""Wave 4 / A6 — per-finding MITRE ATT&CK + CAPEC tagging.

Paper 2510.17521 Tables 10-12 ship technique IDs + CAPEC pattern IDs per
finding. That little bit of taxonomy is what makes a kill-chain coverage
matrix possible — a deliverable section CAI doesn't produce.

The mapping table is intentionally hardcoded (not a remote lookup). The
ATT&CK technique IDs are stable across years; CAPEC IDs are stable as
well. A nightly remote refresh would add ops burden for no analytic gain.

Public API:
    infer_attack_capec(finding) -> (technique_ids, capec_ids)
    tactic_for_technique(technique_id) -> ATT&CK tactic name
    group_by_tactic(findings) -> {tactic: [Finding]}

Mapping covers the 12 vuln classes Sentinel knows about plus three CTF
classes (webshell discovery, RCE, persistence). Anything else falls back
to an empty result — no lie, just no tag.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.core.findings import Finding


# ---------------------------------------------------------------------------
# Vuln-class → (ATT&CK techniques, CAPEC patterns)
# ---------------------------------------------------------------------------

# Each entry is the canonical mapping for the vuln class slug as used in
# sentinel.agent.pentest.vuln_classes.VULN_CLASSES. The CTF-mode classes
# (webshell, rce, persistence) are not in VULN_CLASSES but show up via
# inference from CWE / title for findings produced by CTF agents.
CLASS_TO_ATTACK_CAPEC: dict[str, tuple[list[str], list[str]]] = {
    # ------------- Phase 2 vuln classes (production / BBP) -----------------
    "auth": (
        ["T1078", "T1133"],            # Valid Accounts; External Remote Services
        ["CAPEC-22"],                  # Exploiting Trust in Client
    ),
    "idor": (
        ["T1190"],                     # Exploit Public-Facing Application
        ["CAPEC-66", "CAPEC-39"],      # SQLi-adapted; opaque-token tampering
    ),
    "authz": (
        ["T1190"],
        ["CAPEC-180"],                 # Exploiting Incorrectly Configured ACLs
    ),
    "injection": (
        ["T1190"],
        ["CAPEC-66", "CAPEC-88", "CAPEC-242"],  # SQLi; OS-cmd; code injection
    ),
    "xss": (
        ["T1059.007"],                 # Command and Scripting Interpreter: JS
        ["CAPEC-63"],                  # XSS
    ),
    "ssrf": (
        ["T1190", "T1102"],            # Exploit PFA; Web Service
        ["CAPEC-664"],                 # SSRF
    ),
    "csrf": (
        ["T1190"],
        ["CAPEC-62"],                  # CSRF
    ),
    "jwt_oauth": (
        ["T1078", "T1556"],            # Valid Accounts; Modify Authentication Process
        ["CAPEC-94"],                  # Adversary in the Middle
    ),
    "file_upload": (
        ["T1190", "T1505.003"],        # Exploit PFA; Web Shell
        ["CAPEC-1"],                   # Accessing Functionality Not Properly Constrained by ACLs
    ),
    "cors": (
        ["T1190"],
        ["CAPEC-141"],                 # Cache Poisoning (loose; CORS misconfig has no perfect single CAPEC)
    ),
    "crlf": (
        ["T1190"],
        ["CAPEC-86", "CAPEC-105"],     # XML Injection adapted; HTTP Request Smuggling
    ),
    "websocket": (
        ["T1190"],
        ["CAPEC-31"],                  # Accessing/Intercepting/Modifying HTTP Cookies
    ),

    # ------------- CTF-mode classes (only emitted in non-production) -------
    # Discovered as an existing artifact; NOT when Sentinel itself drops one.
    "webshell": (
        ["T1505.003"],                 # Server Software Component: Web Shell
        ["CAPEC-650"],                 # Upload a Web Shell to a Web Server
    ),
    "rce": (
        ["T1059"],                     # Command and Scripting Interpreter
        ["CAPEC-248"],                 # Command Injection
    ),
    "persistence": (
        ["T1053.003"],                 # Scheduled Task/Job: Cron
        ["CAPEC-549"],                 # Local Execution of Code
    ),
}


# ---------------------------------------------------------------------------
# CWE → vuln-class fallback
# ---------------------------------------------------------------------------

# When the finding doesn't carry a vuln_class hint (e.g. a Semgrep finding
# from the SAST cache, or a third-party scanner that only emits CWE), map
# the CWE to a class. The mapping is a small, hand-curated table; unknown
# CWEs return None so we don't over-tag.
_CWE_TO_CLASS: dict[str, str] = {
    "CWE-287": "auth",
    "CWE-307": "auth",
    "CWE-345": "jwt_oauth",
    "CWE-285": "authz",
    "CWE-639": "idor",
    "CWE-89": "injection",
    "CWE-77": "injection",
    "CWE-78": "injection",
    "CWE-94": "injection",
    "CWE-917": "injection",   # EL injection
    "CWE-79": "xss",
    "CWE-918": "ssrf",
    "CWE-352": "csrf",
    "CWE-434": "file_upload",
    "CWE-22": "file_upload",  # path traversal
    "CWE-98": "file_upload",  # PHP file inclusion
    "CWE-942": "cors",
    "CWE-93": "crlf",
    "CWE-113": "crlf",        # CRLF in HTTP headers
}


# ---------------------------------------------------------------------------
# Title-keyword fallback (last-ditch when no CWE / class hint)
# ---------------------------------------------------------------------------

_TITLE_TO_CLASS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bxss\b|cross[- ]site script", re.I), "xss"),
    (re.compile(r"\bcsrf\b|cross[- ]site request", re.I), "csrf"),
    (re.compile(r"\bssrf\b|server[- ]side request forg", re.I), "ssrf"),
    (re.compile(r"\bidor\b|insecure direct object", re.I), "idor"),
    (re.compile(r"\bsqli?\b|sql injection", re.I), "injection"),
    (re.compile(r"command injection|os command", re.I), "injection"),
    (re.compile(r"template injection|ssti\b", re.I), "injection"),
    (re.compile(r"\bjwt\b|\boauth\b|\bsaml\b|\boidc\b", re.I), "jwt_oauth"),
    (re.compile(r"open redirect", re.I), "auth"),
    (re.compile(r"path traversal|directory traversal|\blfi\b|\brfi\b", re.I), "file_upload"),
    (re.compile(r"file upload", re.I), "file_upload"),
    (re.compile(r"\bcors\b", re.I), "cors"),
    (re.compile(r"\bcrlf\b|header injection|response splitting", re.I), "crlf"),
    (re.compile(r"websocket|cswsh", re.I), "websocket"),
    (re.compile(r"web ?shell|webshell", re.I), "webshell"),
    (re.compile(r"\brce\b|remote code execution", re.I), "rce"),
    (re.compile(r"persistence|cron|systemd timer", re.I), "persistence"),
    (re.compile(r"missing.*auth|brute force|credential|session token|password policy", re.I), "auth"),
    (re.compile(r"privilege escalat|broken access control|missing function.level", re.I), "authz"),
]


def _class_from_finding(finding: "Finding") -> str | None:
    """Best-effort vuln-class slug for a finding.

    Lookup order:
        1. explicit `vulnerability_type` on the finding's `raw` dict
        2. CWE → class table
        3. title regex
    """
    raw = getattr(finding, "raw", None) or {}
    if isinstance(raw, dict):
        vt = (raw.get("vulnerability_class") or raw.get("vuln_class")
              or raw.get("class_slug") or "").strip().lower()
        if vt and vt in CLASS_TO_ATTACK_CAPEC:
            return vt

    cwe = (getattr(finding, "cwe", None) or "").strip().upper()
    if cwe in _CWE_TO_CLASS:
        return _CWE_TO_CLASS[cwe]

    title = (getattr(finding, "title", "") or "")
    for pat, slug in _TITLE_TO_CLASS:
        if pat.search(title):
            return slug

    return None


def infer_attack_capec(finding: "Finding") -> tuple[list[str], list[str]]:
    """Return (technique_ids, capec_ids) for a Finding. Empty lists if no class match."""
    slug = _class_from_finding(finding)
    if not slug:
        return [], []
    techniques, capecs = CLASS_TO_ATTACK_CAPEC.get(slug, ([], []))
    return list(techniques), list(capecs)


# ---------------------------------------------------------------------------
# ATT&CK technique → tactic
# ---------------------------------------------------------------------------

# Hardcoded tactic mapping for every technique the table above can emit.
# Sources: https://attack.mitre.org/techniques/T<id>/
TECHNIQUE_TO_TACTIC: dict[str, str] = {
    "T1078":     "Defense Evasion",       # Valid Accounts spans multiple; primary kill-chain stage for our use is initial-access alt
    "T1133":     "Initial Access",        # External Remote Services
    "T1190":     "Initial Access",        # Exploit Public-Facing Application
    "T1102":     "Command and Control",   # Web Service (also Exfil)
    "T1059":     "Execution",             # Command and Scripting Interpreter
    "T1059.007": "Execution",             # JS sub-technique
    "T1505.003": "Persistence",           # Web Shell
    "T1053.003": "Persistence",           # Scheduled Task: Cron
    "T1556":     "Credential Access",     # Modify Authentication Process
}

# Conventional ATT&CK enterprise tactic ordering used in the heatmap.
TACTIC_ORDER: list[str] = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def tactic_for_technique(technique_id: str) -> str | None:
    """Return the ATT&CK tactic for a technique ID, or None if unknown."""
    if not technique_id:
        return None
    # Normalise: T1190 + T1190.001 both map via the parent if no exact hit.
    if technique_id in TECHNIQUE_TO_TACTIC:
        return TECHNIQUE_TO_TACTIC[technique_id]
    parent = technique_id.split(".", 1)[0]
    return TECHNIQUE_TO_TACTIC.get(parent)


def group_by_tactic(findings: list["Finding"]) -> dict[str, list["Finding"]]:
    """Bucket findings by ATT&CK tactic. A finding with multiple techniques
    appears under each distinct tactic. Findings with no tags are excluded."""
    out: dict[str, list["Finding"]] = {t: [] for t in TACTIC_ORDER}
    for f in findings:
        tactics_seen: set[str] = set()
        for tid in f.attack_technique_ids:
            tactic = tactic_for_technique(tid)
            if tactic and tactic not in tactics_seen:
                out.setdefault(tactic, []).append(f)
                tactics_seen.add(tactic)
    # Drop empty tactics so dashboard doesn't render a wall of "0".
    return {t: lst for t, lst in out.items() if lst}


def tag_finding(finding: "Finding") -> "Finding":
    """In-place tag a Finding with technique + CAPEC IDs. Idempotent — calling
    twice just sets the same values. Returns the same Finding for chaining."""
    techniques, capecs = infer_attack_capec(finding)
    finding.attack_technique_ids = techniques
    finding.capec_ids = capecs
    return finding
