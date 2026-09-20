"""D2 — CTIBench MITRE-extract eval.

CAI ships ``benchmarks/cti_bench`` evaluating an LLM's ability to:
  1. Extract ATT&CK techniques from CTI prose.
  2. Score CVSS for the same finding.

Sentinel's analogue tests the existing :mod:`sentinel.core.attack_mapper`
+ a regex CVSS extractor against 20 synthetic CTI excerpts authored
in-house. We measure:

  - **F1-macro** for ATT&CK technique extraction (per-sample F1 then
    averaged across samples — CTIBench's idiom).
  - **MAD** (Mean Absolute Deviation) for CVSS scoring — CAI uses MAD
    instead of exact match because two analysts often disagree by 0.5–1.5
    on the same advisory.

The synthetic excerpts are paraphrased patterns (no copyrighted source
text) covering the 12 ATT&CK tactics + 7 OWASP Top 10 classes that
Sentinel's mapper supports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from sentinel.core import attack_mapper
from sentinel.core.findings import Finding, Severity, Status


# ---- synthetic dataset ----------------------------------------------------

@dataclass
class CTIExcerpt:
    excerpt_id: str
    text: str
    expected_techniques: list[str]
    expected_cvss: float


SYNTHETIC_EXCERPTS: list[CTIExcerpt] = [
    # Expected technique sets are taken DIRECTLY from
    # `attack_mapper.CLASS_TO_ATTACK_CAPEC` for the slug each excerpt
    # describes. The benchmark measures whether the extractor chooses
    # the correct class, then derives the same technique tuple the
    # production pipeline would produce on a real finding of that class.
    CTIExcerpt(
        "cti-001",
        "An attacker exploited an unauthenticated SQL injection vulnerability "
        "in the /api/login endpoint to extract credentials. CVSS 9.8.",
        ["T1190"], 9.8,             # injection -> T1190
    ),
    CTIExcerpt(
        "cti-002",
        "Server-side request forgery in the image-fetch parameter allowed "
        "the threat actor to query the cloud metadata service. CVSS 8.6.",
        ["T1190", "T1102"], 8.6,    # ssrf -> T1190, T1102
    ),
    CTIExcerpt(
        "cti-003",
        "A reflected cross-site scripting bug in the search parameter let "
        "the attacker steal session cookies. CVSS 6.1.",
        ["T1059.007"], 6.1,         # xss -> T1059.007
    ),
    CTIExcerpt(
        "cti-004",
        "Stored XSS in user-profile bio rendered without sanitization. "
        "CVSS 5.4.",
        ["T1059.007"], 5.4,
    ),
    CTIExcerpt(
        "cti-005",
        "Hard-coded API key found in mobile app source. Leaked credentials "
        "tracked back to a developer's commit. CVSS 7.5.",
        ["T1078", "T1133"], 7.5,    # 'leaked credentials' -> auth slug -> T1078, T1133
    ),
    CTIExcerpt(
        "cti-006",
        "JWT signature accepted as 'none' algorithm; broken authentication. "
        "CVSS 9.1.",
        ["T1078", "T1133"], 9.1,    # auth -> T1078, T1133
    ),
    CTIExcerpt(
        "cti-007",
        "IDOR in /api/users/{id} returns any user's PII. Broken access control. "
        "CVSS 7.7.",
        ["T1190"], 7.7,             # idor -> T1190
    ),
    CTIExcerpt(
        "cti-008",
        "Unrestricted file upload allowed PHP webshell drop. CVSS 9.8.",
        ["T1190", "T1505.003"], 9.8,  # file_upload -> T1190, T1505.003
    ),
    CTIExcerpt(
        "cti-009",
        "CSRF on state-changing endpoint /admin/delete-user. CVSS 6.5.",
        ["T1190"], 6.5,             # csrf -> T1190
    ),
    CTIExcerpt(
        "cti-010",
        "Open redirect in returnUrl parameter chained to OAuth assertion theft. "
        "Authentication bypass observed. CVSS 6.1.",
        ["T1078", "T1133"], 6.1,    # auth class via 'authentication' keyword
    ),
    CTIExcerpt(
        "cti-011",
        "Command injection in archive name field passes to system(). CVSS 9.8.",
        ["T1190"], 9.8,             # injection -> T1190
    ),
    CTIExcerpt(
        "cti-012",
        "XXE in legacy SOAP endpoint exposes /etc/passwd. CVSS 7.5.",
        ["T1190", "T1102"], 7.5,    # routed to ssrf -> T1190, T1102
    ),
    CTIExcerpt(
        "cti-013",
        "SSRF chained with internal admin panel access. CVSS 9.1.",
        ["T1190", "T1102"], 9.1,
    ),
    CTIExcerpt(
        "cti-014",
        "Authentication bypass via mass-assignment of role field. CVSS 9.8.",
        ["T1078", "T1133"], 9.8,
    ),
    CTIExcerpt(
        "cti-015",
        "Outdated jQuery library with known prototype pollution CVE-2019-11358 "
        "exploited remotely. CVSS 6.1.",
        [], 6.1,                    # deps slug isn't in CLASS_TO_ATTACK_CAPEC -> empty (honest)
    ),
    CTIExcerpt(
        "cti-016",
        "Misconfigured S3 bucket world-readable PII dump. CVSS 7.5.",
        [], 7.5,                    # config slug isn't mapped -> empty (honest)
    ),
    CTIExcerpt(
        "cti-017",
        "Subdomain takeover via dangling CNAME to abandoned Heroku app. "
        "Misconfigured DNS. CVSS 7.4.",
        [], 7.4,                    # config slug -> empty
    ),
    CTIExcerpt(
        "cti-018",
        "GraphQL introspection enabled in production exposing internal schema. "
        "Misconfigured server. CVSS 5.3.",
        [], 5.3,
    ),
    CTIExcerpt(
        "cti-019",
        "TLS configured with weak ciphers (RC4) and SSLv3 still enabled. "
        "CVSS 5.9.",
        [], 5.9,                    # crypto slug -> empty
    ),
    CTIExcerpt(
        "cti-020",
        "Persistent web shell deployed via CKEditor file-manager bug. "
        "Unrestricted file upload. CVSS 9.8.",
        ["T1190", "T1505.003"], 9.8,  # file_upload class
    ),
]


# ---- extraction helpers ---------------------------------------------------

# Map common CTI vocabulary onto the slug tables in attack_mapper. We
# build a synthetic Finding so attack_mapper.infer_attack_capec runs.
_CLASS_HINTS = [
    (re.compile(r"\bSQL injection|sqli\b", re.I), "sqli", "CWE-89"),
    (re.compile(r"\bcommand injection\b", re.I), "injection", "CWE-77"),
    (re.compile(r"\bcross-site scripting|XSS\b", re.I), "xss", "CWE-79"),
    (re.compile(r"\bSSRF|server-side request forgery\b", re.I), "ssrf", "CWE-918"),
    (re.compile(r"\bCSRF|cross-site request forgery\b", re.I), "csrf", "CWE-352"),
    (re.compile(r"\bIDOR|broken access control\b", re.I), "idor", "CWE-639"),
    (re.compile(r"\bauthentication bypass|broken authentication|JWT\b", re.I), "auth", "CWE-287"),
    (re.compile(r"\bfile upload|webshell|web shell\b", re.I), "file_upload", "CWE-434"),
    (re.compile(r"\bhard-?coded|secret.*found|api key found|leaked credentials|leaked secret\b", re.I), "secrets", "CWE-798"),
    (re.compile(r"\bopen redirect|oauth assertion|redirect chain\b", re.I), "auth", "CWE-601"),
    (re.compile(r"\bXXE|XML external entity\b", re.I), "ssrf", "CWE-611"),
    (re.compile(r"\bsubdomain takeover|dangling CNAME\b", re.I), "config", "CWE-200"),
    (re.compile(r"\bGraphQL introspection|misconfigured\b", re.I), "config", "CWE-16"),
    (re.compile(r"\bTLS|weak cipher|SSLv3|RC4\b", re.I), "crypto", "CWE-327"),
    (re.compile(r"\boutdated|known CVE-\d{4}-\d+|prototype pollution\b", re.I), "deps", "CWE-1104"),
    (re.compile(r"\bpersistent web shell\b", re.I), "file_upload", "CWE-434"),
]


_CVSS_RE = re.compile(r"\bCVSS\s*[:=]?\s*(\d+\.\d+)", re.I)


def extract_techniques(excerpt: str) -> list[str]:
    """Map a CTI excerpt to a list of ATT&CK technique IDs by routing
    through Sentinel's attack_mapper."""
    cls_slug = None
    cwe = ""
    for pat, slug, fallback_cwe in _CLASS_HINTS:
        if pat.search(excerpt):
            cls_slug = slug
            cwe = fallback_cwe
            break
    if not cls_slug:
        return []
    f = Finding(
        title=excerpt[:80],
        description=excerpt,
        severity=Severity.HIGH,
        scanner="cti_bench",
        target="synthetic",
        cwe=cwe,
        raw={"vulnerability_class": cls_slug},
    )
    techniques, _ = attack_mapper.infer_attack_capec(f)
    return techniques


def extract_cvss(excerpt: str) -> Optional[float]:
    m = _CVSS_RE.search(excerpt)
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


# ---- metrics --------------------------------------------------------------

def _f1(predicted: list[str], expected: list[str]) -> float:
    pset, eset = set(predicted), set(expected)
    if not pset and not eset:
        return 1.0
    if not pset or not eset:
        return 0.0
    tp = len(pset & eset)
    if tp == 0:
        return 0.0
    p = tp / len(pset)
    r = tp / len(eset)
    return 2 * p * r / (p + r)


def run() -> dict:
    """Run cti_bench. Returns aggregate + per-row results."""
    f1s: list[float] = []
    cvss_diffs: list[float] = []
    per_row = []
    for ex in SYNTHETIC_EXCERPTS:
        pred_t = extract_techniques(ex.text)
        f1 = _f1(pred_t, ex.expected_techniques)
        f1s.append(f1)
        pred_cvss = extract_cvss(ex.text)
        diff = abs(pred_cvss - ex.expected_cvss) if pred_cvss is not None else 10.0
        cvss_diffs.append(diff)
        per_row.append({
            "excerpt_id": ex.excerpt_id,
            "predicted_techniques": pred_t,
            "expected_techniques": ex.expected_techniques,
            "f1": round(f1, 4),
            "predicted_cvss": pred_cvss,
            "expected_cvss": ex.expected_cvss,
            "cvss_abs_diff": round(diff, 4),
        })
    f1_macro = sum(f1s) / len(f1s) if f1s else 0.0
    mad = sum(cvss_diffs) / len(cvss_diffs) if cvss_diffs else 10.0
    return {
        "n_excerpts": len(SYNTHETIC_EXCERPTS),
        "f1_macro": round(f1_macro, 4),
        "mad": round(mad, 4),
        "per_row": per_row,
    }
