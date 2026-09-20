"""Wave 4 / A6 — per-finding ATT&CK + CAPEC tagging tests.

Pins the CWE / vuln-class → MITRE technique + CAPEC pattern table from
paper 2510.17521 Tables 10-12. Sentinel groups findings into 12 vuln
classes plus 3 CTF-mode classes. Each maps deterministically to ATT&CK +
CAPEC ID lists; this test file is the table's executable contract.
"""

from __future__ import annotations

import pytest

from sentinel.core.attack_mapper import (
    CLASS_TO_ATTACK_CAPEC,
    TACTIC_ORDER,
    group_by_tactic,
    infer_attack_capec,
    tactic_for_technique,
    tag_finding,
)
from sentinel.core.findings import Finding, Severity


# --------------------------------------------------------------------------
# Default schema
# --------------------------------------------------------------------------


def test_finding_default_attack_and_capec_lists_are_empty():
    f = Finding(title="t", description="d", severity=Severity.HIGH,
                scanner="s", target="https://x")
    assert f.attack_technique_ids == []
    assert f.capec_ids == []


# --------------------------------------------------------------------------
# Per-class lookups (the table from paper 2510.17521 Tables 10-12)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vuln_class,expected_tids,expected_capecs",
    [
        ("auth",       ["T1078", "T1133"],            ["CAPEC-22"]),
        ("idor",       ["T1190"],                     ["CAPEC-66", "CAPEC-39"]),
        ("authz",      ["T1190"],                     ["CAPEC-180"]),
        ("injection",  ["T1190"],                     ["CAPEC-66", "CAPEC-88", "CAPEC-242"]),
        ("xss",        ["T1059.007"],                 ["CAPEC-63"]),
        ("ssrf",       ["T1190", "T1102"],            ["CAPEC-664"]),
        ("csrf",       ["T1190"],                     ["CAPEC-62"]),
        ("jwt_oauth",  ["T1078", "T1556"],            ["CAPEC-94"]),
        ("file_upload",["T1190", "T1505.003"],        ["CAPEC-1"]),
        ("cors",       ["T1190"],                     ["CAPEC-141"]),
        ("crlf",       ["T1190"],                     ["CAPEC-86", "CAPEC-105"]),
        ("websocket",  ["T1190"],                     ["CAPEC-31"]),
        ("webshell",   ["T1505.003"],                 ["CAPEC-650"]),
        ("rce",        ["T1059"],                     ["CAPEC-248"]),
        ("persistence",["T1053.003"],                 ["CAPEC-549"]),
    ],
)
def test_class_to_attack_capec_table(vuln_class, expected_tids, expected_capecs):
    """Every Sentinel-known vuln class has the expected ATT&CK + CAPEC IDs."""
    actual_tids, actual_capecs = CLASS_TO_ATTACK_CAPEC[vuln_class]
    assert actual_tids == expected_tids
    assert actual_capecs == expected_capecs


def test_class_table_covers_all_vuln_classes():
    """Every class in vuln_classes.VULN_CLASSES must have an entry."""
    from sentinel.agent.pentest.vuln_classes import VULN_CLASSES
    for v in VULN_CLASSES:
        assert v.slug in CLASS_TO_ATTACK_CAPEC, (
            f"class {v.slug} has no ATT&CK/CAPEC mapping; "
            "add one to sentinel.core.attack_mapper.CLASS_TO_ATTACK_CAPEC"
        )


# --------------------------------------------------------------------------
# Inference paths (raw vuln_class hint, CWE fallback, title fallback)
# --------------------------------------------------------------------------


def test_infer_via_raw_vuln_class_hint():
    f = Finding(title="x", description="d", severity=Severity.HIGH,
                scanner="s", target="t",
                raw={"vulnerability_class": "xss"})
    tids, caps = infer_attack_capec(f)
    assert "T1059.007" in tids
    assert "CAPEC-63" in caps


def test_infer_via_cwe_fallback():
    """A Finding with only a CWE (no vuln_class hint) still gets tagged
    via the CWE → class fallback table."""
    f = Finding(title="generic finding", description="", severity=Severity.HIGH,
                scanner="semgrep", target="t", cwe="CWE-89")
    tids, caps = infer_attack_capec(f)
    assert tids == ["T1190"]
    assert "CAPEC-66" in caps


def test_infer_via_title_keyword():
    f = Finding(title="Reflected XSS in /search query parameter",
                description="d", severity=Severity.MEDIUM,
                scanner="custom", target="t")
    tids, caps = infer_attack_capec(f)
    assert tids == ["T1059.007"]


def test_infer_unknown_returns_empty():
    """A finding with no class hint, unknown CWE, generic title returns ([], [])."""
    f = Finding(title="some weird issue", description="d",
                severity=Severity.LOW, scanner="s", target="t",
                cwe="CWE-99999")  # not in the fallback table
    tids, caps = infer_attack_capec(f)
    assert tids == []
    assert caps == []


# --------------------------------------------------------------------------
# tag_finding mutates in place
# --------------------------------------------------------------------------


def test_tag_finding_populates_lists():
    f = Finding(title="SQL injection in /login", description="",
                severity=Severity.HIGH, scanner="s", target="t")
    out = tag_finding(f)
    assert out is f
    assert "T1190" in f.attack_technique_ids
    assert "CAPEC-66" in f.capec_ids


def test_tag_finding_idempotent():
    f = Finding(title="CSRF on /transfer", description="", severity=Severity.HIGH,
                scanner="s", target="t")
    tag_finding(f)
    first_tids = list(f.attack_technique_ids)
    first_caps = list(f.capec_ids)
    tag_finding(f)
    assert f.attack_technique_ids == first_tids
    assert f.capec_ids == first_caps


# --------------------------------------------------------------------------
# Triage path tags every finding automatically
# --------------------------------------------------------------------------


def test_triage_path_auto_tags_findings():
    """The triage step (no LLM) must tag every Finding."""
    from sentinel.core.triage import triage_all
    findings = [
        Finding(title="SQLi in /api", description="", severity=Severity.HIGH,
                scanner="semgrep", target="t", cwe="CWE-89"),
        Finding(title="Reflected XSS", description="",
                severity=Severity.MEDIUM, scanner="semgrep", target="t"),
        Finding(title="SSRF in webhook URL", description="",
                severity=Severity.HIGH, scanner="semgrep", target="t",
                cwe="CWE-918"),
    ]
    triage_all(findings, ollama=None)
    assert "T1190" in findings[0].attack_technique_ids
    assert "T1059.007" in findings[1].attack_technique_ids
    assert "T1102" in findings[2].attack_technique_ids


# --------------------------------------------------------------------------
# tactic_for_technique
# --------------------------------------------------------------------------


def test_tactic_for_technique_known_ids():
    assert tactic_for_technique("T1190") == "Initial Access"
    assert tactic_for_technique("T1059.007") == "Execution"
    assert tactic_for_technique("T1505.003") == "Persistence"
    assert tactic_for_technique("T1556") == "Credential Access"


def test_tactic_for_technique_falls_back_to_parent():
    """A future sub-technique not in the table should resolve via parent."""
    # T1059.999 doesn't exist; T1059 is "Execution".
    assert tactic_for_technique("T1059.999") == "Execution"


def test_tactic_for_technique_unknown_returns_none():
    assert tactic_for_technique("T9999") is None
    assert tactic_for_technique("") is None


# --------------------------------------------------------------------------
# group_by_tactic + 3+-tactic heatmap rendering
# --------------------------------------------------------------------------


def test_group_by_tactic_spans_at_least_three_tactics():
    """A mixed engagement should plot multiple distinct tactics on the heatmap."""
    findings = [
        Finding(title="SQLi", description="", severity=Severity.HIGH,
                scanner="s", target="t", cwe="CWE-89"),                 # Initial Access
        Finding(title="Reflected XSS", description="", severity=Severity.MEDIUM,
                scanner="s", target="t"),                                # Execution
        Finding(title="Web shell at /uploads/x.php", description="",
                severity=Severity.CRITICAL, scanner="s", target="t",
                cwe="CWE-434"),                                          # Initial Access via file_upload
        Finding(title="cron persistence on host", description="",
                severity=Severity.HIGH, scanner="s", target="t"),        # Persistence
        Finding(title="Modify Authentication Process JWT confusion",
                description="", severity=Severity.HIGH, scanner="s",
                target="t", raw={"vuln_class": "jwt_oauth"}),            # Credential Access (T1556)
    ]
    for f in findings:
        tag_finding(f)

    groups = group_by_tactic(findings)
    assert "Initial Access" in groups
    assert "Execution" in groups
    assert "Persistence" in groups or "Credential Access" in groups
    # At minimum, 3 distinct tactics with non-zero coverage.
    assert len(groups) >= 3


def test_group_by_tactic_skips_untagged_findings():
    f = Finding(title="weird thing", description="", severity=Severity.LOW,
                scanner="s", target="t")
    groups = group_by_tactic([f])
    assert groups == {}


def test_tactic_order_is_canonical_attack_enterprise():
    """Pin the canonical ATT&CK enterprise tactic ordering."""
    expected_first = "Initial Access"
    expected_last = "Impact"
    assert TACTIC_ORDER[0] == expected_first
    assert TACTIC_ORDER[-1] == expected_last
    # Privilege Escalation comes before Defense Evasion in the canonical
    # enterprise matrix.
    assert TACTIC_ORDER.index("Privilege Escalation") < TACTIC_ORDER.index("Defense Evasion")


# --------------------------------------------------------------------------
# Web event styling (the dashboard registers attack_tactic_<slug> rows)
# --------------------------------------------------------------------------


def test_event_styles_register_per_tactic_keys():
    from sentinel.web.event_styles import EVENT_STYLES, attack_tactic_slug
    # Every canonical tactic must have a registered style — slug coverage.
    for tactic in TACTIC_ORDER:
        slug = attack_tactic_slug(tactic)
        assert slug in EVENT_STYLES, (
            f"missing event-styles entry for {slug} (tactic '{tactic}')"
        )


def test_attack_tactic_slug_round_trip():
    from sentinel.web.event_styles import attack_tactic_slug
    assert attack_tactic_slug("Initial Access") == "attack_tactic_initial_access"
    assert attack_tactic_slug("Privilege Escalation") == "attack_tactic_privilege_escalation"
    assert attack_tactic_slug("Command and Control") == "attack_tactic_command_and_control"
