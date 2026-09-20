"""B13 — Blue-Team agent tests.

Synthetic findings → assert Sigma rule emission, NIST CSF mapping,
and end-to-end deliverable generation. Tests are pure-Python with
no external services.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from sentinel.agent.pentest.blue_teamer import (
    CIS_V8_MAPPING,
    NIST_CSF_MAPPING,
    emit_sigma_rule,
    emit_suricata_rule,
    emit_yara_rule,
    generate_blue_team_deliverables,
    map_to_cis_v8,
    map_to_nist_csf,
)


# ---- mapping helpers ----------------------------------------------------

def test_map_to_nist_csf_known_classes():
    """Each known vuln_class returns at least one CSF subcategory."""
    for cls in ("auth", "authz", "injection", "sqli", "xss", "ssrf",
                  "csrf", "idor", "file_upload", "secrets",
                  "crypto", "config", "deps"):
        subs = map_to_nist_csf(cls)
        assert subs, f"no NIST CSF mapping for {cls}"
        # Each entry is a CSF identifier shape (e.g., PR.AC-1)
        for s in subs:
            assert re.match(r"^[A-Z]{2}\.[A-Z]{2}-\d+$", s), (
                f"invalid CSF subcategory shape: {s}"
            )


def test_map_to_cis_v8_known_classes_have_controls():
    for cls in ("auth", "injection", "sqli", "xss"):
        ctrls = map_to_cis_v8(cls)
        assert ctrls, f"no CIS Controls mapping for {cls}"


def test_map_to_nist_csf_unknown_class_returns_empty():
    assert map_to_nist_csf("nonexistent_class") == []


# ---- Sigma rule emission ------------------------------------------------

def _xss_finding():
    return {
        "id": "XSS-VULN-01",
        "title": "Reflected XSS in /search",
        "description": "User input reflected unsanitized in search results page",
        "vuln_class": "xss",
        "severity": "high",
        "cwe": "CWE-79",
        "location": "/search",
    }


def _idor_finding():
    return {
        "id": "IDOR-VULN-03",
        "title": "Direct user-id access in /api/users",
        "description": "Object id parameter not authorization-checked",
        "vuln_class": "idor",
        "severity": "medium",
        "cwe": "CWE-639",
        "location": "/api/users",
    }


def _ssrf_finding():
    return {
        "id": "SSRF-VULN-02",
        "title": "SSRF via image-fetch parameter",
        "description": "url= parameter accepts arbitrary scheme/host",
        "vuln_class": "ssrf",
        "severity": "critical",
        "cwe": "CWE-918",
        "location": "/api/fetch-image",
    }


def test_emit_sigma_rule_xss_valid_yaml_shape():
    rule = emit_sigma_rule(_xss_finding())
    # Validate YAML by parsing if pyyaml is available; otherwise check
    # textual shape (no @-skipping / no broken indentation).
    try:
        import yaml
        loaded = yaml.safe_load(rule)
    except ImportError:
        # PyYAML unavailable — fall back to structural assertions.
        loaded = None

    if loaded is not None:
        assert "title" in loaded
        assert "id" in loaded
        assert "logsource" in loaded
        assert "detection" in loaded
        assert "level" in loaded
        assert loaded["level"] == "high"
        assert loaded["logsource"]["category"] == "webserver"
        det = loaded["detection"]
        # Must have a `selection:` block + `condition:` line
        assert "condition" in det

    # Always assert text features
    assert "Reflected XSS in /search" in rule
    assert "level: high" in rule
    assert "/search" in rule
    assert "<script" in rule
    # NIST CSF tags wired in
    assert "nist.csf." in rule


def test_emit_sigma_rule_idor_uses_csf_subcategories():
    rule = emit_sigma_rule(_idor_finding())
    # IDOR maps to PR.AC-4 + DE.CM-3
    assert "nist.csf.pr_ac_4" in rule
    assert "nist.csf.de_cm_3" in rule


def test_emit_sigma_rule_severity_normalization():
    f = _xss_finding()
    f["severity"] = "INFO"   # uppercase
    rule = emit_sigma_rule(f)
    assert "level: informational" in rule
    f["severity"] = "unknown"
    rule = emit_sigma_rule(f)
    assert "level: medium" in rule


def test_emit_sigma_rule_stable_id_for_same_finding():
    f1 = _xss_finding()
    f2 = _xss_finding()
    r1 = emit_sigma_rule(f1)
    r2 = emit_sigma_rule(f2)
    # Same finding → same UUID
    id_rx = re.compile(r"^id:\s+([a-f0-9-]{36})", re.MULTILINE)
    m1 = id_rx.search(r1)
    m2 = id_rx.search(r2)
    assert m1 and m2
    assert m1.group(1) == m2.group(1)


# ---- YARA rule emission --------------------------------------------------

def test_emit_yara_rule_for_file_upload():
    f = {
        "id": "UPLOAD-VULN-01",
        "title": "Arbitrary file upload to /api/avatar",
        "vuln_class": "file_upload",
        "severity": "critical",
    }
    rule = emit_yara_rule(f)
    assert rule is not None
    assert "rule sentinel_UPLOAD_VULN_01" in rule
    assert "<?php" in rule
    assert "any of ($s*)" in rule


def test_emit_yara_rule_returns_none_for_xss():
    """XSS isn't a file-bound class; no YARA needed."""
    rule = emit_yara_rule(_xss_finding())
    assert rule is None


def test_emit_yara_rule_for_secrets():
    f = {
        "id": "SECRET-01",
        "title": "AWS access key leaked in repo",
        "description": "AKIA-prefixed key found in commit history",
        "vuln_class": "secrets",
        "severity": "high",
    }
    rule = emit_yara_rule(f)
    assert rule is not None
    assert "AKIA" in rule


# ---- Suricata rule emission ---------------------------------------------

def test_emit_suricata_rule_xss():
    rule = emit_suricata_rule(_xss_finding())
    assert rule is not None
    assert 'msg:"Sentinel: XSS attempt against /search"' in rule
    assert "sid:" in rule
    assert "metadata:sentinel_finding" in rule


def test_emit_suricata_rule_sqli_includes_pcre():
    f = {
        "id": "SQLI-01",
        "title": "Time-based SQLi in /search",
        "vuln_class": "sqli",
        "severity": "critical",
        "location": "/search",
    }
    rule = emit_suricata_rule(f)
    assert rule is not None
    assert "pcre:" in rule
    assert "UNION" in rule


def test_emit_suricata_rule_returns_none_for_secrets():
    """Secret leaks aren't network-detectable in transit."""
    f = {
        "id": "SECRET-01",
        "vuln_class": "secrets",
        "severity": "high",
    }
    rule = emit_suricata_rule(f)
    assert rule is None


# ---- end-to-end deliverable generation ----------------------------------

def test_generate_blue_team_deliverables_emits_files(tmp_path):
    findings = [_xss_finding(), _idor_finding(), _ssrf_finding()]
    out = generate_blue_team_deliverables(
        findings, workspace=str(tmp_path),
        target="api.acme.example", engagement_id="2026-XX-XX-test",
    )
    rules_dir = Path(out["rules_dir"])
    rec_path = Path(out["recommendations"])

    # All three findings produced sigma rules
    sigma_files = list(rules_dir.glob("*.sigma.yml"))
    assert len(sigma_files) == 3

    # XSS + SSRF produced suricata rules; IDOR did not
    sur_files = list(rules_dir.glob("*.suricata.rules"))
    assert len(sur_files) == 2

    # Recommendations file exists + mentions all three findings
    rec_text = rec_path.read_text()
    assert "XSS-VULN-01" in rec_text
    assert "IDOR-VULN-03" in rec_text
    assert "SSRF-VULN-02" in rec_text
    # NIST CSF section
    assert "NIST CSF" in rec_text
    # CIS Controls v8 section
    assert "CIS Controls v8" in rec_text
    assert "16.10" in rec_text   # XSS class -> 16.10


def test_generate_deliverables_finding_count_in_summary(tmp_path):
    out = generate_blue_team_deliverables(
        [_xss_finding()], workspace=str(tmp_path),
        target="x", engagement_id="y",
    )
    assert out["findings_processed"] == 1
    # 1 sigma + 1 suricata for XSS = 2 rules
    assert out["rule_count"] >= 2


def test_generate_deliverables_handles_empty_findings(tmp_path):
    out = generate_blue_team_deliverables(
        [], workspace=str(tmp_path),
        target="x", engagement_id="y",
    )
    assert out["findings_processed"] == 0
    assert out["rule_count"] == 0
    rec_path = Path(out["recommendations"])
    assert rec_path.exists()
