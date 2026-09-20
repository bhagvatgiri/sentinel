"""BENCH-06 regression tests — canonical-vuln scoring module.

Hermetic tests for `sentinel.benchmark.scoring`. NO network, NO docker,
NO real canonical-vulns.yaml file load — every test uses inline
synthetic canonical lists + synthetic finding dicts so the test suite
gates the scorer's MATH and MATCHING LOGIC, not the YAML shape (which
can evolve freely under Plans 02-03/02-04).

Test contract (11 tests):

  Test 1:  match_finding_to_canonical succeeds via CWE + detect_hint substring.
  Test 2:  match_finding_to_canonical succeeds via match_keywords when
           detect_hint is absent in finding fields.
  Test 3:  match_finding_to_canonical returns None on CWE mismatch even if
           detect_hint matches.
  Test 4:  match_finding_to_canonical picks the highest-severity canonical
           on tie-break + emits a DEBUG line listing all candidates.
  Test 5:  score_phase all-match → precision=1.0, recall=1.0, f1=1.0.
  Test 6:  score_phase no-match → precision=0.0, recall=0.0, f1=0.0.
  Test 7:  score_phase partial → precision/recall/F1 = 2/3 (exact).
  Test 8:  score_phase duplicate emitted matches count once (tp=1, fp=1, fn=0).
  Test 9:  verdict_for_phase agentic threshold 0.95 (pass/partial/fail bands).
  Test 10: verdict_for_phase analytical threshold 0.85 (pass/partial/fail).
  Test 11: verdict_for_phase unknown phase falls back to agentic + warns.
"""

from __future__ import annotations

import logging

import pytest

from sentinel.benchmark.scoring import (
    AGENTIC_PHASES,
    ANALYTICAL_PHASES,
    F1_THRESHOLDS,
    match_finding_to_canonical,
    score_phase,
    verdict_for_phase,
)


# ---- Module-level constants (sanity checks) -----------------------------


def test_constants_exposed():
    """The four exported constants must be present and sensibly shaped.
    Downstream Plan 02-03/02-04 import these by name — typos here corrupt
    the cost-delta + verdict report generator silently.
    """
    assert isinstance(AGENTIC_PHASES, list)
    assert isinstance(ANALYTICAL_PHASES, list)
    assert "recon" in AGENTIC_PHASES
    assert "vuln:injection" in AGENTIC_PHASES
    assert "correlation" in ANALYTICAL_PHASES
    assert "report" in ANALYTICAL_PHASES
    assert F1_THRESHOLDS["agentic_pass"] == 0.95
    assert F1_THRESHOLDS["analytical_pass"] == 0.85
    assert F1_THRESHOLDS["partial"] == 0.5


# ---- Matching tests -----------------------------------------------------


def test_match_by_cwe_and_detect_hint():
    """Happy path: CWE matches + detect_hint substring appears in
    finding.location. Returns the canonical id.
    """
    finding = {
        "cwe": "CWE-89",
        "location": "http://127.0.0.1:8080/vulnerabilities/sqli/",
        "title": "SQL injection",
    }
    canonicals = [
        {
            "id": "dvwa-sqli-01",
            "cwe": "CWE-89",
            "detect_hint": "/vulnerabilities/sqli/",
            "severity": "high",
        }
    ]
    assert match_finding_to_canonical(finding, canonicals) == "dvwa-sqli-01"


def test_match_by_match_keywords_overrides_hint_miss():
    """detect_hint NOT in finding fields, but a match_keywords string IS.
    Match still succeeds via the keyword branch.
    """
    finding = {
        "cwe": "CWE-78",
        "location": "http://example.com/admin",  # no /vulnerabilities/exec/
        "title": "OS command injection via ping form",
        "description": "Tested with payload `127.0.0.1; whoami`",
    }
    canonicals = [
        {
            "id": "dvwa-cmdi-01",
            "cwe": "CWE-78",
            "detect_hint": "/vulnerabilities/exec/",
            "severity": "critical",
            "match_keywords": ["command injection", "; whoami"],
        }
    ]
    assert match_finding_to_canonical(finding, canonicals) == "dvwa-cmdi-01"


def test_cwe_mismatch_blocks_match():
    """Even when detect_hint substring matches, a wrong CWE blocks the match.
    Prevents fuzzy URL-only matches from silently inflating F1.
    """
    finding = {
        "cwe": "CWE-79",  # XSS
        "location": "http://127.0.0.1:8080/vulnerabilities/sqli/",
        "title": "Some XSS finding",
    }
    canonicals = [
        {
            "id": "dvwa-sqli-01",
            "cwe": "CWE-89",  # SQLi
            "detect_hint": "/vulnerabilities/sqli/",
            "severity": "high",
        }
    ]
    assert match_finding_to_canonical(finding, canonicals) is None


def test_match_picks_highest_severity_on_tie(caplog):
    """If two canonical entries match the same finding (same CWE, both
    detect_hints present), pick the highest-severity one. Log a DEBUG
    line listing all candidate ids so the operator can refine.
    """
    finding = {
        "cwe": "CWE-89",
        "location": "http://127.0.0.1:8080/vulnerabilities/sqli/",
        "title": "SQL injection in id parameter",
    }
    canonicals = [
        {
            "id": "dvwa-sqli-low",
            "cwe": "CWE-89",
            "detect_hint": "/vulnerabilities/sqli/",
            "severity": "high",
        },
        {
            "id": "dvwa-sqli-critical",
            "cwe": "CWE-89",
            "detect_hint": "/vulnerabilities/sqli/",
            "severity": "critical",
        },
    ]
    with caplog.at_level(logging.DEBUG, logger="sentinel.benchmark.scoring"):
        result = match_finding_to_canonical(finding, canonicals)
    assert result == "dvwa-sqli-critical"
    # Debug log must mention BOTH candidates.
    debug_lines = " ".join(r.message for r in caplog.records
                            if r.levelno == logging.DEBUG)
    assert "dvwa-sqli-low" in debug_lines, debug_lines
    assert "dvwa-sqli-critical" in debug_lines, debug_lines


# ---- score_phase tests --------------------------------------------------


def test_score_phase_all_match():
    """3 emitted findings, 3 canonicals, perfect 1:1 mapping.
    Expected: precision=1.0, recall=1.0, f1=1.0, tp=3, fp=0, fn=0.
    """
    findings = [
        {"cwe": "CWE-89", "location": "/sqli/", "title": "sqli"},
        {"cwe": "CWE-79", "location": "/xss_r/", "title": "xss"},
        {"cwe": "CWE-78", "location": "/exec/", "title": "cmd"},
    ]
    canonicals = [
        {"id": "c1", "cwe": "CWE-89", "detect_hint": "/sqli/", "severity": "high"},
        {"id": "c2", "cwe": "CWE-79", "detect_hint": "/xss_r/", "severity": "high"},
        {"id": "c3", "cwe": "CWE-78", "detect_hint": "/exec/", "severity": "high"},
    ]
    r = score_phase(findings, canonicals)
    assert r["tp"] == 3
    assert r["fp"] == 0
    assert r["fn"] == 0
    assert r["precision"] == pytest.approx(1.0)
    assert r["recall"] == pytest.approx(1.0)
    assert r["f1"] == pytest.approx(1.0)
    assert set(r["matched_canonical_ids"]) == {"c1", "c2", "c3"}
    assert r["unmatched_canonical_ids"] == []


def test_score_phase_no_matches():
    """3 emitted findings, 3 canonicals, zero overlap.
    Expected: precision=0, recall=0, f1=0, tp=0, fp=3, fn=3.
    """
    findings = [
        {"cwe": "CWE-89", "location": "/wrong-path/", "title": "x"},
        {"cwe": "CWE-79", "location": "/another/", "title": "y"},
        {"cwe": "CWE-78", "location": "/elsewhere/", "title": "z"},
    ]
    canonicals = [
        {"id": "c1", "cwe": "CWE-89", "detect_hint": "/sqli/", "severity": "high"},
        {"id": "c2", "cwe": "CWE-79", "detect_hint": "/xss_r/", "severity": "high"},
        {"id": "c3", "cwe": "CWE-78", "detect_hint": "/exec/", "severity": "high"},
    ]
    r = score_phase(findings, canonicals)
    assert r["tp"] == 0
    assert r["fp"] == 3
    assert r["fn"] == 3
    assert r["precision"] == pytest.approx(0.0)
    assert r["recall"] == pytest.approx(0.0)
    assert r["f1"] == pytest.approx(0.0)
    assert r["matched_canonical_ids"] == []
    assert set(r["unmatched_canonical_ids"]) == {"c1", "c2", "c3"}


def test_score_phase_partial():
    """2 of 3 findings match 2 of 3 canonicals; 1 finding is FP; 1 canonical
    is FN. precision = 2/3, recall = 2/3, f1 = 2/3.
    """
    findings = [
        {"cwe": "CWE-89", "location": "/sqli/", "title": "sqli"},   # match c1
        {"cwe": "CWE-79", "location": "/xss_r/", "title": "xss"},   # match c2
        {"cwe": "CWE-22", "location": "/random/", "title": "bogus"}  # FP
    ]
    canonicals = [
        {"id": "c1", "cwe": "CWE-89", "detect_hint": "/sqli/", "severity": "high"},
        {"id": "c2", "cwe": "CWE-79", "detect_hint": "/xss_r/", "severity": "high"},
        {"id": "c3", "cwe": "CWE-78", "detect_hint": "/exec/", "severity": "high"},  # FN
    ]
    r = score_phase(findings, canonicals)
    assert r["tp"] == 2
    assert r["fp"] == 1
    assert r["fn"] == 1
    assert r["precision"] == pytest.approx(2 / 3)
    assert r["recall"] == pytest.approx(2 / 3)
    assert r["f1"] == pytest.approx(2 / 3)
    assert set(r["matched_canonical_ids"]) == {"c1", "c2"}
    assert r["unmatched_canonical_ids"] == ["c3"]


def test_score_phase_duplicate_matches_count_once():
    """Two emitted findings both match the same canonical: the first is TP,
    the second is a duplicate-FP. Canonical's recall slot is still claimed
    exactly once.
    """
    findings = [
        {"cwe": "CWE-89", "location": "/sqli/", "title": "sqli first"},
        {"cwe": "CWE-89", "location": "/sqli/", "title": "sqli duplicate"},
    ]
    canonicals = [
        {"id": "c1", "cwe": "CWE-89", "detect_hint": "/sqli/", "severity": "high"},
    ]
    r = score_phase(findings, canonicals)
    assert r["tp"] == 1
    assert r["fp"] == 1
    assert r["fn"] == 0
    assert r["matched_canonical_ids"] == ["c1"]
    assert r["unmatched_canonical_ids"] == []


# ---- verdict_for_phase tests --------------------------------------------


def test_verdict_for_agentic_phase_pass_at_095():
    """Agentic phases gate `pass` at F1 >= 0.95; partial at >= 0.5; below = fail."""
    assert verdict_for_phase("vuln:injection", 0.96) == "pass"
    assert verdict_for_phase("vuln:injection", 0.95) == "pass"  # boundary inclusive
    assert verdict_for_phase("vuln:injection", 0.85) == "partial"
    assert verdict_for_phase("vuln:injection", 0.50) == "partial"  # boundary inclusive
    assert verdict_for_phase("vuln:injection", 0.49) == "fail"
    assert verdict_for_phase("vuln:injection", 0.0) == "fail"
    # Other agentic phases route the same.
    assert verdict_for_phase("recon", 0.96) == "pass"
    assert verdict_for_phase("exploit:xss", 0.40) == "fail"


def test_verdict_for_analytical_phase_pass_at_085():
    """Analytical phases gate `pass` at F1 >= 0.85; partial at >= 0.5; below = fail."""
    assert verdict_for_phase("correlation", 0.86) == "pass"
    assert verdict_for_phase("correlation", 0.85) == "pass"  # boundary inclusive
    assert verdict_for_phase("correlation", 0.70) == "partial"
    assert verdict_for_phase("correlation", 0.50) == "partial"
    assert verdict_for_phase("correlation", 0.20) == "fail"
    assert verdict_for_phase("report", 0.86) == "pass"
    assert verdict_for_phase("report", 0.49) == "fail"


def test_verdict_unknown_phase_falls_back_to_agentic_thresholds(caplog):
    """Unknown phase name uses the agentic threshold (default, conservative)
    and logs a warning so the operator sees that their canonical-vulns.yaml
    referenced a phase the scorer doesn't know about.
    """
    with caplog.at_level(logging.WARNING, logger="sentinel.benchmark.scoring"):
        assert verdict_for_phase("vuln:future-class", 0.96) == "pass"
        assert verdict_for_phase("vuln:future-class", 0.85) == "partial"
        assert verdict_for_phase("vuln:future-class", 0.40) == "fail"
    # At least one warning mentioning the unknown phase name.
    assert any("vuln:future-class" in r.message for r in caplog.records), (
        f"expected warning about unknown phase, got: "
        f"{[r.message for r in caplog.records]}"
    )
