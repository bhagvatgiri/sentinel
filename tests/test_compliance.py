"""Tests for the compliance mapper — deterministic, no I/O."""

from sentinel.core.findings import Finding, Severity
from sentinel.reporting.compliance import map_finding, render_overlay_markdown, summarize


def _f(cwe=None, title="t") -> Finding:
    return Finding(
        title=title,
        description="d",
        severity=Severity.HIGH,
        scanner="semgrep",
        target="/tmp/x",
        cwe=cwe,
    )


def test_map_finding_known_cwe():
    out = map_finding(_f(cwe="CWE-89"))
    # SQLi should map to controls in all four frameworks.
    assert "PCI" in out and out["PCI"]
    assert "SOC2" in out and out["SOC2"]
    assert "CIS" in out and out["CIS"]
    assert "NIST_CSF" in out and out["NIST_CSF"]


def test_map_finding_unknown_cwe():
    assert map_finding(_f(cwe="CWE-99999")) == {}


def test_map_finding_no_cwe():
    assert map_finding(_f(cwe=None)) == {}


def test_summarize_groups_by_framework_and_control():
    findings = [
        _f(cwe="CWE-79", title="xss-1"),
        _f(cwe="CWE-79", title="xss-2"),
        _f(cwe="CWE-89", title="sqli-1"),
    ]
    out = summarize(findings)
    # Each framework should have entries.
    assert "PCI" in out
    # Two findings for CWE-79 should appear under whatever PCI control(s) it maps to.
    pci_total_refs = sum(len(v) for v in out["PCI"].values())
    assert pci_total_refs >= 2  # at least the two XSS findings appear somewhere


def test_render_overlay_markdown_produces_string():
    findings = [_f(cwe="CWE-89")]
    md = render_overlay_markdown(findings)
    assert isinstance(md, str)
    assert "CWE-89" in md or "PCI" in md or "SOC2" in md
