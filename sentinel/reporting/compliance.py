"""Compliance framework mapper — pure logic to cross-reference CWE → control IDs.

This module aids consultants writing client reports by mapping security findings
to relevant compliance control IDs. The CWE-to-control mapping is CURATED,
not authoritative. Users MUST validate against current control text before delivery.
"""

from __future__ import annotations

from typing import Optional

from sentinel.core.findings import Finding


# Curated CWE → compliance control mapping.
# Covers common CWEs found in real assessments. Not comprehensive.
# Consultants MUST verify against latest published control text before reporting.
_CWE_CONTROLS: dict[str, dict[str, list[str]]] = {
    # Injection families
    "CWE-79": {  # Cross-site Scripting (XSS)
        "PCI": ["6.5.7"],
        "SOC2": ["CC6.1", "CC7.1"],
        "CIS": ["16.5"],
        "NIST_CSF": ["PR.DS-2", "DE.CM-1"],
    },
    "CWE-89": {  # SQL Injection
        "PCI": ["6.5.1"],
        "SOC2": ["CC6.1", "CC7.1"],
        "CIS": ["16.10"],
        "NIST_CSF": ["PR.DS-2", "DE.CM-1"],
    },
    "CWE-78": {  # OS Command Injection
        "PCI": ["6.5.1"],
        "SOC2": ["CC6.1"],
        "CIS": ["16.10"],
        "NIST_CSF": ["PR.DS-2"],
    },
    "CWE-94": {  # Code Injection
        "PCI": ["6.5.1"],
        "SOC2": ["CC6.1"],
        "CIS": ["16.10"],
        "NIST_CSF": ["PR.DS-2"],
    },
    # Path Traversal
    "CWE-22": {  # Path Traversal
        "PCI": ["6.5.8"],
        "SOC2": ["CC6.1"],
        "CIS": ["16.10"],
        "NIST_CSF": ["PR.DS-2"],
    },
    # Information Disclosure
    "CWE-200": {  # Exposure of Sensitive Information
        "PCI": ["6.5.10", "4.1"],
        "SOC2": ["CC6.1", "CC7.2"],
        "CIS": ["13.1", "13.2"],
        "NIST_CSF": ["PR.DS-1", "PR.DS-5"],
    },
    # Authentication & Session Management
    "CWE-287": {  # Improper Authentication
        "PCI": ["6.5.10", "8.2"],
        "SOC2": ["CC6.2", "CC7.2"],
        "CIS": ["6.1", "6.2"],
        "NIST_CSF": ["PR.AC-1"],
    },
    "CWE-306": {  # Missing Authentication for Critical Function
        "PCI": ["8.1", "8.2"],
        "SOC2": ["CC6.2"],
        "CIS": ["6.1"],
        "NIST_CSF": ["PR.AC-1"],
    },
    # Cryptography
    "CWE-295": {  # Improper Certificate Validation
        "PCI": ["4.1"],
        "SOC2": ["CC6.3", "CC7.3"],
        "CIS": ["13.1"],
        "NIST_CSF": ["PR.DS-2"],
    },
    "CWE-319": {  # Cleartext Transmission of Sensitive Information
        "PCI": ["4.1"],
        "SOC2": ["CC6.3"],
        "CIS": ["13.1"],
        "NIST_CSF": ["PR.DS-2"],
    },
    "CWE-326": {  # Inadequate Encryption Strength
        "PCI": ["4.1", "4.2"],
        "SOC2": ["CC6.3"],
        "CIS": ["13.1"],
        "NIST_CSF": ["PR.DS-2"],
    },
    "CWE-327": {  # Use of a Broken or Risky Cryptographic Algorithm
        "PCI": ["4.1"],
        "SOC2": ["CC6.3"],
        "CIS": ["13.1"],
        "NIST_CSF": ["PR.DS-2"],
    },
    # CSRF & Security Misconfig
    "CWE-352": {  # Cross-Site Request Forgery (CSRF)
        "PCI": ["6.5.9"],
        "SOC2": ["CC6.1"],
        "CIS": ["16.5"],
        "NIST_CSF": ["PR.DS-2"],
    },
    # File Upload
    "CWE-434": {  # Unrestricted Upload of File with Dangerous Type
        "PCI": ["6.5.8"],
        "SOC2": ["CC6.1"],
        "CIS": ["13.3"],
        "NIST_CSF": ["PR.DS-2"],
    },
    # Deserialization
    "CWE-502": {  # Deserialization of Untrusted Data
        "PCI": ["6.5.1"],
        "SOC2": ["CC6.1"],
        "CIS": ["16.10"],
        "NIST_CSF": ["PR.DS-2"],
    },
    # XML/XXE
    "CWE-611": {  # Improper Restriction of XML External Entity Reference
        "PCI": ["6.5.1"],
        "SOC2": ["CC6.1"],
        "CIS": ["16.10"],
        "NIST_CSF": ["PR.DS-2"],
    },
    # Permissions & Access
    "CWE-732": {  # Incorrect Permission Assignment for Critical Resource
        "PCI": ["2.2", "7.1"],
        "SOC2": ["CC6.1"],
        "CIS": ["5.1", "5.2"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-2"],
    },
    # Hardcoded Credentials
    "CWE-798": {  # Use of Hard-Coded Credentials
        "PCI": ["2.1", "8.2"],
        "SOC2": ["CC6.2"],
        "CIS": ["4.4"],
        "NIST_CSF": ["PR.AC-1"],
    },
    # SSRF
    "CWE-918": {  # Server-Side Request Forgery (SSRF)
        "PCI": ["6.5.1"],
        "SOC2": ["CC6.1"],
        "CIS": ["16.10"],
        "NIST_CSF": ["PR.DS-2"],
    },
    # Open Redirect
    "CWE-1021": {  # Improper Restriction of Rendered UI Layers or Frames
        "PCI": ["6.5.1"],
        "SOC2": ["CC6.1"],
        "CIS": ["16.5"],
        "NIST_CSF": ["PR.DS-2"],
    },
    # Unsafe Deserialization / Object Binding
    "CWE-1275": {  # Sensitive Cookie with Improper SameSite Attribute
        "PCI": ["6.5.10"],
        "SOC2": ["CC6.1", "CC7.1"],
        "CIS": ["16.5"],
        "NIST_CSF": ["PR.DS-2"],
    },
}


def map_finding(finding: Finding) -> dict[str, list[str]]:
    """Map a finding's CWE to compliance control IDs.

    Args:
        finding: A Finding object.

    Returns:
        Dict of framework → control ID list. Empty dict if no CWE or unknown CWE.

    Example:
        >>> f = Finding(..., cwe="CWE-79", ...)
        >>> map_finding(f)
        {'PCI': ['6.5.7'], 'SOC2': ['CC6.1', 'CC7.1'], ...}
    """
    if not finding.cwe:
        return {}

    cwe_key = finding.cwe if finding.cwe.startswith("CWE-") else f"CWE-{finding.cwe}"
    return _CWE_CONTROLS.get(cwe_key, {})


def summarize(findings: list[Finding]) -> dict[str, dict[str, list[str]]]:
    """Summarize findings by control: which controls have findings against them.

    Args:
        findings: List of Finding objects.

    Returns:
        Dict[framework][control_id] → list of finding fingerprints (for counting).

    Example:
        >>> result = summarize([f1, f2, ...])
        >>> result['PCI']['6.5.7']
        ['abc123def456', 'xyz789']  # 2 findings against PCI 6.5.7
    """
    result: dict[str, dict[str, list[str]]] = {}

    for finding in findings:
        controls = map_finding(finding)
        fp = finding.fingerprint()

        for framework, control_ids in controls.items():
            if framework not in result:
                result[framework] = {}
            for ctrl_id in control_ids:
                if ctrl_id not in result[framework]:
                    result[framework][ctrl_id] = []
                if fp not in result[framework][ctrl_id]:
                    result[framework][ctrl_id].append(fp)

    return result


def render_overlay_markdown(findings: list[Finding]) -> str:
    """Render compliance overlay as markdown for engagement reports.

    Suitable for appending to Obsidian engagement README or PDF export.
    Shows each framework, each control, and finding count.

    Args:
        findings: List of Finding objects.

    Returns:
        Markdown string (suitable for copy-paste into reports).
    """
    summary = summarize(findings)
    if not summary:
        return "## Compliance Framework Overlay\n\nNo findings mapped to frameworks.\n"

    lines = [
        "## Compliance Framework Overlay",
        "",
        "This section maps discovered findings to relevant compliance controls.",
        "**DISCLAIMER**: This mapping is curated, not authoritative. Validate against",
        "the latest published control text before delivery to the client.",
        "",
    ]

    # Sort frameworks for consistent output.
    frameworks_order = ["PCI", "SOC2", "CIS", "NIST_CSF"]
    frameworks = sorted(
        summary.keys(),
        key=lambda x: (frameworks_order.index(x) if x in frameworks_order else 999),
    )

    for framework in frameworks:
        controls = summary[framework]
        total_findings = sum(len(fps) for fps in controls.values())

        lines.append(f"### {_framework_label(framework)}")
        lines.append(f"**Controls with findings:** {len(controls)} | **Total findings:** {total_findings}")
        lines.append("")

        for ctrl_id in sorted(controls.keys()):
            fps = controls[ctrl_id]
            lines.append(f"- **{ctrl_id}** ({len(fps)} finding{'s' if len(fps) != 1 else ''})")

        lines.append("")

    lines.append(
        "---\n"
        "*Generated by Sentinel SBOM/Compliance module.*\n"
        "*For questions or corrections, contact your security consultant.*"
    )

    return "\n".join(lines)


# ---- helpers ----------------------------------------------------------------


def _framework_label(short: str) -> str:
    """Expand framework acronym to full name."""
    labels = {
        "PCI": "PCI-DSS v4.0",
        "SOC2": "SOC 2 Type II",
        "CIS": "CIS Controls v8",
        "NIST_CSF": "NIST Cybersecurity Framework 2.0",
    }
    return labels.get(short, short)
