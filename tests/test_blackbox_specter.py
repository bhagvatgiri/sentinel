"""B3 — BLACKBOX_SPECTER taint-tracking format for SAST findings.

`query_sast_findings(format='blackbox_specter')` renders each match in
the 6-field Hypothesis → Source → Flow → Sink → Confirmation → Evidence
shape so the analysis deliverable carries an auditable data-flow argument.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.agent.pentest.sast_tool import (
    _render_blackbox_specter,
    sast_findings_path,
    write_sast_findings,
)


def test_render_blackbox_specter_has_all_six_fields():
    finding = {
        "title": "SQL injection in user lookup",
        "description": "User input concatenated into SQL string",
        "severity": "high",
        "scanner": "semgrep",
        "location": "src/db/users.py:142",
        "cwe": "89",
        "raw": {
            "rule_id": "python.lang.sqli.string-concat-sql",
            "match": 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
        },
    }
    out = _render_blackbox_specter(finding)
    for field in ("Hypothesis:", "Source:", "Flow:", "Sink:",
                  "Confirmation:", "Evidence:"):
        assert field in out, f"missing field: {field}"
    assert "src/db/users.py:142" in out
    assert "semgrep" in out
    assert "python.lang.sqli.string-concat-sql" in out
    assert "CWE-89" in out


def test_render_blackbox_specter_with_minimal_finding():
    """Sparse finding — only scanner + location. Renderer must not crash;
    placeholders fill the missing semantic fields."""
    finding = {"scanner": "gitleaks", "location": ".env:3"}
    out = _render_blackbox_specter(finding)
    for field in ("Hypothesis:", "Source:", "Flow:", "Sink:",
                  "Confirmation:", "Evidence:"):
        assert field in out
    assert "gitleaks" in out
    assert ".env:3" in out
    # The placeholders for the under-specified fields must clearly
    # signal "agent must fill this in".
    assert "(agent:" in out


def test_render_blackbox_specter_truncates_long_snippets():
    """Match excerpts >220 chars get truncated so the prompt stays bounded."""
    huge = "x" * 1000
    finding = {
        "title": "t", "scanner": "semgrep", "location": "f.py:1",
        "raw": {"rule_id": "r", "match": huge},
    }
    out = _render_blackbox_specter(finding)
    # The rendered match must be truncated.
    assert "x" * 1000 not in out
    assert "…" in out  # ellipsis marker


def test_render_blackbox_specter_emits_code_fence():
    """The rendered block is wrapped in ``` so the agent passes it through
    verbatim into the markdown deliverable."""
    out = _render_blackbox_specter({"scanner": "semgrep", "location": "x:1"})
    assert out.startswith("```")
    assert out.endswith("```")


def test_query_sast_findings_blackbox_specter_format(tmp_path):
    """End-to-end: write a SAST cache, then call the tool with
    format='blackbox_specter' and verify the rendered output has the
    6-field block per match."""
    import asyncio
    from sentinel.agent.pentest import sast_tool, tools as p_tools

    findings = [
        {
            "title": "SQL injection in /api/users",
            "description": "Unsanitized input",
            "severity": "high", "scanner": "semgrep",
            "location": "src/api/users.py:88",
            "cwe": "89",
            "raw": {"rule_id": "rule.sqli.string-concat",
                    "match": "execute(query + user_input)"},
        },
        {
            "title": "Hardcoded AWS key",
            "severity": "critical", "scanner": "gitleaks",
            "location": ".env:5", "cwe": "798",
            "raw": {"rule_id": "gitleaks.aws"},
        },
    ]
    workspace = tmp_path / "ws"
    workspace.mkdir()
    write_sast_findings(workspace, findings)

    # Mock context — the SAST tool reads ctx.workspace_dir.
    class _Ctx:
        workspace_dir = workspace
    p_tools._ctx = _Ctx()  # type: ignore[assignment]
    try:
        result = asyncio.run(
            sast_tool.query_sast_findings.handler({
                "filter": "", "limit": 30, "format": "blackbox_specter",
            })
        )
    finally:
        p_tools._ctx = None  # type: ignore[assignment]

    text = result["content"][0]["text"]
    assert "blackbox_specter" in text
    # Both findings rendered.
    assert "src/api/users.py:88" in text
    assert ".env:5" in text
    # Six-field structure x2.
    assert text.count("Hypothesis:") == 2
    assert text.count("Source:") == 2
    assert text.count("Flow:") == 2
    assert text.count("Sink:") == 2
    assert text.count("Confirmation:") == 2
    assert text.count("Evidence:") == 2


def test_query_sast_findings_default_format_unchanged(tmp_path):
    """Without format='blackbox_specter', the legacy 3-line summary is
    preserved — backwards compat."""
    import asyncio
    from sentinel.agent.pentest import sast_tool, tools as p_tools

    findings = [{"title": "T", "severity": "high", "scanner": "semgrep",
                 "location": "f.py:1", "cwe": "89"}]
    workspace = tmp_path / "ws"
    workspace.mkdir()
    write_sast_findings(workspace, findings)

    class _Ctx:
        workspace_dir = workspace
    p_tools._ctx = _Ctx()  # type: ignore[assignment]
    try:
        result = asyncio.run(
            sast_tool.query_sast_findings.handler({"filter": "", "limit": 30})
        )
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    text = result["content"][0]["text"]
    # Compact format does NOT include the 6-field labels.
    assert "Hypothesis:" not in text
    assert "Sink:" not in text
    # Compact format does include the 3-line per-finding summary.
    assert "loc: f.py:1" in text


def test_query_sast_findings_rejects_unknown_format(tmp_path):
    import asyncio
    from sentinel.agent.pentest import sast_tool, tools as p_tools

    workspace = tmp_path / "ws"
    workspace.mkdir()
    write_sast_findings(workspace, [])

    class _Ctx:
        workspace_dir = workspace
    p_tools._ctx = _Ctx()  # type: ignore[assignment]
    try:
        result = asyncio.run(
            sast_tool.query_sast_findings.handler({"format": "json_export"})
        )
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    assert result.get("is_error") is True
    assert "unknown format" in result["content"][0]["text"]
