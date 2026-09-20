"""Differential report generation."""

from __future__ import annotations

from sentinel.core.findings import Finding, Severity, Status
from sentinel.reporting.diff import (
    FindingDiff, diff_findings, render_diff_markdown,
)


def _f(title, severity, location="/x", scanner="test", target="https://t"):
    return Finding(
        title=title, description="", severity=severity, scanner=scanner,
        target=target, location=location,
    )


def test_diff_no_change_when_sets_identical():
    a = _f("XSS", Severity.HIGH)
    b = _f("XSS", Severity.HIGH)
    diff = diff_findings([a], [b])
    assert diff.counts() == {"closed": 0, "new": 0, "escalated": 0, "reduced": 0, "persisted": 1}
    assert diff.is_clean() is True


def test_diff_detects_new_finding():
    diff = diff_findings([_f("Old", Severity.LOW)],
                         [_f("Old", Severity.LOW), _f("Brand new", Severity.CRITICAL)])
    assert diff.counts()["new"] == 1
    assert diff.new[0].title == "Brand new"
    assert diff.is_clean() is False


def test_diff_detects_closed_finding():
    diff = diff_findings([_f("Was here", Severity.MEDIUM)], [])
    assert diff.counts()["closed"] == 1
    assert diff.closed[0].title == "Was here"


def test_diff_detects_severity_escalation():
    prior = [_f("Open redirect", Severity.MEDIUM)]
    cur = [_f("Open redirect", Severity.HIGH)]
    diff = diff_findings(prior, cur)
    assert diff.counts()["escalated"] == 1
    f, old, new = diff.escalated[0]
    assert old == Severity.MEDIUM
    assert new == Severity.HIGH


def test_diff_detects_severity_reduction():
    prior = [_f("Header", Severity.HIGH)]
    cur = [_f("Header", Severity.LOW)]
    diff = diff_findings(prior, cur)
    assert diff.counts()["reduced"] == 1
    _, old, new = diff.reduced[0]
    assert old == Severity.HIGH and new == Severity.LOW


def test_render_markdown_includes_clean_message_when_no_regressions():
    diff = diff_findings([_f("X", Severity.LOW)], [_f("X", Severity.LOW)])
    md = render_diff_markdown(diff)
    assert "regression-free" in md


def test_render_markdown_lists_new_findings_with_severity_chip():
    diff = diff_findings([], [_f("Y", Severity.CRITICAL)])
    md = render_diff_markdown(diff)
    assert "## New findings" in md
    assert "[critical]" in md
    assert "Y" in md
