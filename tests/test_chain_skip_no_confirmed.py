"""Cuts #1 + #2 (2026-XX-XX cost-cut audit) — verify chain + correlation
phases SKIP when 0 LIVE_CONFIRMED primitives are present.

Across 11 prior scans, chain_execute burned $92.38 / 156 runs / 0
successful chains (every chain abandoned at Step 1 because primitives
were live_disproven). Correlation burned $17.80 / 8 runs producing
empty cross-finding analyses. Both should now skip when count==0.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.agent.pentest.queue_summary import (
    count_live_confirmed_in_queues,
    format_confirmed_for_log,
)


def _write_queue(workspace: Path, cls: str, entries: list[dict]) -> Path:
    deliv = workspace / "deliverables"
    deliv.mkdir(parents=True, exist_ok=True)
    p = deliv / f"{cls}_exploitation_queue.json"
    p.write_text(json.dumps({"vulnerabilities": entries}), encoding="utf-8")
    return p


def test_zero_confirmed_when_no_queues(tmp_path: Path):
    n, lst = count_live_confirmed_in_queues(tmp_path)
    assert n == 0
    assert lst == []


def test_zero_confirmed_when_all_disproven(tmp_path: Path):
    """Real-world ExampleHotel scan: 75 entries, all disproven or manual_verification."""
    _write_queue(tmp_path, "idor", [
        {"ID": "IDOR-01", "evidence_state": "live_disproven",
         "vulnerability_type": "Broken_Object_Level_Authorization",
         "severity_estimate": "high"},
        {"ID": "IDOR-02", "evidence_state": "manual_verification_required",
         "vulnerability_type": "Indirect_Object_Reference",
         "severity_estimate": "medium"},
    ])
    _write_queue(tmp_path, "csrf", [
        {"ID": "CSRF-01", "evidence_state": "live_disproven",
         "vulnerability_type": "missing_csrf_token"},
    ])
    n, lst = count_live_confirmed_in_queues(tmp_path)
    assert n == 0, f"Expected 0 confirmed, got {n}: {lst}"


def test_counts_only_live_confirmed(tmp_path: Path):
    _write_queue(tmp_path, "auth", [
        {"ID": "AUTH-01", "evidence_state": "live_confirmed",
         "title": "Auth bypass via header smuggling",
         "vulnerability_type": "auth_bypass",
         "severity_estimate": "critical"},
        {"ID": "AUTH-02", "evidence_state": "live_disproven"},
        {"ID": "AUTH-03", "evidence_state": "manual_verification_required"},
    ])
    _write_queue(tmp_path, "idor", [
        {"ID": "IDOR-01", "evidence_state": "live_confirmed",
         "vulnerability_type": "BOLA",
         "title": "Member profile by id"},
    ])
    n, lst = count_live_confirmed_in_queues(tmp_path)
    assert n == 2
    classes = {p.cls for p in lst}
    assert classes == {"auth", "idor"}


def test_handles_bare_list_format(tmp_path: Path):
    """Some agents wrote bare lists, not {vulnerabilities: [...]}. Tolerate both."""
    deliv = tmp_path / "deliverables"
    deliv.mkdir(parents=True)
    p = deliv / "xss_exploitation_queue.json"
    p.write_text(json.dumps([
        {"ID": "XSS-01", "evidence_state": "live_confirmed", "title": "stored xss"},
    ]), encoding="utf-8")
    n, lst = count_live_confirmed_in_queues(tmp_path)
    assert n == 1


def test_format_summary_shows_per_class_counts(tmp_path: Path):
    _write_queue(tmp_path, "csrf", [
        {"ID": "CSRF-1", "evidence_state": "live_confirmed"},
        {"ID": "CSRF-2", "evidence_state": "live_confirmed"},
    ])
    _write_queue(tmp_path, "ssrf", [
        {"ID": "SSRF-1", "evidence_state": "live_confirmed"},
    ])
    n, lst = count_live_confirmed_in_queues(tmp_path)
    summary = format_confirmed_for_log(lst)
    assert "3 total" in summary
    assert "csrf=2" in summary
    assert "ssrf=1" in summary


def test_skips_malformed_queue_files(tmp_path: Path):
    deliv = tmp_path / "deliverables"
    deliv.mkdir(parents=True)
    (deliv / "broken_exploitation_queue.json").write_text("{not json", encoding="utf-8")
    (deliv / "good_exploitation_queue.json").write_text(json.dumps({
        "vulnerabilities": [{"ID": "G-1", "evidence_state": "live_confirmed"}]
    }), encoding="utf-8")
    n, _ = count_live_confirmed_in_queues(tmp_path)
    assert n == 1  # broken file skipped, good file counted


def test_format_summary_empty():
    assert format_confirmed_for_log([]) == "(none)"
