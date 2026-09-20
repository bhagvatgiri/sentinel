"""ENG-01/02 regression tests for `sentinel.h1.tracker`.

Hermetic tests — no real `~/.sentinel/` writes, no real Chroma, no real
Scope.load. All disk I/O lives under `tmp_path`. Tests cover:

  - record_submission appends a JSONL row to the ledger path AND writes
    a hash-chained `submission_recorded` event to the audit log
    (AuditLog.verify returns (True, None) after).
  - record_submission rewrites the report's `Status:` line to a token
    in SUBMITTED_STATUS_TOKENS (preserves Plan 01-04's blocked-H1
    scanner contract) when h1_report_id is provided.
  - load_ledger returns chronological order; empty list when missing.
  - engagement_id path-traversal rejection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_record_submission_appends_jsonl_and_audit(tmp_path: Path):
    from sentinel.core.scope import AuditLog
    from sentinel.h1.tracker import record_submission

    ledger = tmp_path / "h1-submissions.jsonl"
    audit = tmp_path / ".audit-acme-bbp.jsonl"

    row = record_submission(
        "acme-bbp",
        "01-xss.md",
        "2026-XX-XXT15:00:00Z",
        ledger_path=ledger,
        audit_log_path=audit,
        weakness="CWE-79",
        severity="high",
        h1_url="https://hackerone.com/reports/9999999",
        h1_report_id="9999999",
        operator="jack",
    )

    # Returned dict has the canonical row shape.
    assert row["engagement_id"] == "acme-bbp"
    assert row["file"] == "01-xss.md"
    assert row["submitted_at"] == "2026-XX-XXT15:00:00Z"
    assert row["weakness"] == "CWE-79"
    assert row["severity"] == "high"
    assert row["h1_report_id"] == "9999999"
    assert row["operator"] == "jack"

    # JSONL row landed on disk.
    assert ledger.is_file()
    lines = [json.loads(l) for l in ledger.read_text().splitlines() if l.strip()]
    assert len(lines) == 1
    assert lines[0]["engagement_id"] == "acme-bbp"
    assert lines[0]["file"] == "01-xss.md"

    # Audit log is hash-chained and verifies clean.
    assert audit.is_file()
    ok, err = AuditLog.verify(audit)
    assert ok is True, err

    # Verify the event kind is `submission_recorded`.
    audit_entries = [
        json.loads(l) for l in audit.read_text().splitlines() if l.strip()
    ]
    assert any(e["event"] == "submission_recorded" for e in audit_entries)


def test_record_submission_rewrites_status_line(tmp_path: Path):
    """When h1_report_id is provided, the report's `**Status:**` line is
    rewritten to `Submitted (H1-<id>)` so Plan 01-04's `_is_submitted`
    helper recognizes it (substring 'submitted' matches the token set)."""
    from sentinel.h1.tracker import record_submission
    from sentinel.state.current_state import _is_submitted

    report = tmp_path / "01-xss.md"
    report.write_text(
        "# Test Report\n\n"
        "**Status:** Ready to submit.\n\n"
        "Body content.\n"
    )

    ledger = tmp_path / "h1-submissions.jsonl"
    audit = tmp_path / ".audit-eng.jsonl"

    record_submission(
        "eng",
        str(report),
        "2026-XX-XXT15:00:00Z",
        ledger_path=ledger,
        audit_log_path=audit,
        h1_report_id="3721487",
    )

    new_text = report.read_text()
    assert "Submitted (H1-3721487)" in new_text
    # Old status replaced — no longer "Ready to submit".
    assert "Ready to submit" not in new_text
    # Sanity: the rewritten status matches the blocked-H1 scanner taxonomy.
    assert _is_submitted("Submitted (H1-3721487)") is True


def test_load_ledger_returns_chronological(tmp_path: Path):
    """load_ledger returns rows oldest-first regardless of write order."""
    from sentinel.h1.tracker import load_ledger, record_submission

    ledger = tmp_path / "h1-submissions.jsonl"
    audit = tmp_path / ".audit.jsonl"

    # Write three rows out of order.
    record_submission(
        "eng-a", "b.md", "2026-XX-XXT15:00:00Z",
        ledger_path=ledger, audit_log_path=audit,
    )
    record_submission(
        "eng-a", "a.md", "2026-XX-XXT12:00:00Z",
        ledger_path=ledger, audit_log_path=audit,
    )
    record_submission(
        "eng-a", "c.md", "2026-XX-XXT18:00:00Z",
        ledger_path=ledger, audit_log_path=audit,
    )

    rows = load_ledger(ledger)
    assert [r["file"] for r in rows] == ["a.md", "b.md", "c.md"]


def test_load_ledger_empty_when_missing(tmp_path: Path):
    """load_ledger returns [] when the ledger file doesn't exist."""
    from sentinel.h1.tracker import load_ledger

    rows = load_ledger(tmp_path / "nonexistent.jsonl")
    assert rows == []


def test_record_submission_rejects_path_traversal(tmp_path: Path):
    """T-02-01-01 — engagement_id with `..` / `/` is rejected with
    ValueError. This prevents writing the audit log outside the project."""
    from sentinel.h1.tracker import record_submission

    ledger = tmp_path / "ledger.jsonl"
    audit = tmp_path / "audit.jsonl"

    for bad in ("../etc", "/abs", "eng/sub", ".hidden", ""):
        with pytest.raises(ValueError):
            record_submission(
                bad, "x.md", "2026-XX-XXT15:00:00Z",
                ledger_path=ledger, audit_log_path=audit,
            )
