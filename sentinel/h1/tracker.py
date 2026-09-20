"""H1 submission ledger + audit-log event writer.

Records every H1 submission moment to two on-disk surfaces:

  1. JSONL ledger at ~/.sentinel/h1-submissions.jsonl (default) — flat
     row-per-submission audit table. `load_ledger` returns chronological
     order (oldest first). The dashboard /h1/submissions route reads
     this same file.

  2. Hash-chained `submission_recorded` event on the engagement's
     `.audit-<engagement_id>.jsonl` via the existing
     `sentinel.core.scope.AuditLog`. `sentinel verify-audit` walks the
     chain and proves the submission timestamp was recorded + not
     edited (T-02-01-02 + T-02-01-05).

`engagement_id` is validated against `^[a-z0-9][a-z0-9._-]*$` so a
malicious or typo'd id with `..` or `/` cannot redirect the audit-log
write outside the project (T-02-01-01).

When `h1_report_id` is provided, the report file's `Status:` line is
also rewritten to `Submitted (H1-<id>)` — the substring 'submitted'
lands in Plan 01-04's `SUBMITTED_STATUS_TOKENS`, so the blocked-H1
scanner stops flagging the report immediately.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional


_ENGAGEMENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def _validate_engagement_id(engagement_id: str) -> None:
    """T-02-01-01 — reject path-traversal / weird ids before they form
    `.audit-<engagement_id>.jsonl` and let the writer touch unexpected
    paths. Allowed: lowercase alphanumeric + `.`/`_`/`-`, first char
    must NOT be a leading dot."""
    if not engagement_id or not isinstance(engagement_id, str):
        raise ValueError("engagement_id must be a non-empty string")
    if not _ENGAGEMENT_ID_RE.match(engagement_id):
        raise ValueError(
            f"engagement_id {engagement_id!r} is not a valid identifier "
            f"(allowed: ^[a-z0-9][a-z0-9._-]*$ — no path separators, no "
            f"leading dot)"
        )


_STATUS_LINE_RE = re.compile(
    r"^(\s*)(\*\*Status:\*\*|Status:)\s+.*$",
    re.MULTILINE,
)


def _rewrite_status_line(report_path: Path, h1_report_id: str) -> None:
    """Rewrite the report's Status line to `Submitted (H1-<id>)`.

    Preserves leading whitespace + the original marker style (bolded or
    plain). If no Status line is present, appends one after the first
    `# ` heading (or at the top if no heading exists).
    """
    if not report_path.is_file():
        return
    try:
        text = report_path.read_text(errors="replace")
    except OSError:
        return

    new_status = f"Submitted (H1-{h1_report_id})"

    def _replace(m: re.Match) -> str:
        indent = m.group(1)
        marker = m.group(2)
        if marker.startswith("**"):
            return f"{indent}**Status:** {new_status}"
        return f"{indent}Status: {new_status}"

    new_text, n = _STATUS_LINE_RE.subn(_replace, text, count=1)
    if n == 0:
        # No Status line found — insert one after the first H1.
        heading_re = re.compile(r"^(#\s+.+?)$", re.MULTILINE)
        m = heading_re.search(text)
        if m:
            insertion = f"\n\n**Status:** {new_status}"
            new_text = text[: m.end()] + insertion + text[m.end():]
        else:
            new_text = f"**Status:** {new_status}\n\n" + text
    try:
        report_path.write_text(new_text)
    except OSError:
        # Best-effort — failing to rewrite the status line is not fatal
        # for the audit-log + ledger writes, which already succeeded.
        pass


def record_submission(
    engagement_id: str,
    file: str,
    submitted_at: str,
    *,
    ledger_path: Path,
    audit_log_path: Path,
    title: Optional[str] = None,
    weakness: Optional[str] = None,
    severity: Optional[str] = None,
    h1_url: Optional[str] = None,
    h1_report_id: Optional[str] = None,
    operator: Optional[str] = None,
) -> dict:
    """Append a JSONL row + hash-chained audit-log event.

    Args:
      engagement_id: validated against `^[a-z0-9][a-z0-9._-]*$`.
      file: the submitted report's file name OR full path. When a path
        is given and the file exists, its Status line is rewritten when
        `h1_report_id` is also provided.
      submitted_at: ISO-8601 UTC timestamp.
      ledger_path: `~/.sentinel/h1-submissions.jsonl` by default
        (caller resolves this).
      audit_log_path: `.audit-<engagement_id>.jsonl` next to the scope
        file (caller resolves this).
      title, weakness, severity, h1_url, h1_report_id, operator:
        optional metadata fields stored in both the JSONL row and the
        audit-log payload.

    Returns:
      The row dict written to the ledger.

    Raises:
      ValueError: engagement_id failed validation (T-02-01-01).
    """
    _validate_engagement_id(engagement_id)

    # Resolve file display name + optional Path object.
    file_path = Path(file)
    file_display = file_path.name if file_path.is_file() else file

    row: dict = {
        "submitted_at": str(submitted_at),
        "engagement_id": engagement_id,
        "file": file_display,
        "title": title or "",
        "h1_url": h1_url or "",
        "h1_report_id": h1_report_id or "",
        "weakness": weakness or "",
        "severity": severity or "",
        "operator": operator or "",
    }

    # 1) Append to the ledger.
    ledger_path = Path(ledger_path)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")

    # 2) Write the hash-chained audit-log event.
    # Lazy import — keeps test imports tight and avoids the scope module
    # import path when callers stub out the audit log for fixtures.
    from sentinel.core.scope import AuditLog

    audit = AuditLog(Path(audit_log_path))
    audit.write(
        "submission_recorded",
        {
            "engagement_id": engagement_id,
            "file": file_display,
            "submitted_at": row["submitted_at"],
            "title": row["title"],
            "weakness": row["weakness"],
            "severity": row["severity"],
            "h1_report_id": row["h1_report_id"],
            "h1_url": row["h1_url"],
            "operator": row["operator"],
        },
    )

    # 3) Rewrite the report's Status line so Plan 01-04's blocked-H1
    #    scanner stops flagging it.
    if h1_report_id and file_path.is_file():
        _rewrite_status_line(file_path, h1_report_id)

    return row


def load_ledger(ledger_path: Path) -> list[dict]:
    """Return all rows in the ledger, sorted chronologically (oldest first).

    Empty list when the file does not exist OR is unreadable. Sorts by
    `submitted_at` string; ISO-8601 sorts lexicographically so chrono
    order is preserved without a date-parse step.
    """
    ledger_path = Path(ledger_path)
    if not ledger_path.is_file():
        return []
    rows: list[dict] = []
    try:
        text = ledger_path.read_text(errors="replace")
    except OSError:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    rows.sort(key=lambda r: r.get("submitted_at", ""))
    return rows
