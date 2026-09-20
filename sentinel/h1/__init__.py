"""H1 submission tooling — tracker + dup-check + prepare.

Phase 2 ENG-01 through ENG-06 plans depend on this package. Three pieces:

  - tracker.record_submission / tracker.load_ledger — JSONL submission
    ledger at ~/.sentinel/h1-submissions.jsonl PLUS a hash-chained
    `submission_recorded` event in the engagement's audit log.

  - dup_check.dup_check — semantic search against the Chroma corpus to
    catch duplicate-probability reports before the operator burns hours on
    submission ceremony.

  - prepare.prepare — bundle evidence/ into a tarball AND extract
    verification curls into a runnable shell script, programmatically
    scope-gated via Scope.authorize_url() so out-of-scope URLs cannot
    leak into a generated artifact.

The CLI wiring lives in sentinel/cli.py (`h1` subcommand group).
The dashboard surface lives at /h1/submissions (sentinel/web/routes/h1.py).
"""

from __future__ import annotations

from sentinel.h1.dup_check import dup_check
from sentinel.h1.prepare import prepare
from sentinel.h1.tracker import load_ledger, record_submission


__all__ = ["record_submission", "load_ledger", "dup_check", "prepare"]
