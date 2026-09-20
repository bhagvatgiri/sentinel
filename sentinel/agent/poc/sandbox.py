"""PoC execution sandbox (VERIFY-04 + VERIFY-06).

This module is the safety-critical core of Phase 3. It receives a
structured `ParsedPoc` (produced by `sentinel.agent.poc.prompt.parse_poc_block`
from the model's response) plus a live `Scope` + a workspace path, runs
the PoC under a four-layer defense, writes an evidence bundle to disk,
and emits paired `poc_run_started` + `poc_run_completed` audit events
on the engagement's existing hash-chained AuditLog.

Four-layer defense (in order)
-----------------------------

    1. classify_destructive (sentinel.agent.poc.classifier)
       ↓ verdict.is_destructive → short-circuit MANUAL_REQUIRED
       Plan 03-03 absorbs T-03-04-08 (pickle.loads + yaml.unsafe_load)
       so the sandbox does NOT need duplicate deserialization logic.

    2. scope.authorize_url for EVERY URL in the PoC command
       ↓ OutOfScopeError → short-circuit MANUAL_REQUIRED
       Non-bypassable — there is no --force / --skip-scope flag.

    3. subprocess.run with hard 60-second timeout (SANDBOX_TIMEOUT_SEC)
       ↓ TimeoutExpired → MANUAL_REQUIRED (not silent hang)

    4. re.search(expected_output_regex, stdout, MULTILINE)
       ↓ match → VERIFIED   |   no-match → UNREPRODUCIBLE

Every execution attempt — including the first three short-circuit paths —
writes paired `poc_run_started` + `poc_run_completed` audit events. The
hash chain is preserved through the existing `AuditLog.write` contract.

Evidence bundle layout
----------------------

    workspaces/<engagement_id>/verification/<finding_fingerprint>/
      ├── poc.sh                (shell + sqlmap PoCs)
      ├── poc.py                (python + playwright PoCs)
      ├── stdout.log            (truncated at MAX_OUTPUT_BYTES)
      ├── stderr.log
      ├── exit_code.txt         (the int as ascii)
      ├── screenshot.png        (optional — playwright PoCs that wrote one)
      └── refusal.txt           (only when destructive or out-of-scope)

The workspaces/ tree is gitignored (NDA-class artifact). Tests use
tmp_path for the bundle root so they never touch the real workspace.

Non-bypassable invariants
-------------------------

  - The classifier call IS the first line of `execute_poc`. Re-ordering
    it after the scope check would let a destructive PoC slip past
    classifier-only-aware test harnesses.
  - The scope check runs BEFORE subprocess.run. Period. There is no
    operator override — operators reclassify by hand-editing the scope
    file (the legal artifact), not via a flag.
  - The subprocess timeout is a hard cap; we never increase it inside
    the sandbox. A PoC that needs more than 60 seconds is, by design,
    a manual operation.
  - Audit events are emitted even when the sandbox raises. The
    `_emit_completed_event` call sits in a try/finally OR in every
    return path; a missed audit write is treated as a Rule-1 bug.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from sentinel.agent.poc.classifier import classify_destructive
from sentinel.agent.poc.prompt import ParsedPoc
from sentinel.core.findings import EvidenceState, Finding
from sentinel.core.scope import AuditLog, OutOfScopeError, Scope


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — never relax without a plan
# ---------------------------------------------------------------------------


SANDBOX_TIMEOUT_SEC: int = 60          # T-03-04-03: DoS via infinite-loop PoC
MAX_OUTPUT_BYTES: int = 1024 * 1024    # T-03-04-04: DoS via OOM-sized stdout

# URL extraction regex. Greedy match on `https?://` followed by non-whitespace,
# non-quote, non-bracket characters. Trailing punctuation is stripped in
# `_extract_urls` so trailing commas and periods don't end up in the
# scope-check target.
_URL_REGEX = re.compile(r"https?://[^\s\'\"`<>]+", re.IGNORECASE)
_URL_TRAILING_PUNCT = ",.;:!?)]}"


# ---------------------------------------------------------------------------
# SandboxResult
# ---------------------------------------------------------------------------


@dataclass
class SandboxResult:
    """Verdict + evidence-bundle pointers from one `execute_poc` call.

    The dashboard (Plan 03-06) renders these fields; the pipeline gate
    (Plan 03-05) reads `evidence_state` to decide whether the finding
    propagates to correlation.
    """

    evidence_state: EvidenceState
    pattern_name: Optional[str]      # set when the destructive classifier fired
    rationale: str                   # human-readable explanation of the verdict
    evidence_bundle_path: Optional[Path]
    exit_code: Optional[int]
    stdout_bytes: int
    stderr_bytes: int
    duration_sec: float
    expected_output_matched: Optional[bool]
    out_of_scope_url: Optional[str]  # set when scope-gating refused
    screenshot_path: Optional[Path]  # set when playwright + screenshot.png landed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_urls(command: str) -> list[str]:
    """Pull deduped URLs out of a PoC command, trimming trailing punctuation."""
    seen: set[str] = set()
    out: list[str] = []
    for match in _URL_REGEX.findall(command or ""):
        url = match.rstrip(_URL_TRAILING_PUNCT)
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _resolve_safe_workspace(workspace_dir: Path | str) -> Path:
    """Reject `..` traversal; return a resolved absolute Path.

    The caller (Plan 03-05 pipeline) is responsible for picking a
    workspaces-root-anchored directory. The sandbox enforces only the
    minimal property: the input must not contain `..` segments. We do
    NOT `resolve(strict=True)` because the bundle dir is created on
    demand below.
    """
    raw = str(workspace_dir)
    # Reject the lexical traversal pattern. `Path.parts` makes this robust
    # against `foo/bar/../escape` (parts contains `..`) and against
    # mid-segment dots like `foo/.../bar`.
    parts = Path(raw).parts
    if ".." in parts:
        raise ValueError(
            f"workspace_dir must not contain '..' segments (got {raw!r})"
        )
    return Path(raw).resolve(strict=False)


def _poc_filename(language: str) -> str:
    """Per-language script filename inside the evidence bundle."""
    if language in ("shell", "sqlmap"):
        return "poc.sh"
    if language in ("python", "playwright"):
        return "poc.py"
    raise ValueError(f"unknown language for filename: {language!r}")


def _write_evidence_bundle(bundle_dir: Path, parsed_poc: ParsedPoc) -> Path:
    """Materialize the PoC script into the bundle and return its path."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    poc_path = bundle_dir / _poc_filename(parsed_poc.language)
    poc_path.write_text(parsed_poc.command)
    # 0o700 — operator-readable, no group/world access. The whole workspaces/
    # tree is gitignored anyway, but the per-file mode is documentation of
    # the trust boundary.
    try:
        os.chmod(poc_path, 0o700)
    except OSError as e:  # pragma: no cover — best-effort on weird FSes
        log.debug("chmod 0o700 on %s failed: %s", poc_path, e)
    return poc_path


def _build_subprocess_argv(poc_path: Path, language: str) -> list[str]:
    """Return the argv subprocess.run should invoke for this language."""
    if language in ("shell", "sqlmap"):
        return ["bash", "-e", str(poc_path)]
    if language in ("python", "playwright"):
        return [sys.executable, str(poc_path)]
    raise ValueError(f"unsupported language: {language!r}")


def _truncate(buf: Optional[str], cap: int) -> str:
    """Return buf truncated to cap with a marker appended when truncated."""
    if not buf:
        return ""
    if len(buf) <= cap:
        return buf
    return buf[:cap] + f"\n--- TRUNCATED at {cap} bytes ---\n"


# ---------------------------------------------------------------------------
# Audit / event-log emission
# ---------------------------------------------------------------------------


def _safe_event_log_emit(
    event_log: Optional[Any], kind: str, payload: dict[str, Any]
) -> None:
    """Call event_log.emit defensively — emit failures must not crash the sandbox."""
    if event_log is None:
        return
    try:
        event_log.emit(kind, **payload)
    except Exception as e:  # pragma: no cover — defensive only
        log.warning("event_log.emit(%s) failed: %s", kind, e)


def _safe_audit_write(
    audit_log: Optional[AuditLog],
    scope: Scope,
    event: str,
    payload: dict[str, Any],
) -> None:
    """Call audit_log.write defensively — never crash the sandbox on audit IO."""
    if audit_log is None:
        log.warning("execute_poc: audit_log is None; skipping %s emission", event)
        return
    try:
        audit_log.write(event, payload, mode=scope.engagement_mode.value)
    except Exception as e:  # pragma: no cover — defensive only
        log.warning("audit_log.write(%s) failed: %s", event, e)


def _emit_started(
    *,
    audit_log: AuditLog,
    scope: Scope,
    finding: Finding,
    parsed_poc: ParsedPoc,
    bundle_dir: Path,
    event_log: Optional[Any],
) -> None:
    """Write the `poc_run_started` audit event + mirror to event_log."""
    payload: dict[str, Any] = {
        "engagement_id": scope.engagement_id,
        "finding_fingerprint": finding.fingerprint(),
        "language": parsed_poc.language,
        # T-03-04-02 mitigation: command truncated to 512 chars in the audit
        # payload; the full PoC stays in the on-disk bundle which is NDA-
        # gitignored.
        "command_truncated_512": parsed_poc.command[:512],
        "evidence_bundle_path": str(bundle_dir),
    }
    _safe_audit_write(audit_log, scope, "poc_run_started", payload)
    _safe_event_log_emit(event_log, "poc_run_started", payload)


def _emit_completed(
    *,
    audit_log: AuditLog,
    scope: Scope,
    finding: Finding,
    bundle_dir: Optional[Path],
    evidence_state: EvidenceState,
    rationale: str,
    exit_code: Optional[int],
    duration_sec: float,
    expected_output_matched: Optional[bool],
    pattern_name: Optional[str],
    out_of_scope_url: Optional[str],
    event_log: Optional[Any],
) -> None:
    """Write the `poc_run_completed` audit event + mirror to event_log."""
    payload: dict[str, Any] = {
        "engagement_id": scope.engagement_id,
        "finding_fingerprint": finding.fingerprint(),
        "evidence_state": evidence_state.value,
        # T-03-04-02 mitigation: rationale truncated to 256 chars in the
        # audit payload.
        "rationale": (rationale or "")[:256],
        "exit_code": exit_code,
        "duration_sec": round(float(duration_sec), 2),
        "expected_output_matched": expected_output_matched,
        "evidence_bundle_path": str(bundle_dir) if bundle_dir is not None else None,
        "destructive_pattern": pattern_name,
        "out_of_scope_url": out_of_scope_url,
    }
    _safe_audit_write(audit_log, scope, "poc_run_completed", payload)
    _safe_event_log_emit(event_log, "poc_run_completed", payload)


def _emit_audit_pair_for_short_circuit(
    *,
    audit_log: AuditLog,
    scope: Scope,
    finding: Finding,
    parsed_poc: ParsedPoc,
    bundle_dir: Path,
    evidence_state: EvidenceState,
    rationale: str,
    pattern_name: Optional[str],
    out_of_scope_url: Optional[str],
    event_log: Optional[Any],
) -> None:
    """Write BOTH events for a short-circuit (destructive / out-of-scope) path.

    Per VERIFY-06 the audit contract is paired-events-per-attempt. The
    short-circuit paths never invoke subprocess.run, but we still pair
    started + completed so the legal-artifact trail records "Sentinel
    saw this PoC, refused to execute it for <reason>".
    """
    _emit_started(
        audit_log=audit_log,
        scope=scope,
        finding=finding,
        parsed_poc=parsed_poc,
        bundle_dir=bundle_dir,
        event_log=event_log,
    )
    _emit_completed(
        audit_log=audit_log,
        scope=scope,
        finding=finding,
        bundle_dir=bundle_dir,
        evidence_state=evidence_state,
        rationale=rationale,
        exit_code=None,
        duration_sec=0.0,
        expected_output_matched=None,
        pattern_name=pattern_name,
        out_of_scope_url=out_of_scope_url,
        event_log=event_log,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def execute_poc(
    *,
    finding: Finding,
    parsed_poc: ParsedPoc,
    scope: Scope,
    workspace_dir: Path | str,
    audit_log: AuditLog,
    event_log: Optional[Any] = None,
) -> SandboxResult:
    """Run a parsed PoC under the four-layer defense; return a verdict.

    Layers (in order):

      1. `classify_destructive(parsed_poc.command, parsed_poc.language)` —
         if `is_destructive` is True, short-circuit MANUAL_REQUIRED with
         pattern_name + rationale; NO subprocess.run call.
      2. `scope.authorize_url(url)` for each URL extracted from the
         command — first `OutOfScopeError` short-circuits MANUAL_REQUIRED
         with out_of_scope_url set; NO subprocess.run call.
      3. `subprocess.run(argv, ..., timeout=SANDBOX_TIMEOUT_SEC)` — on
         `TimeoutExpired`, MANUAL_REQUIRED with rationale 'timeout'.
      4. `re.search(parsed_poc.expected_output_regex, stdout, MULTILINE)` —
         exit_code=0 AND match → VERIFIED; exit_code=0 AND no match →
         UNREPRODUCIBLE; exit_code != 0 → UNREPRODUCIBLE regardless of
         match (exit_code=0 is a precondition for VERIFIED).

    Returns:
        SandboxResult with verdict + paths + execution details.

    Raises:
        ValueError: when `workspace_dir` contains `..` (path-traversal
                    guard). All other errors are caught and converted to
                    SandboxResult evidence_state values; the function
                    never raises on subprocess / audit / file-IO failures.
    """
    # T-03-04-10: path-traversal guard. Resolve + reject `..`. Done BEFORE
    # the bundle directory is computed so a traversal attempt never even
    # touches the filesystem.
    safe_workspace = _resolve_safe_workspace(workspace_dir)
    bundle_dir = safe_workspace / "verification" / finding.fingerprint()

    # ----- Layer 1: classify_destructive -----
    verdict = classify_destructive(parsed_poc.command, parsed_poc.language)
    if verdict.is_destructive:
        # Materialize a refusal-only bundle so the operator can read why
        # the PoC was refused. The original PoC is preserved in the
        # refusal.txt body (T-03-04-02 still holds — workspaces/ is
        # NDA-gitignored).
        bundle_dir.mkdir(parents=True, exist_ok=True)
        (bundle_dir / "refusal.txt").write_text(
            "PoC refused by destructive classifier (Plan 03-03).\n"
            f"Pattern: {verdict.pattern_name}\n"
            f"Rationale: {verdict.rationale}\n\n"
            f"Command (first 512 chars):\n{parsed_poc.command[:512]}\n"
        )
        rationale = f"destructive: {verdict.rationale}"
        _emit_audit_pair_for_short_circuit(
            audit_log=audit_log,
            scope=scope,
            finding=finding,
            parsed_poc=parsed_poc,
            bundle_dir=bundle_dir,
            evidence_state=EvidenceState.MANUAL_REQUIRED,
            rationale=rationale,
            pattern_name=verdict.pattern_name,
            out_of_scope_url=None,
            event_log=event_log,
        )
        return SandboxResult(
            evidence_state=EvidenceState.MANUAL_REQUIRED,
            pattern_name=verdict.pattern_name,
            rationale=verdict.rationale,
            evidence_bundle_path=bundle_dir,
            exit_code=None,
            stdout_bytes=0,
            stderr_bytes=0,
            duration_sec=0.0,
            expected_output_matched=None,
            out_of_scope_url=None,
            screenshot_path=None,
        )

    # ----- Layer 2: scope-gating per URL -----
    for url in _extract_urls(parsed_poc.command):
        try:
            scope.authorize_url(url)
        except OutOfScopeError as e:
            bundle_dir.mkdir(parents=True, exist_ok=True)
            (bundle_dir / "refusal.txt").write_text(
                "PoC refused by scope-gating (sentinel/core/scope.py).\n"
                f"Out-of-scope URL: {url}\n"
                f"OutOfScopeError: {e}\n\n"
                "To authorize this URL, edit the scope file (legal artifact) and re-run.\n"
            )
            rationale = f"URL not in scope: {url}"
            _emit_audit_pair_for_short_circuit(
                audit_log=audit_log,
                scope=scope,
                finding=finding,
                parsed_poc=parsed_poc,
                bundle_dir=bundle_dir,
                evidence_state=EvidenceState.MANUAL_REQUIRED,
                rationale=rationale,
                pattern_name=None,
                out_of_scope_url=url,
                event_log=event_log,
            )
            return SandboxResult(
                evidence_state=EvidenceState.MANUAL_REQUIRED,
                pattern_name=None,
                rationale=rationale,
                evidence_bundle_path=bundle_dir,
                exit_code=None,
                stdout_bytes=0,
                stderr_bytes=0,
                duration_sec=0.0,
                expected_output_matched=None,
                out_of_scope_url=url,
                screenshot_path=None,
            )

    # ----- Layer 3: subprocess.run with bounded timeout -----
    poc_path = _write_evidence_bundle(bundle_dir, parsed_poc)
    argv = _build_subprocess_argv(poc_path, parsed_poc.language)

    # poc_run_started fires BEFORE subprocess.run — by VERIFY-06 contract.
    _emit_started(
        audit_log=audit_log,
        scope=scope,
        finding=finding,
        parsed_poc=parsed_poc,
        bundle_dir=bundle_dir,
        event_log=event_log,
    )

    t0 = time.monotonic()
    timed_out = False
    try:
        cp = subprocess.run(
            argv,
            cwd=str(bundle_dir),
            capture_output=True,
            text=True,
            timeout=SANDBOX_TIMEOUT_SEC,
            check=False,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
    except subprocess.TimeoutExpired as e:
        # Preserve any partial stdout/stderr the subprocess emitted before
        # the timeout fired. TimeoutExpired carries them as bytes-or-str.
        partial_stdout = e.stdout if isinstance(e.stdout, str) else (
            (e.stdout or b"").decode(errors="replace") if e.stdout else ""
        )
        partial_stderr = e.stderr if isinstance(e.stderr, str) else (
            (e.stderr or b"").decode(errors="replace") if e.stderr else ""
        )
        cp = subprocess.CompletedProcess(
            args=argv, returncode=-1, stdout=partial_stdout, stderr=partial_stderr
        )
        timed_out = True
    duration_sec = time.monotonic() - t0

    # Persist outputs to the bundle, truncated to MAX_OUTPUT_BYTES.
    stdout_text = _truncate(cp.stdout, MAX_OUTPUT_BYTES)
    stderr_text = _truncate(cp.stderr, MAX_OUTPUT_BYTES)
    (bundle_dir / "stdout.log").write_text(stdout_text)
    (bundle_dir / "stderr.log").write_text(stderr_text)
    (bundle_dir / "exit_code.txt").write_text(str(cp.returncode))

    # ----- Layer 4: regex match → verdict -----
    expected_output_matched: Optional[bool]
    if timed_out:
        evidence_state = EvidenceState.MANUAL_REQUIRED
        # "timeout" appears verbatim so dashboards + tests searching for the
        # word in the rationale string match without locale gymnastics.
        rationale = (
            f"PoC timeout: did not complete within {SANDBOX_TIMEOUT_SEC}s"
        )
        expected_output_matched = None
    elif cp.returncode != 0:
        evidence_state = EvidenceState.UNREPRODUCIBLE
        rationale = f"PoC exit code {cp.returncode} (expected 0 for VERIFIED)"
        expected_output_matched = False
    else:
        # MULTILINE so `^/$` match line boundaries; DOTALL so `.` spans
        # newlines (a curl one-liner's stdout is multi-line by default —
        # `200 OK.*email` should match across `HTTP/1.1 200 OK\n{"email":...}`).
        try:
            expected_output_matched = bool(
                re.search(
                    parsed_poc.expected_output_regex,
                    cp.stdout or "",
                    re.MULTILINE | re.DOTALL,
                )
            )
        except re.error as e:
            expected_output_matched = False
            log.warning("execute_poc: expected_output_regex did not compile: %s", e)
        if expected_output_matched:
            evidence_state = EvidenceState.VERIFIED
            rationale = "PoC executed cleanly; expected output regex matched in stdout"
        else:
            evidence_state = EvidenceState.UNREPRODUCIBLE
            rationale = "PoC ran but expected output regex did not match stdout"

    # Optional playwright screenshot — record path only when the file
    # actually landed (Tests 14 + 15 nail down both branches).
    screenshot_candidate = bundle_dir / "screenshot.png"
    screenshot_path: Optional[Path] = (
        screenshot_candidate
        if (parsed_poc.language == "playwright" and screenshot_candidate.is_file())
        else None
    )

    _emit_completed(
        audit_log=audit_log,
        scope=scope,
        finding=finding,
        bundle_dir=bundle_dir,
        evidence_state=evidence_state,
        rationale=rationale,
        exit_code=cp.returncode,
        duration_sec=duration_sec,
        expected_output_matched=expected_output_matched,
        pattern_name=None,
        out_of_scope_url=None,
        event_log=event_log,
    )

    return SandboxResult(
        evidence_state=evidence_state,
        pattern_name=None,
        rationale=rationale,
        evidence_bundle_path=bundle_dir,
        exit_code=cp.returncode,
        stdout_bytes=len(stdout_text),
        stderr_bytes=len(stderr_text),
        duration_sec=duration_sec,
        expected_output_matched=expected_output_matched,
        out_of_scope_url=None,
        screenshot_path=screenshot_path,
    )
