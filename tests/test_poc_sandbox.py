"""VERIFY-04 + VERIFY-06 — PoC execution sandbox contract.

Pins the four-layer defense and audit-event pair that Plan 03-04's
`execute_poc` enforces. Tests are hermetic — `subprocess.run` is
monkeypatched, Scope is loaded from a tmp_path yaml fixture, AuditLog
writes to tmp_path/audit.jsonl. NO real network, NO real Playwright,
NO real LLM.

Defense layers covered (in order):

    1. classify_destructive short-circuit — Tests 1, contract-critical
       (asserts subprocess.run NEVER called).
    2. scope.authorize_url short-circuit — Test 2, contract-critical
       (asserts subprocess.run NEVER called).
    3. subprocess.run with 60s timeout — Test 3 (TimeoutExpired -> manual).
    4. expected_output_regex match — Tests 4, 5, 6.

Audit-event pair (`poc_run_started` + `poc_run_completed`) is covered by
Tests 8, 9, 10 and the hash-chain integrity test (Test 9 calls
AuditLog.verify directly).

Tests 14 + 15 nail down the screenshot_path field per Plan 03-04 revision
iter 2 — present when the playwright PoC wrote screenshot.png, None
otherwise.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from sentinel.agent.poc import (
    MAX_OUTPUT_BYTES,
    SANDBOX_TIMEOUT_SEC,
    ParsedPoc,
    SandboxResult,
    execute_poc,
)
from sentinel.core.findings import EvidenceState, Finding, Severity
from sentinel.core.scope import AuditLog, Scope
from sentinel.web.event_styles import EVENT_STYLES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_scope_yaml(tmp_path: Path) -> Path:
    """Write a minimal scope file that authorizes loopback + a test domain."""
    today = "2026-01-01"
    until = "2030-12-31"
    yaml_text = (
        f"client: testclient\n"
        f"engagement_id: test-engagement-03-04\n"
        f"authorized_by: test@example.com\n"
        f"valid_from: {today}\n"
        f"valid_until: {until}\n"
        f"targets:\n"
        f"  domains:\n"
        f"    - target.example.com\n"
        f"    - 127.0.0.1\n"
        f"    - localhost\n"
        f"  ips:\n"
        f"    - 127.0.0.1/32\n"
    )
    p = tmp_path / "scope.yaml"
    p.write_text(yaml_text)
    return p


@pytest.fixture
def scope_and_audit(tmp_path: Path):
    """Build a real Scope + real AuditLog rooted in tmp_path."""
    scope_path = _write_scope_yaml(tmp_path)
    audit_path = tmp_path / "audit.jsonl"
    scope = Scope.load(scope_path, audit_log_path=audit_path)
    assert scope.audit_log is not None
    return scope, scope.audit_log, tmp_path


@pytest.fixture
def workspace_dir(tmp_path: Path) -> Path:
    """Plain workspaces/<engagement>/ root for the sandbox to write into."""
    p = tmp_path / "workspaces" / "test-engagement-03-04"
    p.mkdir(parents=True, exist_ok=True)
    return p


@pytest.fixture
def finding() -> Finding:
    """Generic in-scope finding for the sandbox to verify."""
    return Finding(
        title="IDOR on /api/users/{id}",
        description="Test finding",
        severity=Severity.HIGH,
        scanner="vuln:idor",
        target="http://target.example.com",
        location="/api/users/1",
        cwe="CWE-639",
    )


class StubEventLog:
    """Captures event_log.emit() calls for assertion."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def emit(self, kind: str, **payload: Any) -> None:
        self.calls.append((kind, payload))


# ---------------------------------------------------------------------------
# Test 1 — destructive short-circuit (CONTRACT-CRITICAL)
# ---------------------------------------------------------------------------


def test_execute_poc_destructive_short_circuits_without_subprocess(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T1 (THE contract test): destructive PoC NEVER reaches subprocess.run.

    `classify_destructive` (Plan 03-03) is the first layer. When it
    returns is_destructive=True the sandbox MUST set
    evidence_state=MANUAL_REQUIRED and refuse, with zero subprocess
    invocations.
    """
    scope, audit, _ = scope_and_audit
    calls: list[Any] = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    # Use a shell-classifiable destructive verb so the classifier fires under
    # language='shell'. Plan 03-03's classifier filters SQL patterns when the
    # caller pins language='shell', so 'DROP TABLE users' alone would skip
    # the sql_drop_table pattern — we use rm -rf which is shell-flagged.
    parsed = ParsedPoc(
        command="rm -rf /tmp/anything",
        language="shell",
        expected_output_regex=r".*",
        rationale="destructive shell verb",
    )
    result = execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )

    assert calls == [], "subprocess.run must NOT be called for destructive PoCs"
    assert isinstance(result, SandboxResult)
    assert result.evidence_state == EvidenceState.MANUAL_REQUIRED
    assert result.pattern_name == "shell_rm_rf"


# ---------------------------------------------------------------------------
# Test 2 — out-of-scope short-circuit (CONTRACT-CRITICAL)
# ---------------------------------------------------------------------------


def test_execute_poc_out_of_scope_url_short_circuits(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T2: any URL outside scope short-circuits BEFORE subprocess.run."""
    scope, audit, _ = scope_and_audit
    calls: list[Any] = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="curl -s http://not-in-scope.example.com/admin",
        language="shell",
        expected_output_regex=r".*",
        rationale="out of scope target",
    )
    result = execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )

    assert calls == [], "subprocess.run must NOT be called for out-of-scope URLs"
    assert result.evidence_state == EvidenceState.MANUAL_REQUIRED
    assert result.out_of_scope_url is not None
    assert "not-in-scope.example.com" in result.out_of_scope_url
    assert "scope" in result.rationale.lower()


# ---------------------------------------------------------------------------
# Test 3 — timeout produces MANUAL_REQUIRED
# ---------------------------------------------------------------------------


def test_execute_poc_timeout_produces_manual_required(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T3: subprocess.TimeoutExpired -> evidence_state=MANUAL_REQUIRED."""
    scope, audit, _ = scope_and_audit

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=SANDBOX_TIMEOUT_SEC)

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="curl -s http://127.0.0.1/slow",
        language="shell",
        expected_output_regex=r"ok",
        rationale="hang test",
    )
    result = execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )
    assert result.evidence_state == EvidenceState.MANUAL_REQUIRED
    assert "timeout" in result.rationale.lower()


# ---------------------------------------------------------------------------
# Test 4 — regex match -> VERIFIED
# ---------------------------------------------------------------------------


def test_execute_poc_regex_match_produces_verified(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T4: exit_code=0 + regex matches stdout -> VERIFIED."""
    scope, audit, _ = scope_and_audit

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout='HTTP/1.1 200 OK\n{"email":"admin@x"}',
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="curl -s http://127.0.0.1/api/users/2",
        language="shell",
        expected_output_regex=r"200 OK.*email",
        rationale="t4 match",
    )
    result = execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )
    assert result.evidence_state == EvidenceState.VERIFIED
    assert result.expected_output_matched is True
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Test 5 — regex mismatch -> UNREPRODUCIBLE
# ---------------------------------------------------------------------------


def test_execute_poc_regex_mismatch_produces_unreproducible(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T5: exit_code=0 but regex doesn't match -> UNREPRODUCIBLE."""
    scope, audit, _ = scope_and_audit

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout="HTTP/1.1 200 OK\n{}", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="curl -s http://127.0.0.1/api/users/2",
        language="shell",
        expected_output_regex=r"SQLite NOT_FOUND",
        rationale="t5 mismatch",
    )
    result = execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )
    assert result.evidence_state == EvidenceState.UNREPRODUCIBLE
    assert result.expected_output_matched is False


# ---------------------------------------------------------------------------
# Test 6 — non-zero exit + regex match still UNREPRODUCIBLE
# ---------------------------------------------------------------------------


def test_execute_poc_nonzero_exit_with_match_still_unreproducible(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T6: exit_code != 0 -> UNREPRODUCIBLE regardless of regex match.

    Contract: exit_code=0 is a precondition for VERIFIED. A PoC that
    "ran successfully" but reported failure (exit_code=1) is treated as
    unreproducible — the harness ran fine, the bug just didn't reproduce.
    """
    scope, audit, _ = scope_and_audit

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout="HTTP/1.1 200 OK\nemail=admin",
            stderr="curl: error happened",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="curl -s http://127.0.0.1/api/users/2",
        language="shell",
        expected_output_regex=r"200 OK.*email",
        rationale="t6",
    )
    result = execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )
    assert result.evidence_state == EvidenceState.UNREPRODUCIBLE
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Test 7 — evidence bundle files present
# ---------------------------------------------------------------------------


def test_execute_poc_writes_evidence_bundle_files(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T7: poc.sh / stdout.log / stderr.log / exit_code.txt all written."""
    scope, audit, _ = scope_and_audit

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout="hello\n", stderr="warn\n"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="curl -s http://127.0.0.1/",
        language="shell",
        expected_output_regex=r"hello",
        rationale="t7",
    )
    result = execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )
    bundle_dir = workspace_dir / "verification" / finding.fingerprint()
    assert result.evidence_bundle_path == bundle_dir
    assert (bundle_dir / "poc.sh").is_file()
    assert (bundle_dir / "stdout.log").is_file()
    assert (bundle_dir / "stderr.log").is_file()
    assert (bundle_dir / "exit_code.txt").is_file()
    assert (bundle_dir / "exit_code.txt").read_text().strip() == "0"


# ---------------------------------------------------------------------------
# Test 8 — paired audit events written
# ---------------------------------------------------------------------------


def test_execute_poc_writes_paired_audit_events(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T8: poc_run_started THEN poc_run_completed in the audit log."""
    scope, audit, tmp_path = scope_and_audit

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout="ok", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="curl -s http://127.0.0.1/",
        language="shell",
        expected_output_regex=r"ok",
        rationale="t8",
    )
    execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )

    import json

    lines = [
        json.loads(ln)
        for ln in (tmp_path / "audit.jsonl").read_text().splitlines()
        if ln.strip()
    ]
    events = [e["event"] for e in lines]
    # poc_run_started + poc_run_completed both present, in that order, with
    # matching finding_fingerprint in payload.
    assert "poc_run_started" in events
    assert "poc_run_completed" in events
    started_idx = events.index("poc_run_started")
    completed_idx = events.index("poc_run_completed")
    assert started_idx < completed_idx, "started must precede completed"
    fp = finding.fingerprint()
    started_payload = lines[started_idx]["payload"]
    completed_payload = lines[completed_idx]["payload"]
    assert started_payload.get("finding_fingerprint") == fp
    assert completed_payload.get("finding_fingerprint") == fp


# ---------------------------------------------------------------------------
# Test 9 — audit chain still verifies after execute_poc
# ---------------------------------------------------------------------------


def test_execute_poc_audit_chain_verifies(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T9: AuditLog.verify on the file returns (True, None)."""
    scope, audit, tmp_path = scope_and_audit

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout="ok", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="curl -s http://127.0.0.1/",
        language="shell",
        expected_output_regex=r"ok",
        rationale="t9",
    )
    execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )
    ok, err = AuditLog.verify(tmp_path / "audit.jsonl")
    assert ok is True, f"audit chain verify failed: {err}"


# ---------------------------------------------------------------------------
# Test 10 — event_log.emit invoked when provided
# ---------------------------------------------------------------------------


def test_execute_poc_emits_event_log_when_event_log_provided(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T10: event_log.emit fires once for started and once for completed."""
    scope, audit, _ = scope_and_audit

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout="ok", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="curl -s http://127.0.0.1/",
        language="shell",
        expected_output_regex=r"ok",
        rationale="t10",
    )
    stub = StubEventLog()
    execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=stub,
    )
    kinds = [k for k, _ in stub.calls]
    assert kinds.count("poc_run_started") == 1
    assert kinds.count("poc_run_completed") == 1


# ---------------------------------------------------------------------------
# Test 11 — oversized stdout truncated
# ---------------------------------------------------------------------------


def test_execute_poc_truncates_oversized_output(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T11: stdout > MAX_OUTPUT_BYTES is truncated; file size bounded."""
    scope, audit, _ = scope_and_audit

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout="A" * (2 * MAX_OUTPUT_BYTES),
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="curl -s http://127.0.0.1/",
        language="shell",
        expected_output_regex=r"A",
        rationale="t11",
    )
    result = execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )
    bundle_dir = workspace_dir / "verification" / finding.fingerprint()
    stdout_size = (bundle_dir / "stdout.log").stat().st_size
    # Allow a generous ExampleChat for the truncation-marker line we append.
    assert stdout_size <= MAX_OUTPUT_BYTES + 512, (
        f"stdout.log not truncated: {stdout_size} bytes vs cap {MAX_OUTPUT_BYTES}"
    )
    # The sandbox still reports a verdict (regex matches "A" in the truncated body)
    assert result.evidence_state == EvidenceState.VERIFIED


# ---------------------------------------------------------------------------
# Test 12 — workspace path traversal rejected
# ---------------------------------------------------------------------------


def test_execute_poc_rejects_workspace_traversal(
    monkeypatch, scope_and_audit, tmp_path, finding
):
    """T12: workspace_dir containing `..` is rejected BEFORE any file write."""
    scope, audit, _ = scope_and_audit
    calls: list[Any] = []

    def fake_run(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    traversal_path = tmp_path / "workspaces" / ".." / "escape"
    parsed = ParsedPoc(
        command="curl -s http://127.0.0.1/",
        language="shell",
        expected_output_regex=r".",
        rationale="t12",
    )
    with pytest.raises(ValueError):
        execute_poc(
            finding=finding,
            parsed_poc=parsed,
            scope=scope,
            workspace_dir=traversal_path,
            audit_log=audit,
            event_log=None,
        )
    # And subprocess.run was never called.
    assert calls == []
    assert not (tmp_path / "escape").exists()


# ---------------------------------------------------------------------------
# Test 13 — python language uses sys.executable
# ---------------------------------------------------------------------------


def test_execute_poc_python_language_runs_python_binary(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T13: language='python' dispatches via sys.executable on poc.py."""
    scope, audit, _ = scope_and_audit
    recorded: list[list[str]] = []

    def fake_run(*args, **kwargs):
        recorded.append(list(args[0]))
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="print('ok')",
        language="python",
        expected_output_regex=r"ok",
        rationale="t13",
    )
    execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )
    assert recorded, "subprocess.run should have been invoked"
    argv = recorded[0]
    assert argv[0] == sys.executable
    assert argv[1].endswith("poc.py")


# ---------------------------------------------------------------------------
# Test 14 — playwright PoC writes screenshot.png -> screenshot_path set
# ---------------------------------------------------------------------------


def test_execute_poc_records_screenshot_path_when_present(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T14 (revision iter 2): screenshot.png present -> screenshot_path set."""
    scope, audit, _ = scope_and_audit
    bundle_dir = workspace_dir / "verification" / finding.fingerprint()

    def fake_run(*args, **kwargs):
        # Simulate the playwright PoC writing screenshot.png during its run.
        # cwd kwarg is set by the sandbox to bundle_dir; we use the closure
        # directly to avoid relying on cwd interpretation in the mock.
        (bundle_dir).mkdir(parents=True, exist_ok=True)
        (bundle_dir / "screenshot.png").write_bytes(b"\x00")
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="from playwright.sync_api import sync_playwright",
        language="playwright",
        expected_output_regex=r"ok",
        rationale="t14",
    )
    result = execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )
    assert result.screenshot_path == bundle_dir / "screenshot.png"
    assert (bundle_dir / "screenshot.png").is_file()


# ---------------------------------------------------------------------------
# Test 15 — playwright PoC without screenshot.png -> screenshot_path None
# ---------------------------------------------------------------------------


def test_execute_poc_screenshot_absent_returns_none(
    monkeypatch, scope_and_audit, workspace_dir, finding
):
    """T15 (revision iter 2): no screenshot file -> screenshot_path is None."""
    scope, audit, _ = scope_and_audit

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    parsed = ParsedPoc(
        command="from playwright.sync_api import sync_playwright",
        language="playwright",
        expected_output_regex=r"ok",
        rationale="t15",
    )
    result = execute_poc(
        finding=finding,
        parsed_poc=parsed,
        scope=scope,
        workspace_dir=workspace_dir,
        audit_log=audit,
        event_log=None,
    )
    assert result.screenshot_path is None
    bundle_dir = workspace_dir / "verification" / finding.fingerprint()
    # Other bundle artefacts still landed.
    assert (bundle_dir / "stdout.log").is_file()
    assert (bundle_dir / "stderr.log").is_file()
    assert (bundle_dir / "exit_code.txt").is_file()


# ---------------------------------------------------------------------------
# Test 16 — event_styles registers the two new event kinds
# ---------------------------------------------------------------------------


def test_event_styles_has_poc_run_entries():
    """T16: poc_run_started + poc_run_completed both registered, group=phase."""
    assert "poc_run_started" in EVENT_STYLES
    assert "poc_run_completed" in EVENT_STYLES
    assert EVENT_STYLES["poc_run_started"]["group"] == "phase"
    assert EVENT_STYLES["poc_run_completed"]["group"] == "phase"
