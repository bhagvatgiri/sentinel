"""Human-in-the-loop signup tool — gate / scope / completion / timeout / audit chain.

Mirrors tests/test_human_login_tool.py's _make_ctx factory + asyncio.run
pattern. The audit-chain test (#6) uses a REAL AuditLog (via tmp_path) so
the hash chain genuinely walks; everything else mocks the AuditLog.write
to keep tests fast.

Test #7 is the B1 regression guard: every human_signup_* audit entry MUST
carry mode=ctx.scope.engagement_mode.value.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import time
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from sentinel.agent.pentest import human_signup_tool as h
from sentinel.core.scope import AuditLog, OutOfScopeError


def _make_ctx(tmp_path: Path, *, allow_human_signup=True,
              job_id="test-signup-job", real_audit_path: Path | None = None,
              engagement_id="test-eng-signup"):
    if real_audit_path is not None:
        audit = AuditLog(real_audit_path)
    else:
        audit = MagicMock()
        audit.write = MagicMock()
    event_log = MagicMock()
    event_log.emit = MagicMock()
    scope = MagicMock()
    scope.authorize_url = MagicMock()
    scope.engagement_id = engagement_id
    scope.engagement_mode = SimpleNamespace(value="bbp")
    scope.allow_human_signup = allow_human_signup
    scope.auth_credentials = []  # list, not Mock — agent appends
    return SimpleNamespace(
        scope=scope, audit=audit, event_log=event_log,
        current_phase="vuln:auth", job_id=job_id,
    )


# ---------------------------------------------------------------------------
# Test 1: allow_human_signup=False refuses immediately
# ---------------------------------------------------------------------------
def test_refuses_when_not_opted_in(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path, allow_human_signup=False)
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    result = asyncio.run(h.human_signup.handler({
        "url": "https://example.com/signup", "reason": "test",
    }))
    assert result.get("is_error") is True
    text = result["content"][0]["text"]
    assert "allow_human_signup" in text


# ---------------------------------------------------------------------------
# Test 2: out-of-scope URL refused via authorize_url
# ---------------------------------------------------------------------------
def test_refuses_out_of_scope_url(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path, allow_human_signup=True)
    ctx.scope.authorize_url = MagicMock(side_effect=OutOfScopeError("not in scope"))
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    result = asyncio.run(h.human_signup.handler({
        "url": "https://evil.com/signup", "reason": "test",
    }))
    assert result.get("is_error") is True
    assert "out-of-scope" in result["content"][0]["text"]


# ---------------------------------------------------------------------------
# Test 3: pending-record written + human_signup_needed emitted
# ---------------------------------------------------------------------------
def test_writes_pending_and_emits_needed_event(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path, allow_human_signup=True)
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    monkeypatch.setattr(h, "DEFAULT_TIMEOUT_SEC", 5.0)
    monkeypatch.setattr(h, "POLL_INTERVAL_SEC", 0.05)
    monkeypatch.chdir(tmp_path)

    async def runit():
        task = asyncio.create_task(h.human_signup.handler({
            "url": "https://example.com/signup", "reason": "captcha unsolvable",
        }))
        await asyncio.sleep(0.15)
        log_path = h.signup_log_path(ctx.job_id, tmp_path / "runs")
        records = h._read_records(log_path)
        pending = [r for r in records if r.get("status") == "pending"]
        # Cancel the still-blocked task so the test exits cleanly.
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        return pending

    pending = asyncio.run(runit())
    assert len(pending) == 1, f"expected one pending record, got {pending}"
    assert pending[0]["url"] == "https://example.com/signup"
    assert pending[0]["reason"] == "captcha unsolvable"
    # Event emitted with the right kind
    emits = [c.args[0] for c in ctx.event_log.emit.call_args_list]
    assert "human_signup_needed" in emits, emits


# ---------------------------------------------------------------------------
# Test 4: completion flow — creds persisted at 0o600 + auth_credentials synthesized
# ---------------------------------------------------------------------------
def test_completion_persists_creds_and_synthesizes_auth_entry(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path, allow_human_signup=True,
                     engagement_id="myeng")
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    monkeypatch.setattr(h, "DEFAULT_TIMEOUT_SEC", 5.0)
    monkeypatch.setattr(h, "POLL_INTERVAL_SEC", 0.05)
    monkeypatch.chdir(tmp_path)
    # Redirect Path.home() to tmp_path so the creds file lands in the test
    # sandbox, not the operator's real ~/.sentinel/
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    env_vars_to_cleanup = []

    async def runit():
        task = asyncio.create_task(h.human_signup.handler({
            "url": "https://example.com/signup", "reason": "test signup",
        }))
        await asyncio.sleep(0.15)
        log_path = h.signup_log_path(ctx.job_id, tmp_path / "runs")
        records = h._read_records(log_path)
        pending = [r for r in records if r.get("status") == "pending"]
        assert pending, "no pending record written"
        rid = pending[0]["id"]
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": time.time(), "id": rid, "status": "completed",
                "username": "alice@example.com", "password": "hunter2-super-strong",
                "operator_note": "test signal",
            }) + "\n")
        return await asyncio.wait_for(task, timeout=3.0)

    try:
        result = asyncio.run(runit())
        assert result.get("is_error") is None or result.get("is_error") is False
        text = result["content"][0]["text"]
        # auth_credentials synthesized
        assert len(ctx.scope.auth_credentials) == 1
        entry = ctx.scope.auth_credentials[0]
        assert entry["method"] == "form"
        assert entry["username"] == "alice@example.com"
        assert entry["url"] == "https://example.com/signup"
        assert entry["name"].startswith("human-signup-")
        assert entry["password_env"].startswith("_INLINE_")
        env_vars_to_cleanup.append(entry["password_env"])
        # env var was set
        assert os.environ.get(entry["password_env"]) == "hunter2-super-strong"
        # creds file at ~/.sentinel/<eid>.creds.json with mode 0o600
        creds_file = tmp_path / ".sentinel" / "myeng.creds.json"
        assert creds_file.is_file(), f"creds file missing: {creds_file}"
        mode = creds_file.stat().st_mode & 0o777
        assert mode == 0o600, f"creds file mode {oct(mode)}, expected 0o600"
        creds = json.loads(creds_file.read_text())
        # Password never appears in the return text
        assert "hunter2-super-strong" not in text
        assert creds["password"] == "hunter2-super-strong"
        assert creds["username"] == "alice@example.com"
    finally:
        for var in env_vars_to_cleanup:
            os.environ.pop(var, None)


# ---------------------------------------------------------------------------
# Test 5: timeout — no completion → human_signup_timeout
# ---------------------------------------------------------------------------
def test_times_out_and_emits_timeout_event(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path, allow_human_signup=True)
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    monkeypatch.setattr(h, "DEFAULT_TIMEOUT_SEC", 0.6)
    monkeypatch.setattr(h, "POLL_INTERVAL_SEC", 0.1)
    monkeypatch.chdir(tmp_path)

    result = asyncio.run(h.human_signup.handler({
        "url": "https://example.com/signup", "reason": "test",
    }))
    assert result.get("is_error") is True
    assert "Timed out" in result["content"][0]["text"]
    emits = [c.args[0] for c in ctx.event_log.emit.call_args_list]
    assert "human_signup_timeout" in emits, emits


# ---------------------------------------------------------------------------
# Test 6: audit chain integrity through a completed flow
# ---------------------------------------------------------------------------
def test_audit_chain_integrity_after_completion(tmp_path, monkeypatch):
    """Use a real AuditLog so the hash chain genuinely walks through
    human_signup_needed + human_signup_completed."""
    audit_path = tmp_path / "audit.jsonl"
    ctx = _make_ctx(tmp_path, allow_human_signup=True,
                     real_audit_path=audit_path,
                     engagement_id="audit-eng")
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    monkeypatch.setattr(h, "DEFAULT_TIMEOUT_SEC", 5.0)
    monkeypatch.setattr(h, "POLL_INTERVAL_SEC", 0.05)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    env_to_clean = []

    async def runit():
        task = asyncio.create_task(h.human_signup.handler({
            "url": "https://example.com/signup", "reason": "audit test",
        }))
        await asyncio.sleep(0.15)
        log_path = h.signup_log_path(ctx.job_id, tmp_path / "runs")
        records = h._read_records(log_path)
        pending = [r for r in records if r.get("status") == "pending"]
        assert pending
        rid = pending[0]["id"]
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": time.time(), "id": rid, "status": "completed",
                "username": "bob", "password": "p4ssword",
            }) + "\n")
        return await asyncio.wait_for(task, timeout=3.0)

    try:
        result = asyncio.run(runit())
        assert result.get("is_error") is None or result.get("is_error") is False
        if ctx.scope.auth_credentials:
            env_to_clean.append(ctx.scope.auth_credentials[0]["password_env"])
        ok, err = AuditLog.verify(audit_path)
        assert ok, f"audit chain broken: {err}"
    finally:
        for var in env_to_clean:
            os.environ.pop(var, None)


# ---------------------------------------------------------------------------
# Test 7 (B1 regression guard): every human_signup_* audit entry carries mode=
# ---------------------------------------------------------------------------
def test_every_human_signup_audit_entry_carries_mode_kwarg(tmp_path, monkeypatch):
    audit_path = tmp_path / "audit.jsonl"
    ctx = _make_ctx(tmp_path, allow_human_signup=True,
                     real_audit_path=audit_path,
                     engagement_id="mode-eng")
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    monkeypatch.setattr(h, "DEFAULT_TIMEOUT_SEC", 5.0)
    monkeypatch.setattr(h, "POLL_INTERVAL_SEC", 0.05)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    env_to_clean = []

    async def runit():
        task = asyncio.create_task(h.human_signup.handler({
            "url": "https://example.com/signup", "reason": "mode test",
        }))
        await asyncio.sleep(0.15)
        log_path = h.signup_log_path(ctx.job_id, tmp_path / "runs")
        records = h._read_records(log_path)
        pending = [r for r in records if r.get("status") == "pending"]
        rid = pending[0]["id"]
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": time.time(), "id": rid, "status": "completed",
                "username": "u", "password": "p",
            }) + "\n")
        return await asyncio.wait_for(task, timeout=3.0)

    try:
        asyncio.run(runit())
        if ctx.scope.auth_credentials:
            env_to_clean.append(ctx.scope.auth_credentials[0]["password_env"])
        # Walk the audit JSONL: every human_signup_* line MUST have a
        # non-empty mode field equal to the scope's engagement_mode.value.
        expected_mode = ctx.scope.engagement_mode.value
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if not str(entry.get("event", "")).startswith("human_signup_"):
                continue
            mode_val = entry.get("mode")
            assert mode_val == expected_mode, (
                f"audit entry {entry.get('event')!r} carries mode={mode_val!r} "
                f"expected {expected_mode!r}; B1 violation"
            )
    finally:
        for var in env_to_clean:
            os.environ.pop(var, None)


# ---------------------------------------------------------------------------
# Test 8: skipped flow → human_signup_skipped + no creds written
# ---------------------------------------------------------------------------
def test_skipped_flow_returns_err_no_creds_written(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path, allow_human_signup=True, engagement_id="skip-eng")
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    monkeypatch.setattr(h, "DEFAULT_TIMEOUT_SEC", 5.0)
    monkeypatch.setattr(h, "POLL_INTERVAL_SEC", 0.05)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    async def runit():
        task = asyncio.create_task(h.human_signup.handler({
            "url": "https://example.com/signup", "reason": "skip test",
        }))
        await asyncio.sleep(0.15)
        log_path = h.signup_log_path(ctx.job_id, tmp_path / "runs")
        records = h._read_records(log_path)
        rid = [r for r in records if r.get("status") == "pending"][0]["id"]
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": time.time(), "id": rid, "status": "skipped",
            }) + "\n")
        return await asyncio.wait_for(task, timeout=3.0)

    result = asyncio.run(runit())
    assert result.get("is_error") is True
    text = result["content"][0]["text"].lower()
    assert "skipped" in text
    # No creds file written
    assert not (tmp_path / ".sentinel" / "skip-eng.creds.json").exists()
    assert ctx.scope.auth_credentials == []
    emits = [c.args[0] for c in ctx.event_log.emit.call_args_list]
    assert "human_signup_skipped" in emits, emits


# ---------------------------------------------------------------------------
# Test 9: signup_log_path / list_pending / find_completion exports
# ---------------------------------------------------------------------------
def test_helper_exports_exist():
    assert callable(h.signup_log_path)
    assert callable(h.list_pending)
    assert callable(h.find_completion)
    assert h.human_signup in h.ALL_TOOLS
