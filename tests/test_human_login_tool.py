"""Human-in-the-loop login tool — request/complete/skip/timeout flows."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from sentinel.agent.pentest import human_login_tool as h


def _make_ctx(tmp_path: Path, *, browser_strategy="cdp", job_id="test-job-001"):
    audit = MagicMock()
    audit.write = MagicMock()
    event_log = MagicMock()
    event_log.emit = MagicMock()
    scope = MagicMock()
    scope.authorize_url = MagicMock()  # in scope (no raise)
    scope.engagement_id = "test-eng"
    scope.engagement_mode = SimpleNamespace(value="bbp")
    scope.browser_strategy = browser_strategy
    scope.chrome_cdp_port = 9222
    scope.auth_cookies = []
    return SimpleNamespace(
        scope=scope, audit=audit, event_log=event_log,
        current_phase="vuln:csrf", job_id=job_id,
    )


def test_list_pending_filters_completed_and_skipped():
    records = [
        {"id": "a1", "status": "pending", "ts": 1.0, "url": "u1"},
        {"id": "a2", "status": "pending", "ts": 2.0, "url": "u2"},
        {"id": "a1", "status": "completed", "ts": 3.0},
        {"id": "a3", "status": "pending", "ts": 4.0, "url": "u3"},
        {"id": "a2", "status": "skipped", "ts": 5.0},
    ]
    pending = h.list_pending(records)
    ids = [p["id"] for p in pending]
    assert ids == ["a3"]


def test_find_completion_returns_first_match():
    records = [
        {"id": "x", "status": "pending"},
        {"id": "x", "status": "completed", "ts": 10.0},
    ]
    found = h.find_completion(records, "x")
    assert found is not None
    assert found["status"] == "completed"


def test_find_completion_returns_none_when_only_pending():
    records = [{"id": "y", "status": "pending"}]
    assert h.find_completion(records, "y") is None


def test_request_human_login_refuses_non_cdp_strategy(tmp_path: Path, monkeypatch):
    """Without browser_strategy=cdp the tool refuses (no profile to land cookies in)."""
    ctx = _make_ctx(tmp_path, browser_strategy=None)
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    result = asyncio.run(h.request_human_login.handler({
        "url": "https://example.com/login", "reason": "test",
        "account_creation_required": False, "policy_notes": "",
    }))
    assert result.get("is_error") is True
    text = result["content"][0]["text"]
    assert "browser_strategy=cdp" in text


def test_request_human_login_refuses_out_of_scope(tmp_path: Path, monkeypatch):
    from sentinel.core.scope import OutOfScopeError
    ctx = _make_ctx(tmp_path)
    ctx.scope.authorize_url = MagicMock(side_effect=OutOfScopeError("oos"))
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    result = asyncio.run(h.request_human_login.handler({
        "url": "https://evil.com/login", "reason": "test",
        "account_creation_required": False, "policy_notes": "",
    }))
    assert result.get("is_error") is True
    assert "out-of-scope" in result["content"][0]["text"]


def test_request_human_login_completes_when_operator_signals(tmp_path: Path, monkeypatch):
    """Tool blocks, then unblocks when operator appends a `completed` record."""
    ctx = _make_ctx(tmp_path)
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    monkeypatch.setattr(h, "DEFAULT_TIMEOUT_SEC", 5.0)
    monkeypatch.setattr(h, "POLL_INTERVAL_SEC", 0.05)
    # Force the runs dir to tmp_path so we can write the completion record.
    monkeypatch.chdir(tmp_path)

    # Mock chrome_profile.snapshot_cookies_async to return some cookies.
    async def fake_snapshot(port):
        return [
            {"name": "session", "value": "abc", "domain": ".example.com",
             "path": "/", "secure": True, "httpOnly": True},
        ]
    from sentinel.agent import chrome_profile as _cp
    monkeypatch.setattr(_cp, "snapshot_cookies_async", fake_snapshot)
    monkeypatch.setattr(_cp, "resolve_cdp_port", lambda scope: 9222)

    async def run_test():
        # Fire the tool call as a background task.
        task = asyncio.create_task(h.request_human_login.handler({
            "url": "https://example.com/login", "reason": "needs auth",
            "account_creation_required": False, "policy_notes": "",
        }))
        # Give it a moment to write its pending record.
        await asyncio.sleep(0.15)
        log_path = h.login_log_path(ctx.job_id, tmp_path / "runs")
        records = h._read_records(log_path)
        # Find the pending record's ID and append a completion.
        pending = [r for r in records if r.get("status") == "pending"]
        assert pending, "pending record should be written by now"
        rid = pending[0]["id"]
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": time.time(), "id": rid, "status": "completed",
                "operator_note": "test signal",
            }) + "\n")
        result = await asyncio.wait_for(task, timeout=3.0)
        return result

    result = asyncio.run(run_test())
    assert result.get("is_error") is None or result.get("is_error") is False
    text = result["content"][0]["text"]
    assert "Refreshed Chrome profile cookies" in text
    # Verify scope.auth_cookies was replaced with snapshot.
    assert len(ctx.scope.auth_cookies) == 1
    assert ctx.scope.auth_cookies[0]["name"] == "session"


def test_request_human_login_skipped_returns_err(tmp_path: Path, monkeypatch):
    ctx = _make_ctx(tmp_path)
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    monkeypatch.setattr(h, "DEFAULT_TIMEOUT_SEC", 5.0)
    monkeypatch.setattr(h, "POLL_INTERVAL_SEC", 0.05)
    monkeypatch.chdir(tmp_path)

    async def run_test():
        task = asyncio.create_task(h.request_human_login.handler({
            "url": "https://example.com/login", "reason": "test",
            "account_creation_required": False, "policy_notes": "",
        }))
        await asyncio.sleep(0.15)
        log_path = h.login_log_path(ctx.job_id, tmp_path / "runs")
        records = h._read_records(log_path)
        pending = [r for r in records if r.get("status") == "pending"]
        assert pending
        rid = pending[0]["id"]
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": time.time(), "id": rid, "status": "skipped",
            }) + "\n")
        return await asyncio.wait_for(task, timeout=3.0)

    result = asyncio.run(run_test())
    assert result.get("is_error") is True
    assert "skipped" in result["content"][0]["text"].lower()


def test_request_human_login_times_out(tmp_path: Path, monkeypatch):
    """No completion appears → tool returns _err after timeout."""
    ctx = _make_ctx(tmp_path)
    monkeypatch.setattr(h, "_require_ctx", lambda: ctx)
    monkeypatch.setattr(h, "DEFAULT_TIMEOUT_SEC", 0.6)  # 600ms timeout
    monkeypatch.setattr(h, "POLL_INTERVAL_SEC", 0.1)
    monkeypatch.chdir(tmp_path)

    result = asyncio.run(h.request_human_login.handler({
        "url": "https://example.com/login", "reason": "test",
        "account_creation_required": False, "policy_notes": "",
    }))
    assert result.get("is_error") is True
    assert "Timed out" in result["content"][0]["text"]
