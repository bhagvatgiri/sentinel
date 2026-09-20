"""Hermetic tests for sentinel/agent/pentest/bbot_tool.py.

Mocks bbot subprocess + JSON event stream. No real network.
"""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest


@pytest.fixture
def fake_ctx(tmp_path):
    """Build a fake ctx with scope + audit + event_log."""
    ctx = MagicMock()
    ctx.scope = MagicMock()
    ctx.scope.engagement_mode.value = "bbp"
    ctx.scope.client = "testclient"
    ctx.scope.engagement_id = "e1"
    ctx.scope.authorize_url = MagicMock()
    ctx.audit = MagicMock()
    ctx.audit.write = MagicMock()
    ctx.event_log = MagicMock()
    ctx.event_log.emit = MagicMock()
    ctx.job_id = "job-test"
    ctx.runs_dir = tmp_path
    return ctx


# Sample bbot JSON event stream (one event per line, matches real bbot --json output)
SAMPLE_BBOT_EVENTS = [
    {"type": "DNS_NAME", "data": "api.target.com", "module": "subfinder", "scope_distance": 0},
    {"type": "OPEN_TCP_PORT", "data": "api.target.com:443", "module": "naabu", "scope_distance": 0},
    {"type": "HTTP_RESPONSE", "data": {"url": "https://api.target.com", "status": 200}, "module": "httpx", "scope_distance": 0},
    {"type": "EMAIL_ADDRESS", "data": "admin@target.com", "module": "email_extract", "scope_distance": 0},
    {"type": "URL", "data": "https://api.target.com/admin", "module": "wappalyzer", "scope_distance": 0},
]


@pytest.mark.asyncio
async def test_run_bbot_scope_gated(fake_ctx, monkeypatch):
    """run_bbot calls scope.authorize_url before spawning bbot."""
    from sentinel.agent.pentest import bbot_tool

    monkeypatch.setattr(bbot_tool, "_require_ctx", lambda: fake_ctx)

    # Mock subprocess to NOT actually run bbot
    async def fake_run(target, modules, intensity):
        return SAMPLE_BBOT_EVENTS

    monkeypatch.setattr(bbot_tool, "_run_bbot_subprocess", fake_run)

    await bbot_tool.run_bbot.handler(
        {"target": "https://api.target.com", "modules": "subfinder,httpx", "intensity": "passive"}
    )

    fake_ctx.scope.authorize_url.assert_called_once_with("https://api.target.com")


@pytest.mark.asyncio
async def test_run_bbot_emits_audit_with_mode(fake_ctx, monkeypatch):
    """bbot_run_completed event written with mode= kwarg (B1 discipline)."""
    from sentinel.agent.pentest import bbot_tool

    monkeypatch.setattr(bbot_tool, "_require_ctx", lambda: fake_ctx)

    async def fake_run(target, modules, intensity):
        return SAMPLE_BBOT_EVENTS

    monkeypatch.setattr(bbot_tool, "_run_bbot_subprocess", fake_run)

    await bbot_tool.run_bbot.handler(
        {"target": "target.com", "modules": "subfinder", "intensity": "passive"}
    )

    audit_calls = fake_ctx.audit.write.call_args_list
    assert any(c.args[0] == "bbot_run_completed" for c in audit_calls)
    # B1 mode discipline
    for c in audit_calls:
        assert c.kwargs.get("mode") == "bbp", (
            f"audit.write({c.args[0]!r}) missing mode= kwarg"
        )


@pytest.mark.asyncio
async def test_run_bbot_returns_structured_summary(fake_ctx, monkeypatch):
    """Tool result has per-event-type counts."""
    from sentinel.agent.pentest import bbot_tool

    monkeypatch.setattr(bbot_tool, "_require_ctx", lambda: fake_ctx)

    async def fake_run(target, modules, intensity):
        return SAMPLE_BBOT_EVENTS

    monkeypatch.setattr(bbot_tool, "_run_bbot_subprocess", fake_run)

    result = await bbot_tool.run_bbot.handler(
        {"target": "target.com", "modules": "all", "intensity": "passive"}
    )

    # Result is _ok / _err shape: {"content": [{"type": "text", "text": "..."}], ...}
    assert result.get("is_error") is not True
    text = result["content"][0]["text"]
    # Body must mention event counts.
    assert "DNS_NAME" in text or "dns_name" in text.lower() or "5" in text  # 5 total events


@pytest.mark.asyncio
async def test_run_bbot_handles_out_of_scope(fake_ctx, monkeypatch):
    """When scope.authorize_url raises OutOfScopeError, tool returns _err without spawning."""
    from sentinel.agent.pentest import bbot_tool
    from sentinel.core.scope import OutOfScopeError

    monkeypatch.setattr(bbot_tool, "_require_ctx", lambda: fake_ctx)
    fake_ctx.scope.authorize_url.side_effect = OutOfScopeError("out of scope")

    spawned = MagicMock()
    monkeypatch.setattr(bbot_tool, "_run_bbot_subprocess", spawned)

    result = await bbot_tool.run_bbot.handler(
        {"target": "out-of-scope.com", "modules": "subfinder", "intensity": "passive"}
    )

    # Should be an error result
    assert result.get("is_error") is True
    text = result["content"][0]["text"]
    assert "out of scope" in text.lower() or "scope" in text.lower()
    spawned.assert_not_called()


@pytest.mark.asyncio
async def test_run_bbot_intensity_validated(fake_ctx, monkeypatch):
    """intensity must be passive | active | intrusive."""
    from sentinel.agent.pentest import bbot_tool

    monkeypatch.setattr(bbot_tool, "_require_ctx", lambda: fake_ctx)

    result = await bbot_tool.run_bbot.handler(
        {"target": "target.com", "modules": "subfinder", "intensity": "wild"}
    )
    assert result.get("is_error") is True
    text = result["content"][0]["text"].lower()
    assert "intensity" in text and "passive" in text
