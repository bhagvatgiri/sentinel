"""Hermetic tests for sentinel/agent/pentest/oauth_install_tool.py.

Mocks the browser consent flow + httpx token exchange. No real network.
Mirrors tests/test_oob_tool.py conventions.
"""
from __future__ import annotations
from unittest.mock import AsyncMock, MagicMock
import pytest


@pytest.fixture
def fake_ctx():
    ctx = MagicMock()
    ctx.scope = MagicMock()
    ctx.scope.engagement_mode.value = "bbp"
    ctx.scope.client = "testclient"
    ctx.scope.engagement_id = "e1"
    ctx.scope.authorize_url = MagicMock(return_value=None)
    ctx.scope.oauth_test_apps = [
        {
            "name": "test-app",
            "client_id_env": "FAKE_CLIENT_ID",
            "client_secret_env": "FAKE_CLIENT_SECRET",
            "authorize_url": "https://example.com/oauth/authorize?client_id={client_id}",
            "redirect_uri": "https://callback.invalid/cb",
            "token_url": "https://example.com/oauth/token",
        }
    ]
    ctx.audit = MagicMock()
    ctx.audit.write = MagicMock()
    ctx.event_log = MagicMock()
    ctx.event_log.emit = MagicMock()
    ctx.job_id = "job-test"
    return ctx


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    from sentinel.agent.pentest import oauth_install_tool as oat
    oat.reset_captured_tokens()
    monkeypatch.setenv("FAKE_CLIENT_ID", "test-client-12345")
    monkeypatch.setenv("FAKE_CLIENT_SECRET", "test-secret-67890")
    yield
    oat.reset_captured_tokens()


def _fake_httpx(body: str, status: int = 200):
    class FakeResp:
        status_code = status
        text = body
        def json(self):
            import json
            return json.loads(self.text)
    class FakeClient:
        def __init__(self, **kw):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def post(self, url, data=None, **kw):
            return FakeResp()
    return FakeClient


@pytest.mark.asyncio
async def test_install_unknown_app_returns_err(fake_ctx, monkeypatch):
    from sentinel.agent.pentest import oauth_install_tool as oat
    monkeypatch.setattr(oat, "_require_ctx", lambda: fake_ctx)
    result = await oat.oauth_install_app.handler({"name": "nonexistent"})
    assert result.get("is_error") is True
    assert "nonexistent" in result["content"][0]["text"].lower()


@pytest.mark.asyncio
async def test_install_missing_env_var_returns_err(fake_ctx, monkeypatch):
    from sentinel.agent.pentest import oauth_install_tool as oat
    monkeypatch.delenv("FAKE_CLIENT_ID", raising=False)
    monkeypatch.setattr(oat, "_require_ctx", lambda: fake_ctx)
    result = await oat.oauth_install_app.handler({"name": "test-app"})
    assert result.get("is_error") is True
    assert "FAKE_CLIENT_ID" in result["content"][0]["text"]


@pytest.mark.asyncio
async def test_install_full_flow_captures_tokens(fake_ctx, monkeypatch):
    from sentinel.agent.pentest import oauth_install_tool as oat
    monkeypatch.setattr(oat, "_require_ctx", lambda: fake_ctx)

    async def fake_navigate(authorize_url, redirect_uri):
        return "fake-auth-code-abc123"
    monkeypatch.setattr(oat, "_browser_navigate_and_capture_code", fake_navigate)
    monkeypatch.setattr(
        "httpx.AsyncClient",
        _fake_httpx('{"ok":true,"access_token":"opaque-token.xoxb-1-FAKE",'
                    '"refresh_token":"opaque-token-1-FAKEREFRESH","expires_in":43200,'
                    '"token_type":"bot","scope":"channels:read",'
                    '"authed_user":{"refresh_token":"opaque-token-1-USERREF",'
                    '"access_token":"opaque-token.xoxp-1-USER"}}'),
    )

    result = await oat.oauth_install_app.handler({"name": "test-app"})
    assert result.get("is_error") is not True
    text = result["content"][0]["text"]
    assert "completed" in text.lower()

    captured = oat._CAPTURED_TOKENS.get("test-app", {})
    assert captured["refresh_token"] == "opaque-token-1-FAKEREFRESH"
    assert captured["access_token"] == "opaque-token.xoxb-1-FAKE"
    assert captured["user_refresh_token"] == "opaque-token-1-USERREF"
    assert captured["user_access_token"] == "opaque-token.xoxp-1-USER"

    audit_kinds = [c.args[0] for c in fake_ctx.audit.write.call_args_list]
    assert "oauth_install_started" in audit_kinds
    assert "oauth_install_completed" in audit_kinds
    # B1: every audit.write includes mode=
    for c in fake_ctx.audit.write.call_args_list:
        assert c.kwargs.get("mode") == "bbp"


@pytest.mark.asyncio
async def test_install_scope_gates_token_url(fake_ctx, monkeypatch):
    """Scope-gate sacred — authorize_url called for the token endpoint."""
    from sentinel.agent.pentest import oauth_install_tool as oat
    from sentinel.core.scope import OutOfScopeError
    monkeypatch.setattr(oat, "_require_ctx", lambda: fake_ctx)
    fake_ctx.scope.authorize_url.side_effect = OutOfScopeError("nope")

    async def fake_navigate(authorize_url, redirect_uri):
        raise AssertionError("must not navigate when scope refuses")
    monkeypatch.setattr(oat, "_browser_navigate_and_capture_code", fake_navigate)

    result = await oat.oauth_install_app.handler({"name": "test-app"})
    assert result.get("is_error") is True
    assert "out-of-scope" in result["content"][0]["text"].lower()


@pytest.mark.asyncio
async def test_install_redirect_uri_not_scope_gated(fake_ctx, monkeypatch):
    """The redirect_uri (operator callback, host out of target scope) must NOT
    be passed to scope.authorize_url — only authorize_url + token_url are."""
    from sentinel.agent.pentest import oauth_install_tool as oat
    monkeypatch.setattr(oat, "_require_ctx", lambda: fake_ctx)

    async def fake_navigate(authorize_url, redirect_uri):
        return "code-xyz"
    monkeypatch.setattr(oat, "_browser_navigate_and_capture_code", fake_navigate)
    monkeypatch.setattr(
        "httpx.AsyncClient",
        _fake_httpx('{"ok":true,"refresh_token":"r","access_token":"a","expires_in":3600}'),
    )
    await oat.oauth_install_app.handler({"name": "test-app"})

    gated = [c.args[0] for c in fake_ctx.scope.authorize_url.call_args_list]
    assert "https://callback.invalid/cb" not in gated
    # authorize_url (client_id-substituted) + token_url WERE gated
    assert any("example.com/oauth/authorize" in u for u in gated)
    assert any("example.com/oauth/token" in u for u in gated)


@pytest.mark.asyncio
async def test_install_failure_emits_failed_audit(fake_ctx, monkeypatch):
    from sentinel.agent.pentest import oauth_install_tool as oat
    monkeypatch.setattr(oat, "_require_ctx", lambda: fake_ctx)

    async def fake_navigate(authorize_url, redirect_uri):
        raise RuntimeError("consent button missing")
    monkeypatch.setattr(oat, "_browser_navigate_and_capture_code", fake_navigate)

    result = await oat.oauth_install_app.handler({"name": "test-app"})
    assert result.get("is_error") is True
    audit_kinds = [c.args[0] for c in fake_ctx.audit.write.call_args_list]
    assert "oauth_install_failed" in audit_kinds
    for c in fake_ctx.audit.write.call_args_list:
        assert c.kwargs.get("mode") == "bbp"


@pytest.mark.asyncio
async def test_get_token_returns_captured(fake_ctx, monkeypatch):
    from sentinel.agent.pentest import oauth_install_tool as oat
    monkeypatch.setattr(oat, "_require_ctx", lambda: fake_ctx)
    oat._CAPTURED_TOKENS["test-app"] = {
        "refresh_token": "opaque-token-1-CACHED",
        "access_token": "opaque-token.xoxb-1-CACHED",
        "user_refresh_token": "opaque-token-1-USERCACHED",
        "user_access_token": "opaque-token.xoxp-1-USERCACHED",
        "expires_in": 43200, "scope": "", "token_type": "bot",
        "captured_at_utc": "2026-XX-XXT00:00:00+00:00",
    }
    r1 = await oat.get_oauth_install_token.handler({"name": "test-app", "token_type": "bot_refresh"})
    assert "opaque-token-1-CACHED" in r1["content"][0]["text"]
    r2 = await oat.get_oauth_install_token.handler({"name": "test-app", "token_type": "user_refresh"})
    assert "opaque-token-1-USERCACHED" in r2["content"][0]["text"]


@pytest.mark.asyncio
async def test_get_token_unknown_type_errors(fake_ctx, monkeypatch):
    from sentinel.agent.pentest import oauth_install_tool as oat
    monkeypatch.setattr(oat, "_require_ctx", lambda: fake_ctx)
    oat._CAPTURED_TOKENS["test-app"] = {"refresh_token": "X"}
    r = await oat.get_oauth_install_token.handler({"name": "test-app", "token_type": "garbage"})
    assert r.get("is_error") is True
    assert "token_type" in r["content"][0]["text"].lower()


@pytest.mark.asyncio
async def test_get_token_not_installed_errors(fake_ctx, monkeypatch):
    from sentinel.agent.pentest import oauth_install_tool as oat
    monkeypatch.setattr(oat, "_require_ctx", lambda: fake_ctx)
    r = await oat.get_oauth_install_token.handler({"name": "never", "token_type": "bot_refresh"})
    assert r.get("is_error") is True
    assert "not installed" in r["content"][0]["text"].lower()


@pytest.mark.asyncio
async def test_event_log_emit_uses_kwargs_shape(fake_ctx, monkeypatch):
    """event_log.emit must be called as emit(kind, **payload) — matches the
    real signature `def emit(self, kind, **payload)`."""
    from sentinel.agent.pentest import oauth_install_tool as oat
    monkeypatch.setattr(oat, "_require_ctx", lambda: fake_ctx)

    async def fake_navigate(authorize_url, redirect_uri):
        return "code-xyz"
    monkeypatch.setattr(oat, "_browser_navigate_and_capture_code", fake_navigate)
    monkeypatch.setattr(
        "httpx.AsyncClient",
        _fake_httpx('{"ok":true,"refresh_token":"r","access_token":"a","expires_in":3600}'),
    )
    await oat.oauth_install_app.handler({"name": "test-app"})

    for c in fake_ctx.event_log.emit.call_args_list:
        assert len(c.args) == 1 and isinstance(c.args[0], str)
    kinds = [c.args[0] for c in fake_ctx.event_log.emit.call_args_list]
    assert "oauth_install_started" in kinds
    assert "oauth_install_completed" in kinds
