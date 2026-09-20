"""Verify bearer-token login propagates to http_get (httpx) calls.

Regression guard for the bug where _login_bearer only set the Authorization
header on the Playwright browser context, leaving http_get unauthenticated.
"""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock

import httpx


class _FakeAuditLog:
    def write(self, *a, **kw): pass


class _FakeScope:
    """Minimal stand-in for sentinel.core.scope.Scope.

    Mirrors the surface the pentest tools touch: research_headers,
    auth_cookies, auth_credentials, authorize_url().
    """
    def __init__(self):
        self.research_headers = {"X-HackerOne-Researcher": "test"}
        self.auth_cookies = []
        self.auth_credentials = [
            {"name": "tester", "method": "bearer", "token_env": "FAKE_BEARER_TOKEN"}
        ]
        self.domains = ["api.ExampleChat.com"]
        self.repos = []
        self.ips = []

    def authorize_url(self, url):  # no error = in scope
        return None


@pytest.fixture
def fake_ctx(tmp_path):
    """Real PentestContext with a fake httpx client we can monkey-patch per-test."""
    from sentinel.agent.pentest import tools as p_tools
    ws = tmp_path / "ws"; ws.mkdir()
    ctx = p_tools.PentestContext(
        scope=_FakeScope(),
        audit=_FakeAuditLog(),
        workspace_dir=ws,
        http=httpx.AsyncClient(),
        rate_limit_per_host_sec=0.0,
        fetch_timeout_sec=10.0,
    )
    p_tools.set_context(ctx)
    return ctx


@pytest.fixture(autouse=True)
def _reset_bearer_state():
    """Clear module-level bearer state between tests."""
    from sentinel.agent.pentest import auth_tool
    if hasattr(auth_tool, "_BEARER_TOKENS_BY_HOST"):
        auth_tool._BEARER_TOKENS_BY_HOST.clear()
    yield
    if hasattr(auth_tool, "_BEARER_TOKENS_BY_HOST"):
        auth_tool._BEARER_TOKENS_BY_HOST.clear()


def _mock_browser(monkeypatch):
    """Stub the Playwright browser path so _login_bearer doesn't spawn Chromium."""
    from sentinel.agent.pentest import browser_tool as p_browser
    fake_page = AsyncMock()
    fake_page.context = AsyncMock()
    fake_page.context.set_extra_http_headers = AsyncMock()
    fake_page.close = AsyncMock()
    fake_session = AsyncMock()
    fake_session.page = AsyncMock(return_value=fake_page)
    monkeypatch.setattr(p_browser, "_get_session", lambda: fake_session)


def _patch_http_capture(monkeypatch, ctx):
    """Replace ctx.http.get with a capturing fake. Returns the captured dict."""
    captured = {"headers": None}

    async def fake_get(url, headers=None, cookies=None, **kw):
        captured["url"] = url
        captured["headers"] = dict(headers or {})
        captured["cookies"] = dict(cookies or {})
        from types import SimpleNamespace
        return SimpleNamespace(
            status_code=200,
            url=url,
            headers={},
            text="ok",
            content=b"ok",
            history=[],
        )

    monkeypatch.setattr(ctx.http, "get", fake_get)
    return captured


@pytest.mark.asyncio
async def test_bearer_login_then_http_get_includes_authorization(fake_ctx, monkeypatch):
    """End-to-end: login(method=bearer) → subsequent http_get propagates Authorization header."""
    monkeypatch.setenv("FAKE_BEARER_TOKEN", "xoxb-fake-token-12345")

    from sentinel.agent.pentest import auth_tool, tools as t

    _mock_browser(monkeypatch)

    # 1) Login via bearer
    result = await auth_tool.login.handler({"name": "tester", "method": "bearer"})
    text = str(result)
    assert "applied" in text.lower() or "ok" in text.lower(), f"login bearer failed: {result}"

    # 2) Now http_get a ExampleChat URL — must include Authorization header
    captured = _patch_http_capture(monkeypatch, fake_ctx)

    await t.http_get.handler({
        "url": "https://api.ExampleChat.com/api/auth.test",
        "headers": "",
        "follow_redirects": "true",
    })

    headers = captured["headers"] or {}
    assert "Authorization" in headers, (
        f"http_get did NOT propagate Authorization header. Headers captured: {headers}"
    )
    assert headers["Authorization"].startswith("Bearer "), (
        f"Authorization not a Bearer token: {headers['Authorization']}"
    )
    assert "xoxb-fake-token-12345" in headers["Authorization"]


@pytest.mark.asyncio
async def test_caller_provided_authorization_wins_over_bearer_state(fake_ctx, monkeypatch):
    """If caller passes Authorization in headers arg, it overrides the bearer state."""
    monkeypatch.setenv("FAKE_BEARER_TOKEN", "xoxb-bearer-state-12345")

    from sentinel.agent.pentest import auth_tool, tools as t

    _mock_browser(monkeypatch)

    await auth_tool.login.handler({"name": "tester", "method": "bearer"})

    captured = _patch_http_capture(monkeypatch, fake_ctx)

    await t.http_get.handler({
        "url": "https://api.ExampleChat.com/api/auth.test",
        "headers": '{"Authorization": "Bearer xoxp-caller-override-67890"}',
        "follow_redirects": "true",
    })

    headers = captured["headers"] or {}
    assert "xoxp-caller-override-67890" in headers.get("Authorization", "")
    assert "xoxb-bearer-state-12345" not in headers.get("Authorization", "")


@pytest.mark.asyncio
async def test_no_bearer_login_no_authorization_added(fake_ctx, monkeypatch):
    """Without prior login(bearer), http_get adds NO Authorization header."""
    from sentinel.agent.pentest import tools as t

    captured = _patch_http_capture(monkeypatch, fake_ctx)

    await t.http_get.handler({
        "url": "https://api.ExampleChat.com/api/auth.test",
        "headers": "",
        "follow_redirects": "true",
    })

    headers = captured["headers"] or {}
    assert "Authorization" not in headers, (
        f"http_get added Authorization without prior login: {headers}"
    )
