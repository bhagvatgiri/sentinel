"""http_get must surface server hints in its result + emit response_hint_surfaced.

Mirrors tests/test_research_headers.py http_get harness (PentestContext +
mock.patch.object(ctx.http, "get")).
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest import mock
from unittest.mock import MagicMock

import httpx
import pytest


class _FakeScope:
    def __init__(self):
        self.research_headers = {}
        self.domains = ["example.com"]
        self.repos = []
        self.ips = []
        self.auth_cookies = []
    def authorize_url(self, url):
        return None


class _FakeAudit:
    def write(self, *a, **k):
        return None


@pytest.fixture
def http_ctx(tmp_path):
    from sentinel.agent.pentest import tools as p_tools
    ws = tmp_path / "ws"; ws.mkdir()
    ctx = p_tools.PentestContext(
        scope=_FakeScope(),
        audit=_FakeAudit(),
        workspace_dir=ws,
        http=httpx.AsyncClient(),
        rate_limit_per_host_sec=0.0,
        fetch_timeout_sec=10.0,
    )
    ctx.event_log = MagicMock()
    p_tools.set_context(ctx)
    return ctx


def _resp(text="", headers=None, status=200, url="https://example.com/"):
    return SimpleNamespace(
        status_code=status, url=url, headers=headers or {}, text=text,
        content=text.encode(), history=[],
    )


def test_http_get_surfaces_body_hint_and_emits_event(http_ctx):
    from sentinel.agent.pentest import tools as p_tools
    body = ('{"ok":false,"error":"refresh_token_invalid","messages":'
            '["please try using oauth.v2.access instead"]}')

    async def fake_get(url, **kwargs):
        return _resp(text=body)

    with mock.patch.object(http_ctx.http, "get", side_effect=fake_get):
        out = asyncio.run(p_tools.http_get.handler({"url": "https://example.com/x", "headers": ""}))

    text = out["content"][0]["text"]
    assert "SERVER HINTS" in text
    assert "use_alternative_endpoint" in text
    assert "oauth.v2.access" in text

    kinds = [c.args[0] for c in http_ctx.event_log.emit.call_args_list]
    assert "response_hint_surfaced" in kinds


def test_http_get_no_hint_no_section_no_event(http_ctx):
    from sentinel.agent.pentest import tools as p_tools

    async def fake_get(url, **kwargs):
        return _resp(text='{"ok": true, "data": [1, 2, 3]}')

    with mock.patch.object(http_ctx.http, "get", side_effect=fake_get):
        out = asyncio.run(p_tools.http_get.handler({"url": "https://example.com/x", "headers": ""}))

    text = out["content"][0]["text"]
    assert "SERVER HINTS" not in text
    kinds = [c.args[0] for c in http_ctx.event_log.emit.call_args_list]
    assert "response_hint_surfaced" not in kinds


def test_http_get_surfaces_location_header_hint(http_ctx):
    from sentinel.agent.pentest import tools as p_tools

    async def fake_get(url, **kwargs):
        return _resp(text="<html>moved</html>", status=301,
                     headers={"Location": "https://example.com/api/v2/new"})

    with mock.patch.object(http_ctx.http, "get", side_effect=fake_get):
        out = asyncio.run(p_tools.http_get.handler({"url": "https://example.com/x", "headers": ""}))

    text = out["content"][0]["text"]
    assert "SERVER HINTS" in text
    assert "follow_redirect" in text
    assert "/api/v2/new" in text


def test_http_get_event_emit_uses_kwargs_shape(http_ctx):
    from sentinel.agent.pentest import tools as p_tools

    async def fake_get(url, **kwargs):
        return _resp(text='{"error":"use POST instead of GET"}')

    with mock.patch.object(http_ctx.http, "get", side_effect=fake_get):
        asyncio.run(p_tools.http_get.handler({"url": "https://example.com/x", "headers": ""}))

    emit_calls = [c for c in http_ctx.event_log.emit.call_args_list
                  if c.args and c.args[0] == "response_hint_surfaced"]
    assert emit_calls
    c = emit_calls[0]
    assert len(c.args) == 1  # kind only positional; payload is kwargs
    assert c.kwargs.get("url") == "https://example.com/x"
    assert c.kwargs.get("hint_count", 0) >= 1
