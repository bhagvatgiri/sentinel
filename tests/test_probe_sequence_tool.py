"""Hermetic tests for probe_sequence_tool.py.

Real PentestContext + mocked ctx.http.request (mirrors test_http_get_response_hints).
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest import mock
from unittest.mock import MagicMock

import httpx
import pytest

from sentinel.core.scope import OutOfScopeError


class _FakeScope:
    def __init__(self, deny_substr: str | None = None):
        self.engagement_mode = type("Mode", (), {"value": "bbp"})()
        self.research_headers = {}
        self.domains = ["example.com"]
        self.repos = []
        self.ips = []
        self.auth_cookies = []
        self._deny = deny_substr
    def authorize_url(self, url):
        if self._deny and self._deny in url:
            raise OutOfScopeError(f"out of scope: {url}")
        return None


class _FakeAudit:
    def __init__(self):
        self.calls = []
    def write(self, event, payload, **kw):
        self.calls.append((event, payload, kw))


@pytest.fixture
def ctx(tmp_path):
    from sentinel.agent.pentest import tools as p_tools
    ws = tmp_path / "ws"; ws.mkdir()
    c = p_tools.PentestContext(
        scope=_FakeScope(),
        audit=_FakeAudit(),
        workspace_dir=ws,
        http=httpx.AsyncClient(),
        rate_limit_per_host_sec=0.0,
        fetch_timeout_sec=10.0,
    )
    c.event_log = MagicMock()
    p_tools.set_context(c)
    return c


def _resp(text="", status=200):
    return SimpleNamespace(status_code=status, text=text)


def _run(steps):
    from sentinel.agent.pentest import probe_sequence_tool as pst
    return asyncio.run(pst.probe_sequence.handler({"steps": json.dumps(steps)}))


def test_invalid_json_returns_err(ctx):
    from sentinel.agent.pentest import probe_sequence_tool as pst
    out = asyncio.run(pst.probe_sequence.handler({"steps": "{not json"}))
    assert out.get("is_error") is True


def test_empty_returns_err(ctx):
    from sentinel.agent.pentest import probe_sequence_tool as pst
    out = asyncio.run(pst.probe_sequence.handler({"steps": "[]"}))
    assert out.get("is_error") is True


def test_too_many_steps_returns_err(ctx):
    steps = [{"name": f"s{i}", "url": "https://example.com/x"} for i in range(13)]
    out = _run(steps)
    assert out.get("is_error") is True
    assert "max" in out["content"][0]["text"].lower()


def test_extract_and_substitute_across_steps(ctx):
    captured_urls = []

    async def fake_request(method, url, **kw):
        captured_urls.append(url)
        if "first" in url:
            return _resp(text='{"refresh_token":"opaque-token-1-SECRETVALUE","authed_user":{"id":"U123"}}')
        return _resp(text='{"ok":true}')

    with mock.patch.object(ctx.http, "request", side_effect=fake_request):
        out = _run([
            {"name": "rotate", "method": "POST", "url": "https://example.com/first",
             "extract": {"REFRESH": {"json": "refresh_token"},
                         "UID": {"json": "authed_user.id"}}},
            {"name": "replay", "method": "POST",
             "url": "https://example.com/use?t=${REFRESH}&u=${UID}"},
        ])

    text = out["content"][0]["text"]
    assert out.get("is_error") is not True
    # Step 2 URL had the extracted values substituted in
    assert "t=opaque-token-1-SECRETVALUE&u=U123" in captured_urls[1]
    # Secret value is NOT echoed in full in the summary (length+prefix only)
    assert "opaque-token-1-SECRETVALUE" not in text
    assert "REFRESH=" in text and "len=" in text


def test_regex_extraction(ctx):
    async def fake_request(method, url, **kw):
        return _resp(text="set-cookie: session=ABC123XYZ; path=/")
    with mock.patch.object(ctx.http, "request", side_effect=fake_request):
        out = _run([
            {"name": "grab", "url": "https://example.com/login",
             "extract": {"SESS": {"regex": "session=([A-Z0-9]+)"}}},
        ])
    assert out.get("is_error") is not True
    assert "SESS=" in out["content"][0]["text"]


def test_out_of_scope_step_stops_sequence(ctx):
    ctx.scope = _FakeScope(deny_substr="/evil")
    from sentinel.agent.pentest import tools as p_tools
    p_tools.set_context(ctx)

    calls = {"n": 0}
    async def fake_request(method, url, **kw):
        calls["n"] += 1
        return _resp(text="{}")

    with mock.patch.object(ctx.http, "request", side_effect=fake_request):
        out = _run([
            {"name": "ok", "url": "https://example.com/ok"},
            {"name": "bad", "url": "https://example.com/evil"},
            {"name": "never", "url": "https://example.com/after"},
        ])
    text = out["content"][0]["text"]
    assert "out-of-scope" in text
    # Only the first step's request fired; the out-of-scope step never sent,
    # and the sequence stopped (3rd step never ran).
    assert calls["n"] == 1


def test_audit_mode_discipline_and_events(ctx):
    async def fake_request(method, url, **kw):
        return _resp(text='{"x":1}')
    with mock.patch.object(ctx.http, "request", side_effect=fake_request):
        _run([{"name": "a", "url": "https://example.com/a"}])

    # Every audit.write carried mode= (B1)
    assert ctx.audit.calls
    kinds = [c[0] for c in ctx.audit.calls]
    assert "probe_sequence_started" in kinds
    assert "probe_sequence_completed" in kinds
    for event, payload, kw in ctx.audit.calls:
        assert kw.get("mode") == "bbp", f"{event} missing mode="

    # event_log.emit uses (kind, **payload) shape
    for c in ctx.event_log.emit.call_args_list:
        assert len(c.args) == 1 and isinstance(c.args[0], str)
    emit_kinds = [c.args[0] for c in ctx.event_log.emit.call_args_list]
    assert "probe_sequence_started" in emit_kinds
    assert "probe_sequence_completed" in emit_kinds
