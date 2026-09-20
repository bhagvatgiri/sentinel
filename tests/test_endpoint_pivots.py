"""Cross-endpoint pivot ledger (Tier 3 #6) — unit + http_get integration."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest import mock
from unittest.mock import MagicMock

import httpx
import pytest

from sentinel.agent.pentest import endpoint_pivots as ep
from sentinel.agent.pentest.response_hints import Hint


@pytest.fixture(autouse=True)
def _reset():
    ep.reset_all()
    yield
    ep.reset_all()


# ---- ledger unit tests ----------------------------------------------------


def test_record_only_pivot_kinds():
    hints = [
        Hint("use_alternative_endpoint", "use X instead", "oauth.v2.access", "..."),
        Hint("missing_required_parameter", "X required", "client_id", "..."),  # not a pivot
        Hint("follow_redirect", "Location: ...", "https://x/api/v2", "..."),
    ]
    new = ep.record_pivot_hints("job1", "https://x/api/legacy", hints)
    assert len(new) == 2
    suggested = {p["suggested"] for p in ep.pending("job1")}
    assert suggested == {"oauth.v2.access", "https://x/api/v2"}


def test_record_dedups():
    h = [Hint("use_alternative_endpoint", "s", "oauth.v2.access", "x")]
    ep.record_pivot_hints("job1", "https://x/a", h)
    ep.record_pivot_hints("job1", "https://x/a", h)  # same from+suggested
    assert len(ep.pending("job1")) == 1


def test_mark_probed_resolves_by_substring():
    ep.record_pivot_hints("job1", "https://x/a",
                          [Hint("use_alternative_endpoint", "s", "oauth.v2.access", "x")])
    assert len(ep.pending("job1")) == 1
    resolved = ep.mark_probed("job1", "https://ExampleChat.com/api/oauth.v2.access?x=1")
    assert len(resolved) == 1
    assert ep.pending("job1") == []


def test_pending_isolated_per_job():
    ep.record_pivot_hints("jobA", "u", [Hint("use_alternative_endpoint", "s", "a.b", "x")])
    assert ep.pending("jobB") == []
    assert len(ep.pending("jobA")) == 1


# ---- pending_pivots tool --------------------------------------------------


@pytest.mark.asyncio
async def test_pending_pivots_tool_empty(monkeypatch):
    ctx = MagicMock(); ctx.job_id = "job1"
    monkeypatch.setattr(ep, "_require_ctx", lambda: ctx)
    out = await ep.pending_pivots.handler({})
    assert "no pending" in out["content"][0]["text"].lower()


@pytest.mark.asyncio
async def test_pending_pivots_tool_lists(monkeypatch):
    ctx = MagicMock(); ctx.job_id = "job1"
    monkeypatch.setattr(ep, "_require_ctx", lambda: ctx)
    ep.record_pivot_hints("job1", "https://x/legacy",
                          [Hint("use_alternative_endpoint", "s", "oauth.v2.access", "x")])
    out = await ep.pending_pivots.handler({})
    text = out["content"][0]["text"]
    assert "oauth.v2.access" in text
    assert "1 pending" in text


# ---- http_get integration -------------------------------------------------


class _FakeScope:
    def __init__(self):
        self.engagement_mode = type("M", (), {"value": "bbp"})()
        self.research_headers = {}
        self.domains = ["example.com"]
        self.repos = []; self.ips = []; self.auth_cookies = []
    def authorize_url(self, url):
        return None


class _FakeAudit:
    def write(self, *a, **k):
        return None


@pytest.fixture
def http_ctx(tmp_path):
    from sentinel.agent.pentest import tools as p_tools
    ws = tmp_path / "ws"; ws.mkdir()
    c = p_tools.PentestContext(
        scope=_FakeScope(), audit=_FakeAudit(), workspace_dir=ws,
        http=httpx.AsyncClient(), rate_limit_per_host_sec=0.0, fetch_timeout_sec=10.0,
    )
    c.event_log = MagicMock()
    c.job_id = "jobX"
    p_tools.set_context(c)
    return c


def test_http_get_records_pivot_then_resolves(http_ctx):
    from sentinel.agent.pentest import tools as p_tools

    async def fake_get(url, **kwargs):
        if "legacy" in url:
            return SimpleNamespace(
                status_code=400, url=url, headers={},
                text='{"error":"please try using /api/v2/token instead"}',
                content=b"", history=[])
        return SimpleNamespace(status_code=200, url=url, headers={},
                               text='{"ok":true}', content=b"", history=[])

    with mock.patch.object(http_ctx.http, "get", side_effect=fake_get):
        # First call surfaces the pivot hint → recorded as pending.
        asyncio.run(p_tools.http_get.handler({"url": "https://example.com/api/legacy", "headers": ""}))
        assert len(ep.pending("jobX")) == 1
        assert ep.pending("jobX")[0]["suggested"] == "/api/v2/token"

        # Agent follows the hint → pivot resolved.
        asyncio.run(p_tools.http_get.handler({"url": "https://example.com/api/v2/token", "headers": ""}))
        assert ep.pending("jobX") == []

    kinds = [c.args[0] for c in http_ctx.event_log.emit.call_args_list]
    assert "endpoint_pivot_recorded" in kinds
    assert "endpoint_pivot_resolved" in kinds
