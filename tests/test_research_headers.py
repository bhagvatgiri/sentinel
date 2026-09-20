"""Tests for the `research_headers` Scope feature.

Researcher-tagged HTTP headers (e.g. `X-HackerOne-Research: <h1-handle>`)
get auto-injected on every outgoing test request from the pentest tools
when the engagement's scope yaml declares them. Reusable for any future
H1 / Bugcrowd / Synack / Intigriti program.

Brain-grow's `fetch_url` is INTENTIONALLY out of scope — brain reaches
arbitrary research URLs (docs sites, vendor blogs) where leaking the
researcher's H1 handle would be worse than not tagging. Headers apply
only to pentest tools that touch declared-in-scope hosts.
"""

from __future__ import annotations

import json
import shlex
from datetime import date
from pathlib import Path
from unittest import mock

import pytest


# ---- Scope.load parses research_headers ---------------------------------


def _write_scope(tmp_path: Path, *, research_headers_block: str = "") -> Path:
    """Write a minimal scope yaml; optionally append a research_headers block."""
    body = (
        "client: testco\n"
        "engagement_id: test-eng-001\n"
        "authorized_by: tester@example.com\n"
        "valid_from: 2026-01-01\n"
        "valid_until: 2027-01-01\n"
        "targets:\n"
        "  domains:\n"
        "    - example.com\n"
    )
    if research_headers_block:
        body += "\n" + research_headers_block + "\n"
    p = tmp_path / "scope.yaml"
    p.write_text(body)
    return p


def test_scope_default_research_headers_is_empty(tmp_path):
    from sentinel.core.scope import Scope
    s = Scope.load(_write_scope(tmp_path))
    assert s.research_headers == {}


def test_scope_parses_research_headers_block(tmp_path):
    from sentinel.core.scope import Scope
    block = (
        "research_headers:\n"
        "  X-HackerOne-Research: researcher-handle\n"
        "  X-Custom-Header: value with spaces\n"
    )
    s = Scope.load(_write_scope(tmp_path, research_headers_block=block))
    assert s.research_headers == {
        "X-HackerOne-Research": "researcher-handle",
        "X-Custom-Header": "value with spaces",
    }


def test_scope_rejects_non_dict_research_headers(tmp_path):
    from sentinel.core.scope import Scope, ScopeError
    block = (
        "research_headers:\n"
        "  - X-Bad-Format: as-list\n"
    )
    with pytest.raises(ScopeError):
        Scope.load(_write_scope(tmp_path, research_headers_block=block))


def test_scope_rejects_empty_header_key(tmp_path):
    from sentinel.core.scope import Scope, ScopeError
    block = (
        "research_headers:\n"
        "  '': researcher-handle\n"
    )
    with pytest.raises(ScopeError):
        Scope.load(_write_scope(tmp_path, research_headers_block=block))


# ---- bash_tool curl-injection helpers -----------------------------------


def test_inject_curl_research_headers_no_op_for_non_curl():
    from sentinel.agent.pentest.bash_tool import _inject_curl_research_headers
    argv = ["nmap", "-sV", "example.com"]
    out = _inject_curl_research_headers(argv, {"X-HackerOne-Research": "researcher-handle"})
    assert out == argv  # unchanged


def test_inject_curl_research_headers_no_op_when_empty():
    from sentinel.agent.pentest.bash_tool import _inject_curl_research_headers
    argv = ["curl", "https://example.com/"]
    assert _inject_curl_research_headers(argv, {}) == argv


def test_inject_curl_research_headers_adds_dash_h_after_curl():
    from sentinel.agent.pentest.bash_tool import _inject_curl_research_headers
    argv = ["curl", "-s", "https://example.com/"]
    out = _inject_curl_research_headers(argv, {"X-HackerOne-Research": "researcher-handle"})
    assert out[0] == "curl"
    assert "-H" in out
    h_index = out.index("-H")
    assert out[h_index + 1] == "X-HackerOne-Research: researcher-handle"
    # Original args still present + in original order after the inserted -H.
    assert out[-2] == "-s"
    assert out[-1] == "https://example.com/"


def test_inject_curl_research_headers_does_not_duplicate_existing_header():
    """If the agent already set X-HackerOne-Research itself, don't double-inject."""
    from sentinel.agent.pentest.bash_tool import _inject_curl_research_headers
    argv = ["curl", "-H", "X-HackerOne-Research: agent-typed-it",
            "https://example.com/"]
    out = _inject_curl_research_headers(argv, {"X-HackerOne-Research": "researcher-handle"})
    # No duplicate -H for the same key.
    h_count = sum(1 for i, t in enumerate(out)
                  if t == "-H" and "X-HackerOne-Research" in out[i + 1])
    assert h_count == 1
    # Caller's value wins.
    assert any("agent-typed-it" in t for t in out)


def test_inject_curl_headers_into_compound_targets_only_curl_components():
    """Compound `curl ... | grep ...` only injects into the curl side."""
    from sentinel.agent.pentest.bash_tool import _inject_curl_headers_into_compound
    cmd = "curl -s https://example.com/ | grep -i 'auth'"
    out = _inject_curl_headers_into_compound(
        cmd, {"X-HackerOne-Research": "researcher-handle"}
    )
    # curl side has the header inserted...
    assert "X-HackerOne-Research: researcher-handle" in out
    # ...grep side is unchanged.
    assert "grep" in out
    assert "X-HackerOne-Research" not in out.split("|")[1]


# ---- http_get + browser_get integration via mocked context --------------


class _FakeAuditLog:
    def write(self, *a, **kw): pass


class _FakeScope:
    def __init__(self, research_headers, domains=("example.com",)):
        self.research_headers = research_headers
        self.domains = list(domains)
        self.repos = []
        self.ips = []
    def authorize_url(self, url): return None  # always pass


@pytest.fixture
def http_ctx(tmp_path):
    """Monkey-patch the pentest BrainContext-equivalent for http_get."""
    from sentinel.agent.pentest import tools as p_tools
    import httpx
    ws = tmp_path / "ws"; ws.mkdir()
    ctx = p_tools.PentestContext(
        scope=_FakeScope({"X-HackerOne-Research": "researcher-handle"}),
        audit=_FakeAuditLog(),
        workspace_dir=ws,
        http=httpx.AsyncClient(),
        rate_limit_per_host_sec=0.0,
        fetch_timeout_sec=10.0,
    )
    p_tools.set_context(ctx)
    return ctx


def test_http_get_injects_research_headers(http_ctx):
    """http_get must merge scope.research_headers into the httpx call."""
    import asyncio
    from sentinel.agent.pentest import tools as p_tools

    captured: dict = {}

    async def fake_get(url, **kwargs):
        captured["url"] = url
        captured["headers"] = kwargs.get("headers", {})
        from types import SimpleNamespace
        return SimpleNamespace(
            status_code=200, url=url, headers={}, text="ok",
            content=b"ok", history=[],
        )

    with mock.patch.object(http_ctx.http, "get", side_effect=fake_get):
        out = asyncio.run(p_tools.http_get.handler({
            "url": "https://example.com/", "headers": "",
        }))
    # _ok return shape lacks is_error key entirely; _err sets it True.
    assert out.get("is_error") is not True
    assert captured["headers"]["X-HackerOne-Research"] == "researcher-handle"


def test_http_get_caller_header_overrides_scope_header(http_ctx):
    """If the agent explicitly passes the same header, caller value wins."""
    import asyncio
    from sentinel.agent.pentest import tools as p_tools

    captured: dict = {}

    async def fake_get(url, **kwargs):
        captured["headers"] = kwargs.get("headers", {})
        from types import SimpleNamespace
        return SimpleNamespace(
            status_code=200, url=url, headers={}, text="ok",
            content=b"ok", history=[],
        )

    with mock.patch.object(http_ctx.http, "get", side_effect=fake_get):
        asyncio.run(p_tools.http_get.handler({
            "url": "https://example.com/",
            "headers": json.dumps({"X-HackerOne-Research": "agent-override"}),
        }))
    assert captured["headers"]["X-HackerOne-Research"] == "agent-override"


def test_http_get_with_empty_research_headers_emits_no_extra(http_ctx, tmp_path):
    """Empty scope.research_headers is a no-op — same call shape as before
    the feature shipped (regression guard)."""
    import asyncio
    from sentinel.agent.pentest import tools as p_tools

    # Re-set context with empty headers.
    http_ctx.scope = _FakeScope({})
    p_tools.set_context(http_ctx)

    captured: dict = {}

    async def fake_get(url, **kwargs):
        captured["headers"] = kwargs.get("headers", {})
        from types import SimpleNamespace
        return SimpleNamespace(
            status_code=200, url=url, headers={}, text="ok",
            content=b"ok", history=[],
        )

    with mock.patch.object(http_ctx.http, "get", side_effect=fake_get):
        asyncio.run(p_tools.http_get.handler({"url": "https://example.com/", "headers": ""}))
    assert "X-HackerOne-Research" not in captured["headers"]
