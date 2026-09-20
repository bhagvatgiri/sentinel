"""B4 — JS Surface Mapper additions.

Net-new vs the existing js_intel_tool: GraphQL operationName literals,
Apollo persisted-query SHA256 hashes, sourcemap content, modulepreload
<link> discovery, WebSocket / SSE endpoints.
"""

from __future__ import annotations

import asyncio

import pytest

from sentinel.agent.pentest import js_intel_tool as ji
from sentinel.agent.pentest import tools as p_tools


# ---- pure-extractor unit tests --------------------------------------------

def test_extract_persisted_queries_apollo_format():
    js = """
    const ops = {
      sha256Hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    };
    """
    out = ji._extract_persisted_queries(js)
    assert "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" in out


def test_extract_persisted_queries_dedupes_and_lowercases():
    js = """
      sha256Hash: "ABCDEF0123456789ABCDEF0123456789",
      sha256Hash: "abcdef0123456789ABCDEF0123456789",
    """
    out = ji._extract_persisted_queries(js)
    # Lowercased + de-duplicated.
    assert out == ["abcdef0123456789abcdef0123456789"]


def test_extract_graphql_opnames_strict():
    js = """
      operationName: "ListOrders",
      operationName: 'GetUserProfile',
      operationName: "AdminPurgeQueue",
    """
    out = ji._extract_graphql_opnames(js)
    assert "ListOrders" in out
    assert "GetUserProfile" in out
    assert "AdminPurgeQueue" in out


def test_extract_graphql_opnames_skips_non_identifiers():
    """`operationName: ""` and operationName with weird chars must be
    rejected — keeps signal high."""
    js = """
      operationName: "",
      operationName: "Bad!Name",
      operationName: "ValidQuery",
    """
    out = ji._extract_graphql_opnames(js)
    assert out == ["ValidQuery"]


def test_extract_websocket_endpoints():
    js = """
      const ws = new WebSocket("wss://chat.example.com/socket");
      const ws2 = new WebSocket('ws://internal.example.com/admin');
    """
    out = ji._extract_websocket_endpoints(js)
    assert "wss://chat.example.com/socket" in out
    assert "ws://internal.example.com/admin" in out


def test_extract_sse_endpoints_eventsource_constructor():
    js = """
      const es = new EventSource("/api/notifications/stream");
      const es2 = new EventSource('/api/admin/audit-tail');
    """
    out = ji._extract_sse_endpoints(js)
    assert "/api/notifications/stream" in out
    assert "/api/admin/audit-tail" in out


def test_extract_sse_endpoints_content_type_marker():
    js = """response.headers["Content-Type"] = "text/event-stream";"""
    out = ji._extract_sse_endpoints(js)
    assert "text/event-stream" in out


def test_extract_modulepreload_links_vite():
    html = """
      <html><head>
        <link rel="modulepreload" href="/assets/vendor-abc123.js">
        <link rel="modulepreload" href="/assets/admin-def456.js" crossorigin>
        <link rel="stylesheet" href="/assets/main.css">
      </head></html>
    """
    out = ji._extract_modulepreload_links(html)
    assert "/assets/vendor-abc123.js" in out
    assert "/assets/admin-def456.js" in out
    # Stylesheet not included.
    assert "/assets/main.css" not in out


# ---- js_surface_map tool wrapper ------------------------------------------

class _Scope:
    research_headers: dict = {}
    auth_cookies: list = []
    def authorize_url(self, _url: str) -> None:  # always-pass for inline tests
        return None


class _Audit:
    def write(self, *_a, **_kw) -> None:
        return None


class _Ctx:
    scope = _Scope()
    audit = _Audit()
    workspace_dir = None
    http = None
    fetch_timeout_sec = 30.0
    rate_limit_per_host_sec = 1.0
    last_fetch_at: dict = {}
    pages_fetched = 0
    deliverables_written = 0
    brain_queue = None
    event_log = None
    current_phase = ""


def test_js_surface_map_inline_html_and_js():
    """Inline content path (no URL fetch) — exercises the full extractor
    pipeline without scope-gating."""
    html = """
    <html><head>
      <link rel="modulepreload" href="/assets/x-abc.js">
    </head></html>
    """
    js = """
      operationName: "ListOrgs",
      sha256Hash: "deadbeefdeadbeefdeadbeefdeadbeef",
      const ws = new WebSocket("wss://stream.example.com/feed");
      const es = new EventSource("/sse/audit");
    """
    p_tools._ctx = _Ctx()  # type: ignore[assignment]
    try:
        result = asyncio.run(
            ji.js_surface_map.handler({
                "html_content": html, "js_content": js,
            })
        )
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    text = result["content"][0]["text"]
    # Each surface category must surface a hit.
    assert "ListOrgs" in text
    assert "deadbeefdeadbeefdeadbeefdeadbeef" in text
    assert "wss://stream.example.com/feed" in text
    assert "/sse/audit" in text
    assert "/assets/x-abc.js" in text


def test_js_surface_map_requires_input():
    p_tools._ctx = _Ctx()  # type: ignore[assignment]
    try:
        result = asyncio.run(ji.js_surface_map.handler({}))
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    assert result.get("is_error") is True
