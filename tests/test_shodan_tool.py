"""B10 — Shodan MCP wrapper tests.

We mock httpx.AsyncClient.get because real Shodan calls would burn API
credits and require a key in CI. The scope-gate path on shodan_host_info
is the most important assertion.
"""

from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.agent.pentest import shodan_tool, tools as p_tools
from sentinel.core.scope import OutOfScopeError


class _Audit:
    def write(self, *_a, **_kw) -> None:
        return None


def _ok_response(payload: dict, status: int = 200):
    """Build a fake httpx.Response object."""
    resp = MagicMock()
    resp.status_code = status
    resp.json = MagicMock(return_value=payload)
    resp.text = json.dumps(payload)
    return resp


def _ctx_with_scope(scope_obj, http_client) -> object:
    class _Ctx:
        scope = scope_obj
        audit = _Audit()
        workspace_dir = None
        http = http_client
        fetch_timeout_sec = 30.0
        rate_limit_per_host_sec = 1.0
        last_fetch_at: dict = {}
        pages_fetched = 0
        deliverables_written = 0
        brain_queue = None
        event_log = None
        current_phase = ""
    return _Ctx()


def test_shodan_search_requires_query():
    p_tools._ctx = _ctx_with_scope(MagicMock(), None)  # type: ignore[assignment]
    try:
        out = asyncio.run(shodan_tool.shodan_search.handler({"query": ""}))
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    assert out.get("is_error") is True


def test_shodan_search_requires_api_key(monkeypatch):
    """Without SHODAN_API_KEY set, must refuse cleanly."""
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.delenv("shodan_search_api_key", raising=False)
    p_tools._ctx = _ctx_with_scope(MagicMock(), None)  # type: ignore[assignment]
    try:
        out = asyncio.run(
            shodan_tool.shodan_search.handler({"query": "apache"})
        )
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    assert out.get("is_error") is True
    assert "SHODAN_API_KEY" in out["content"][0]["text"]


def test_shodan_search_happy_path(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")
    fake_payload = {
        "matches": [
            {"ip_str": "1.2.3.4", "port": 443, "org": "Example Inc",
             "hostnames": ["www.example.com"],
             "location": {"country_name": "US"},
             "data": "HTTP/1.1 200 OK\nServer: nginx"},
        ],
    }
    http = MagicMock()
    http.get = AsyncMock(return_value=_ok_response(fake_payload))
    p_tools._ctx = _ctx_with_scope(MagicMock(), http)  # type: ignore[assignment]
    try:
        out = asyncio.run(
            shodan_tool.shodan_search.handler({"query": "apache", "limit": 5})
        )
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    text = out["content"][0]["text"]
    assert "1.2.3.4" in text
    assert "Example Inc" in text
    # API call was made.
    http.get.assert_called_once()
    # Limit was capped + threaded into params.
    args, kwargs = http.get.call_args
    assert kwargs["params"]["query"] == "apache"
    assert kwargs["params"]["limit"] == 5
    assert kwargs["params"]["key"] == "test-key"


def test_shodan_search_caps_limit(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "k")
    http = MagicMock()
    http.get = AsyncMock(return_value=_ok_response({"matches": []}))
    p_tools._ctx = _ctx_with_scope(MagicMock(), http)  # type: ignore[assignment]
    try:
        asyncio.run(
            shodan_tool.shodan_search.handler({"query": "x", "limit": 5000})
        )
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    args, kwargs = http.get.call_args
    assert kwargs["params"]["limit"] == 100


def test_shodan_host_info_scope_gated(monkeypatch):
    """IP outside scope → refusal, no API call made."""
    monkeypatch.setenv("SHODAN_API_KEY", "k")
    scope = MagicMock()
    scope.authorize_url.side_effect = OutOfScopeError("ip out of scope")
    http = MagicMock()
    http.get = AsyncMock()
    p_tools._ctx = _ctx_with_scope(scope, http)  # type: ignore[assignment]
    try:
        out = asyncio.run(
            shodan_tool.shodan_host_info.handler({"ip": "8.8.8.8"})
        )
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    assert out.get("is_error") is True
    assert "out-of-scope" in out["content"][0]["text"]
    # No HTTP call.
    http.get.assert_not_called()


def test_shodan_host_info_in_scope_happy_path(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "k")
    scope = MagicMock()
    scope.authorize_url.return_value = None
    http = MagicMock()
    http.get = AsyncMock(return_value=_ok_response({
        "ip_str": "10.0.0.5",
        "org": "Tenant Org", "ports": [22, 443],
        "vulns": ["CVE-2024-1234"],
    }))
    p_tools._ctx = _ctx_with_scope(scope, http)  # type: ignore[assignment]
    try:
        out = asyncio.run(
            shodan_tool.shodan_host_info.handler({"ip": "10.0.0.5"})
        )
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    assert out.get("is_error") is None or out["is_error"] is False
    text = out["content"][0]["text"]
    assert "10.0.0.5" in text
    assert "CVE-2024-1234" in text
    assert "22, 443" in text


def test_shodan_host_info_404_returns_ok_with_no_record(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "k")
    scope = MagicMock()
    scope.authorize_url.return_value = None
    http = MagicMock()
    resp = MagicMock()
    resp.status_code = 404
    resp.text = ""
    http.get = AsyncMock(return_value=resp)
    p_tools._ctx = _ctx_with_scope(scope, http)  # type: ignore[assignment]
    try:
        out = asyncio.run(
            shodan_tool.shodan_host_info.handler({"ip": "10.0.0.5"})
        )
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    assert out.get("is_error") is None or out["is_error"] is False
    assert "no record" in out["content"][0]["text"]


def test_shodan_search_audit_logged(monkeypatch):
    """Every search must hit AuditLog.write()."""
    monkeypatch.setenv("SHODAN_API_KEY", "k")
    fake_http = MagicMock()
    fake_http.get = AsyncMock(return_value=_ok_response({"matches": []}))
    audit_calls: list = []

    class _AuditTrack:
        def write(self, evt, payload):
            audit_calls.append((evt, payload))

    ctx = _ctx_with_scope(MagicMock(), fake_http)
    ctx.audit = _AuditTrack()  # override
    p_tools._ctx = ctx  # type: ignore[assignment]
    try:
        asyncio.run(
            shodan_tool.shodan_search.handler({"query": "test", "limit": 3})
        )
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    assert any(c[0] == "shodan_search" for c in audit_calls)


def test_shodan_search_falls_back_to_cai_compat_var(monkeypatch):
    """CAI uses `shodan_search_api_key` env var; we accept it for parity."""
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.setenv("shodan_search_api_key", "from-cai")
    http = MagicMock()
    http.get = AsyncMock(return_value=_ok_response({"matches": []}))
    p_tools._ctx = _ctx_with_scope(MagicMock(), http)  # type: ignore[assignment]
    try:
        out = asyncio.run(
            shodan_tool.shodan_search.handler({"query": "x"})
        )
    finally:
        p_tools._ctx = None  # type: ignore[assignment]
    args, kwargs = http.get.call_args
    assert kwargs["params"]["key"] == "from-cai"
