"""Tests for the Phase-75 dns_lookup MCP tool + bash-allowlist tightening.

Network calls are mocked. We exercise:

- Record-type validation
- Stdlib-fallback path for A / AAAA / CNAME
- Allowlist no longer accepts dig/nslookup (forces agents through the
  scope-gated dns_lookup tool)
"""

from __future__ import annotations

from unittest import mock

import pytest

from sentinel.agent.pentest import bash_tool, dns_tool


def test_dns_tool_record_types_include_common():
    expected = {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"}
    assert expected <= set(dns_tool._RECORD_TYPES)


def test_resolve_socket_fallback_a(monkeypatch):
    fake_addrinfo = [
        (None, None, None, None, ("203.0.113.1", 0)),
        (None, None, None, None, ("203.0.113.2", 0)),
    ]
    monkeypatch.setattr(dns_tool.socket, "getaddrinfo", lambda *a, **k: fake_addrinfo)
    out = dns_tool._resolve_with_socket_fallback("example.com", "A")
    assert out == ["203.0.113.1", "203.0.113.2"]


def test_resolve_socket_fallback_returns_empty_on_gai_error(monkeypatch):
    def boom(*a, **k):
        raise dns_tool.socket.gaierror("nope")
    monkeypatch.setattr(dns_tool.socket, "getaddrinfo", boom)
    assert dns_tool._resolve_with_socket_fallback("example.com", "A") == []


def test_resolve_socket_fallback_unsupported_record_type():
    # MX/TXT/SRV go through dnspython only — fallback returns [].
    assert dns_tool._resolve_with_socket_fallback("example.com", "MX") == []


def test_dig_removed_from_bash_allowlist():
    assert "dig" not in bash_tool.ALLOWED_BINARIES
    assert "nslookup" not in bash_tool.ALLOWED_BINARIES


def test_other_recon_binaries_still_allowed():
    # Ensure we didn't accidentally tighten beyond intent.
    for binary in ("nmap", "nuclei", "subfinder", "ffuf", "curl", "host"):
        assert binary in bash_tool.ALLOWED_BINARIES


def test_dns_tool_module_exports_all_tools():
    assert dns_tool.ALL_TOOLS, "dns_tool must export at least one MCP tool"
