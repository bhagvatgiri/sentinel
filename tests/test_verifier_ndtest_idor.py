"""Phase 2.5 — IDOR verifier test-workspace non-destructive (ND) mode.

When scope.auth_credentials has ≥2 bearer creds, the IDOR verifier should
run an automatic cross-tenant probe instead of stopping at
manual_verification_required.

Tests cover:
- live_confirmed (cred B reads cred A's resource ID)
- live_disproven (cred B gets 403 / tenant-isolation marker)
- fallback to requires_two_accounts when <2 bearer creds (back-compat)
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from sentinel.agent.pentest.verifier_tool import VerificationContext
from sentinel.agent.pentest.verifiers import idor as idor_v
from sentinel.core.findings import EvidenceState


def _make_scope_mock():
    scope = MagicMock()
    scope.authorize_url = MagicMock()  # no-op (in-scope)
    scope.engagement_id = "test-ndtest-idor"
    # engagement_mode.value access pattern
    scope.engagement_mode.value = "production"
    return scope


def _make_ctx(*, tmp_path: Path, auth_credentials, queue_entry=None,
              audit_writer=None, event_emit=None):
    return VerificationContext(
        scope=_make_scope_mock(),
        target="https://ExampleChat.example.com",
        workspace_dir=tmp_path,
        vuln_class="idor",
        queue_entry=queue_entry or {
            "ID": "IDOR-VULN-01",
            "vulnerability_type": "Cross-workspace IDOR",
            "source_endpoint": "GET /api/conversations/CXXXX1234",
        },
        entry_id="IDOR-VULN-01",
        evidence_dir=tmp_path / "evidence",
        auth_credentials=auth_credentials,
        auth_cookies=[],
        research_headers={"User-Agent": "sentinel-test"},
        audit_writer=audit_writer,
        event_emit=event_emit,
    )


# ---- helpers --------------------------------------------------------------


class _FakeResp:
    def __init__(self, status: int, body: str = "", headers=None):
        self.status_code = status
        self.text = body
        self.headers = headers or {}


def _install_fake_get(monkeypatch, handler):
    """Patch httpx.AsyncClient.get to call our handler.

    Handler signature: (url: str, headers: dict) -> _FakeResp
    """
    async def fake_get(self, url, headers=None):
        return handler(url, headers or {})

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)


# ---- live_confirmed: cred B reads cred A's resource ----------------------


def test_idor_ndtest_two_bearer_confirmed(tmp_path, monkeypatch):
    """B uses A's victim_id; server returns 200 + victim_id reflected."""
    monkeypatch.setenv("WS1_TOKEN", "tok-A")
    monkeypatch.setenv("WS2_TOKEN", "tok-B")

    creds = [
        {"name": "ws1", "method": "bearer", "token_env": "WS1_TOKEN"},
        {"name": "ws2", "method": "bearer", "token_env": "WS2_TOKEN"},
    ]
    audit = MagicMock()
    events: list[tuple] = []

    def _emit(kind, **payload):
        events.append((kind, payload))

    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        audit_writer=audit, event_emit=_emit,
        queue_entry={
            "ID": "IDOR-VULN-01",
            "vulnerability_type": "Cross-workspace IDOR",
            "source_endpoint": "GET /api/conversations/CXXXX1234",
        },
    )

    def handler(url, headers):
        # Step 1 (list as A): return a body with a resource ID.
        if "Bearer tok-A" in headers.get("Authorization", ""):
            return _FakeResp(
                200,
                body='{"channels":[{"id":"CABCDEFG12","name":"general"}]}',
            )
        # Step 2 (cred B reads CABCDEFG12 from cred A's workspace).
        if "Bearer tok-B" in headers.get("Authorization", ""):
            assert "CABCDEFG12" in url, f"expected victim ID in URL: {url}"
            return _FakeResp(
                200,
                body='{"channel":{"id":"CABCDEFG12","name":"general","members":[]}}',
            )
        return _FakeResp(401)

    _install_fake_get(monkeypatch, handler)

    result = asyncio.run(idor_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_CONFIRMED, \
        f"expected LIVE_CONFIRMED, got {result.state}: {result.summary}"
    assert "Cross-workspace IDOR confirmed" in result.summary
    # Audit + event were emitted.
    audit.write.assert_any_call(
        "verifier_ndtest_attempted",
        {"vuln_class": "idor", "entry_id": "IDOR-VULN-01",
         "list_url": "https://ExampleChat.example.com/api/conversations",
         "suspect": "https://ExampleChat.example.com/api/conversations/CXXXX1234",
         "mode": "production"},
    )
    kinds = [k for k, _ in events]
    assert "verifier_ndtest_attempted" in kinds
    assert "verifier_ndtest_confirmed" in kinds


# ---- live_disproven: cred B gets 403 / tenant-isolation marker -----------


def test_idor_ndtest_two_bearer_disproven_on_isolation_marker(tmp_path, monkeypatch):
    """B gets team_access_not_allowed → live_disproven."""
    monkeypatch.setenv("WS1_TOKEN", "tok-A")
    monkeypatch.setenv("WS2_TOKEN", "tok-B")

    creds = [
        {"name": "ws1", "method": "bearer", "token_env": "WS1_TOKEN"},
        {"name": "ws2", "method": "bearer", "token_env": "WS2_TOKEN"},
    ]
    ctx = _make_ctx(tmp_path=tmp_path, auth_credentials=creds)

    def handler(url, headers):
        if "Bearer tok-A" in headers.get("Authorization", ""):
            return _FakeResp(200, body='{"channels":[{"id":"CABCDEFG12"}]}')
        # ExampleChat-style isolation error
        return _FakeResp(
            200, body='{"ok":false,"error":"team_access_not_allowed"}',
        )

    _install_fake_get(monkeypatch, handler)

    result = asyncio.run(idor_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_DISPROVEN, \
        f"expected LIVE_DISPROVEN, got {result.state}: {result.summary}"
    assert "tenant isolation" in result.summary.lower() or \
           "does not reproduce" in result.summary.lower()
    assert result.evidence["isolation_marker"] == "team_access_not_allowed"


def test_idor_ndtest_two_bearer_disproven_on_403(tmp_path, monkeypatch):
    """B gets 403 status → live_disproven (no marker needed)."""
    monkeypatch.setenv("WS1_TOKEN", "tok-A")
    monkeypatch.setenv("WS2_TOKEN", "tok-B")

    creds = [
        {"name": "ws1", "method": "bearer", "token_env": "WS1_TOKEN"},
        {"name": "ws2", "method": "bearer", "token_env": "WS2_TOKEN"},
    ]
    ctx = _make_ctx(tmp_path=tmp_path, auth_credentials=creds)

    def handler(url, headers):
        if "Bearer tok-A" in headers.get("Authorization", ""):
            return _FakeResp(200, body='{"channels":[{"id":"CABCDEFG12"}]}')
        return _FakeResp(403, body='{"error":"forbidden"}')

    _install_fake_get(monkeypatch, handler)

    result = asyncio.run(idor_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_DISPROVEN
    assert result.evidence["test_status"] == 403


# ---- back-compat: <2 bearer creds → REQUIRES_TWO_ACCOUNTS ---------------


def test_idor_no_bearer_falls_back_to_two_accounts(tmp_path):
    """Zero auth_credentials → REQUIRES_TWO_ACCOUNTS (unchanged behavior)."""
    ctx = _make_ctx(tmp_path=tmp_path, auth_credentials=[])
    result = asyncio.run(idor_v.verify(ctx))
    assert result.state is EvidenceState.REQUIRES_TWO_ACCOUNTS


def test_idor_one_bearer_falls_back_to_two_accounts(tmp_path):
    """Single bearer cred → still REQUIRES_TWO_ACCOUNTS."""
    creds = [{"name": "ws1", "method": "bearer", "token_env": "X_TOKEN"}]
    ctx = _make_ctx(tmp_path=tmp_path, auth_credentials=creds)
    result = asyncio.run(idor_v.verify(ctx))
    assert result.state is EvidenceState.REQUIRES_TWO_ACCOUNTS


def test_idor_two_form_creds_no_bearer_returns_manual(tmp_path):
    """Two form-method creds (no bearer) → MANUAL (auto-orchestration deferred)."""
    creds = [
        {"name": "u1", "method": "form", "username": "a", "password_env": "PW1"},
        {"name": "u2", "method": "form", "username": "b", "password_env": "PW2"},
    ]
    ctx = _make_ctx(tmp_path=tmp_path, auth_credentials=creds)
    result = asyncio.run(idor_v.verify(ctx))
    # 2 non-bearer accounts → fall-through to manual_required (suspect set)
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert result.evidence["n_bearer_creds"] == 0
