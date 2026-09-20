"""Phase 2.5 — auth verifier non-destructive (test-account bypass) mode.

The generic auth-bypass branch now probes the bypass payload against
the verifier's OWN test account (we own it; probe doesn't mutate other
users' state) and reads the response for bypass-success markers
(reset_token, MFA bypass flag, access_token re-issue) WITHOUT consuming
the returned token.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from sentinel.agent.pentest.verifier_tool import VerificationContext
from sentinel.agent.pentest.verifiers import auth as auth_v
from sentinel.core.findings import EvidenceState


def _make_scope_mock():
    scope = MagicMock()
    scope.authorize_url = MagicMock()
    scope.engagement_id = "test-ndtest-auth"
    scope.engagement_mode.value = "production"
    return scope


def _make_ctx(*, tmp_path: Path, auth_credentials, queue_entry=None,
              audit_writer=None, event_emit=None):
    return VerificationContext(
        scope=_make_scope_mock(),
        target="https://example.com",
        workspace_dir=tmp_path,
        vuln_class="auth",
        queue_entry=queue_entry or {
            "ID": "AUTH-VULN-NDX-01",
            "vulnerability_type": "Password reset bypass",
            "exploitation_hypothesis": "password reset endpoint returns "
                                        "reset token without challenge",
            "source_endpoint": "POST /api/auth/reset",
            "missing_defense": "no challenge required",
        },
        entry_id="AUTH-VULN-NDX-01",
        evidence_dir=tmp_path / "evidence",
        auth_credentials=auth_credentials,
        auth_cookies=[],
        research_headers={"User-Agent": "sentinel-test"},
        audit_writer=audit_writer,
        event_emit=event_emit,
    )


class _FakeResp:
    def __init__(self, status=200, body="", headers=None):
        self.status_code = status
        self.text = body
        self.headers = headers or {}


def _patch_post(monkeypatch, handler):
    async def fake_post(self, url, *, data=None, headers=None):
        return handler(url, data or {}, headers or {})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)


def _patch_story_runner_noop(monkeypatch):
    """Disable YAML stories so the test isolates the Python verifier."""
    async def fake_run(*a, **kw):
        return []
    monkeypatch.setattr(
        "sentinel.agent.pentest.verifiers.auth.run_class_stories", fake_run,
    )


# ---- live_confirmed: reset_token in response ----------------------------


def test_auth_ndtest_confirmed_on_reset_token_returned(tmp_path, monkeypatch):
    monkeypatch.setenv("X_TOKEN", "tok")
    creds = [{"name": "u1", "method": "bearer", "token_env": "X_TOKEN",
              "username": "verifier_test_user"}]
    events: list[tuple] = []
    audit = MagicMock()

    def handler(url, data, headers):
        # Server returns a reset_token WITHOUT challenging the caller.
        return _FakeResp(
            200,
            body='{"status":"ok","reset_token":"abcd1234efgh5678"}',
            headers={"content-type": "application/json"},
        )

    _patch_post(monkeypatch, handler)
    _patch_story_runner_noop(monkeypatch)

    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds, audit_writer=audit,
        event_emit=lambda k, **p: events.append((k, p)),
    )
    result = asyncio.run(auth_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_CONFIRMED, \
        f"expected LIVE_CONFIRMED, got {result.state}: {result.summary}"
    assert "Auth-bypass confirmed" in result.summary
    assert "reset_token" in result.summary
    kinds = [k for k, _ in events]
    assert "verifier_ndtest_attempted" in kinds
    assert "verifier_ndtest_confirmed" in kinds


def test_auth_ndtest_confirmed_on_mfa_bypass_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("X_TOKEN", "tok")
    creds = [{"name": "u1", "method": "bearer", "token_env": "X_TOKEN",
              "username": "u"}]

    def handler(url, data, headers):
        return _FakeResp(
            200,
            body='{"status":"ok","mfa_bypass":true,"session":"abc"}',
        )

    _patch_post(monkeypatch, handler)
    _patch_story_runner_noop(monkeypatch)

    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        queue_entry={
            "ID": "AUTH-VULN-NDX-02",
            "vulnerability_type": "MFA bypass",
            "exploitation_hypothesis": "MFA bypass returns valid session",
            "source_endpoint": "POST /api/auth/mfa-verify",
        },
    )
    result = asyncio.run(auth_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_CONFIRMED
    assert "MFA bypass" in result.summary


# ---- live_disproven: 4xx rejection --------------------------------------


def test_auth_ndtest_disproven_on_401(tmp_path, monkeypatch):
    monkeypatch.setenv("X_TOKEN", "tok")
    creds = [{"name": "u1", "method": "bearer", "token_env": "X_TOKEN",
              "username": "u"}]

    def handler(url, data, headers):
        return _FakeResp(401, body='{"error":"challenge required"}')

    _patch_post(monkeypatch, handler)
    _patch_story_runner_noop(monkeypatch)

    ctx = _make_ctx(tmp_path=tmp_path, auth_credentials=creds)
    result = asyncio.run(auth_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_DISPROVEN
    assert "defense holds" in result.summary.lower()


# ---- destructive-bypass safety net --------------------------------------


def test_auth_destructive_bypass_stays_manual_even_with_bearer(tmp_path, monkeypatch):
    """Destructive bypass hints (delete account / change-password) must NOT
    trigger an auto-test even if bearer cred is present."""
    creds = [{"name": "u1", "method": "bearer", "token_env": "X",
              "username": "u"}]
    _patch_story_runner_noop(monkeypatch)
    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        queue_entry={
            "ID": "AUTH-VULN-NDX-03",
            "vulnerability_type": "Account takeover via password change",
            "exploitation_hypothesis": "change-password without confirmation",
            "source_endpoint": "POST /api/auth/change-password",
        },
    )
    result = asyncio.run(auth_v.verify(ctx))
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "destructive" in result.summary.lower()


# ---- back-compat: no creds → MANUAL ------------------------------------


def test_auth_no_bearer_falls_back_to_manual(tmp_path, monkeypatch):
    _patch_story_runner_noop(monkeypatch)
    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=[],
        queue_entry={
            "ID": "AUTH-VULN-NDX-04",
            "vulnerability_type": "Default credentials",
            "notes": "admin/admin worked",
        },
    )
    result = asyncio.run(auth_v.verify(ctx))
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "Default-creds" in result.summary or \
           "Operator: verify manually" in result.summary


# ---- back-compat: bearer cred but no ND-hint → MANUAL -------------------


def test_auth_bearer_without_nd_hint_returns_manual(tmp_path, monkeypatch):
    """Bearer cred present but the hypothesis isn't one of the ND-test
    sub-types (password-reset / token-reissue / MFA / session-fix). The
    generic fallback should still return MANUAL."""
    monkeypatch.setenv("X_TOKEN", "tok")
    creds = [{"name": "u1", "method": "bearer", "token_env": "X_TOKEN",
              "username": "u"}]
    _patch_story_runner_noop(monkeypatch)
    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        queue_entry={
            "ID": "AUTH-VULN-NDX-05",
            "vulnerability_type": "Generic auth-class finding",
            "exploitation_hypothesis": "(no specific bypass class)",
            "source_endpoint": "POST /api/auth/login",
        },
    )
    result = asyncio.run(auth_v.verify(ctx))
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED
    # Make sure we got the generic fallback path, NOT the ND-test path.
    assert "Default-creds" in result.summary or \
           "Operator: verify manually" in result.summary
