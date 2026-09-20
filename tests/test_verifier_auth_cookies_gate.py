"""Fix 6 (2026-XX-XX) — verifiers must accept `auth_cookies` as auth-equivalent.

Before Fix 6: csrf, jwt_oauth verifiers gated on `ctx.auth_credentials`
only. With the Real-Chrome-via-CDP profile populating `auth_cookies` (44
live cookies after `sentinel chrome bootstrap`), the verifiers still
emitted REQUIRES_TEST_CREDENTIALS — wrong, because the cookies represent
a live authenticated session.

After Fix 6: gate is `not auth_credentials AND not auth_cookies`. With
cookies-only, the verifier still can't auto-perform cross-origin POST
(csrf) or JWT mutation (jwt_oauth), but the verdict downgrades to
MANUAL_VERIFICATION_REQUIRED instead of REQUIRES_TEST_CREDENTIALS so the
operator gets useful next steps.

idor.py is NOT changed — single cookie session can't demonstrate
cross-account IDOR, so REQUIRES_TWO_ACCOUNTS still fires when fewer than
2 auth_credentials are configured. Documented limitation.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from sentinel.agent.pentest.verifier_tool import VerificationContext
from sentinel.agent.pentest.verifiers import csrf as csrf_v
from sentinel.agent.pentest.verifiers import jwt_oauth as jwt_v
from sentinel.agent.pentest.verifiers import idor as idor_v
from sentinel.core.findings import EvidenceState


def _make_ctx(
    *,
    auth_credentials=None,
    auth_cookies=None,
    queue_entry=None,
    tmp_path: Path,
) -> VerificationContext:
    scope = MagicMock()
    scope.authorize_url = MagicMock()  # no-op (in scope)
    scope.engagement_id = "test-fix6"
    return VerificationContext(
        scope=scope,
        target="https://example.com",
        workspace_dir=tmp_path,
        vuln_class="csrf",
        queue_entry=queue_entry or {
            "ID": "TEST-01",
            "vulnerability_type": "missing CSRF token",
            "exploitation_hypothesis": "form has no anti-CSRF token",
            "source_endpoint": "/account/update",
            "missing_defense": "no csrf token in form html",
        },
        entry_id="TEST-01",
        evidence_dir=tmp_path / "evidence",
        auth_credentials=auth_credentials or [],
        auth_cookies=auth_cookies or [],
    )


# ---- csrf verifier ---------------------------------------------------------


def test_csrf_with_cookies_only_does_not_demand_credentials(tmp_path: Path, monkeypatch):
    """Cookies-only session → MANUAL_VERIFICATION_REQUIRED (not REQUIRES_TEST_CREDENTIALS).

    The token-absence path (line 126) gate previously rejected cookies-only
    scopes; Fix 6 should accept them.
    """
    cookies = [
        {"name": "session", "value": "abc", "domain": "example.com",
         "path": "/", "secure": True, "httpOnly": True},
    ]
    ctx = _make_ctx(auth_cookies=cookies, tmp_path=tmp_path)

    # Mock httpx.AsyncClient.get to return a body without a CSRF token field.
    class FakeResponse:
        text = '<html><form action="/update"><input name="email"></form></html>'

    class FakeClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def get(self, url, headers=None): return FakeResponse()

    monkeypatch.setattr("sentinel.agent.pentest.verifiers.csrf.httpx.AsyncClient", FakeClient)

    result = asyncio.run(csrf_v._verify_token_absence(ctx))
    assert result is not None
    assert result.state != EvidenceState.REQUIRES_TEST_CREDENTIALS, (
        f"Cookies-only csrf must not demand credentials; got {result.state}: {result.summary}"
    )
    assert result.state == EvidenceState.MANUAL_VERIFICATION_REQUIRED


def test_csrf_with_neither_credentials_nor_cookies_still_demands_creds(tmp_path: Path, monkeypatch):
    """Empty auth scope → REQUIRES_TEST_CREDENTIALS (back-compat preserved)."""
    ctx = _make_ctx(tmp_path=tmp_path)  # both empty

    class FakeResponse:
        text = '<html><form action="/update"><input name="email"></form></html>'

    class FakeClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def get(self, url, headers=None): return FakeResponse()

    monkeypatch.setattr("sentinel.agent.pentest.verifiers.csrf.httpx.AsyncClient", FakeClient)

    result = asyncio.run(csrf_v._verify_token_absence(ctx))
    assert result.state == EvidenceState.REQUIRES_TEST_CREDENTIALS


def test_csrf_generic_path_with_cookies_returns_manual_not_creds(tmp_path: Path):
    """Generic CSRF path (line 170) — cookies-only must reach MANUAL not REQUIRES_TEST_CREDENTIALS."""
    cookies = [{"name": "sess", "value": "x", "domain": "example.com", "path": "/"}]
    ctx = _make_ctx(
        auth_cookies=cookies, tmp_path=tmp_path,
        queue_entry={
            "ID": "TEST-02",
            "vulnerability_type": "csrf-generic",
            "exploitation_hypothesis": "generic csrf claim",
            "source_endpoint": "/transfer",
            "missing_defense": "(generic — no specific token-absence claim)",
        },
    )
    result = asyncio.run(csrf_v.verify(ctx))
    assert result.state != EvidenceState.REQUIRES_TEST_CREDENTIALS, (
        f"got {result.state}: {result.summary}"
    )
    assert result.state == EvidenceState.MANUAL_VERIFICATION_REQUIRED


# ---- jwt_oauth verifier ---------------------------------------------------


def test_jwt_oauth_with_jwt_cookie_does_not_demand_credentials(tmp_path: Path):
    """A cookie whose value is a JWT-shaped string counts as a captured token."""
    cookies = [
        {"name": "id_token",
         "value": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature_blob_xyz",
         "domain": "example.com", "path": "/"},
    ]
    ctx = _make_ctx(auth_cookies=cookies, tmp_path=tmp_path)
    result = asyncio.run(jwt_v.verify(ctx))
    assert result.state != EvidenceState.REQUIRES_TEST_CREDENTIALS, (
        f"JWT cookie must satisfy the gate; got {result.state}: {result.summary}"
    )
    assert result.state == EvidenceState.MANUAL_VERIFICATION_REQUIRED
    # auth_source should mention CDP profile
    assert "CDP" in result.evidence.get("auth_source", "") or \
           "cookies" in result.evidence.get("auth_source", "")


def test_jwt_oauth_with_neither_credentials_nor_cookies(tmp_path: Path):
    """Empty auth → REQUIRES_TEST_CREDENTIALS (back-compat)."""
    ctx = _make_ctx(tmp_path=tmp_path)
    result = asyncio.run(jwt_v.verify(ctx))
    assert result.state == EvidenceState.REQUIRES_TEST_CREDENTIALS


def test_jwt_oauth_with_non_jwt_cookies_only(tmp_path: Path):
    """Cookies present but none are JWT-shaped → REQUIRES_TEST_CREDENTIALS w/ updated message."""
    cookies = [
        {"name": "session", "value": "opaque_session_id_not_a_jwt",
         "domain": "example.com", "path": "/"},
    ]
    ctx = _make_ctx(auth_cookies=cookies, tmp_path=tmp_path)
    result = asyncio.run(jwt_v.verify(ctx))
    assert result.state == EvidenceState.REQUIRES_TEST_CREDENTIALS
    assert "no JWT-shaped" in result.summary or "JWT" in result.summary


# ---- idor verifier (NOT changed; cookies don't help with two-account IDOR) ---


def test_idor_with_cookies_but_no_credentials_still_demands_two_accounts(tmp_path: Path):
    """idor.py is NOT changed — single cookie session can't do A→B IDOR.

    Documented limitation: cookies represent ONE session; cross-account
    IDOR needs at least 2 distinct accounts. Future PR could add
    auth_cookies_per_account schema.
    """
    cookies = [{"name": "sess", "value": "x", "domain": "example.com", "path": "/"}]
    ctx = _make_ctx(auth_cookies=cookies, tmp_path=tmp_path)
    result = asyncio.run(idor_v.verify(ctx))
    assert result.state == EvidenceState.REQUIRES_TWO_ACCOUNTS or \
           result.state == EvidenceState.MANUAL_VERIFICATION_REQUIRED, (
        f"idor cookies-only verdict; got {result.state}"
    )


def test_idor_with_two_credentials_can_proceed(tmp_path: Path):
    """Sanity: idor with two creds doesn't gate on count."""
    creds = [
        {"name": "userA", "method": "form", "username": "a", "password_env": "X"},
        {"name": "userB", "method": "form", "username": "b", "password_env": "Y"},
    ]
    ctx = _make_ctx(auth_credentials=creds, tmp_path=tmp_path)
    result = asyncio.run(idor_v.verify(ctx))
    assert result.state != EvidenceState.REQUIRES_TWO_ACCOUNTS
