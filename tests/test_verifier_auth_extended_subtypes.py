"""I2: auth verifier ND-mode coverage for rate-limit / default-creds / brute-force.

The ExampleChat scan's 6 auth-class hypotheses all fell through to
manual_verification_required with the summary "Auth-class entry not in
(open-redirect | max_auth_age) category". The existing ND-mode only covered
those 2 sub-types. This adds 3 more with strict destructive-vs-non-destructive
safety controls:

- **rate-limit**     — observe ONE probe; check for Retry-After / X-RateLimit-*
                       headers. Non-destructive by construction (1 read).
- **default-creds**  — send ONE login attempt with admin/admin. Failure =
                       disproven. Success with session-token = confirmed.
                       The probe itself is non-destructive — we never
                       establish a session, just read the response.
- **brute-force**    — send N≤5 invalid-password attempts against OUR test
                       account's username. If 429/Retry-After fires by attempt
                       N → disproven (lockout working). If all N succeed with
                       same response shape and no throttle → confirmed.
                       Safety cap at 5 attempts is enforced regardless of
                       hypothesis hint.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.agent.pentest.verifiers import auth as auth_verifier
from sentinel.core.findings import EvidenceState


# ============================ helpers ============================


class _FakeScope:
    """Minimal scope stub the verifier needs."""
    def __init__(self):
        self.engagement_mode = type("Mode", (), {"value": "bbp"})()

    def authorize_url(self, url: str) -> None:
        return None  # always in scope


class _FakeResp:
    def __init__(self, status: int = 200, headers: Optional[dict] = None,
                 text: str = ""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text


def _build_ctx(
    entry: dict,
    bearer_creds: Optional[list[dict]] = None,
    target: str = "https://api.test.example",
) -> Any:
    """Build a fake VerificationContext for the auth verifier."""
    if bearer_creds is None:
        bearer_creds = [{
            "method": "bearer",
            "name": "tester",
            "token_env": "TEST_BEARER",
        }]
    ctx = MagicMock()
    ctx.scope = _FakeScope()
    ctx.target = target
    ctx.auth_credentials = bearer_creds
    ctx.auth_cookies = []
    ctx.research_headers = {"User-Agent": "sentinel-verifier-test/1.0"}
    ctx.queue_entry = entry
    ctx.entry_id = entry.get("ID", "AUTH-VULN-TEST")
    ctx.audit = MagicMock()
    ctx.emit = MagicMock()
    return ctx


# ============================ _entry_kind detection ============================


def test_entry_kind_detects_rate_limit():
    entry = {
        "vulnerability_type": "Rate limit bypass on login endpoint",
        "exploitation_hypothesis": "/login does not enforce per-IP throttle",
    }
    assert auth_verifier._entry_kind(entry) == "rate_limit"


def test_entry_kind_detects_default_creds():
    entry = {
        "vulnerability_type": "Default credentials accepted on admin panel",
        "exploitation_hypothesis": "admin/admin works on /admin",
    }
    assert auth_verifier._entry_kind(entry) == "default_creds"


def test_entry_kind_detects_brute_force():
    entry = {
        "vulnerability_type": "Brute force on login is unthrottled",
        "exploitation_hypothesis": "no account lockout after failed attempts",
    }
    assert auth_verifier._entry_kind(entry) == "brute_force"


def test_entry_kind_prefers_specific_over_generic():
    """Open-redirect hint wins over generic rate-limit mention."""
    entry = {
        "vulnerability_type": "Open redirect via returnUrl",
        "exploitation_hypothesis": "rate limit also missing but redirect is the bug",
    }
    assert auth_verifier._entry_kind(entry) == "open_redirect"


# ============================ rate-limit verifier ============================


@pytest.mark.asyncio
async def test_rate_limit_live_disproven_when_retry_after_present():
    """Server sends Retry-After → rate-limit is enforced → disproven."""
    entry = {
        "ID": "AUTH-VULN-RL-01",
        "vulnerability_type": "Rate limit bypass",
        "source_endpoint": "POST /api/login",
    }
    ctx = _build_ctx(entry)

    with patch("httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.__aenter__.return_value = mock_instance
        mock_instance.post = AsyncMock(return_value=_FakeResp(
            status=429,
            headers={"Retry-After": "60", "X-RateLimit-Remaining": "0"},
            text='{"ok":false,"error":"rate_limited"}',
        ))
        mock_client.return_value = mock_instance

        result = await auth_verifier._verify_rate_limit_ndtest(ctx)

    assert result.state == EvidenceState.LIVE_DISPROVEN
    assert "rate" in result.summary.lower() or "throttle" in result.summary.lower()


@pytest.mark.asyncio
async def test_rate_limit_single_probe_no_throttle_headers_downgrades_to_manual():
    """D3 (2026-XX-XX audit): a SINGLE probe with no rate-limit headers is NOT
    sufficient to auto-confirm "rate-limit missing" — silent limiters exist, and
    one sample proves nothing. The verifier must downgrade to
    MANUAL_VERIFICATION_REQUIRED rather than emit a false-Critical LIVE_CONFIRMED.
    This is one of the operator's documented false-positive sources."""
    entry = {
        "ID": "AUTH-VULN-RL-02",
        "vulnerability_type": "Rate limit missing",
        "source_endpoint": "POST /api/login",
    }
    ctx = _build_ctx(entry)

    with patch("httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.__aenter__.return_value = mock_instance
        mock_instance.post = AsyncMock(return_value=_FakeResp(
            status=401,
            headers={"Content-Type": "application/json"},
            text='{"ok":false,"error":"invalid_credentials"}',
        ))
        mock_client.return_value = mock_instance

        result = await auth_verifier._verify_rate_limit_ndtest(ctx)

    assert result.state == EvidenceState.MANUAL_VERIFICATION_REQUIRED
    # The summary should explain WHY it's inconclusive (single probe / needs
    # more samples / rate-limit can't be confirmed from one observation).
    assert any(
        k in result.summary.lower()
        for k in ("rate", "throttle", "single", "probe", "manual", "insufficient")
    )


# ============================ default-creds verifier ============================


@pytest.mark.asyncio
async def test_default_creds_live_disproven_on_401():
    """admin/admin → 401 → defense holds → disproven."""
    entry = {
        "ID": "AUTH-VULN-DC-01",
        "vulnerability_type": "Default credentials test",
        "source_endpoint": "POST /api/login",
    }
    ctx = _build_ctx(entry)

    with patch("httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.__aenter__.return_value = mock_instance
        mock_instance.post = AsyncMock(return_value=_FakeResp(
            status=401, text='{"ok":false,"error":"not_authed"}',
        ))
        mock_client.return_value = mock_instance

        result = await auth_verifier._verify_default_creds_ndtest(ctx)

    assert result.state == EvidenceState.LIVE_DISPROVEN
    assert "401" in result.summary or "rejected" in result.summary.lower()


@pytest.mark.asyncio
async def test_default_creds_live_confirmed_on_200_with_session_token():
    """admin/admin → 200 + session_token returned → CONFIRMED (high severity)."""
    entry = {
        "ID": "AUTH-VULN-DC-02",
        "vulnerability_type": "Default credentials accepted",
        "source_endpoint": "POST /api/login",
    }
    ctx = _build_ctx(entry)

    with patch("httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.__aenter__.return_value = mock_instance
        mock_instance.post = AsyncMock(return_value=_FakeResp(
            status=200,
            text='{"ok":true,"access_token":"abc123def456ghijkl","user":"admin"}',
        ))
        mock_client.return_value = mock_instance

        result = await auth_verifier._verify_default_creds_ndtest(ctx)

    assert result.state == EvidenceState.LIVE_CONFIRMED
    assert "default" in result.summary.lower() or "admin" in result.summary.lower()


# ============================ brute-force verifier ============================


@pytest.mark.asyncio
async def test_brute_force_live_disproven_when_429_fires_early():
    """5 attempts, 429 fires at attempt 3 → lockout working → disproven."""
    entry = {
        "ID": "AUTH-VULN-BF-01",
        "vulnerability_type": "Brute force on login",
        "source_endpoint": "POST /api/login",
    }
    ctx = _build_ctx(entry)

    responses = [
        _FakeResp(status=401, text='{"error":"invalid"}'),
        _FakeResp(status=401, text='{"error":"invalid"}'),
        _FakeResp(status=429, headers={"Retry-After": "60"},
                  text='{"error":"rate_limited"}'),
    ]

    with patch("httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.__aenter__.return_value = mock_instance
        mock_instance.post = AsyncMock(side_effect=responses + [responses[-1]] * 5)
        mock_client.return_value = mock_instance

        result = await auth_verifier._verify_brute_force_ndtest(ctx)

    assert result.state == EvidenceState.LIVE_DISPROVEN
    assert "lockout" in result.summary.lower() or "throttle" in result.summary.lower() \
        or "429" in result.summary


@pytest.mark.asyncio
async def test_brute_force_full_budget_unthrottled_is_manual_not_confirmed():
    """D4 (2026-XX-XX audit): 5 invalid attempts with no throttle is a STRONG
    candidate but NOT proof — a limiter with threshold >5, or keyed on IP /
    longer window / downstream WAF, would not have fired. Auto-confirming this
    was a documented false-positive source, so the verdict is now
    MANUAL_VERIFICATION_REQUIRED (held for operator review, not auto-submitted)."""
    entry = {
        "ID": "AUTH-VULN-BF-02",
        "vulnerability_type": "Brute force on login is unthrottled",
        "source_endpoint": "POST /api/login",
    }
    ctx = _build_ctx(entry)

    response = _FakeResp(status=401, text='{"error":"invalid_credentials"}')

    with patch("httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.__aenter__.return_value = mock_instance
        mock_instance.post = AsyncMock(return_value=response)
        mock_client.return_value = mock_instance

        result = await auth_verifier._verify_brute_force_ndtest(ctx)

    assert result.state == EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "throttle" in result.summary.lower() or "lockout" in result.summary.lower()


@pytest.mark.asyncio
async def test_brute_force_safety_cap_at_5_attempts():
    """Even if hypothesis suggests 100 attempts, verifier sends at most 5."""
    entry = {
        "ID": "AUTH-VULN-BF-03",
        "vulnerability_type": "Brute force",
        "exploitation_hypothesis": "send 100 attempts to confirm",
        "source_endpoint": "POST /api/login",
    }
    ctx = _build_ctx(entry)

    response = _FakeResp(status=401, text='{"error":"invalid"}')

    with patch("httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.__aenter__.return_value = mock_instance
        mock_instance.post = AsyncMock(return_value=response)
        mock_client.return_value = mock_instance

        result = await auth_verifier._verify_brute_force_ndtest(ctx)

        # Count actual post calls — must be <= 5
        n_calls = mock_instance.post.call_count
        assert n_calls <= 5, (
            f"Safety cap violated: brute-force verifier sent {n_calls} probes; "
            f"max allowed is 5 regardless of hypothesis hint"
        )
        assert n_calls >= 3, "Need enough attempts to actually classify"


# ============================ safety: destructive hints still blocked ============================


@pytest.mark.asyncio
async def test_destructive_hint_in_brute_force_text_still_blocked():
    """Even with rate-limit/brute-force language, if 'account takeover' or
    similar destructive hint is present → manual_required wins."""
    entry = {
        "ID": "AUTH-VULN-DEST-01",
        "vulnerability_type": "Brute force leading to account takeover",
        "exploitation_hypothesis": "Account takeover via password brute force",
        "source_endpoint": "POST /api/login",
    }
    ctx = _build_ctx(entry)

    # If destructive hint is detected, verifier shouldn't even spawn httpx
    with patch("httpx.AsyncClient") as mock_client:
        result = await auth_verifier._verify_generic_auth(ctx)
        assert not mock_client.called or mock_client.return_value.__aenter__.called is False, \
            "Destructive hint should short-circuit before httpx call"

    assert result.state == EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "destructive" in result.summary.lower() \
        or "account takeover" in result.summary.lower() \
        or "manual" in result.summary.lower()


# ============================ back-compat ============================


@pytest.mark.asyncio
async def test_existing_password_reset_ndtest_still_works():
    """The pre-existing password-reset / token-reissue / MFA / session-fix
    hints must continue to dispatch to _generic_auth_ndtest."""
    entry = {
        "ID": "AUTH-VULN-PR-01",
        "vulnerability_type": "Password reset token exposed",
        "exploitation_hypothesis": "password-reset endpoint leaks reset_token in response",
        "source_endpoint": "POST /api/password/reset",
    }
    ctx = _build_ctx(entry)
    # _entry_kind returns "generic"; the existing path dispatches to _generic_auth_ndtest
    kind = auth_verifier._entry_kind(entry)
    # New kinds should NOT clash — password-reset is "generic" (existing) not new
    assert kind in ("generic",), (
        f"password-reset entry should still classify as 'generic', got {kind!r} — "
        f"new sub-types must not poach the existing ND path"
    )
