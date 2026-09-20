"""oauth_refresh_replay verifier sub-type — RFC 6749 §10.4 rotation/replay.

Mirrors tests/test_verifier_auth_extended_subtypes.py conventions. The probe
reads cached tokens from oauth_install_tool._CAPTURED_TOKENS (populated when the
vuln agent calls oauth_install_app) and runs the 5-step rotation/replay
sequence over httpx. All hermetic — httpx + the token cache are mocked.

This is the verifier that would have autonomously caught the 2026-XX-XX ExampleChat
OAuth refresh-token replay bug.
"""
from __future__ import annotations

from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.agent.pentest.verifiers import auth as auth_verifier
from sentinel.core.findings import EvidenceState


# ============================ helpers ============================


class _FakeScopeOAuth:
    """Scope stub with oauth_test_apps + matches_oauth_test_app."""

    def __init__(self, app: dict, out_of_scope: bool = False):
        self.engagement_mode = type("Mode", (), {"value": "bbp"})()
        self.oauth_test_apps = [app]
        self._app = app
        self._out_of_scope = out_of_scope

    def authorize_url(self, url: str) -> None:
        if self._out_of_scope:
            from sentinel.core.scope import OutOfScopeError
            raise OutOfScopeError(f"out of scope: {url}")
        return None

    def matches_oauth_test_app(self, url: str) -> Optional[dict]:
        from urllib.parse import urlparse
        host = (urlparse(url if "://" in url else f"https://{url}").hostname or "").lower()
        app_host = (urlparse(self._app["token_url"]).hostname or "").lower()
        return self._app if host and host == app_host else None


def _app(name: str = "ExampleChat-ws1") -> dict:
    return {
        "name": name,
        "client_id_env": "OAUTH_CID",
        "client_secret_env": "OAUTH_CSEC",
        "authorize_url": "https://ExampleChat.com/oauth/v2/authorize",
        "redirect_uri": "https://callback.invalid/cb",
        "token_url": "https://ExampleChat.com/api/oauth.v2.access",
    }


class _FakeResp:
    def __init__(self, body: str):
        self._body = body
    def json(self):
        import json
        return json.loads(self._body)


def _build_ctx(entry: dict, scope: _FakeScopeOAuth,
               target: str = "https://ExampleChat.com") -> Any:
    ctx = MagicMock()
    ctx.scope = scope
    ctx.target = target
    ctx.auth_credentials = []
    ctx.auth_cookies = []
    ctx.research_headers = {}
    ctx.queue_entry = entry
    ctx.entry_id = entry.get("ID", "AUTH-VULN-OAUTH-01")
    ctx.audit = MagicMock()
    ctx.emit = MagicMock()
    return ctx


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    from sentinel.agent.pentest import oauth_install_tool as oat
    oat.reset_captured_tokens()
    monkeypatch.setenv("OAUTH_CID", "cid")
    monkeypatch.setenv("OAUTH_CSEC", "csec")
    # Skip the 60s eventual-consistency wait in tests.
    monkeypatch.setattr(auth_verifier, "_OAUTH_REPLAY_DELAY_SECONDS", 0)
    yield
    oat.reset_captured_tokens()


def _seed_tokens(name: str = "ExampleChat-ws1", refresh: str = "opaque-token-1-ORIGINAL"):
    from sentinel.agent.pentest import oauth_install_tool as oat
    oat._CAPTURED_TOKENS[name] = {
        "refresh_token": refresh, "access_token": "opaque-token.xoxb-1-AC",
        "user_refresh_token": "", "user_access_token": "",
        "expires_in": 43200, "scope": "", "token_type": "bot",
        "captured_at_utc": "2026-XX-XXT00:00:00+00:00",
    }


# ============================ classification ============================


def test_entry_kind_oauth_refresh_from_endpoint():
    entry = {"vulnerability_type": "Missing rate limit",
             "source_endpoint": "POST /api/oauth.v2.access"}
    assert auth_verifier._entry_kind(entry) == "oauth_refresh_replay"


def test_entry_kind_oauth_refresh_from_grant_type():
    entry = {"vulnerability_type": "Token endpoint flaw",
             "exploitation_hypothesis": "grant_type=refresh_token without RFC 6749 invalidation"}
    assert auth_verifier._entry_kind(entry) == "oauth_refresh_replay"


def test_entry_kind_oauth_refresh_from_rotation_phrase():
    entry = {"vulnerability_type": "Token rotation does not invalidate prior token"}
    assert auth_verifier._entry_kind(entry) == "oauth_refresh_replay"


def test_entry_kind_oauth_refresh_wins_over_rate_limit():
    entry = {"vulnerability_type": "No rate limit on oauth.v2.access refresh endpoint",
             "exploitation_hypothesis": "unthrottled refresh_token grant"}
    assert auth_verifier._entry_kind(entry) == "oauth_refresh_replay"


def test_entry_kind_plain_login_still_rate_limit():
    """Negative: a plain login rate-limit finding must NOT become oauth."""
    entry = {"vulnerability_type": "No rate limiting on login form",
             "source_endpoint": "POST /login"}
    assert auth_verifier._entry_kind(entry) == "rate_limit"


# ============================ probe behaviour ============================


@pytest.mark.asyncio
async def test_destructive_hint_short_circuits():
    entry = {"ID": "X", "vulnerability_type": "oauth refresh token replay",
             "exploitation_hypothesis": "delete account via refresh replay then wipe data",
             "source_endpoint": "POST /api/oauth.v2.access"}
    ctx = _build_ctx(entry, _FakeScopeOAuth(_app()))
    result = await auth_verifier._verify_oauth_refresh_replay_ndtest(ctx)
    assert result.state == EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "destructive" in result.summary.lower()


@pytest.mark.asyncio
async def test_no_matching_app_returns_manual():
    entry = {"ID": "X", "source_endpoint": "POST /api/oauth.v2.access"}
    # token_url host is ExampleChat.com but target/suspect host is other.example
    ctx = _build_ctx(entry, _FakeScopeOAuth(_app()), target="https://other.example")
    result = await auth_verifier._verify_oauth_refresh_replay_ndtest(ctx)
    assert result.state == EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "oauth_test_apps" in result.summary


@pytest.mark.asyncio
async def test_no_cached_tokens_returns_manual():
    entry = {"ID": "X", "source_endpoint": "POST /api/oauth.v2.access"}
    ctx = _build_ctx(entry, _FakeScopeOAuth(_app()))
    # No _seed_tokens — cache empty
    result = await auth_verifier._verify_oauth_refresh_replay_ndtest(ctx)
    assert result.state == EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "oauth_install_app" in result.summary


@pytest.mark.asyncio
async def test_out_of_scope_token_url_returns_error():
    entry = {"ID": "X", "source_endpoint": "POST /api/oauth.v2.access"}
    _seed_tokens()
    ctx = _build_ctx(entry, _FakeScopeOAuth(_app(), out_of_scope=True))
    result = await auth_verifier._verify_oauth_refresh_replay_ndtest(ctx)
    assert result.state == EvidenceState.VERIFICATION_ERROR
    assert "scope" in result.summary.lower()


@pytest.mark.asyncio
async def test_baseline_rotation_fails_returns_manual():
    entry = {"ID": "X", "source_endpoint": "POST /api/oauth.v2.access"}
    _seed_tokens()
    ctx = _build_ctx(entry, _FakeScopeOAuth(_app()))
    with patch("httpx.AsyncClient") as mock_client:
        inst = AsyncMock()
        inst.__aenter__.return_value = inst
        inst.post = AsyncMock(return_value=_FakeResp('{"ok":false,"error":"invalid_refresh_token"}'))
        mock_client.return_value = inst
        result = await auth_verifier._verify_oauth_refresh_replay_ndtest(ctx)
    assert result.state == EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "baseline" in result.summary.lower()


@pytest.mark.asyncio
async def test_replay_rejected_returns_disproven():
    """T1 ok, T2 (replay original) rejected → RFC compliant → live_disproven."""
    entry = {"ID": "X", "source_endpoint": "POST /api/oauth.v2.access"}
    _seed_tokens()
    ctx = _build_ctx(entry, _FakeScopeOAuth(_app()))
    responses = [
        _FakeResp('{"ok":true,"refresh_token":"opaque-token-1-NEW"}'),       # T1
        _FakeResp('{"ok":false,"error":"invalid_refresh_token"}'),  # T2
    ]
    with patch("httpx.AsyncClient") as mock_client:
        inst = AsyncMock()
        inst.__aenter__.return_value = inst
        inst.post = AsyncMock(side_effect=responses)
        mock_client.return_value = inst
        result = await auth_verifier._verify_oauth_refresh_replay_ndtest(ctx)
    assert result.state == EvidenceState.LIVE_DISPROVEN
    assert "invalidate" in result.summary.lower() or "rejected" in result.summary.lower()
    kinds = [c.args[0] for c in ctx.audit.call_args_list]
    assert "oauth_refresh_replay_disproven" in kinds


@pytest.mark.asyncio
async def test_replay_accepted_confidential_client_disproven():
    """T1 ok, T2 replay ok, but no-secret refresh REJECTED → confidential client
    → rotation optional → LIVE_DISPROVEN (expected, not a finding)."""
    entry = {"ID": "X", "source_endpoint": "POST /api/oauth.v2.access"}
    _seed_tokens()
    ctx = _build_ctx(entry, _FakeScopeOAuth(_app()))
    responses = [
        _FakeResp('{"ok":true,"refresh_token":"opaque-token-1-NEW"}'),     # T1 rotate
        _FakeResp('{"ok":true,"refresh_token":"opaque-token-1-REPLAY"}'),  # T2 replay ok
        _FakeResp('{"ok":false,"error":"bad_client_secret"}'),     # no-secret → confidential
    ]
    with patch("httpx.AsyncClient") as mock_client:
        inst = AsyncMock()
        inst.__aenter__.return_value = inst
        inst.post = AsyncMock(side_effect=responses)
        mock_client.return_value = inst
        result = await auth_verifier._verify_oauth_refresh_replay_ndtest(ctx)
    assert result.state == EvidenceState.LIVE_DISPROVEN
    assert "confidential" in result.summary.lower()
    assert result.evidence["client_type"] == "confidential"
    kinds = [c.args[0] for c in ctx.audit.call_args_list]
    assert "oauth_refresh_replay_disproven" in kinds


@pytest.mark.asyncio
async def test_replay_public_revoked_after_grace_disproven():
    """Public client (no-secret accepted), but prior token revoked after grace →
    LIVE_DISPROVEN (replay only inside grace window — expected)."""
    entry = {"ID": "X", "source_endpoint": "POST /api/oauth.v2.access"}
    _seed_tokens()
    ctx = _build_ctx(entry, _FakeScopeOAuth(_app()))
    responses = [
        _FakeResp('{"ok":true,"refresh_token":"n1"}'),   # T1
        _FakeResp('{"ok":true,"refresh_token":"n2"}'),   # T2 replay ok
        _FakeResp('{"ok":true,"refresh_token":"n3"}'),   # no-secret accepted → public
        _FakeResp('{"ok":false,"error":"token_expired"}'),  # T3 grace → revoked
    ]
    with patch("httpx.AsyncClient") as mock_client:
        inst = AsyncMock()
        inst.__aenter__.return_value = inst
        inst.post = AsyncMock(side_effect=responses)
        mock_client.return_value = inst
        result = await auth_verifier._verify_oauth_refresh_replay_ndtest(ctx)
    assert result.state == EvidenceState.LIVE_DISPROVEN
    assert "grace" in result.summary.lower()
    assert result.evidence["client_type"] == "public"


@pytest.mark.asyncio
async def test_replay_public_revoked_by_cap_disproven():
    """Public client, survives grace, but revoked once active-token cap exceeded
    → LIVE_DISPROVEN."""
    entry = {"ID": "X", "source_endpoint": "POST /api/oauth.v2.access"}
    _seed_tokens()
    ctx = _build_ctx(entry, _FakeScopeOAuth(_app()))
    responses = [
        _FakeResp('{"ok":true}'),   # T1
        _FakeResp('{"ok":true}'),   # T2 replay ok
        _FakeResp('{"ok":true}'),   # no-secret → public
        _FakeResp('{"ok":true}'),   # T3 grace survives
        _FakeResp('{"ok":true}'),   # cap rotate 1
        _FakeResp('{"ok":true}'),   # cap rotate 2
        _FakeResp('{"ok":false,"error":"token_revoked"}'),  # cap replay → revoked
    ]
    with patch("httpx.AsyncClient") as mock_client:
        inst = AsyncMock()
        inst.__aenter__.return_value = inst
        inst.post = AsyncMock(side_effect=responses)
        mock_client.return_value = inst
        result = await auth_verifier._verify_oauth_refresh_replay_ndtest(ctx)
    assert result.state == EvidenceState.LIVE_DISPROVEN
    assert "cap" in result.summary.lower()


@pytest.mark.asyncio
async def test_replay_public_survives_everything_confirmed_low_severity():
    """Public client, survives grace AND cap → LIVE_CONFIRMED but SHOULD-level
    (no Critical / no CVSS 9.1)."""
    entry = {"ID": "X", "source_endpoint": "POST /api/oauth.v2.access"}
    _seed_tokens()
    ctx = _build_ctx(entry, _FakeScopeOAuth(_app()))
    responses = [_FakeResp('{"ok":true}')] * 7  # all 7 calls succeed
    with patch("httpx.AsyncClient") as mock_client:
        inst = AsyncMock()
        inst.__aenter__.return_value = inst
        inst.post = AsyncMock(side_effect=responses)
        mock_client.return_value = inst
        result = await auth_verifier._verify_oauth_refresh_replay_ndtest(ctx)
    assert result.state == EvidenceState.LIVE_CONFIRMED
    assert result.evidence["client_type"] == "public"
    # severity recalibrated — no Critical / 9.1 framing
    assert "9.1" not in result.summary
    assert "critical" not in result.summary.lower() or "not critical" in result.summary.lower()
    assert "should" in result.summary.lower()
    kinds = [c.args[0] for c in ctx.audit.call_args_list]
    assert "oauth_refresh_replay_started" in kinds
    assert "oauth_refresh_replay_verified" in kinds
    for c in ctx.audit.call_args_list:
        assert c.args[1].get("mode") == "bbp", "verifier audit payload missing mode= (B1)"
