"""Hermetic tests for oauth_checklist.py (Tier 2 #5).

Mocks httpx + the captured-token cache. No real network.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
import pytest

from sentinel.agent.pentest import oauth_checklist as oac
from sentinel.core.scope import OutOfScopeError


def _app(authorize_url="https://ExampleChat.com/oauth/v2/authorize?client_id=X&state=abc&code_challenge=Y"):
    return {
        "name": "ExampleChat-ws1",
        "client_id_env": "OAUTH_CID",
        "client_secret_env": "OAUTH_CSEC",
        "authorize_url": authorize_url,
        "redirect_uri": "https://callback.invalid/cb",
        "token_url": "https://ExampleChat.com/api/oauth.v2.access",
    }


class _Scope:
    def __init__(self, deny=False):
        self.engagement_mode = type("M", (), {"value": "bbp"})()
        self._deny = deny
    def authorize_url(self, url):
        if self._deny:
            raise OutOfScopeError("nope")
        return None


def _captured(refresh="opaque-token-1-ORIG"):
    return {"refresh_token": refresh, "access_token": "a", "user_refresh_token": "",
            "user_access_token": "", "expires_in": 1, "scope": "", "token_type": "bot",
            "captured_at_utc": "2026-XX-XXT00:00:00+00:00"}


def _fake_httpx(monkeypatch, responses):
    """responses: list of dict bodies returned per POST call."""
    state = {"i": 0}
    class FakeResp:
        def __init__(self, body): self._b = body
        def json(self):
            import json; return json.loads(self._b)
    class FakeClient:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, data=None, **kw):
            i = state["i"]; state["i"] += 1
            return FakeResp(responses[min(i, len(responses) - 1)])
    monkeypatch.setattr("httpx.AsyncClient", FakeClient)
    return state


# ---- static checks --------------------------------------------------------


@pytest.mark.asyncio
async def test_state_and_pkce_pass_when_present(monkeypatch):
    r1 = await oac._check_rfc6749_s10_12_state(_Scope(), _app(), "c", "s", None)
    assert r1.state == "pass"
    r2 = await oac._check_rfc9700_pkce(_Scope(), _app(), "c", "s", None)
    assert r2.state == "pass"


@pytest.mark.asyncio
async def test_state_and_pkce_inconclusive_when_absent(monkeypatch):
    app = _app(authorize_url="https://ExampleChat.com/oauth/v2/authorize?client_id=X")
    r1 = await oac._check_rfc6749_s10_12_state(_Scope(), app, "c", "s", None)
    assert r1.state == "inconclusive"
    r2 = await oac._check_rfc9700_pkce(_Scope(), app, "c", "s", None)
    assert r2.state == "inconclusive"


# ---- §6 client-auth -------------------------------------------------------


@pytest.mark.asyncio
async def test_s6_pass_when_no_secret_rejected(monkeypatch):
    _fake_httpx(monkeypatch, ['{"ok":false,"error":"bad_client_secret"}'])
    r = await oac._check_rfc6749_s6_client_auth(_Scope(), _app(), "cid", "csec", _captured())
    assert r.state == "pass"


@pytest.mark.asyncio
async def test_s6_fail_when_no_secret_accepted(monkeypatch):
    _fake_httpx(monkeypatch, ['{"ok":true,"refresh_token":"new"}'])
    r = await oac._check_rfc6749_s6_client_auth(_Scope(), _app(), "cid", "csec", _captured())
    assert r.state == "fail"


@pytest.mark.asyncio
async def test_s6_skipped_without_tokens(monkeypatch):
    r = await oac._check_rfc6749_s6_client_auth(_Scope(), _app(), "cid", "csec", None)
    assert r.state == "skipped"


@pytest.mark.asyncio
async def test_s6_skipped_out_of_scope(monkeypatch):
    r = await oac._check_rfc6749_s6_client_auth(_Scope(deny=True), _app(), "cid", "csec", _captured())
    assert r.state == "skipped"


# ---- §10.4 rotation -------------------------------------------------------


@pytest.mark.asyncio
async def test_s10_4_pass_confidential_when_replay_accepted(monkeypatch):
    """Replay accepted but no-secret rejected → confidential client → pass
    (rotation optional; not a finding). Recalibrated 2026-XX-XX."""
    _fake_httpx(monkeypatch, ['{"ok":true,"refresh_token":"new"}',   # T1
                              '{"ok":true,"refresh_token":"replay"}',  # T2 replay ok
                              '{"ok":false,"error":"bad_client_secret"}'])  # no-secret → confidential
    r = await oac._check_rfc6749_s10_4_rotation(_Scope(), _app(), "cid", "csec", _captured())
    assert r.state == "pass"
    assert "confidential" in r.summary.lower()
    assert "9.1" not in r.summary


@pytest.mark.asyncio
async def test_s10_4_fail_public_when_replay_accepted(monkeypatch):
    """Replay accepted AND no-secret accepted → public client → fail (SHOULD)."""
    _fake_httpx(monkeypatch, ['{"ok":true,"refresh_token":"new"}',   # T1
                              '{"ok":true,"refresh_token":"replay"}',  # T2 replay ok
                              '{"ok":true,"refresh_token":"nosecret"}'])  # no-secret → public
    r = await oac._check_rfc6749_s10_4_rotation(_Scope(), _app(), "cid", "csec", _captured())
    assert r.state == "fail"
    assert "public" in r.summary.lower()
    assert "9.1" not in r.summary
    assert "should" in r.summary.lower()


@pytest.mark.asyncio
async def test_s10_4_pass_when_replay_rejected(monkeypatch):
    _fake_httpx(monkeypatch, ['{"ok":true,"refresh_token":"new"}',
                              '{"ok":false,"error":"invalid_refresh_token"}'])
    r = await oac._check_rfc6749_s10_4_rotation(_Scope(), _app(), "cid", "csec", _captured())
    assert r.state == "pass"


@pytest.mark.asyncio
async def test_s10_4_inconclusive_when_baseline_fails(monkeypatch):
    _fake_httpx(monkeypatch, ['{"ok":false,"error":"invalid_refresh_token"}'])
    r = await oac._check_rfc6749_s10_4_rotation(_Scope(), _app(), "cid", "csec", _captured())
    assert r.state == "inconclusive"


# ---- run_oauth_rfc_checklist + tool ---------------------------------------


@pytest.mark.asyncio
async def test_checklist_runs_all_and_audits(monkeypatch):
    # §6 reject (pass), §10.4 rotate ok then replay reject (pass)
    _fake_httpx(monkeypatch, [
        '{"ok":false,"error":"bad_client_secret"}',   # §6 no-secret
        '{"ok":true,"refresh_token":"new"}',          # §10.4 T1
        '{"ok":false,"error":"invalid_refresh_token"}',  # §10.4 T2
    ])
    audit = MagicMock()
    emit = MagicMock()
    results = await oac.run_oauth_rfc_checklist(
        scope=_Scope(), audit_writer=audit, event_emit=emit,
        app=_app(), client_id="cid", client_secret="csec", captured=_captured(),
    )
    assert len(results) == len(oac.CHECKS)
    states = {r.name: r.state for r in results}
    assert states["client_auth_on_refresh"] == "pass"
    assert states["refresh_rotation_invalidation"] == "pass"
    # audit mode discipline (B1)
    kinds = [c.args[0] for c in audit.write.call_args_list]
    assert "oauth_rfc_check" in kinds
    assert "oauth_rfc_audit_completed" in kinds
    for c in audit.write.call_args_list:
        assert c.kwargs.get("mode") == "bbp"


@pytest.mark.asyncio
async def test_oauth_rfc_audit_tool_reports_fail(monkeypatch):
    from sentinel.agent.pentest import oauth_install_tool as oat
    from sentinel.agent.pentest import tools as p_tools
    oat.reset_captured_tokens()
    oat._CAPTURED_TOKENS["ExampleChat-ws1"] = _captured()
    monkeypatch.setenv("OAUTH_CID", "cid")
    monkeypatch.setenv("OAUTH_CSEC", "csec")

    ctx = MagicMock()
    ctx.scope = _Scope()
    ctx.scope.oauth_test_apps = [_app()]
    ctx.audit = MagicMock()
    ctx.event_log = MagicMock()
    monkeypatch.setattr(oac, "_require_ctx", lambda: ctx)

    # §6 reject (pass), §10.4 rotate ok then replay ACCEPT (fail)
    _fake_httpx(monkeypatch, [
        '{"ok":false,"error":"bad_client_secret"}',
        '{"ok":true,"refresh_token":"new"}',
        '{"ok":true,"refresh_token":"replay"}',
    ])
    out = await oac.oauth_rfc_audit.handler({"app_name": "ExampleChat-ws1"})
    text = out["content"][0]["text"]
    assert "FAIL" in text
    assert "§10.4" in text
    oat.reset_captured_tokens()


@pytest.mark.asyncio
async def test_oauth_rfc_audit_unknown_app_errors(monkeypatch):
    ctx = MagicMock()
    ctx.scope = _Scope()
    ctx.scope.oauth_test_apps = []
    monkeypatch.setattr(oac, "_require_ctx", lambda: ctx)
    out = await oac.oauth_rfc_audit.handler({"app_name": "nope"})
    assert out.get("is_error") is True
