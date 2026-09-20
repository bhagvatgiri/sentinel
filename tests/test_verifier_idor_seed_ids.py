"""Phase 2.5 — IDOR verifier seed-ID pre-fetch.

Live ExampleChat scan exposed a gap: IDOR hypotheses with placeholder URLs
(`/api/users.info?user={user_id}`) returned `user_not_found` when probed
directly, because the placeholder was never substituted with a real ID
from cred A's workspace. All 7 IDOR entries on the ExampleChat run fell through
to `manual_verification_required`.

Fix: pre-seed real `team_id`, `user_id`, and `channel_id` values once per
cred A via `auth.test` + `conversations.list` + `users.list`, then
substitute them into the suspect URL before the cross-tenant probe.

Tests:
- `_seed_workspace_ids` returns the expected dict from canned responses
- `_cross_tenant_ndtest` substitutes `{user_id}` / `{channel_id}` /
  `{team_id}` placeholders before issuing cred-B probe
- graceful fallback (`manual_verification_required` + clear msg) when
  the hypothesis needs `{file_id}` but cred A lacks `files:read`
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from sentinel.agent.pentest.verifier_tool import VerificationContext
from sentinel.agent.pentest.verifiers import idor as idor_v
from sentinel.core.findings import EvidenceState


def _make_scope_mock():
    scope = MagicMock()
    scope.authorize_url = MagicMock()
    scope.engagement_id = "test-seed-idor"
    scope.engagement_mode.value = "production"
    return scope


def _make_ctx(*, tmp_path: Path, auth_credentials, queue_entry=None,
              audit_writer=None, event_emit=None,
              target="https://ExampleChat.example.com"):
    return VerificationContext(
        scope=_make_scope_mock(),
        target=target,
        workspace_dir=tmp_path,
        vuln_class="idor",
        queue_entry=queue_entry or {
            "ID": "IDOR-SEED-01",
            "vulnerability_type": "Cross-workspace IDOR",
            "source_endpoint": "GET /api/users.info?user={user_id}",
        },
        entry_id=queue_entry.get("ID") if queue_entry else "IDOR-SEED-01",
        evidence_dir=tmp_path / "evidence",
        auth_credentials=auth_credentials,
        auth_cookies=[],
        research_headers={"User-Agent": "sentinel-test"},
        audit_writer=audit_writer,
        event_emit=event_emit,
    )


class _FakeResp:
    def __init__(self, status: int, body: str = "", headers=None):
        self.status_code = status
        self.text = body
        self.headers = headers or {}


def _install_fake_get(monkeypatch, handler):
    async def fake_get(self, url, headers=None):
        return handler(url, headers or {})
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)


# ---------- _seed_workspace_ids -------------------------------------------


def test_seed_workspace_ids_canned_happy_path(tmp_path, monkeypatch):
    """auth.test + conversations.list + users.list return real IDs."""
    monkeypatch.setenv("WS1_TOKEN", "tok-A")
    cred = {"name": "ws1", "method": "bearer", "token_env": "WS1_TOKEN"}
    ctx = _make_ctx(tmp_path=tmp_path, auth_credentials=[cred])

    def handler(url, headers):
        if "auth.test" in url:
            return _FakeResp(
                200,
                body=json.dumps({
                    "ok": True,
                    "team_id": "T0B4R63QJE5",
                    "user_id": "U0B4PAW6690",
                }),
            )
        if "conversations.list" in url:
            return _FakeResp(
                200,
                body=json.dumps({
                    "ok": True,
                    "channels": [
                        {"id": "C0BAA1111", "name": "general"},
                        {"id": "C0BBB2222", "name": "random"},
                    ],
                }),
            )
        if "users.list" in url:
            return _FakeResp(
                200,
                body=json.dumps({
                    "ok": True,
                    "members": [
                        {"id": "U0BAA1111", "name": "alice"},
                        {"id": "U0BBB2222", "name": "bob"},
                    ],
                }),
            )
        return _FakeResp(404, body="{}")

    _install_fake_get(monkeypatch, handler)

    seed = asyncio.run(idor_v._seed_workspace_ids(ctx, cred))
    assert seed["team_id"] == "T0B4R63QJE5"
    assert seed["user_id"] == "U0B4PAW6690"
    assert "C0BAA1111" in seed["channel_ids"]
    assert "U0BAA1111" in seed["user_ids"]


def test_seed_workspace_ids_missing_scope_graceful(tmp_path, monkeypatch):
    """When users.list returns missing_scope, channel_ids/user_ids empty."""
    monkeypatch.setenv("WS1_TOKEN", "tok-A")
    cred = {"name": "ws1", "method": "bearer", "token_env": "WS1_TOKEN"}
    ctx = _make_ctx(tmp_path=tmp_path, auth_credentials=[cred])

    def handler(url, headers):
        if "auth.test" in url:
            return _FakeResp(200, body=json.dumps({
                "ok": True, "team_id": "TXX", "user_id": "UYY",
            }))
        # All list endpoints fail.
        return _FakeResp(
            200, body=json.dumps({"ok": False, "error": "missing_scope"}),
        )

    _install_fake_get(monkeypatch, handler)
    seed = asyncio.run(idor_v._seed_workspace_ids(ctx, cred))
    assert seed["team_id"] == "TXX"
    assert seed["user_id"] == "UYY"
    assert seed["channel_ids"] == []
    assert seed["user_ids"] == []


def test_seed_workspace_ids_auth_test_failure_returns_empty(tmp_path, monkeypatch):
    """When auth.test itself fails, all fields fall back to empty/None."""
    monkeypatch.setenv("WS1_TOKEN", "tok-A")
    cred = {"name": "ws1", "method": "bearer", "token_env": "WS1_TOKEN"}
    ctx = _make_ctx(tmp_path=tmp_path, auth_credentials=[cred])

    def handler(url, headers):
        return _FakeResp(401, body=json.dumps({"ok": False, "error": "invalid_auth"}))

    _install_fake_get(monkeypatch, handler)
    seed = asyncio.run(idor_v._seed_workspace_ids(ctx, cred))
    # Spec is "graceful failures — empty list" — so callers can still detect
    # the missing IDs (None / empty) and bail to manual.
    assert seed.get("team_id") in (None, "")
    assert seed.get("user_id") in (None, "")
    assert seed["channel_ids"] == []
    assert seed["user_ids"] == []


# ---------- placeholder substitution in _cross_tenant_ndtest --------------


def test_cross_tenant_ndtest_substitutes_user_id_placeholder(tmp_path, monkeypatch):
    """`{user_id}` in suspect URL is swapped for a seed-list user_id."""
    monkeypatch.setenv("WS1_TOKEN", "tok-A")
    monkeypatch.setenv("WS2_TOKEN", "tok-B")
    creds = [
        {"name": "ws1", "method": "bearer", "token_env": "WS1_TOKEN"},
        {"name": "ws2", "method": "bearer", "token_env": "WS2_TOKEN"},
    ]
    captured_urls: list[str] = []

    def handler(url, headers):
        # auth.test / list calls (cred A only).
        if "Bearer tok-A" in headers.get("Authorization", ""):
            if "auth.test" in url:
                return _FakeResp(200, body=json.dumps({
                    "ok": True, "team_id": "TXX", "user_id": "UAAOWN",
                }))
            if "conversations.list" in url:
                return _FakeResp(200, body=json.dumps({
                    "ok": True, "channels": [{"id": "C0BCH001"}],
                }))
            if "users.list" in url:
                return _FakeResp(200, body=json.dumps({
                    "ok": True, "members": [{"id": "U0BVICTIM"}],
                }))
        # Cred B probe: the placeholder must have been substituted with
        # U0BVICTIM before the request fires.
        if "Bearer tok-B" in headers.get("Authorization", ""):
            captured_urls.append(url)
            return _FakeResp(
                200, body=json.dumps({
                    "ok": True, "user": {"id": "U0BVICTIM", "email": "v@x"},
                }),
            )
        return _FakeResp(404, body="{}")

    _install_fake_get(monkeypatch, handler)

    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        queue_entry={
            "ID": "IDOR-SEED-USER",
            "vulnerability_type": "Cross-workspace IDOR",
            "source_endpoint": "GET /api/users.info?user={user_id}",
        },
    )
    result = asyncio.run(idor_v.verify(ctx))
    assert any("U0BVICTIM" in u for u in captured_urls), \
        f"expected substituted user_id in probe URL, got {captured_urls!r}"
    assert result.state is EvidenceState.LIVE_CONFIRMED, \
        f"expected LIVE_CONFIRMED, got {result.state}: {result.summary}"


def test_cross_tenant_ndtest_substitutes_channel_id_placeholder(tmp_path, monkeypatch):
    """`{channel_id}` is swapped for a seed-list channel_id."""
    monkeypatch.setenv("WS1_TOKEN", "tok-A")
    monkeypatch.setenv("WS2_TOKEN", "tok-B")
    creds = [
        {"name": "ws1", "method": "bearer", "token_env": "WS1_TOKEN"},
        {"name": "ws2", "method": "bearer", "token_env": "WS2_TOKEN"},
    ]
    captured_urls: list[str] = []

    def handler(url, headers):
        if "Bearer tok-A" in headers.get("Authorization", ""):
            if "auth.test" in url:
                return _FakeResp(200, body=json.dumps({
                    "ok": True, "team_id": "TXX", "user_id": "UA",
                }))
            if "conversations.list" in url:
                return _FakeResp(200, body=json.dumps({
                    "ok": True, "channels": [{"id": "CHVICTIM01"}],
                }))
            if "users.list" in url:
                return _FakeResp(200, body=json.dumps({
                    "ok": True, "members": [],
                }))
        if "Bearer tok-B" in headers.get("Authorization", ""):
            captured_urls.append(url)
            # Cred B successfully reads CHVICTIM01 (cross-tenant leak).
            return _FakeResp(200, body=json.dumps({
                "ok": True, "channel": {"id": "CHVICTIM01"},
            }))
        return _FakeResp(404, body="{}")

    _install_fake_get(monkeypatch, handler)

    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        queue_entry={
            "ID": "IDOR-SEED-CHAN",
            "vulnerability_type": "Cross-workspace IDOR",
            "source_endpoint": "GET /api/conversations.info?channel={channel_id}",
        },
    )
    result = asyncio.run(idor_v.verify(ctx))
    assert any("CHVICTIM01" in u for u in captured_urls), \
        f"expected substituted channel_id in probe URL, got {captured_urls!r}"
    assert result.state is EvidenceState.LIVE_CONFIRMED


def test_cross_tenant_ndtest_file_id_placeholder_falls_back_to_manual(
        tmp_path, monkeypatch):
    """Hypothesis needs {file_id} but cred A has no files:read scope →
    verifier should return MANUAL_VERIFICATION_REQUIRED with a clear msg
    about the missing scope, NOT crash and NOT fire a useless probe."""
    monkeypatch.setenv("WS1_TOKEN", "tok-A")
    monkeypatch.setenv("WS2_TOKEN", "tok-B")
    creds = [
        {"name": "ws1", "method": "bearer", "token_env": "WS1_TOKEN"},
        {"name": "ws2", "method": "bearer", "token_env": "WS2_TOKEN"},
    ]
    cred_b_calls: list[str] = []

    def handler(url, headers):
        if "Bearer tok-A" in headers.get("Authorization", ""):
            if "auth.test" in url:
                return _FakeResp(200, body=json.dumps({
                    "ok": True, "team_id": "TXX", "user_id": "UA",
                }))
            # No files:read scope → conversations/users do return data,
            # but the hypothesis needs file_id specifically.
            if "conversations.list" in url:
                return _FakeResp(200, body=json.dumps({
                    "ok": True, "channels": [{"id": "CXX"}],
                }))
            if "users.list" in url:
                return _FakeResp(200, body=json.dumps({
                    "ok": True, "members": [{"id": "UXX"}],
                }))
        if "Bearer tok-B" in headers.get("Authorization", ""):
            cred_b_calls.append(url)
        return _FakeResp(404, body="{}")

    _install_fake_get(monkeypatch, handler)

    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        queue_entry={
            "ID": "IDOR-SEED-FILE",
            "vulnerability_type": "Cross-workspace IDOR",
            "source_endpoint": "GET /api/files.info?file={file_id}",
        },
    )
    result = asyncio.run(idor_v.verify(ctx))
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED
    # No probe fired against cred B because we have no file_id to inject.
    assert cred_b_calls == [], \
        f"verifier shouldn't probe without a file_id, but called {cred_b_calls!r}"
    # Summary is operator-actionable.
    msg = result.summary.lower()
    assert "file" in msg
    assert "scope" in msg or "files:read" in msg


# ---------- back-compat: no placeholders still works ----------------------


def test_cross_tenant_ndtest_no_placeholders_back_compat(tmp_path, monkeypatch):
    """Suspect URL with no `{...}` placeholders still runs the old scrape
    path (call as A → pull ID from body → probe as B)."""
    monkeypatch.setenv("WS1_TOKEN", "tok-A")
    monkeypatch.setenv("WS2_TOKEN", "tok-B")
    creds = [
        {"name": "ws1", "method": "bearer", "token_env": "WS1_TOKEN"},
        {"name": "ws2", "method": "bearer", "token_env": "WS2_TOKEN"},
    ]

    def handler(url, headers):
        # Seed calls return reasonable data so we exercise BOTH paths.
        if "auth.test" in url:
            return _FakeResp(200, body=json.dumps({
                "ok": True, "team_id": "T", "user_id": "U",
            }))
        if "conversations.list" in url or "users.list" in url:
            return _FakeResp(200, body=json.dumps({"ok": True, "channels": [],
                                                    "members": []}))
        # The actual cross-tenant probe.
        if "Bearer tok-A" in headers.get("Authorization", ""):
            return _FakeResp(200, body='{"channels":[{"id":"CABCDEFG12"}]}')
        if "Bearer tok-B" in headers.get("Authorization", ""):
            assert "CABCDEFG12" in url
            return _FakeResp(200, body='{"channel":{"id":"CABCDEFG12"}}')
        return _FakeResp(404)

    _install_fake_get(monkeypatch, handler)

    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        queue_entry={
            "ID": "IDOR-SEED-BACKCOMPAT",
            "vulnerability_type": "Cross-workspace IDOR",
            "source_endpoint": "GET /api/conversations/CXXXX1234",
        },
    )
    result = asyncio.run(idor_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_CONFIRMED
