"""Phase 2.5 — CSRF verifier non-destructive (reversible-action) mode.

When bearer cred + reversible-action hint (star/pin/bookmark/post-message
/toggle-preference) + suspect URL are all present, the verifier sends
a cross-origin POST and ALWAYS rolls back. live_confirmed only fires
when both the cross-origin POST succeeds AND the rollback succeeds.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from sentinel.agent.pentest.verifier_tool import VerificationContext
from sentinel.agent.pentest.verifiers import csrf as csrf_v
from sentinel.core.findings import EvidenceState


def _make_scope_mock():
    scope = MagicMock()
    scope.authorize_url = MagicMock()
    scope.engagement_id = "test-ndtest-csrf"
    scope.engagement_mode.value = "production"
    return scope


def _make_ctx(*, tmp_path: Path, auth_credentials, queue_entry=None,
              audit_writer=None, event_emit=None):
    return VerificationContext(
        scope=_make_scope_mock(),
        target="https://example.com",
        workspace_dir=tmp_path,
        vuln_class="csrf",
        queue_entry=queue_entry or {
            "ID": "CSRF-VULN-01",
            "vulnerability_type": "CSRF on star action",
            "exploitation_hypothesis": "attacker can star a message via CSRF",
            "source_endpoint": "POST /api/star/MSG123",
            "missing_defense": "no origin-check",
            "notes": "reversible star action",
        },
        entry_id="CSRF-VULN-01",
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


# ---- live_confirmed: do succeeds + rollback succeeds ---------------------


def test_csrf_ndtest_confirmed_when_do_and_undo_succeed(tmp_path, monkeypatch):
    monkeypatch.setenv("X_TOKEN", "tok")
    creds = [{"name": "u1", "method": "bearer", "token_env": "X_TOKEN"}]
    audit = MagicMock()
    events: list[tuple] = []

    posts = []

    def handler(url, data, headers):
        posts.append((url, headers.get("Origin"), headers.get("Authorization")))
        return _FakeResp(200, body='{"ok":true}',
                          headers={"content-type": "application/json"})

    _patch_post(monkeypatch, handler)

    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds, audit_writer=audit,
        event_emit=lambda k, **p: events.append((k, p)),
    )
    result = asyncio.run(csrf_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_CONFIRMED, \
        f"expected LIVE_CONFIRMED, got {result.state}: {result.summary}"
    # 2 posts: do (Origin attacker) + undo (Origin target).
    assert len(posts) == 2
    do_url, do_origin, do_auth = posts[0]
    undo_url, undo_origin, undo_auth = posts[1]
    assert "star" in do_url
    assert "unstar" in undo_url, f"undo url should swap star→unstar; got {undo_url}"
    assert do_origin == "https://attacker.example.com"
    assert undo_origin == "https://example.com"
    assert "Bearer tok" in (do_auth or "")
    kinds = [k for k, _ in events]
    assert "verifier_ndtest_attempted" in kinds
    assert "verifier_ndtest_confirmed" in kinds


# ---- live_disproven: 403 on cross-origin POST ---------------------------


def test_csrf_ndtest_disproven_on_4xx(tmp_path, monkeypatch):
    monkeypatch.setenv("X_TOKEN", "tok")
    creds = [{"name": "u1", "method": "bearer", "token_env": "X_TOKEN"}]
    events: list[tuple] = []

    def handler(url, data, headers):
        if "unstar" in url:
            return _FakeResp(200, body='{"ok":true}')
        return _FakeResp(403, body='{"error":"origin not allowed"}')

    _patch_post(monkeypatch, handler)

    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        event_emit=lambda k, **p: events.append((k, p)),
    )
    result = asyncio.run(csrf_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_DISPROVEN
    assert "defense holds" in result.summary.lower()


# ---- rollback failure → MANUAL (don't claim confirmed) ------------------


def test_csrf_ndtest_rollback_failure_returns_manual(tmp_path, monkeypatch):
    """If the do succeeded but the undo failed, the verifier must NOT
    claim live_confirmed — it can't prove the action is reversible."""
    monkeypatch.setenv("X_TOKEN", "tok")
    creds = [{"name": "u1", "method": "bearer", "token_env": "X_TOKEN"}]

    def handler(url, data, headers):
        if "unstar" in url:
            return _FakeResp(500, body='{"error":"undo failed"}')
        return _FakeResp(200, body='{"ok":true}')

    _patch_post(monkeypatch, handler)

    ctx = _make_ctx(tmp_path=tmp_path, auth_credentials=creds)
    result = asyncio.run(csrf_v.verify(ctx))
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "rollback" in result.summary.lower()


# ---- back-compat: destructive hint → MANUAL even with creds -------------


def test_csrf_destructive_endpoint_still_manual_even_with_bearer(tmp_path):
    creds = [{"name": "u1", "method": "bearer", "token_env": "X"}]
    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        queue_entry={
            "ID": "CSRF-VULN-02",
            "vulnerability_type": "CSRF on cancel-membership",
            "exploitation_hypothesis": "attacker can cancel-membership",
            "source_endpoint": "POST /account/cancel-membership",
        },
    )
    result = asyncio.run(csrf_v.verify(ctx))
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "Non-destructive policy" in result.summary or \
           "destructive" in result.summary.lower()


# ---- back-compat: no creds → REQUIRES_TEST_CREDENTIALS (unchanged) ------


def test_csrf_no_creds_no_cookies_still_demands_credentials(tmp_path):
    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=[],
        queue_entry={
            "ID": "CSRF-VULN-03",
            "vulnerability_type": "Generic CSRF",
            "exploitation_hypothesis": "generic claim, no specific hint",
            "source_endpoint": "POST /transfer",
        },
    )
    result = asyncio.run(csrf_v.verify(ctx))
    assert result.state is EvidenceState.REQUIRES_TEST_CREDENTIALS


# ---- back-compat: no reversible-action hint + bearer → MANUAL not LIVE --


def test_csrf_bearer_without_reversible_hint_returns_manual(tmp_path):
    """Bearer cred present but no reversible action keyword → MANUAL."""
    creds = [{"name": "u1", "method": "bearer", "token_env": "X"}]
    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        queue_entry={
            "ID": "CSRF-VULN-04",
            "vulnerability_type": "Generic CSRF",
            "exploitation_hypothesis": "no reversible-action keyword present",
            "source_endpoint": "POST /api/transfer",
            "notes": "(generic claim)",
        },
    )
    result = asyncio.run(csrf_v.verify(ctx))
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "reversible-action hint" in result.summary or \
           "Generic CSRF" in result.summary
