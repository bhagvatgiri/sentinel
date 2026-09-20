"""Phase 2.5 — SSRF verifier non-destructive (OOB) mode test.

The SSRF verifier registers an OOB token, injects it into the suspect
URL parameter, fires one GET, and polls the OOB oracle for callbacks:
- callbacks received → live_confirmed
- no callbacks within window → live_disproven
- scope.oob_callbacks == "disabled" → manual_verification_required (back-compat)
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

import httpx
import pytest

from sentinel.agent.pentest.verifier_tool import VerificationContext
from sentinel.agent.pentest.verifiers import ssrf as ssrf_v
from sentinel.core.findings import EvidenceState


def _make_scope_mock(*, oob_callbacks=None, engagement_id="t-ndtest-ssrf"):
    scope = MagicMock()
    scope.authorize_url = MagicMock()
    scope.engagement_id = engagement_id
    scope.engagement_mode.value = "production"
    scope.oob_callbacks = oob_callbacks
    return scope


def _make_ctx(
    *, tmp_path: Path, scope=None, queue_entry=None,
    audit_writer=None, event_emit=None,
):
    return VerificationContext(
        scope=scope or _make_scope_mock(),
        target="https://example.com",
        workspace_dir=tmp_path,
        vuln_class="ssrf",
        queue_entry=queue_entry or {
            "ID": "SSRF-VULN-01",
            "vulnerability_type": "Blind SSRF via url param",
            "source_endpoint": "GET /api/fetch?url=https%3A%2F%2Fdefault.example.com",
        },
        entry_id="SSRF-VULN-01",
        evidence_dir=tmp_path / "evidence",
        auth_credentials=[],
        auth_cookies=[],
        research_headers={"User-Agent": "sentinel-test"},
        audit_writer=audit_writer,
        event_emit=event_emit,
    )


class _FakeSession:
    """Stand-in for oob_tool._OobSession; deterministic register + poll."""

    def __init__(self, callbacks=None, token="abcd1234"):
        self.token = token
        self._callbacks = callbacks or []
        self.collect_calls = 0

    async def register_token(self, purpose: str) -> str:
        return self.token

    def full_url_for(self, token: str) -> str:
        return f"{token}.oast.example.invalid"

    async def collect_callbacks(self, token: str, wait_seconds: int) -> list[dict]:
        self.collect_calls += 1
        # First call returns the callbacks (or empty); subsequent calls = []
        if self.collect_calls == 1:
            return list(self._callbacks)
        return []


def _patch_oob(monkeypatch, fake_session):
    """Patch oob_tool._get_session_for_job to return fake_session."""
    from sentinel.agent.pentest import oob_tool

    async def fake_get(job_id):
        return fake_session

    monkeypatch.setattr(oob_tool, "_get_session_for_job", fake_get)


def _patch_httpx_noop(monkeypatch):
    """Patch httpx.AsyncClient.get to a no-op (the verifier doesn't need
    the response — it's just triggering the SSRF)."""

    async def fake_get(self, url, headers=None):
        class R:
            status_code = 200
            text = ""
            headers: dict = {}
        return R()

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)


# ---- live_confirmed: OOB callback received -------------------------------


def test_ssrf_ndtest_confirmed_on_callback(tmp_path, monkeypatch):
    audit = MagicMock()
    events: list[tuple] = []
    fake = _FakeSession(
        callbacks=[{"protocol": "http", "src_ip": "10.0.0.1",
                    "ts": "2026-XX-XXT03:00:00Z", "data": "GET /probe HTTP/1.1"}],
    )
    _patch_oob(monkeypatch, fake)
    _patch_httpx_noop(monkeypatch)

    ctx = _make_ctx(
        tmp_path=tmp_path, audit_writer=audit,
        event_emit=lambda k, **p: events.append((k, p)),
    )
    result = asyncio.run(ssrf_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_CONFIRMED, \
        f"expected LIVE_CONFIRMED, got {result.state}: {result.summary}"
    assert "SSRF confirmed" in result.summary
    assert result.evidence["oob_token"] == "abcd1234"
    kinds = [k for k, _ in events]
    assert "verifier_ndtest_attempted" in kinds
    assert "verifier_ndtest_confirmed" in kinds


# ---- live_disproven: no callback within window ---------------------------


def test_ssrf_ndtest_disproven_when_no_callback(tmp_path, monkeypatch):
    audit = MagicMock()
    events: list[tuple] = []
    fake = _FakeSession(callbacks=[])
    _patch_oob(monkeypatch, fake)
    _patch_httpx_noop(monkeypatch)
    # Speed up poll window so the test is fast.
    monkeypatch.setattr(ssrf_v, "_POLL_WINDOW_SEC", 0.1)
    monkeypatch.setattr(ssrf_v, "_POLL_INTERVAL_SEC", 0.05)

    ctx = _make_ctx(
        tmp_path=tmp_path, audit_writer=audit,
        event_emit=lambda k, **p: events.append((k, p)),
    )
    result = asyncio.run(ssrf_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_DISPROVEN
    assert "does not reproduce" in result.summary
    kinds = [k for k, _ in events]
    assert "verifier_ndtest_disproven" in kinds


# ---- back-compat: scope.oob_callbacks=='disabled' → manual ---------------


def test_ssrf_disabled_oob_returns_manual(tmp_path, monkeypatch):
    scope = _make_scope_mock(oob_callbacks="disabled")
    ctx = _make_ctx(tmp_path=tmp_path, scope=scope)
    result = asyncio.run(ssrf_v.verify(ctx))
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "OOB probing not allowed" in result.summary


def test_ssrf_no_source_endpoint_returns_manual(tmp_path):
    ctx = _make_ctx(
        tmp_path=tmp_path,
        queue_entry={"ID": "SSRF-VULN-02", "vulnerability_type": "Blind SSRF"},
    )
    result = asyncio.run(ssrf_v.verify(ctx))
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED


def test_ssrf_token_registration_failure_returns_error(tmp_path, monkeypatch):
    """If the OOB subprocess is dead, surface as VERIFICATION_ERROR."""
    from sentinel.agent.pentest import oob_tool

    class DeadSession:
        async def register_token(self, purpose):
            raise RuntimeError("interactsh-client subprocess exited")

        def full_url_for(self, token):
            return f"{token}.oast.example.invalid"

        async def collect_callbacks(self, token, wait_seconds):
            return []

    async def fake_get(job_id):
        return DeadSession()

    monkeypatch.setattr(oob_tool, "_get_session_for_job", fake_get)

    ctx = _make_ctx(tmp_path=tmp_path)
    result = asyncio.run(ssrf_v.verify(ctx))
    assert result.state is EvidenceState.VERIFICATION_ERROR
    assert "OOB token registration failed" in result.summary
