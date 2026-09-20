"""Phase 2.5 — file_upload verifier non-destructive (test PNG) mode.

When scope.auth_credentials has a bearer cred + the queue entry has an
upload endpoint URL, the verifier should:
- generate a real 1x1 PNG with payload in filename/EXIF/trailing bytes
- POST it via bearer auth to the upload endpoint
- flag live_confirmed on Content-Type mismatch / payload reflection /
  filename echo
- flag live_disproven on 4xx rejection
- fall back to manual_verification_required when bearer/endpoint missing
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from sentinel.agent.pentest.verifier_tool import VerificationContext
from sentinel.agent.pentest.verifiers import file_upload as fu_v
from sentinel.core.findings import EvidenceState


def _make_scope_mock():
    scope = MagicMock()
    scope.authorize_url = MagicMock()
    scope.engagement_id = "test-ndtest-fileupload"
    scope.engagement_mode.value = "production"
    return scope


def _make_ctx(*, tmp_path: Path, auth_credentials, queue_entry=None,
              audit_writer=None, event_emit=None):
    return VerificationContext(
        scope=_make_scope_mock(),
        target="https://example.com",
        workspace_dir=tmp_path,
        vuln_class="file_upload",
        queue_entry=queue_entry or {
            "ID": "UPLOAD-VULN-01",
            "vulnerability_type": "Unrestricted file upload — filename injection",
            "exploitation_hypothesis": "filename injected reflects in response",
            "source_endpoint": "POST /api/upload",
            "missing_defense": "filename not sanitized",
        },
        entry_id="UPLOAD-VULN-01",
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
    async def fake_post(self, url, *, files=None, headers=None):
        return handler(url, files, headers or {})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)


# ---- live_confirmed cases ------------------------------------------------


def test_file_upload_confirmed_on_filename_reflection(tmp_path, monkeypatch):
    """Server echoes the unsanitized filename back → filename-injection confirmed."""
    monkeypatch.setenv("X_TOKEN", "tok")
    creds = [{"name": "u1", "method": "bearer", "token_env": "X_TOKEN"}]
    audit = MagicMock()
    events: list[tuple] = []

    def handler(url, files, headers):
        # files: {"file": (filename, f, "image/png")}
        filename = files["file"][0]
        return _FakeResp(
            200,
            body=f'{{"status":"ok","stored":"{filename}"}}',
            headers={"content-type": "application/json"},
        )

    _patch_post(monkeypatch, handler)

    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        audit_writer=audit,
        event_emit=lambda k, **p: events.append((k, p)),
        queue_entry={
            "ID": "UPLOAD-VULN-01",
            "vulnerability_type": "filename injection",
            "exploitation_hypothesis": "<script> in filename echoes back",
            "source_endpoint": "POST /api/upload",
            "missing_defense": "filename not sanitized",
        },
    )
    result = asyncio.run(fu_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_CONFIRMED, \
        f"expected LIVE_CONFIRMED, got {result.state}: {result.summary}"
    assert "raw filename echoed" in result.summary or \
           "reflected" in result.summary
    kinds = [k for k, _ in events]
    assert "verifier_ndtest_attempted" in kinds
    assert "verifier_ndtest_confirmed" in kinds


def test_file_upload_confirmed_on_content_type_mismatch(tmp_path, monkeypatch):
    """Server returns the PNG with text/html → Content-Type confusion confirmed."""
    monkeypatch.setenv("X_TOKEN", "tok")
    creds = [{"name": "u1", "method": "bearer", "token_env": "X_TOKEN"}]

    def handler(url, files, headers):
        return _FakeResp(
            200, body="stored",
            headers={"content-type": "text/html"},
        )

    _patch_post(monkeypatch, handler)

    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        queue_entry={
            "ID": "UPLOAD-VULN-02",
            "vulnerability_type": "Content-Type mismatch",
            "exploitation_hypothesis": "polyglot PHP/JSP served as text/*",
            "source_endpoint": "POST /api/upload",
            "missing_defense": "mime-type not enforced",
        },
    )
    result = asyncio.run(fu_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_CONFIRMED
    assert "Content-Type" in result.summary


# ---- live_disproven case -------------------------------------------------


def test_file_upload_disproven_on_4xx(tmp_path, monkeypatch):
    """Server rejects the upload (400) → live_disproven."""
    monkeypatch.setenv("X_TOKEN", "tok")
    creds = [{"name": "u1", "method": "bearer", "token_env": "X_TOKEN"}]
    events: list[tuple] = []

    def handler(url, files, headers):
        return _FakeResp(400, body='{"error":"invalid filename"}',
                          headers={"content-type": "application/json"})

    _patch_post(monkeypatch, handler)

    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        event_emit=lambda k, **p: events.append((k, p)),
    )
    result = asyncio.run(fu_v.verify(ctx))
    assert result.state is EvidenceState.LIVE_DISPROVEN
    assert "rejected" in result.summary.lower()
    assert "verifier_ndtest_disproven" in [k for k, _ in events]


# ---- fallback cases ------------------------------------------------------


def test_file_upload_no_creds_falls_back_to_manual(tmp_path):
    """No bearer cred → MANUAL with the original message."""
    ctx = _make_ctx(tmp_path=tmp_path, auth_credentials=[])
    result = asyncio.run(fu_v.verify(ctx))
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "no bearer credentials" in result.summary


def test_file_upload_no_endpoint_falls_back_to_manual(tmp_path, monkeypatch):
    """Bearer cred present but no upload_endpoint → MANUAL."""
    monkeypatch.setenv("X_TOKEN", "tok")
    creds = [{"name": "u1", "method": "bearer", "token_env": "X_TOKEN"}]
    ctx = _make_ctx(
        tmp_path=tmp_path, auth_credentials=creds,
        queue_entry={
            "ID": "UPLOAD-VULN-03",
            "vulnerability_type": "(no endpoint)",
        },
    )
    result = asyncio.run(fu_v.verify(ctx))
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert "no upload-endpoint" in result.summary


# ---- helper: PNG builder sanity check ------------------------------------


def test_png_builder_produces_valid_signature():
    blob = fu_v._build_test_png(exif_comment="hello", trailing_bytes=b"<?php ?>")
    assert blob.startswith(fu_v._PNG_SIGNATURE)
    assert b"IHDR" in blob
    assert b"IEND" in blob
    # Trailing bytes preserved after IEND chunk.
    assert blob.endswith(b"<?php ?>")
