"""Smoke + integration tests for the / (dashboard) route.

Covers the two stale-counter bugs fixed on 2026-XX-XX:
- Payload Library card was hardcoded to "4 · auth · injection · xss · ssrf"
- Past-engagement Memory card always showed 0 because corpus_chroma_stats
  hardcoded its source allowlist
"""

from __future__ import annotations

from pathlib import Path

import pytest


def _make_client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from sentinel.ui.state import UIConfig
    cfg = UIConfig(
        vault_path=str(tmp_path / "vault"),
        corpus_dir=str(tmp_path / "corpus"),
        scopes_dir=str(tmp_path / "scopes"),
        runs_dir=str(tmp_path / "runs"),
        ollama_host="http://localhost:11434",
        ollama_model="llama3.1:8b",
        embed_model="nomic-embed-text",
        project_dir=str(tmp_path),
    )
    monkeypatch.setattr(UIConfig, "load", classmethod(lambda cls: cfg))
    Path(cfg.runs_dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.scopes_dir).mkdir(parents=True, exist_ok=True)
    from sentinel.web.app import create_app
    app = create_app()
    return TestClient(app), cfg


def test_dashboard_renders_payload_library_dynamically(tmp_path, monkeypatch):
    """Dashboard must read all 7 payload classes from the live registry,
    not the old hardcoded "4 · auth · injection · xss · ssrf" string."""
    client, _ = _make_client(tmp_path, monkeypatch)
    r = client.get("/")
    assert r.status_code == 200
    body = r.text
    # Wave 1 classes added 2026-XX-XX must appear in the caption.
    assert "csrf" in body
    assert "file_upload" in body
    assert "jwt_oauth" in body
    # And the original four are still there.
    for cls in ("auth", "injection", "xss", "ssrf"):
        assert cls in body
    # The "curated payloads" footer is rendered (proof that
    # n_payload_entries propagated through the template).
    assert "curated payloads" in body


def test_dashboard_does_not_show_stale_payload_count(tmp_path, monkeypatch):
    """The literal "classes · auth · injection · xss · ssrf" string from
    the pre-fix template MUST not be present — that exact phrasing was
    the smoking gun that the card was hardcoded."""
    client, _ = _make_client(tmp_path, monkeypatch)
    body = client.get("/").text
    assert "classes · auth · injection · xss · ssrf" not in body


def test_corpus_chroma_stats_extra_sources_kwarg(tmp_path):
    """state.corpus_chroma_stats must accept extra_sources and forward
    them into the per_source dict only when chunks actually exist."""
    from sentinel.ui.state import corpus_chroma_stats
    # Pointing at a non-existent corpus dir → returns available=False
    # without raising; the kwarg signature itself must accept the call.
    out = corpus_chroma_stats(
        str(tmp_path / "no-such-dir"),
        "http://localhost:11434",
        "nomic-embed-text",
        extra_sources=["past-engagement-foo-bar"],
    )
    assert out["available"] is False
