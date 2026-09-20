"""Smoke test for the /library FastAPI route."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _make_client(tmp_path, monkeypatch):
    """Spin up the FastAPI app pointing at a temp project_dir."""
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
    # The route calls deps.get_config() which calls UIConfig.load() — patch
    # both so whichever path FastAPI takes, it gets our cfg.
    monkeypatch.setattr(UIConfig, "load", classmethod(lambda cls: cfg))

    from sentinel.web.app import create_app
    app = create_app()
    return TestClient(app), cfg


def test_library_renders_when_catalog_missing(tmp_path, monkeypatch):
    client, cfg = _make_client(tmp_path, monkeypatch)
    r = client.get("/library")
    assert r.status_code == 200
    body = r.text
    assert "Library" in body
    assert "No catalog" in body or "extract-security-books-catalog" in body


def test_library_renders_with_catalog_and_progress(tmp_path, monkeypatch):
    lib = tmp_path / "library"
    lib.mkdir()
    (lib / "security-books-catalog.json").write_text(json.dumps({
        "source": "https://example/",
        "fetched_at": "2026-XX-XXT00:00:00Z",
        "n_entries": 2,
        "categories": {"Bug Hunting": 1, "Web Application Security": 1},
        "books": [
            {
                "title": "Test Book One",
                "author": "Alice",
                "category": "Bug Hunting",
                "expected_filename": "test_one.pdf",
                "notion_url": "https://example/notion/one",
                "page_id": "1111-2222-3333",
            },
            {
                "title": "Test Book Two",
                "author": "Bob",
                "category": "Web Application Security",
                "expected_filename": "test_two.pdf",
                "notion_url": "",
                "page_id": "",
            },
        ],
    }))
    (lib / "download-progress.json").write_text(json.dumps({
        "books": {
            "Bug Hunting/test_one.pdf": {
                "status": "downloaded",
                "size": 5242880,
                "path": "library/Bug Hunting/test_one.pdf",
                "sha256": "abc",
                "last_run": "2026-XX-XXT00:00:00Z",
            },
        },
        "runs": [{
            "started_at": "2026-XX-XXT00:00:00Z",
            "downloaded": 1, "skipped": 0, "failed": 0, "bytes": 5242880,
        }],
    }))
    (lib / "PERMISSION.txt").write_text("Authorization: granted by the operator 2026-XX-XX.")

    client, cfg = _make_client(tmp_path, monkeypatch)
    r = client.get("/library")
    assert r.status_code == 200
    body = r.text
    # Tile counts.
    assert "Test Book One" in body
    assert "Test Book Two" in body
    assert "5.0 MB" in body              # downloaded book size
    assert "Alice" in body and "Bob" in body
    # Status chips.
    assert "on disk" in body
    assert "missing" in body
    # Permission excerpt.
    assert "Authorization: granted by the operator" in body
    # Categories appear as section headers.
    assert "Bug Hunting" in body
    assert "Web Application Security" in body
