"""Regression test for UI parity gap (2026-XX-XX): /signup-pending route
existed but had no link in the main nav, so operators couldn't navigate to
it without typing the URL. The base.html nav block must include the link.
"""

from __future__ import annotations

from pathlib import Path


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


def test_signup_pending_link_in_main_nav(tmp_path, monkeypatch):
    """Dashboard (/) must include an <a href="/signup-pending"> link in the
    main nav so operators can reach the human-in-the-loop signup queue."""
    client, _ = _make_client(tmp_path, monkeypatch)
    body = client.get("/").text
    assert 'href="/signup-pending"' in body, (
        "Expected /signup-pending link in main nav, but it was missing. "
        "The base.html nav must include it so operators can reach the "
        "pending-signup queue without typing the URL."
    )
