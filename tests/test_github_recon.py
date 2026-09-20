"""Tests for the GitHub-recon passive intel module (2026-XX-XX)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from sentinel.agent import github_recon as gr


# ---------------------------------------------------------------------------
# derive_org_candidates
# ---------------------------------------------------------------------------

def test_derive_apex_from_url():
    assert gr.derive_org_candidates("https://api.coupang.com") == ["coupang"]
    assert gr.derive_org_candidates("https://www.ExampleMarket.com") == ["ExampleMarket"]
    assert gr.derive_org_candidates("https://staging.api.acme.io") == ["acme"]


def test_derive_hyphen_variant():
    """`acme-corp.com` → both `acme-corp` and `acmecorp` (orgs use either)."""
    cands = gr.derive_org_candidates("https://api.acme-corp.com")
    assert cands[0] == "acme-corp"
    assert "acmecorp" in cands


def test_derive_strips_common_subdomains():
    for sub in ("api", "app", "auth", "staging", "dev", "admin", "secure"):
        assert gr.derive_org_candidates(f"https://{sub}.example.com") == ["example"]


def test_derive_empty_or_invalid_returns_empty():
    assert gr.derive_org_candidates("") == []
    # Bare hyphenated string is treated as a host; both hyphen + no-hyphen
    # variants are returned (orgs use either convention).
    assert gr.derive_org_candidates("not-a-url") == ["not-a-url", "notaurl"]


# ---------------------------------------------------------------------------
# enumerate_org_repos (mocked GitHub API)
# ---------------------------------------------------------------------------

def _mock_response(status, json_body=None):
    m = mock.MagicMock()
    m.status_code = status
    m.json = lambda: (json_body if json_body is not None else [])
    return m


def test_enumerate_returns_repos_on_200():
    fake_repos = [
        {"name": "api", "full_name": "acme/api", "html_url": "https://github.com/acme/api",
         "description": "x", "stargazers_count": 42, "archived": False,
         "pushed_at": "2026-XX-XXT00:00:00Z"},
        {"name": "old", "full_name": "acme/old", "html_url": "https://github.com/acme/old",
         "description": "y", "stargazers_count": 1, "archived": True,
         "pushed_at": "2020-01-01T00:00:00Z"},
    ]
    with mock.patch("httpx.Client") as MC:
        MC.return_value.__enter__.return_value.get.side_effect = [
            _mock_response(200, fake_repos),
        ]
        out = gr.enumerate_org_repos("acme")
    assert len(out) == 2
    # archived sorts last
    assert out[-1]["name"] == "old"
    assert out[0]["name"] == "api"
    assert out[0]["stars"] == 42


def test_enumerate_404_returns_empty():
    with mock.patch("httpx.Client") as MC:
        MC.return_value.__enter__.return_value.get.side_effect = [
            _mock_response(404), _mock_response(404),
        ]
        assert gr.enumerate_org_repos("does-not-exist") == []


def test_enumerate_falls_back_to_users_on_404():
    """If /orgs/X 404s, try /users/X (personal account)."""
    fake = [{"name": "personal", "full_name": "alice/personal",
             "html_url": "https://github.com/alice/personal", "description": "",
             "stargazers_count": 0, "archived": False, "pushed_at": ""}]
    with mock.patch("httpx.Client") as MC:
        MC.return_value.__enter__.return_value.get.side_effect = [
            _mock_response(404),       # /orgs/alice
            _mock_response(200, fake), # /users/alice
        ]
        out = gr.enumerate_org_repos("alice")
    assert len(out) == 1
    assert out[0]["full_name"] == "alice/personal"


def test_enumerate_rate_limit_returns_what_it_has():
    with mock.patch("httpx.Client") as MC:
        MC.return_value.__enter__.return_value.get.side_effect = [_mock_response(403)]
        assert gr.enumerate_org_repos("acme") == []


# ---------------------------------------------------------------------------
# trufflehog wrapper (mocked subprocess)
# ---------------------------------------------------------------------------

def test_trufflehog_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(gr.shutil, "which", lambda _: None)
    r = gr.run_trufflehog_org("acme", tmp_path)
    assert r["available"] is False
    assert r["ok"] is False
    assert "not on PATH" in r["error"]


def test_trufflehog_parses_jsonl(tmp_path, monkeypatch):
    monkeypatch.setattr(gr.shutil, "which", lambda name: "/usr/bin/trufflehog")
    sample = {
        "DetectorName": "AWS",
        "Verified": True,
        "Raw": "AKIAEXAMPLEKEY1234567",
        "SourceMetadata": {"Data": {"Github": {
            "repository": "acme/api", "file": "config/prod.env",
            "line": 42, "commit": "abc123def456",
        }}},
    }
    def fake_run(cmd, stdout, stderr, env, timeout, check):
        # Simulate trufflehog writing JSONL to its stdout (= our raw_path).
        stdout.write((json.dumps(sample) + "\n").encode())
        m = mock.MagicMock(); m.returncode = 0; m.stderr = b""
        return m
    monkeypatch.setattr(gr.subprocess, "run", fake_run)
    r = gr.run_trufflehog_org("acme", tmp_path)
    assert r["available"] and r["ok"]
    assert len(r["findings"]) == 1
    f = r["findings"][0]
    assert f["detector"] == "AWS"
    assert f["repo"] == "acme/api"
    assert f["verified"] is True
    assert "AKIA" in f["secret_excerpt"]


def test_trufflehog_timeout_degrades_cleanly(tmp_path, monkeypatch):
    monkeypatch.setattr(gr.shutil, "which", lambda name: "/usr/bin/trufflehog")
    def fake_run(*a, **kw):
        raise gr.subprocess.TimeoutExpired(cmd="trufflehog", timeout=1)
    monkeypatch.setattr(gr.subprocess, "run", fake_run)
    r = gr.run_trufflehog_org("acme", tmp_path, timeout_sec=1)
    assert r["available"] and not r["ok"]
    assert "timed out" in r["error"]


# ---------------------------------------------------------------------------
# briefing synthesis (pure)
# ---------------------------------------------------------------------------

def test_briefing_includes_orgs_repos_findings(tmp_path):
    scan = {
        "orgs_scanned": ["acme"],
        "repos": [{"name": "api", "full_name": "acme/api",
                   "url": "https://github.com/acme/api",
                   "stars": 100, "archived": False, "pushed_at": "2026-XX-XXT00:00:00Z"}],
        "trufflehog": {
            "available": True, "ok": True,
            "findings": [
                {"detector": "AWS", "repo": "acme/api", "file": "config.env",
                 "line": 12, "commit": "abc12345", "verified": True,
                 "secret_excerpt": "AKIA..."},
                {"detector": "ExampleChat", "repo": "acme/web", "file": "ExampleChat.ts",
                 "line": 7, "commit": "def67890", "verified": False,
                 "secret_excerpt": "xoxb-..."},
            ],
        },
    }
    p = gr.synthesize_github_briefing(scan, "https://acme.com", tmp_path)
    md = p.read_text()
    assert "GitHub Recon Briefing" in md
    assert "Orgs scanned: acme" in md
    assert "acme/api" in md
    assert "AWS" in md and "AKIA" in md
    assert "VERIFIED live" in md  # the verified-section header
    assert "Manual hunting checklist" in md


def test_briefing_handles_missing_trufflehog(tmp_path):
    scan = {"orgs_scanned": ["acme"], "repos": [],
            "trufflehog": {"available": False, "ok": False, "findings": [],
                           "error": "trufflehog not on PATH"}}
    md = gr.synthesize_github_briefing(scan, "https://acme.com", tmp_path).read_text()
    assert "trufflehog: NOT INSTALLED" in md
    assert "brew install trufflehog" in md


def test_briefing_zero_findings_says_so(tmp_path):
    scan = {"orgs_scanned": ["acme"], "repos": [],
            "trufflehog": {"available": True, "ok": True, "findings": []}}
    md = gr.synthesize_github_briefing(scan, "https://acme.com", tmp_path).read_text()
    assert "0 findings" in md
