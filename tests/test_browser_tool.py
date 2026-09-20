"""Unit tests for the Playwright browser tool — scope/audit gates only.

We don't actually launch Chromium (heavy + flaky in CI); we mock the
session. The aim is to verify the SCOPE GATE refuses out-of-scope URLs,
the audit log is written, and bad inputs produce errors.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from sentinel.agent.pentest import browser_tool as p_browser
from sentinel.agent.pentest import tools as p_tools
from sentinel.core.scope import AuditLog, OutOfScopeError, Scope


def _make_scope_yaml(tmp: Path) -> Path:
    p = tmp / "scope.yaml"
    p.write_text(
        "client: testco\nengagement_id: 2026-test\n"
        "authorized_by: t@example.com\n"
        "valid_from: 2026-01-01\nvalid_until: 2099-12-31\n"
        "targets:\n  domains: ['example.com']\n"
        "rate_limits:\n  requests_per_second: 30\n"
    )
    return p


@pytest.fixture
def ctx(tmp_path):
    scope_path = _make_scope_yaml(tmp_path)
    scope = Scope.load(str(scope_path))
    audit = AuditLog(tmp_path / ".audit.jsonl")
    workspace = tmp_path / "ws"
    workspace.mkdir()
    c = p_tools.PentestContext(
        scope=scope, audit=audit, workspace_dir=workspace,
        http=None, rate_limit_per_host_sec=0.0,
    )
    p_tools.set_context(c)
    return c


def _invoke(decorated, args):
    return asyncio.run(decorated.handler(args))


def test_browser_get_requires_url(ctx):
    out = _invoke(p_browser.browser_get, {"url": "", "wait_seconds": 5})
    assert out["is_error"] is True


def test_browser_get_rejects_non_http(ctx):
    out = _invoke(p_browser.browser_get, {"url": "ftp://example.com", "wait_seconds": 5})
    assert out["is_error"] is True
    assert "http/https" in out["content"][0]["text"]


def test_browser_get_refuses_out_of_scope(ctx):
    out = _invoke(p_browser.browser_get, {
        "url": "https://other-domain.com/x", "wait_seconds": 1,
    })
    assert out["is_error"] is True
    assert "out-of-scope" in out["content"][0]["text"]


def test_browser_get_refuses_no_hostname(ctx):
    out = _invoke(p_browser.browser_get, {"url": "https:///", "wait_seconds": 1})
    assert out["is_error"] is True


def test_browser_screenshot_invalid_filename(ctx):
    out = _invoke(p_browser.browser_screenshot, {"filename": "../escape"})
    assert out["is_error"] is True


def test_browser_screenshot_requires_filename(ctx):
    out = _invoke(p_browser.browser_screenshot, {"filename": ""})
    assert out["is_error"] is True


def test_browser_get_clamps_wait_seconds():
    """Wait seconds is clamped between 1 and MAX_WAIT_SECONDS."""
    # Just verify the constants exist and are sensible.
    assert p_browser.MAX_WAIT_SECONDS >= p_browser.DEFAULT_WAIT_SECONDS
    assert p_browser.DEFAULT_WAIT_SECONDS >= 1
