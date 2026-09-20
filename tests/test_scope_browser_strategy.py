"""Tests for browser_strategy / chrome_profile_dir / chrome_cdp_port scope fields.

Added 2026-XX-XX with the Real-Chrome-via-CDP DataDome bypass feature.
These fields gate whether the scan attaches to the operator's running
Chrome via CDP instead of spawning Playwright's bundled Chromium.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from sentinel.core.scope import Scope, ScopeError


def _scope_yaml(tmp_path: Path, **overrides) -> Path:
    today = date.today()
    data = {
        "client": "test-client",
        "engagement_id": "test-cdp-001",
        "authorized_by": "test@example.com",
        "valid_from": (today - timedelta(days=1)).isoformat(),
        "valid_until": (today + timedelta(days=30)).isoformat(),
        "targets": {
            "domains": ["example.com"],
        },
    }
    data.update(overrides)
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_browser_strategy_defaults_to_none(tmp_path: Path):
    """Unset browser_strategy → None (uses Playwright spawn path)."""
    scope = Scope.load(_scope_yaml(tmp_path))
    assert scope.browser_strategy is None
    assert scope.chrome_profile_dir is None
    assert scope.chrome_cdp_port == 9222


def test_browser_strategy_yaml_round_trip_cdp(tmp_path: Path):
    """browser_strategy=cdp + chrome_profile_dir + chrome_cdp_port load cleanly."""
    scope = Scope.load(_scope_yaml(
        tmp_path,
        browser_strategy="cdp",
        chrome_profile_dir="/tmp/chrome-profile",
        chrome_cdp_port=9333,
    ))
    assert scope.browser_strategy == "cdp"
    assert scope.chrome_profile_dir == "/tmp/chrome-profile"
    assert scope.chrome_cdp_port == 9333


def test_browser_strategy_cdp_port_defaults_when_omitted(tmp_path: Path):
    """browser_strategy=cdp without chrome_cdp_port → defaults to 9222."""
    scope = Scope.load(_scope_yaml(tmp_path, browser_strategy="cdp"))
    assert scope.browser_strategy == "cdp"
    assert scope.chrome_cdp_port == 9222


def test_browser_strategy_invalid_raises(tmp_path: Path):
    """Unknown browser_strategy values are rejected at load time."""
    with pytest.raises(ScopeError) as exc_info:
        Scope.load(_scope_yaml(tmp_path, browser_strategy="bogus_strategy"))
    assert "browser_strategy" in str(exc_info.value)
    assert "bogus_strategy" in str(exc_info.value)


def test_browser_strategy_normalizes_case(tmp_path: Path):
    """Case-insensitive — operator can write CDP, Cdp, cdp."""
    scope = Scope.load(_scope_yaml(tmp_path, browser_strategy="CDP"))
    assert scope.browser_strategy == "cdp"


def test_browser_strategy_playwright_spawn_explicit(tmp_path: Path):
    """Explicit playwright_spawn value loads as canonical string."""
    scope = Scope.load(_scope_yaml(tmp_path, browser_strategy="playwright_spawn"))
    assert scope.browser_strategy == "playwright_spawn"


def test_chrome_cdp_port_validation(tmp_path: Path):
    """Out-of-range port rejected."""
    with pytest.raises(ScopeError):
        Scope.load(_scope_yaml(tmp_path, chrome_cdp_port=99999))
    with pytest.raises(ScopeError):
        Scope.load(_scope_yaml(tmp_path, chrome_cdp_port=0))


def test_agent_browser_cdp_strategy_accepted(tmp_path: Path):
    """agent_browser_cdp is reserved-for-future-use but loads cleanly."""
    scope = Scope.load(_scope_yaml(tmp_path, browser_strategy="agent_browser_cdp"))
    assert scope.browser_strategy == "agent_browser_cdp"
