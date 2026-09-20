"""Tests for sentinel.agent.chrome_profile — Real-Chrome-via-CDP helpers.

Added 2026-XX-XX with the DataDome bypass feature. Tests cover the
non-network helpers (binary discovery, profile-dir resolution, port
defaults). Network-dependent helpers (attach_status, verify_session) are
mock-tested for the cold-port path; warm-port tests require a real
running Chrome and live in a separate manual integration test.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from sentinel.agent import chrome_profile


# ---- discover_chrome_binary -----------------------------------------------


def test_discover_chrome_binary_env_override(tmp_path: Path):
    """$SENTINEL_CHROME_BINARY wins when it points to an existing file."""
    fake_chrome = tmp_path / "fake-chrome"
    fake_chrome.write_text("#!/bin/sh\necho 'fake'\n")
    with patch.dict("os.environ", {"SENTINEL_CHROME_BINARY": str(fake_chrome)}):
        result = chrome_profile.discover_chrome_binary()
    assert result == str(fake_chrome)


def test_discover_chrome_binary_env_override_missing_raises(tmp_path: Path):
    """$SENTINEL_CHROME_BINARY pointing nowhere raises ChromeBinaryNotFound."""
    with patch.dict("os.environ", {"SENTINEL_CHROME_BINARY": str(tmp_path / "missing")}):
        with pytest.raises(chrome_profile.ChromeBinaryNotFound):
            chrome_profile.discover_chrome_binary()


def test_discover_chrome_binary_no_chrome_raises(monkeypatch):
    """Linux PATH search returns nothing → ChromeBinaryNotFound."""
    monkeypatch.delenv("SENTINEL_CHROME_BINARY", raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(chrome_profile.ChromeBinaryNotFound):
        chrome_profile.discover_chrome_binary()


# ---- resolve_profile_dir / resolve_cdp_port -------------------------------


def test_resolve_profile_dir_uses_scope_field(tmp_path: Path):
    """When scope.chrome_profile_dir is set, it wins (with ~ expansion)."""
    scope = SimpleNamespace(
        chrome_profile_dir=str(tmp_path / "custom-profile"),
        engagement_id="ignored",
    )
    result = chrome_profile.resolve_profile_dir(scope)
    assert result == (tmp_path / "custom-profile").resolve()


def test_resolve_profile_dir_fallback_uses_engagement_id():
    """Unset chrome_profile_dir → ~/.sentinel/chrome-profiles/<engagement_id>."""
    scope = SimpleNamespace(
        chrome_profile_dir=None,
        engagement_id="my-eng-2026-XX-XX",
    )
    result = chrome_profile.resolve_profile_dir(scope)
    assert "my-eng-2026-XX-XX" in str(result)
    assert ".sentinel" in str(result) or "chrome-profiles" in str(result)


def test_resolve_cdp_port_default():
    """Unset / falsy chrome_cdp_port → 9222."""
    scope = SimpleNamespace(chrome_cdp_port=None)
    assert chrome_profile.resolve_cdp_port(scope) == 9222
    scope = SimpleNamespace(chrome_cdp_port=0)
    assert chrome_profile.resolve_cdp_port(scope) == 9222


def test_resolve_cdp_port_explicit():
    """Explicit port wins."""
    scope = SimpleNamespace(chrome_cdp_port=9444)
    assert chrome_profile.resolve_cdp_port(scope) == 9444


# ---- attach_status (cold-port path; warm-port is integration) -------------


def test_attach_status_cold_port_returns_none():
    """Probe a port that's almost certainly not bound → None, no exception."""
    # Pick a high port unlikely to be in use (and we don't bind anything).
    result = chrome_profile.attach_status(cdp_port=58721)
    assert result is None


def test_attach_status_swallows_url_errors(monkeypatch):
    """URLError / OSError / TimeoutError all return None (operator-facing CLI uses as poll)."""
    import urllib.error
    def _raise(*args, **kwargs):
        raise urllib.error.URLError("simulated cold port")
    monkeypatch.setattr("urllib.request.urlopen", _raise)
    assert chrome_profile.attach_status(cdp_port=9222) is None


# ---- acquire_browser branch logic (mocked) --------------------------------


def test_acquire_browser_cdp_path_calls_connect_over_cdp(monkeypatch):
    """scope.browser_strategy=cdp + warm port → connect_over_cdp + contexts[0]."""
    scope = SimpleNamespace(
        browser_strategy="cdp",
        chrome_cdp_port=9222,
        engagement_id="test",
    )

    # Mock attach_status to return a "warm" version dict.
    monkeypatch.setattr(
        chrome_profile, "attach_status",
        lambda port: {"Browser": "Chrome/130.0.0.0"},
    )

    fake_context = object()
    fake_browser = SimpleNamespace(contexts=[fake_context])

    class FakeChromium:
        async def connect_over_cdp(self, url):
            assert "9222" in url
            return fake_browser

    fake_pw = SimpleNamespace(chromium=FakeChromium())

    browser, context, owns = asyncio.run(chrome_profile.acquire_browser(scope, fake_pw))

    assert browser is fake_browser
    assert context is fake_context
    assert owns is False  # caller does NOT own operator's Chrome


def test_acquire_browser_cdp_path_cold_port_raises(monkeypatch):
    """scope.browser_strategy=cdp + cold port → RuntimeError with operator hint."""
    scope = SimpleNamespace(
        browser_strategy="cdp",
        chrome_cdp_port=9222,
        engagement_id="test",
    )
    monkeypatch.setattr(chrome_profile, "attach_status", lambda port: None)
    fake_pw = SimpleNamespace(chromium=SimpleNamespace())
    with pytest.raises(RuntimeError) as exc_info:
        asyncio.run(chrome_profile.acquire_browser(scope, fake_pw))
    assert "bootstrap" in str(exc_info.value).lower()


def test_snapshot_cookies_cold_port_returns_empty(monkeypatch):
    """No Chrome listening → snapshot returns empty list, not exception."""
    monkeypatch.setattr(chrome_profile, "attach_status", lambda port: None)
    result = chrome_profile.snapshot_cookies(cdp_port=58721)
    assert result == []


def test_snapshot_cookies_async_no_contexts_returns_empty(monkeypatch):
    """Chrome warm but no contexts → empty list."""
    monkeypatch.setattr(
        chrome_profile, "attach_status",
        lambda port: {"Browser": "Chrome/148"},
    )
    monkeypatch.setattr(chrome_profile, "ensure_target", lambda port: True)

    # Mock async_playwright to return a browser with no contexts.
    class FakeBrowser:
        def __init__(self):
            self.contexts = []

    class FakeChromium:
        async def connect_over_cdp(self, url):
            return FakeBrowser()

    class FakePW:
        def __init__(self):
            self.chromium = FakeChromium()

    class FakePlaywrightCM:
        async def __aenter__(self):
            return FakePW()
        async def __aexit__(self, *args):
            pass

    def fake_async_playwright():
        return FakePlaywrightCM()

    import playwright.async_api as _pw_async
    monkeypatch.setattr(_pw_async, "async_playwright", fake_async_playwright)

    result = chrome_profile.snapshot_cookies(cdp_port=9222)
    assert result == []


def test_snapshot_cookies_normalizes_playwright_format(monkeypatch):
    """Cookies returned by Playwright get normalized to scope.auth_cookies shape."""
    monkeypatch.setattr(
        chrome_profile, "attach_status",
        lambda port: {"Browser": "Chrome/148"},
    )
    monkeypatch.setattr(chrome_profile, "ensure_target", lambda port: True)

    fake_cookies = [
        {"name": "datadome", "value": "abc123", "domain": ".ExamplePay.com",
         "path": "/", "secure": True, "httpOnly": False, "expires": 1234567890},
        {"name": "session", "value": "xyz", "domain": "developer.ExamplePay.com",
         "path": "/dashboard", "secure": True, "httpOnly": True},
        # Malformed — missing name should be skipped.
        {"value": "orphan", "domain": "x.com"},
    ]

    class FakeContext:
        async def cookies(self):
            return fake_cookies

    class FakeBrowser:
        def __init__(self):
            self.contexts = [FakeContext()]

    class FakeChromium:
        async def connect_over_cdp(self, url):
            return FakeBrowser()

    class FakePW:
        def __init__(self):
            self.chromium = FakeChromium()

    class FakePlaywrightCM:
        async def __aenter__(self):
            return FakePW()
        async def __aexit__(self, *args):
            pass

    def fake_async_playwright():
        return FakePlaywrightCM()

    import playwright.async_api as _pw_async
    monkeypatch.setattr(_pw_async, "async_playwright", fake_async_playwright)

    result = chrome_profile.snapshot_cookies(cdp_port=9222)
    assert len(result) == 2  # malformed entry skipped
    assert {c["name"] for c in result} == {"datadome", "session"}
    # Normalized fields
    for c in result:
        assert isinstance(c["secure"], bool)
        assert isinstance(c["httpOnly"], bool)
        assert "path" in c
        assert "domain" in c
    # No expires field leaks through (we don't normalize it; intentional —
    # scope.yaml's _load_auth_cookies handles expires separately).
    # We verify our normalization shape matches scope.auth_cookies expectations.


def test_acquire_browser_default_path_calls_launch():
    """Unset / playwright_spawn strategy → chromium.launch() with stealth args."""
    scope = SimpleNamespace(browser_strategy=None, engagement_id="test")

    launched = {}

    class FakeChromium:
        async def launch(self, headless=False, args=None):
            launched["headless"] = headless
            launched["args"] = list(args or [])
            return "fake-browser"

    fake_pw = SimpleNamespace(chromium=FakeChromium())
    browser, context, owns = asyncio.run(chrome_profile.acquire_browser(scope, fake_pw))
    assert browser == "fake-browser"
    assert context is None  # caller constructs context with their own settings
    assert owns is True
    assert launched["headless"] is True
    assert any("AutomationControlled" in a for a in launched["args"])
