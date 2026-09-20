"""_BrowserSession dual-launch tests for NopeCHA captcha-solver mode.

Mocks all Playwright objects via AsyncMock — no real Chromium ever launches.

Covers the eight assertions plus tempdir cleanup spec'd in PLAN Task 3:
  1. default path (captcha_solver=None) → chromium.launch + new_context
  2. nopecha path → chromium.launch_persistent_context with --load-extension
  3. nopecha + missing ext dir → RuntimeError naming the installer
  4. browser_strategy=cdp wins over captcha_solver=nopecha
  5. NOPECHA_KEY + valid .extension-id → chrome.storage.local.set seeding
  6. captcha_solved auto-emit when pre-detect vendor disappears post-wait
  7. Scope.from_yaml rejects captcha_solver=anticaptcha (Task 1 integration)
  8. STEALTH_INIT_JS applied in BOTH paths
  9. close() removes the per-job tempdir on disk
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


STEALTH_SENTINEL = "/*STEALTH_INIT_SENTINEL*/"


def _install_playwright_stub(monkeypatch, *, persistent_context_mock=None,
                              launch_mock=None, context_mock=None,
                              browser_mock=None, page_mock=None,
                              connect_over_cdp_mock=None):
    """Inject a stub `playwright.async_api` module into sys.modules.

    Returns the namespace handles the test can introspect via .call_args.
    """
    import sys

    page = page_mock or AsyncMock()
    page.set_extra_http_headers = AsyncMock()
    page.evaluate = AsyncMock(return_value=None)
    page.close = AsyncMock()

    ctx = context_mock or AsyncMock()
    ctx.add_init_script = AsyncMock()
    ctx.add_cookies = AsyncMock()
    ctx.new_page = AsyncMock(return_value=page)
    ctx.close = AsyncMock()

    browser = browser_mock or AsyncMock()
    browser.new_context = AsyncMock(return_value=ctx)
    browser.close = AsyncMock()
    browser.contexts = []

    chromium = SimpleNamespace(
        launch=launch_mock or AsyncMock(return_value=browser),
        launch_persistent_context=(
            persistent_context_mock or AsyncMock(return_value=ctx)
        ),
        connect_over_cdp=(
            connect_over_cdp_mock or AsyncMock(return_value=browser)
        ),
    )

    pw = SimpleNamespace(chromium=chromium, stop=AsyncMock())

    pw_starter = AsyncMock(return_value=pw)
    async_pw_callable = MagicMock(return_value=SimpleNamespace(start=pw_starter))

    stub = SimpleNamespace(async_playwright=async_pw_callable)
    monkeypatch.setitem(sys.modules, "playwright.async_api", stub)
    monkeypatch.setitem(sys.modules, "playwright", SimpleNamespace(async_api=stub))

    return SimpleNamespace(
        pw=pw, chromium=chromium, browser=browser, context=ctx, page=page,
        async_playwright_callable=async_pw_callable,
    )


def _patch_stealth(monkeypatch):
    """Stub get_stealth_init_js to return a known sentinel so we can assert
    add_init_script(sentinel) in both launch paths."""
    from sentinel.agent.pentest import browser_stealth
    monkeypatch.setattr(
        browser_stealth, "get_stealth_init_js", lambda: STEALTH_SENTINEL,
    )


def _make_scope(captcha_solver=None, browser_strategy=None,
                domains=("example.com",), auth_cookies=None,
                research_headers=None):
    s = MagicMock()
    s.captcha_solver = captcha_solver
    s.browser_strategy = browser_strategy
    s.domains = list(domains)
    s.auth_cookies = list(auth_cookies or [])
    s.research_headers = dict(research_headers or {})
    s.engagement_mode = SimpleNamespace(value="bbp")
    s.engagement_id = "test-eng"
    return s


def _install_ctx(monkeypatch, scope, job_id="job-test", phase="vuln:auth"):
    """Plant a shared PentestContext on tools._ctx so _BrowserSession.page()
    can read scope from it."""
    audit = MagicMock()
    audit.write = MagicMock()
    event_log = MagicMock()
    event_log.emit = MagicMock()
    ctx = SimpleNamespace(
        scope=scope, audit=audit, event_log=event_log,
        current_phase=phase, job_id=job_id,
        last_fetch_at={}, rate_limit_per_host_sec=0.0,
        pages_fetched=0,
    )
    from sentinel.agent.pentest import tools as p_tools
    monkeypatch.setattr(p_tools, "_ctx", ctx)
    return ctx


# ---------------------------------------------------------------------------
# Assertion 1: default path (captcha_solver=None) → launch + new_context
# ---------------------------------------------------------------------------
def test_default_path_uses_launch_and_new_context(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    stub = _install_playwright_stub(monkeypatch)
    _patch_stealth(monkeypatch)
    scope = _make_scope(captcha_solver=None)
    _install_ctx(monkeypatch, scope)

    from sentinel.agent.pentest.browser_tool import _BrowserSession
    sess = _BrowserSession("vuln:auth")

    async def runit():
        await sess.page()
        await sess.close()

    asyncio.run(runit())

    assert stub.chromium.launch.call_count == 1
    assert stub.chromium.launch_persistent_context.call_count == 0
    assert stub.browser.new_context.call_count == 1
    # stealth applied
    init_calls = stub.context.add_init_script.call_args_list
    assert any(STEALTH_SENTINEL in str(c) for c in init_calls), (
        f"stealth init not applied in default path: {init_calls}"
    )


# ---------------------------------------------------------------------------
# Assertion 2: nopecha path → launch_persistent_context with --load-extension
# ---------------------------------------------------------------------------
def test_nopecha_path_uses_persistent_context_with_extension(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Materialize a fake external/nopecha-extension/ dir so _resolve_nopecha_ext_path
    # passes.
    ext = tmp_path / "external" / "nopecha-extension"
    ext.mkdir(parents=True)
    (ext / "manifest.json").write_text("{}")
    (ext / ".extension-id").write_text("UNKNOWN")  # skip seeding

    stub = _install_playwright_stub(monkeypatch)
    _patch_stealth(monkeypatch)
    scope = _make_scope(captcha_solver="nopecha")
    _install_ctx(monkeypatch, scope, job_id="job-nopecha", phase="vuln:idor")

    from sentinel.agent.pentest.browser_tool import _BrowserSession
    sess = _BrowserSession("vuln:idor")

    async def runit():
        await sess.page()
        await sess.close()

    asyncio.run(runit())

    assert stub.chromium.launch.call_count == 0, "default launch should not fire"
    assert stub.chromium.launch_persistent_context.call_count == 1
    call = stub.chromium.launch_persistent_context.call_args
    kwargs = call.kwargs
    assert kwargs.get("headless") is False
    args_list = kwargs.get("args") or []
    joined = " ".join(args_list)
    assert "--load-extension=" in joined, f"missing --load-extension: {args_list}"
    assert "external/nopecha-extension" in joined or str(ext) in joined, (
        f"--load-extension path doesn't point at external/nopecha-extension: {joined}"
    )
    udd = kwargs.get("user_data_dir")
    assert udd is not None
    udd_str = str(udd)
    # Per-job tempdir under runs/.tmp/browser-data/
    assert "runs/.tmp/browser-data" in udd_str or "runs\\.tmp\\browser-data" in udd_str, (
        f"user_data_dir not under runs/.tmp/browser-data: {udd_str}"
    )
    # Stealth applied on the returned persistent context
    init_calls = stub.context.add_init_script.call_args_list
    assert any(STEALTH_SENTINEL in str(c) for c in init_calls)


# ---------------------------------------------------------------------------
# Assertion 3: nopecha + missing ext dir → RuntimeError naming installer
# ---------------------------------------------------------------------------
def test_nopecha_missing_ext_dir_raises_runtime_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Do NOT create external/nopecha-extension/
    stub = _install_playwright_stub(monkeypatch)
    _patch_stealth(monkeypatch)
    scope = _make_scope(captcha_solver="nopecha")
    _install_ctx(monkeypatch, scope)

    from sentinel.agent.pentest.browser_tool import _BrowserSession
    sess = _BrowserSession("vuln:auth")

    async def runit():
        await sess.page()

    with pytest.raises(RuntimeError) as exc_info:
        asyncio.run(runit())
    assert "./tools/install-nopecha-extension.sh" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Assertion 4: browser_strategy=cdp wins over captcha_solver=nopecha
# ---------------------------------------------------------------------------
def test_cdp_strategy_wins_over_nopecha(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)
    ext = tmp_path / "external" / "nopecha-extension"
    ext.mkdir(parents=True)
    (ext / "manifest.json").write_text("{}")
    (ext / ".extension-id").write_text("UNKNOWN")

    stub = _install_playwright_stub(monkeypatch)
    _patch_stealth(monkeypatch)
    # Force the chrome_profile.attach_status to return something truthy so
    # the CDP branch survives its bootstrap-required check.
    from sentinel.agent import chrome_profile as _cp
    monkeypatch.setattr(_cp, "attach_status", lambda port: {"version": "fake"})
    monkeypatch.setattr(_cp, "resolve_cdp_port", lambda scope: 9222)

    scope = _make_scope(captcha_solver="nopecha", browser_strategy="cdp")
    _install_ctx(monkeypatch, scope)

    from sentinel.agent.pentest.browser_tool import _BrowserSession
    sess = _BrowserSession("vuln:auth")

    async def runit():
        await sess.page()
        await sess.close()

    import logging
    with caplog.at_level(logging.WARNING):
        asyncio.run(runit())

    assert stub.chromium.connect_over_cdp.call_count == 1
    assert stub.chromium.launch_persistent_context.call_count == 0
    assert stub.chromium.launch.call_count == 0
    # CDP branch logs a warning about the ignored captcha_solver
    assert any(
        "captcha_solver" in rec.message.lower() and "ignored" in rec.message.lower()
        for rec in caplog.records
    ), f"CDP branch should warn about ignored captcha_solver; got: {[r.message for r in caplog.records]}"


# ---------------------------------------------------------------------------
# Assertion 5: NOPECHA_KEY + valid .extension-id → chrome.storage.local.set
# ---------------------------------------------------------------------------
def test_nopecha_key_seeding_when_extension_id_known(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ext = tmp_path / "external" / "nopecha-extension"
    ext.mkdir(parents=True)
    (ext / "manifest.json").write_text("{}")
    (ext / ".extension-id").write_text("dknlfmjaanfblgfdfebhijalfmhmjjjo")
    monkeypatch.setenv("NOPECHA_KEY", "test-nopecha-key-12345")

    stub = _install_playwright_stub(monkeypatch)
    _patch_stealth(monkeypatch)
    scope = _make_scope(captcha_solver="nopecha")
    _install_ctx(monkeypatch, scope, job_id="job-seed", phase="vuln:auth")

    from sentinel.agent.pentest.browser_tool import _BrowserSession
    sess = _BrowserSession("vuln:auth")

    async def runit():
        await sess.page()
        await sess.close()

    asyncio.run(runit())

    # The seeding page.evaluate should fire with chrome.storage.local.set
    # and the key value.
    eval_calls = stub.page.evaluate.call_args_list
    matched = [
        c for c in eval_calls
        if "chrome.storage.local.set" in str(c) and "test-nopecha-key-12345" in str(c)
    ]
    assert matched, (
        f"NOPECHA_KEY seeding never called chrome.storage.local.set: {eval_calls}"
    )


# ---------------------------------------------------------------------------
# Assertion 6: captcha_solved auto-emit when pre-detect vendor disappears
# ---------------------------------------------------------------------------
def test_captcha_solved_emits_when_vendor_clears_after_wait(monkeypatch):
    """Pure helper test for _maybe_emit_captcha_solved.

    The full browser_get integration path is exercised by the existing
    test_browser_tool.py scope-gate tests. Here we just assert the helper
    emits to both event_log and audit with the right payload."""
    scope = _make_scope(captcha_solver="nopecha")
    ctx = SimpleNamespace(
        scope=scope, audit=MagicMock(), event_log=MagicMock(),
        current_phase="vuln:auth", job_id="job-emit",
        last_fetch_at={}, rate_limit_per_host_sec=0.0,
        pages_fetched=0,
    )
    ctx.audit.write = MagicMock()
    ctx.event_log.emit = MagicMock()
    from sentinel.agent.pentest import browser_tool as bt
    bt._maybe_emit_captcha_solved(
        ctx, url="https://example.com/login",
        vendor="DataDome", took_ms=1234,
    )
    assert ctx.event_log.emit.called
    emit_kwargs = ctx.event_log.emit.call_args
    assert emit_kwargs.args[0] == "captcha_solved", emit_kwargs
    assert ctx.audit.write.called
    audit_args = ctx.audit.write.call_args
    assert audit_args.args[0] == "captcha_solved"
    payload = audit_args.args[1]
    assert payload.get("solver") == "nopecha"
    assert payload.get("type") == "DataDome"


# ---------------------------------------------------------------------------
# Assertion 7: Scope rejects captcha_solver=anticaptcha (integration)
# ---------------------------------------------------------------------------
def test_scope_rejects_unknown_captcha_solver(tmp_path):
    from datetime import date, timedelta
    import yaml
    from sentinel.core.scope import Scope, ScopeError
    today = date.today()
    data = {
        "client": "c", "engagement_id": "e", "authorized_by": "a@b.c",
        "valid_from": (today - timedelta(days=1)).isoformat(),
        "valid_until": (today + timedelta(days=30)).isoformat(),
        "targets": {"domains": ["example.com"]},
        "captcha_solver": "anticaptcha",
    }
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data))
    with pytest.raises(ScopeError) as exc_info:
        Scope.load(str(p))
    msg = str(exc_info.value)
    assert "captcha_solver" in msg or "anticaptcha" in msg


# ---------------------------------------------------------------------------
# Assertion 8: stealth applied in BOTH paths (default + nopecha)
# Covered partially by assertions 1+2 above; this is the explicit pin.
# ---------------------------------------------------------------------------
def test_stealth_applied_in_both_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ext = tmp_path / "external" / "nopecha-extension"
    ext.mkdir(parents=True)
    (ext / "manifest.json").write_text("{}")
    (ext / ".extension-id").write_text("UNKNOWN")
    _patch_stealth(monkeypatch)

    for solver in (None, "nopecha"):
        stub = _install_playwright_stub(monkeypatch)
        scope = _make_scope(captcha_solver=solver)
        _install_ctx(monkeypatch, scope, job_id=f"job-{solver}",
                     phase=f"vuln:{solver or 'def'}")
        from sentinel.agent.pentest.browser_tool import _BrowserSession
        sess = _BrowserSession(f"vuln:{solver or 'def'}")
        asyncio.run(sess.page())
        asyncio.run(sess.close())
        calls = stub.context.add_init_script.call_args_list
        assert any(STEALTH_SENTINEL in str(c) for c in calls), (
            f"stealth not applied for captcha_solver={solver}: {calls}"
        )


# ---------------------------------------------------------------------------
# Assertion 9: close() removes per-job tempdir
# ---------------------------------------------------------------------------
def test_nopecha_close_removes_tempdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ext = tmp_path / "external" / "nopecha-extension"
    ext.mkdir(parents=True)
    (ext / "manifest.json").write_text("{}")
    (ext / ".extension-id").write_text("UNKNOWN")
    stub = _install_playwright_stub(monkeypatch)
    _patch_stealth(monkeypatch)
    scope = _make_scope(captcha_solver="nopecha")
    _install_ctx(monkeypatch, scope, job_id="job-cleanup", phase="vuln:c")

    from sentinel.agent.pentest.browser_tool import _BrowserSession
    sess = _BrowserSession("vuln:c")

    async def runit():
        await sess.page()
        # Capture the user_data_dir before close
        captured = stub.chromium.launch_persistent_context.call_args.kwargs["user_data_dir"]
        await sess.close()
        return captured

    captured_dir = asyncio.run(runit())
    assert captured_dir is not None
    assert not Path(captured_dir).exists(), (
        f"tempdir {captured_dir} was not cleaned up by close()"
    )
