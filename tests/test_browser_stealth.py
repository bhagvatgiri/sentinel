"""Smoke tests for the browser_stealth init script.

Two layers of testing:

1. **Pure-string tests** — verify the JS template contains the expected
   patches + native-shape registry pattern. Cheap, run on every commit.

2. **Live-Playwright tests** — actually launch headless Chromium with
   the stealth applied + assert each spoof took effect by reading
   navigator.* / window.* values. Marked `@pytest.mark.live_browser` —
   skipped by default in CI; opt-in via `pytest -m live_browser`.

The live tests intentionally do NOT hit external services (no
bot.sannysoft.com, no ExamplePay.com). They run an inline data-URI HTML page
that re-reads its own navigator/window state. That's faster, hermetic,
and avoids depending on a third-party signal.
"""

from __future__ import annotations

import pytest

from sentinel.agent.pentest.browser_stealth import (
    STEALTH_HOOKS,
    STEALTH_INIT_JS,
    get_stealth_init_js,
)


# ───────────── Pure-string tests (cheap, always run) ─────────────────

def test_init_script_is_idempotent():
    """The script must guard against double-application — re-running on
    the same page shouldn't double-patch (would corrupt the toString shim)."""
    assert "__sentinel_stealth_applied" in STEALTH_INIT_JS
    assert "if (window.__sentinel_stealth_applied) return" in STEALTH_INIT_JS


def test_init_script_patches_function_toString():
    """The whole point of the script — masking patched fns as native."""
    assert "Function.prototype.toString" in STEALTH_INIT_JS
    # The native-shape template
    assert "[native code]" in STEALTH_INIT_JS
    # The WeakSet that tracks our patched fns
    assert "WeakSet" in STEALTH_INIT_JS
    # The wrapper itself must register itself (otherwise it's caught)
    assert "_nativeWrapped.add(_toStringWrapper)" in STEALTH_INIT_JS


def test_init_script_patches_navigator_webdriver():
    assert "Navigator.prototype.webdriver" in STEALTH_INIT_JS
    assert "delete Navigator.prototype.webdriver" in STEALTH_INIT_JS


def test_init_script_patches_navigator_plugins():
    """Real Chrome on Mac has 5 plugins; headless has 0. We populate 5."""
    assert "PluginArray.prototype" in STEALTH_INIT_JS
    assert "PDF Viewer" in STEALTH_INIT_JS
    assert "Chrome PDF Viewer" in STEALTH_INIT_JS
    assert "MimeType.prototype" in STEALTH_INIT_JS


def test_init_script_patches_navigator_languages():
    assert "navigator" in STEALTH_INIT_JS.lower()
    assert "['en-US', 'en']" in STEALTH_INIT_JS or "[\"en-US\", \"en\"]" in STEALTH_INIT_JS


def test_init_script_patches_permissions_query_consistency():
    """The mismatch DataDome explicitly probes:
    Notification.permission='default' but permissions.query returns 'denied'."""
    assert "permissions.query" in STEALTH_INIT_JS
    assert "Notification.permission" in STEALTH_INIT_JS


def test_init_script_patches_window_chrome():
    assert "window.chrome" in STEALTH_INIT_JS
    assert "OnInstalledReason" in STEALTH_INIT_JS  # realistic chrome.runtime shape


def test_init_script_patches_webgl_vendor_renderer():
    """37445 = UNMASKED_VENDOR_WEBGL, 37446 = UNMASKED_RENDERER_WEBGL."""
    assert "37445" in STEALTH_INIT_JS
    assert "37446" in STEALTH_INIT_JS
    assert "WebGLRenderingContext.prototype" in STEALTH_INIT_JS


def test_init_script_patches_hardware_consistency():
    assert "hardwareConcurrency" in STEALTH_INIT_JS
    assert "deviceMemory" in STEALTH_INIT_JS


def test_init_script_patches_window_dimensions():
    assert "outerWidth" in STEALTH_INIT_JS
    assert "outerHeight" in STEALTH_INIT_JS


def test_init_script_masks_error_stack():
    """Detectors throw an Error and inspect .stack for puppeteer/playwright
    file paths — we strip those."""
    assert "Error.prototype" in STEALTH_INIT_JS
    assert "puppeteer" in STEALTH_INIT_JS
    assert "sentinel_stealth" in STEALTH_INIT_JS or "__sentinel_" in STEALTH_INIT_JS


def test_get_stealth_init_js_returns_full_template():
    out = get_stealth_init_js()
    assert isinstance(out, str)
    assert len(out) > 1000  # full template is ~7KB
    assert "[native code]" in out


def test_stealth_hooks_documented():
    """Every patch in the JS should have a one-line description in the hook
    list — for documentation + UI surface (events page)."""
    assert isinstance(STEALTH_HOOKS, list)
    assert len(STEALTH_HOOKS) >= 10
    for name, desc in STEALTH_HOOKS:
        assert isinstance(name, str) and name
        assert isinstance(desc, str) and len(desc) > 10


# ───────────── Live-Playwright tests (opt-in, slower) ────────────────
# Skipped by default; run with: pytest -m live_browser tests/test_browser_stealth.py

@pytest.mark.live_browser
@pytest.mark.asyncio
async def test_stealth_actually_hides_webdriver():
    """End-to-end: launch chromium with stealth, verify navigator.webdriver
    is undefined (not true) on a data-URI page."""
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True,
            args=["--disable-blink-features=AutomationControlled"])
        context = await browser.new_context()
        await context.add_init_script(get_stealth_init_js())
        page = await context.new_page()
        await page.goto("data:text/html,<html><body>x</body></html>")
        wd = await page.evaluate("() => navigator.webdriver")
        assert wd is None or wd is False, (
            f"navigator.webdriver should be undefined/false (got {wd!r})")
        await browser.close()


@pytest.mark.live_browser
@pytest.mark.asyncio
async def test_stealth_function_toString_returns_native_for_patched():
    """The crown jewel — the patched webdriver getter must return
    [native code] from .toString()."""
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()
        await context.add_init_script(get_stealth_init_js())
        page = await context.new_page()
        await page.goto("data:text/html,<html><body>x</body></html>")
        # Read the descriptor + toString it (this is what DataDome does)
        js = """() => {
            const d = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
            return d && d.get ? d.get.toString() : 'none';
        }"""
        toStr = await page.evaluate(js)
        assert "[native code]" in toStr, (
            f"Patched webdriver getter should look native (got {toStr!r})")
        await browser.close()


@pytest.mark.live_browser
@pytest.mark.asyncio
async def test_stealth_populates_plugins():
    """Real Chrome has 5 plugins; we populate 5."""
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()
        await context.add_init_script(get_stealth_init_js())
        page = await context.new_page()
        await page.goto("data:text/html,<html><body>x</body></html>")
        n = await page.evaluate("() => navigator.plugins.length")
        assert n >= 3, f"navigator.plugins.length should be ≥3 (got {n})"
        await browser.close()


@pytest.mark.live_browser
@pytest.mark.asyncio
async def test_stealth_populates_languages():
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()
        await context.add_init_script(get_stealth_init_js())
        page = await context.new_page()
        await page.goto("data:text/html,<html><body>x</body></html>")
        langs = await page.evaluate("() => navigator.languages")
        assert isinstance(langs, list) and len(langs) >= 1
        assert "en" in langs[0].lower()
        await browser.close()


@pytest.mark.live_browser
@pytest.mark.asyncio
async def test_stealth_survives_datadome_iframe_detection():
    """The EXACT detection method DataDome publishes against
    puppeteer-extra-stealth (https://datadome.co/threat-research/
    how-datadome-detects-puppeteer-extra-stealth/):

        let iframe = document.createElement('iframe');
        iframe.srcdoc = 'datadome';
        document.body.appendChild(iframe);
        let detected = iframe.contentWindow.self.get?.toString();

    On puppeteer-extra-stealth this returns the proxy handler's source.
    On our implementation it returns undefined / empty string (real browser
    behavior) because we DO NOT use a Proxy on iframe.contentWindow."""
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()
        await context.add_init_script(get_stealth_init_js())
        page = await context.new_page()
        await page.goto("data:text/html,<html><body>x</body></html>")
        result = await page.evaluate("""() => {
            const iframe = document.createElement('iframe');
            iframe.srcdoc = 'datadome';
            document.body.appendChild(iframe);
            // Their EXACT detection line:
            const detected = iframe.contentWindow.self.get?.toString();
            return {
                detected: detected,
                detected_type: typeof detected,
                length: detected ? detected.length : 0,
            };
        }""")
        # On a real browser: detected is undefined.
        # On puppeteer-extra-stealth: detected is the proxy handler source code.
        # On our implementation: must NOT contain stealth source markers.
        if result["detected"]:
            # If it's defined, make sure it doesn't reveal our internals
            for marker in ("contentWindowProxy", "intercepting", "Reflect.get",
                           "sentinel_stealth", "_nativeWrapped",
                           "puppeteer", "playwright"):
                assert marker not in result["detected"], (
                    f"DataDome iframe-detection probe leaked our stealth "
                    f"internals via '{marker}'. detected={result['detected']!r}"
                )
        # Either undefined (real-browser behavior) or a clean value with no
        # stealth source-code leak — both pass the DataDome check.
        await browser.close()


@pytest.mark.live_browser
@pytest.mark.asyncio
async def test_stealth_webgl_vendor_renderer():
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()
        await context.add_init_script(get_stealth_init_js())
        page = await context.new_page()
        await page.goto("data:text/html,<html><body><canvas id=c></canvas></body></html>")
        result = await page.evaluate("""() => {
            const c = document.querySelector('#c');
            const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
            if (!gl) return null;
            return {
                vendor: gl.getParameter(37445),
                renderer: gl.getParameter(37446),
            };
        }""")
        assert result is not None
        # Real Mac M-series strings, not "Google Inc." / "SwiftShader"
        assert "Apple" in result["vendor"], f"WebGL vendor: {result['vendor']!r}"
        assert "Apple" in result["renderer"], f"WebGL renderer: {result['renderer']!r}"
        await browser.close()
