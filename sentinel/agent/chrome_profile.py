"""Real-Chrome-via-CDP profile management — DataDome bypass primitive.

Why this exists: Chrome-for-Testing (Playwright's bundled Chromium) is
fingerprinted by every modern bot manager (DataDome, Cloudflare, Akamai,
PerimeterX). The user's ACTUAL installed Google Chrome ships with a
fingerprint shared by billions of real users — bot managers can't fight
it without taking out their own customers' real traffic.

Strategy:
1. Operator runs `sentinel chrome bootstrap --scope <yaml>`. We launch
   their installed Chrome with --remote-debugging-port=9222 and
   --user-data-dir=<per-engagement-profile>. A visible window opens.
2. Operator solves the DataDome challenge once and signs in. Profile
   saves cookies/storage to disk. They close the window when done.
3. Sentinel's pipeline (browser_tool, verifiers/xss, etc.) calls
   `acquire_browser(scope, pw)`, which when scope.browser_strategy=='cdp'
   does `pw.chromium.connect_over_cdp("http://localhost:9222")` and
   returns `(browser, browser.contexts[0])` — the profile's default
   context, with all the cookies. Pages opened in that context inherit
   the authenticated session.

Critical detail: `browser.new_context()` on a CDP-attached Chrome
creates an empty incognito context — DEFEATS the entire purpose. Always
use `browser.contexts[0]` for the cookied path.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import json as _json


log = logging.getLogger(__name__)


DEFAULT_CDP_PORT = 9222
DEFAULT_PROFILE_ROOT = Path.home() / ".sentinel" / "chrome-profiles"


# ---- Chrome binary discovery ----------------------------------------------


_DARWIN_CHROME_PATHS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
)

_LINUX_CHROME_NAMES = (
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
)


class ChromeBinaryNotFound(RuntimeError):
    """Raised when no installed Chrome / Chromium binary can be located."""


def discover_chrome_binary() -> str:
    """Return absolute path to the user's installed Chrome.

    macOS: searches /Applications first (Google Chrome, then Canary, then
    Chromium). Linux: PATH lookup for google-chrome / chromium.
    Override with $SENTINEL_CHROME_BINARY for either platform.
    """
    override = os.environ.get("SENTINEL_CHROME_BINARY", "").strip()
    if override:
        if Path(override).is_file():
            return override
        raise ChromeBinaryNotFound(
            f"$SENTINEL_CHROME_BINARY={override!r} does not exist or is not a file"
        )
    if sys.platform == "darwin":
        for path in _DARWIN_CHROME_PATHS:
            if Path(path).is_file():
                return path
        raise ChromeBinaryNotFound(
            "No Google Chrome / Chromium found in /Applications. Install "
            "Chrome from google.com/chrome or set $SENTINEL_CHROME_BINARY."
        )
    # Linux + others: PATH lookup
    for name in _LINUX_CHROME_NAMES:
        path = shutil.which(name)
        if path:
            return path
    raise ChromeBinaryNotFound(
        f"No Chrome binary found on PATH (tried {list(_LINUX_CHROME_NAMES)}). "
        "Install google-chrome or set $SENTINEL_CHROME_BINARY."
    )


# ---- Profile-dir resolution -----------------------------------------------


def resolve_profile_dir(scope: Any) -> Path:
    """Return absolute Path to this engagement's Chrome profile dir.

    Honors scope.chrome_profile_dir if set (with ~ expansion), otherwise
    falls back to ~/.sentinel/chrome-profiles/<engagement_id>.
    """
    raw = getattr(scope, "chrome_profile_dir", None)
    if raw:
        return Path(raw).expanduser().resolve()
    eng_id = getattr(scope, "engagement_id", "default")
    return (DEFAULT_PROFILE_ROOT / eng_id).resolve()


def resolve_cdp_port(scope: Any) -> int:
    """Return the CDP port for this engagement (default 9222)."""
    return int(getattr(scope, "chrome_cdp_port", DEFAULT_CDP_PORT) or DEFAULT_CDP_PORT)


# ---- Bootstrap -------------------------------------------------------------


@dataclass
class BootstrapResult:
    pid: int
    cdp_url: str
    profile_dir: Path
    chrome_binary: str


def bootstrap_profile(
    profile_dir: Path,
    cdp_port: int = DEFAULT_CDP_PORT,
    chrome_binary: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
) -> BootstrapResult:
    """Launch the user's real Chrome with remote-debugging + per-eng profile.

    Returns immediately after spawning the subprocess. The Chrome window
    stays open so the operator can solve any anti-bot challenge and sign
    in. Profile data persists on disk in `profile_dir` for subsequent
    `connect_over_cdp` calls.

    Idempotency: if a Chrome is already listening on cdp_port (probably
    from a prior bootstrap), this raises RuntimeError rather than
    spawning a second one. Operator must `chrome clean` first.
    """
    if attach_status(cdp_port) is not None:
        raise RuntimeError(
            f"Chrome already listening on CDP port {cdp_port}. "
            f"Run `sentinel chrome clean` first or pick a different port."
        )

    binary = chrome_binary or discover_chrome_binary()
    profile_dir.mkdir(parents=True, exist_ok=True)
    args = [
        binary,
        f"--remote-debugging-port={cdp_port}",
        f"--user-data-dir={profile_dir}",
        # Disable the "default browser" prompt + first-run wizard noise so
        # the operator's view is the target page, not Chrome chrome.
        "--no-first-run",
        "--no-default-browser-check",
        # Open a blank page; operator navigates manually after solving.
        "about:blank",
    ]
    if extra_args:
        args.extend(extra_args)

    # Detach: don't tie Chrome's lifetime to the Python process. Chrome
    # outlives the bootstrap CLI invocation so the operator can interact
    # with it across terminal sessions.
    proc = subprocess.Popen(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    # Give Chrome 5 seconds to bind the debugging port. Without this,
    # immediate downstream `attach_status()` calls flap on cold starts.
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if attach_status(cdp_port) is not None:
            break
        time.sleep(0.2)

    return BootstrapResult(
        pid=proc.pid,
        cdp_url=f"http://localhost:{cdp_port}",
        profile_dir=profile_dir,
        chrome_binary=binary,
    )


# ---- Status / probe --------------------------------------------------------


def list_targets(cdp_port: int = DEFAULT_CDP_PORT) -> Optional[list[dict]]:
    """Return the list of CDP targets (tabs/pages/workers) or None if cold."""
    url = f"http://localhost:{cdp_port}/json"
    try:
        with urllib.request.urlopen(url, timeout=1.5) as resp:
            data = _json.loads(resp.read().decode("utf-8", errors="replace"))
            return data if isinstance(data, list) else []
    except (urllib.error.URLError, ConnectionError, TimeoutError, _json.JSONDecodeError, OSError):
        return None


def ensure_target(cdp_port: int = DEFAULT_CDP_PORT, url: str = "about:blank") -> bool:
    """Make sure Chrome has at least one page target.

    Playwright's `connect_over_cdp` fails with the misleading
    "Browser.setDownloadBehavior: Browser context management is not supported"
    error when Chrome is alive but has zero page targets (operator closed
    all tabs). This helper creates a blank tab via the JSON DevTools API
    so connect_over_cdp has something to attach to.

    Returns True if a target now exists (existing or freshly opened),
    False on cold port or HTTP failure.
    """
    targets = list_targets(cdp_port)
    if targets is None:
        return False
    if any(t.get("type") == "page" for t in targets):
        return True
    # No page targets — open one.
    try:
        from urllib.parse import quote
        req = urllib.request.Request(
            f"http://localhost:{cdp_port}/json/new?{quote(url, safe='')}",
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = _json.loads(resp.read().decode("utf-8", errors="replace"))
            return isinstance(data, dict) and data.get("type") == "page"
    except (urllib.error.URLError, ConnectionError, TimeoutError, _json.JSONDecodeError, OSError) as e:
        log.warning("ensure_target: failed to open tab on port %d: %s", cdp_port, e)
        return False


def attach_status(cdp_port: int = DEFAULT_CDP_PORT) -> Optional[dict]:
    """Return Chrome version metadata if Chrome is reachable on the port.

    Returns None if the port is cold (no listener / refused / timeout).
    Network failures are swallowed and treated as "not running" — this
    function MUST NOT raise on a missing-Chrome (operator-facing CLI uses
    it as a poll).
    """
    url = f"http://localhost:{cdp_port}/json/version"
    try:
        with urllib.request.urlopen(url, timeout=1.5) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = _json.loads(body)
            if not isinstance(data, dict):
                return None
            return data
    except (urllib.error.URLError, ConnectionError, TimeoutError, _json.JSONDecodeError, OSError):
        return None


async def snapshot_cookies_async(
    cdp_port: int = DEFAULT_CDP_PORT,
    timeout_sec: float = 10.0,
) -> list[dict]:
    """Snapshot every cookie from the CDP-attached Chrome profile's default context.

    Returns a list in scope.auth_cookies format:
        [{"name", "value", "domain", "path", "secure", "httpOnly"}, ...]
    Empty list on cold port / no contexts / Playwright failure (caller can
    decide whether to fall back to scope.yaml's static auth_cookies block).

    Why we go through Playwright: Network.getAllCookies via raw CDP returns
    only cookies for the current target's URL. Playwright's
    `BrowserContext.cookies()` calls Storage.getCookies which returns the
    profile's full jar (cross-origin, cross-tab) — that's what we want for
    handing the cookies to httpx clients across many domains.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log.warning("snapshot_cookies: playwright not installed")
        return []

    if attach_status(cdp_port) is None:
        return []
    ensure_target(cdp_port)

    async def _snap() -> list[dict]:
        async with async_playwright() as pw:
            browser = await pw.chromium.connect_over_cdp(f"http://localhost:{cdp_port}")
            try:
                contexts = browser.contexts
                if not contexts:
                    return []
                cookies = await contexts[0].cookies()
            finally:
                # Don't close — operator's Chrome.
                pass
        out: list[dict] = []
        for c in cookies:
            name = c.get("name")
            value = c.get("value")
            if not name or value is None:
                continue
            out.append({
                "name": str(name),
                "value": str(value),
                "domain": str(c.get("domain", "")),
                "path": str(c.get("path", "/")),
                "secure": bool(c.get("secure", False)),
                "httpOnly": bool(c.get("httpOnly", False)),
            })
        return out

    try:
        return await asyncio.wait_for(_snap(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        log.warning("snapshot_cookies: timed out after %.1fs", timeout_sec)
        return []
    except Exception as e:
        log.warning("snapshot_cookies: failed: %s", e)
        return []


def snapshot_cookies(cdp_port: int = DEFAULT_CDP_PORT) -> list[dict]:
    """Sync wrapper around snapshot_cookies_async for CLI / pipeline use."""
    return asyncio.run(snapshot_cookies_async(cdp_port))


async def verify_session(
    cdp_port: int,
    probe_url: str,
    *,
    screenshot_path: Optional[Path] = None,
    timeout_sec: float = 20.0,
) -> dict:
    """Attach via CDP, GET probe_url in the profile's default context, return verdict.

    Returns:
        {
            "ok": bool,
            "status": int,           # HTTP status of the probe (0 on connect failure)
            "final_url": str,        # post-redirect URL
            "title": str,            # page <title>
            "looks_authenticated": bool,
            "screenshot": Optional[str],  # path written if requested
            "error": Optional[str],
        }

    looks_authenticated heuristic: probe returned 200 AND final_url didn't
    redirect to a /signin /login path (the typical "you got logged out"
    pattern). NOT a guarantee — operator should also eyeball the screenshot.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "ok": False, "status": 0, "final_url": probe_url, "title": "",
            "looks_authenticated": False, "screenshot": None,
            "error": "playwright not installed (pip install -e '.[browser]')",
        }

    if attach_status(cdp_port) is None:
        return {
            "ok": False, "status": 0, "final_url": probe_url, "title": "",
            "looks_authenticated": False, "screenshot": None,
            "error": f"No Chrome listening on CDP port {cdp_port} — bootstrap first.",
        }

    # Auto-open a tab if Chrome has none — Playwright's connect_over_cdp
    # otherwise fails with a misleading Browser.setDownloadBehavior error.
    if not ensure_target(cdp_port):
        return {
            "ok": False, "status": 0, "final_url": probe_url, "title": "",
            "looks_authenticated": False, "screenshot": None,
            "error": f"Could not ensure a tab on Chrome port {cdp_port}.",
        }

    async def _probe() -> dict:
        async with async_playwright() as pw:
            browser = await pw.chromium.connect_over_cdp(f"http://localhost:{cdp_port}")
            try:
                contexts = browser.contexts
                if not contexts:
                    return {
                        "ok": False, "status": 0, "final_url": probe_url, "title": "",
                        "looks_authenticated": False, "screenshot": None,
                        "error": "Chrome has no contexts — profile may be empty",
                    }
                context = contexts[0]
                page = await context.new_page()
                try:
                    # Navigate with domcontentloaded as fast-path; fall back
                    # to the response status from the actual GET. Some SPAs
                    # never fire networkidle (perpetual XHR polling), so we
                    # don't wait for it; we sleep briefly to let initial JS
                    # paint render before the screenshot.
                    response = await page.goto(probe_url, wait_until="domcontentloaded", timeout=15_000)
                    status = response.status if response else 0
                    # Best-effort SPA paint wait — try networkidle for a few
                    # seconds, but don't fail the verify if it never fires.
                    try:
                        await page.wait_for_load_state("networkidle", timeout=4_000)
                    except Exception:
                        await asyncio.sleep(2.0)
                    final_url = page.url
                    title = await page.title()
                    final_low = final_url.lower()
                    looks_auth = (
                        status == 200
                        and "/signin" not in final_low
                        and "/login" not in final_low
                        and "/auth/" not in final_low
                    )
                    sshot_path = None
                    if screenshot_path:
                        screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                        await page.screenshot(path=str(screenshot_path), full_page=False)
                        sshot_path = str(screenshot_path)
                    return {
                        "ok": True, "status": status, "final_url": final_url,
                        "title": title, "looks_authenticated": looks_auth,
                        "screenshot": sshot_path, "error": None,
                    }
                finally:
                    await page.close()
            finally:
                # Don't close the browser — it's the operator's running Chrome.
                pass

    try:
        return await asyncio.wait_for(_probe(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        return {
            "ok": False, "status": 0, "final_url": probe_url, "title": "",
            "looks_authenticated": False, "screenshot": None,
            "error": f"verify_session timed out after {timeout_sec}s",
        }


# ---- Acquire-browser helper for Sentinel's runtime callers ----------------


async def acquire_browser(scope: Any, pw: Any) -> tuple[Any, Any, bool]:
    """Return (browser, context, owns_browser) based on scope.browser_strategy.

    Used by browser_tool.py's _BrowserSession + verifiers/xss.py to keep
    the CDP-vs-spawn branch in one place. The third element tells the
    caller whether THEY own the browser lifecycle (True for spawn — close
    on session teardown; False for CDP — DON'T close, it's the operator's
    Chrome).

    Strategy values:
        None / "playwright_spawn" → chromium.launch(headless=True) +
            new_context(...). Caller owns browser.
        "cdp" / "agent_browser_cdp" → connect_over_cdp + browser.contexts[0].
            Caller does NOT own browser (operator's running Chrome).

    Caller is responsible for additional context setup (cookies, init
    scripts, headers) since spawn vs CDP have different best practices:
    spawn needs auth_cookies injection; CDP profile already has them.
    """
    strategy = (getattr(scope, "browser_strategy", None) or "").lower()

    if strategy in ("cdp", "agent_browser_cdp"):
        cdp_port = resolve_cdp_port(scope)
        if attach_status(cdp_port) is None:
            raise RuntimeError(
                f"scope.browser_strategy={strategy!r} requires Chrome listening "
                f"on CDP port {cdp_port}. Run `sentinel chrome bootstrap "
                f"--scope <scope.yaml>` first."
            )
        # Playwright's connect_over_cdp fails when Chrome has zero page
        # targets — it tries Browser.setDownloadBehavior on a non-existent
        # context. Open a blank tab first if needed.
        ensure_target(cdp_port)
        browser = await pw.chromium.connect_over_cdp(f"http://localhost:{cdp_port}")
        contexts = browser.contexts
        if not contexts:
            # Fresh CDP attach with no contexts — fall back to creating one.
            # This happens when Chrome was launched without a tab (rare).
            context = await browser.new_context()
        else:
            context = contexts[0]
        return browser, context, False

    # Default / playwright_spawn — preserve existing behavior so caller
    # continues to apply its own user-agent / viewport / headers / stealth.
    browser = await pw.chromium.launch(
        headless=True,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--disable-features=IsolateOrigins,site-per-process",
            "--disable-site-isolation-trials",
        ],
    )
    # Caller is expected to .new_context() with their own settings — return
    # None here so they explicitly construct it. We can't know the right
    # user_agent / viewport / extra_http_headers / stealth set from here.
    return browser, None, True


# ---- Cleanup --------------------------------------------------------------


def shutdown_chrome(cdp_port: int = DEFAULT_CDP_PORT, timeout_sec: float = 5.0) -> bool:
    """Shut down the Chrome listening on cdp_port.

    Tries three increasingly-aggressive strategies in order:
      1. CDP Browser.close via WebSocket (clean shutdown — Chrome flushes
         profile data, closes tabs gracefully).
      2. SIGTERM by PID — discovered via lsof on the port (Chrome still
         flushes most state on SIGTERM via shutdown handlers).
      3. Returns False if neither worked (operator must kill manually).

    Returns True if Chrome went cold within timeout_sec, False if it stayed
    up. Returns False immediately if no Chrome was listening.
    """
    if attach_status(cdp_port) is None:
        return False

    # ---- strategy 1: CDP Browser.close via WebSocket ----------------------
    info = attach_status(cdp_port)
    ws_url = (info or {}).get("webSocketDebuggerUrl", "")
    if ws_url:
        try:
            from websocket import create_connection  # type: ignore
            ws = create_connection(ws_url, timeout=2.0)
            ws.send(_json.dumps({"id": 1, "method": "Browser.close"}))
            try:
                ws.recv()  # Chrome may not respond before closing socket
            except Exception:
                pass
            ws.close()
        except Exception as e:
            # SHUTDOWN-02 (2026-XX-XX): was log.debug — operator couldn't
            # see strategy-1 failures unless SHIM_LOG_LEVEL=DEBUG. Now at
            # WARNING so the dashboard / default log stream surfaces them.
            log.warning(
                "shutdown_chrome: WebSocket Browser.close failed "
                "(strategy 1 of 3): %s", e,
            )

    # Also try the legacy /json/close endpoint for very old Chrome builds.
    try:
        urllib.request.urlopen(
            f"http://localhost:{cdp_port}/json/close", timeout=1.0,
        ).read()
    except Exception as e:
        # SHUTDOWN-02 (2026-XX-XX): previously `except Exception: pass`
        # which swallowed the failure silently. Surface as WARNING so the
        # operator can see which strategy noop'd.
        log.warning(
            "shutdown_chrome: legacy /json/close fallback failed "
            "(strategy 1b): %s", e,
        )

    # ---- strategy 2: SIGTERM by PID via lsof ------------------------------
    # Wait briefly for graceful shutdown; if still up, find the PID.
    time.sleep(1.0)
    if attach_status(cdp_port) is None:
        return True

    pid = _pid_listening_on(cdp_port)
    if pid:
        log.info("shutdown_chrome: graceful close failed; SIGTERM PID %d", pid)
        try:
            import signal as _signal
            os.kill(pid, _signal.SIGTERM)
        except (ProcessLookupError, PermissionError) as e:
            log.warning("shutdown_chrome: SIGTERM PID %d failed: %s", pid, e)

    # ---- wait for port to go cold ----------------------------------------
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if attach_status(cdp_port) is None:
            return True
        time.sleep(0.2)
    # SHUTDOWN-02 (2026-XX-XX): final-fallthrough was a silent `return False`.
    # Surface as WARNING with the operator's next manual step so they don't
    # have to grep DEBUG logs to find out why the dashboard reported a
    # degraded shutdown state.
    log.warning(
        "shutdown_chrome: all 3 strategies completed but port %d still "
        "listening after %.1fs — operator may need to run `kill -9 %s` "
        "manually (or `pkill -f remote-debugging-port=%d`)",
        cdp_port, timeout_sec, pid if pid else "<PID>", cdp_port,
    )
    return False  # didn't go cold; operator may need to kill manually


def _pid_listening_on(port: int) -> Optional[int]:
    """Return the PID of the process listening on `port`, or None.

    macOS / Linux: parses `lsof -nP -iTCP:<port> -sTCP:LISTEN -t` output.
    """
    try:
        result = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
            capture_output=True, text=True, timeout=3.0,
        )
        if result.returncode != 0:
            return None
        pids = [p.strip() for p in result.stdout.splitlines() if p.strip()]
        if not pids:
            return None
        # Multiple matches → take the first (Chrome itself is usually parent).
        return int(pids[0])
    except (subprocess.TimeoutExpired, ValueError, FileNotFoundError):
        return None
