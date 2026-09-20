"""Tier-2 anti-bot bypass: cookie harvest from a real-Chrome session.

Operator opens a real Chrome browser via Playwright (NOT headless), navigates
to the target URL, manually solves the DataDome/Cloudflare/Akamai challenge
(usually just "let the page finish loading"), then we read the resulting
cookies from the browser context and persist them into the scope YAML's
`auth_cookies` block.

After harvest, every subsequent http_get / browser_get for that domain
sends the harvested cookie automatically — Sentinel looks like a returning
human visitor instead of a fresh-session bot.

Why this works:
  1. Real Chrome with a real human user passes DataDome's TLS check (BoringSSL)
     AND its JS challenge (full execution + correct timing) AND its
     behavioral check (real mouse + scroll movements during the page load).
  2. DataDome issues a `datadome` cookie (typically valid 1-3 hours)
     marking this client as "human, OK to allow".
  3. Subsequent requests with the cookie skip all the challenge logic
     and get straight to the real content.

This module is the CLI entrypoint (`sentinel datadome-harvest <url>
--scope <path>`). It writes back to the scope YAML preserving everything
else (other fields, comments, formatting where YAML library allows).
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Any, Optional

import yaml


log = logging.getLogger(__name__)


# Cookie names commonly issued by major anti-bot vendors. We harvest only
# these so we don't accidentally exfiltrate every site cookie (analytics,
# tracking, etc.) — operator security: scope.yaml gets only what's needed.
_INTERESTING_COOKIE_NAMES = {
    # DataDome
    "datadome",
    "_pddc_dd_",
    "dd-cookie",
    # Cloudflare Bot Management / Turnstile
    "cf_clearance",
    "__cf_bm",
    "cf_chl_2",
    # Akamai Bot Manager
    "_abck",
    "ak_bmsc",
    "bm_sz",
    "bm_sv",
    "bm_mi",
    # Imperva / Incapsula
    "incap_ses_",   # prefix match
    "visid_incap_",
    "_incapsula_",
    # PerimeterX / HUMAN
    "_pxhd",
    "_px3",
    "_pxvid",
    "px-captcha",
    # Vercel Attack Challenge Mode
    "_vercel_jwt",
    "_vcrcs",
    # Generic session-protection cookies
    "session-bot-protection",
}


def _is_interesting_cookie(name: str) -> bool:
    """True if the cookie looks like an anti-bot challenge artifact worth
    persisting. Whitelist (not blacklist) for operator safety."""
    n = name.lower()
    if n in _INTERESTING_COOKIE_NAMES:
        return True
    # Prefix matches (Imperva uses incap_ses_<num>)
    for prefix in ("incap_ses_", "visid_incap_", "cf_chl_"):
        if n.startswith(prefix):
            return True
    return False


async def harvest_cookies_via_real_chrome(
    target_url: str,
    headed: bool = True,
    wait_seconds_after_load: int = 10,
) -> list[dict]:
    """Open a real Chrome browser, navigate to target_url, wait for the
    operator to solve any anti-bot challenge, then return the cookies.

    Args:
        target_url: URL to visit (operator solves any challenge here)
        headed: True = visible browser (operator can interact); False
                = headless (DataDome will block, only useful for testing)
        wait_seconds_after_load: how long to wait after page reaches
                'networkidle' before reading cookies. Gives DataDome time
                to issue the post-challenge cookie.

    Returns: list of cookie dicts in the format scope._load_auth_cookies expects.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError as e:
        raise RuntimeError(
            "Playwright not installed. Run: "
            "pip install -e '.[browser]' && playwright install chromium"
        ) from e

    print(f"\n[harvest] Launching {'real Chrome (headed)' if headed else 'headless Chromium'}...")
    async with async_playwright() as pw:
        # Use real Chrome channel when available — it has the correct TLS
        # fingerprint that DataDome won't flag at the edge.
        launch_kwargs = {
            "headless": not headed,
            "args": ["--disable-blink-features=AutomationControlled"],
        }
        try:
            launch_kwargs["channel"] = "chrome"
            browser = await pw.chromium.launch(**launch_kwargs)
        except Exception:
            # Fallback to bundled Chromium if real Chrome isn't installed
            launch_kwargs.pop("channel", None)
            browser = await pw.chromium.launch(**launch_kwargs)

        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/130.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 800},
            locale="en-US",
        )
        page = await context.new_page()
        print(f"[harvest] Navigating to {target_url}...")
        try:
            await page.goto(target_url, timeout=60_000, wait_until="networkidle")
        except Exception as e:
            print(f"[harvest] Navigation timeout/error (continuing anyway): {e}")
        print(f"[harvest] Waiting {wait_seconds_after_load}s for challenge to settle...")
        await asyncio.sleep(wait_seconds_after_load)

        if headed:
            print()
            print("=" * 70)
            print("  OPERATOR ACTION REQUIRED")
            print("=" * 70)
            print(f"  A Chrome window should be open at:")
            print(f"    {target_url}")
            print(f"  ")
            print(f"  If you see a CAPTCHA / 'verifying you are human' page,")
            print(f"  solve it now in the browser window. After the page shows")
            print(f"  the real target content, return here and press ENTER")
            print(f"  to capture the cookies.")
            print("=" * 70)
            try:
                # blocking input — works in CLI invocation
                input("\n  Press ENTER when the page shows real content (not the challenge)... ")
            except EOFError:
                # Non-interactive: just wait extra time then proceed
                await asyncio.sleep(30)

        all_cookies = await context.cookies()
        await browser.close()

    print(f"\n[harvest] Browser closed. Total cookies received: {len(all_cookies)}")
    interesting = [c for c in all_cookies if _is_interesting_cookie(c.get("name", ""))]
    print(f"[harvest] Anti-bot cookies identified: {len(interesting)}")
    for c in interesting:
        # Show a redacted preview so the operator sees what was captured
        # without leaking the full token to the terminal log.
        v = c.get("value", "")
        v_preview = (v[:8] + "…" + v[-4:]) if len(v) > 16 else v
        print(f"  → {c.get('domain'):<20} {c.get('name'):<25} = {v_preview} (len={len(v)})")
    return interesting


def write_cookies_to_scope(scope_path: Path, cookies: list[dict]) -> None:
    """Persist harvested cookies into scope.yaml's auth_cookies block.

    Reads the existing YAML, replaces / merges the auth_cookies key, and
    writes back. Comments + key ordering are not preserved (PyYAML limit) —
    if the operator wants a clean diff, they can re-format manually.
    """
    if not scope_path.is_file():
        raise FileNotFoundError(f"Scope file not found: {scope_path}")

    raw = scope_path.read_text()
    data = yaml.safe_load(raw) or {}

    # Convert Playwright cookie shape to our scope.auth_cookies shape.
    out_cookies = []
    for c in cookies:
        entry = {
            "name": c["name"],
            "value": c["value"],
            "domain": c.get("domain", ""),
            "path": c.get("path", "/"),
            "secure": bool(c.get("secure", True)),
            "httpOnly": bool(c.get("httpOnly", False)),
        }
        # Add expires if Playwright provided it (epoch seconds)
        if "expires" in c and c["expires"] not in (-1, 0, None):
            try:
                from datetime import datetime, timezone
                ts = float(c["expires"])
                entry["expires"] = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            except Exception:
                pass
        out_cookies.append(entry)

    # Merge with existing auth_cookies (de-dupe by (domain, name))
    existing = data.get("auth_cookies") or []
    if not isinstance(existing, list):
        existing = []
    by_key = {(e.get("domain", ""), e.get("name", "")): e for e in existing}
    for entry in out_cookies:
        by_key[(entry["domain"], entry["name"])] = entry  # overwrite/insert
    data["auth_cookies"] = list(by_key.values())

    # Write back. yaml.safe_dump with default_flow_style=False produces
    # a readable block style; sort_keys=False preserves operator-typed
    # field order for the top-level keys.
    new_yaml = yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
    scope_path.write_text(new_yaml)
    print(f"\n[harvest] Wrote {len(out_cookies)} cookie(s) to {scope_path}")
    print(f"[harvest] Total cookies in scope.auth_cookies: {len(data['auth_cookies'])}")


async def run_harvest(target_url: str, scope_path: str | Path,
                      headed: bool = True, wait_after_load: int = 10) -> int:
    """End-to-end: harvest cookies + persist to scope.yaml.

    Returns process exit code (0 = success, non-zero = error).
    """
    scope_path = Path(scope_path)
    if not scope_path.is_file():
        print(f"ERROR: scope file not found: {scope_path}", file=sys.stderr)
        return 2

    try:
        cookies = await harvest_cookies_via_real_chrome(
            target_url, headed=headed, wait_seconds_after_load=wait_after_load,
        )
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"ERROR during harvest: {e}", file=sys.stderr)
        return 4

    if not cookies:
        print("\n[harvest] No anti-bot cookies captured — challenge may not have")
        print("           been solved, or the target doesn't use a recognized vendor.")
        print("           Cookies seen but not persisted (not in our anti-bot whitelist).")
        return 1

    try:
        write_cookies_to_scope(scope_path, cookies)
    except Exception as e:
        print(f"ERROR persisting cookies: {e}", file=sys.stderr)
        return 5

    print("\n[harvest] DONE. Future scans will inject these cookies on every")
    print("           matching-domain request via http_get + browser_get.")
    print("           Cookies typically expire in 1-3 hours — re-run when blocked.")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """Entrypoint for `sentinel datadome-harvest`."""
    import argparse
    p = argparse.ArgumentParser(
        prog="sentinel datadome-harvest",
        description="Harvest anti-bot cookies (DataDome/Cloudflare/Akamai/etc.) "
                    "from a real-Chrome session and persist them into scope.yaml's "
                    "auth_cookies block. Subsequent scans use the cookies to bypass "
                    "the anti-bot challenge.",
    )
    p.add_argument("url", help="Target URL to visit + capture cookies from")
    p.add_argument("--scope", required=True, help="Path to engagement scope YAML")
    p.add_argument("--headless", action="store_true",
                    help="Use headless Chromium instead of real Chrome (FOR TESTING — "
                         "DataDome will block headless and you'll get no cookies)")
    p.add_argument("--wait-after-load", type=int, default=10,
                    help="Seconds to wait after page reaches 'networkidle' before "
                         "reading cookies (default 10)")
    args = p.parse_args(argv)
    return asyncio.run(run_harvest(
        args.url, args.scope,
        headed=not args.headless,
        wait_after_load=args.wait_after_load,
    ))


if __name__ == "__main__":
    sys.exit(main())
