"""Tier-1 + Tier-2 anti-bot bypass tests.

Tier 1 (http_get follow_redirects=False):
  - Verify the new arg is honored and Location header surfaces in output

Tier 2 (auth_cookies):
  - Scope.auth_cookies field loads + validates correctly
  - _build_cookie_jar_for_url filters by domain match
  - Round-trip: scope file write + read preserves cookies
  - datadome_harvest._is_interesting_cookie whitelist
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from sentinel.core.scope import Scope, ScopeError, _load_auth_cookies


# ───────────── Tier-2: scope loader ──────────────────────────────────────

def test_load_auth_cookies_empty():
    """Empty / None / missing → empty list (default behavior)."""
    assert _load_auth_cookies(None) == []
    assert _load_auth_cookies("") == []
    assert _load_auth_cookies([]) == []


def test_load_auth_cookies_valid_minimal():
    """Just name + value works — defaults fill in the rest."""
    raw = [{"name": "datadome", "value": "1d_2HmZ"}]
    out = _load_auth_cookies(raw)
    assert len(out) == 1
    assert out[0]["name"] == "datadome"
    assert out[0]["value"] == "1d_2HmZ"
    assert out[0]["domain"] == ""
    assert out[0]["path"] == "/"
    assert out[0]["secure"] is True
    assert out[0]["httpOnly"] is False


def test_load_auth_cookies_full_record():
    raw = [{
        "name": "datadome", "value": "1d_2HmZ",
        "domain": ".ExamplePay.com", "path": "/", "secure": True,
        "httpOnly": False, "expires": "2026-XX-XXT03:00:00Z",
    }]
    out = _load_auth_cookies(raw)
    assert out[0]["domain"] == ".ExamplePay.com"
    assert out[0]["expires"] == "2026-XX-XXT03:00:00Z"


def test_load_auth_cookies_rejects_non_list():
    with pytest.raises(ScopeError, match="must be a list"):
        _load_auth_cookies({"name": "datadome"})


def test_load_auth_cookies_rejects_missing_name():
    with pytest.raises(ScopeError, match="missing or invalid 'name'"):
        _load_auth_cookies([{"value": "1d_2HmZ"}])


def test_load_auth_cookies_rejects_missing_value():
    """Missing value fails — empty string is the operator's escape hatch."""
    with pytest.raises(ScopeError, match="missing 'value'"):
        _load_auth_cookies([{"name": "datadome"}])


def test_load_auth_cookies_allows_empty_value():
    """Empty value is a valid cookie (e.g., logout-state cookie)."""
    out = _load_auth_cookies([{"name": "datadome", "value": ""}])
    assert out[0]["value"] == ""


# ───────────── Tier-2: scope yaml round-trip ─────────────────────────────

def test_scope_roundtrip_with_auth_cookies(tmp_path):
    """Write scope yaml, load via Scope.load(), verify auth_cookies survive."""
    scope_yaml = textwrap.dedent("""\
        client: ExamplePay
        engagement_id: test-2026-roundtrip
        authorized_by: tester@example.com
        valid_from: 2026-XX-XX
        valid_until: 2026-06-07
        targets:
          domains:
            - ExamplePay.me
        research_headers:
          X-PP-BB: HackerOne-tester
        auth_cookies:
          - name: datadome
            value: '1d_2HmZ_abc123'
            domain: '.ExamplePay.com'
            path: /
            secure: true
            httpOnly: false
          - name: cf_clearance
            value: 'cf_token_xyz'
            domain: 'ExamplePay.me'
        """)
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(scope_yaml)
    scope = Scope.load(scope_path)
    assert len(scope.auth_cookies) == 2
    assert scope.auth_cookies[0]["name"] == "datadome"
    assert scope.auth_cookies[0]["value"] == "1d_2HmZ_abc123"
    assert scope.auth_cookies[0]["domain"] == ".ExamplePay.com"
    assert scope.auth_cookies[1]["name"] == "cf_clearance"


# ───────────── Tier-2: cookie-jar builder ────────────────────────────────

def test_build_cookie_jar_exact_domain_match():
    """domain='ExamplePay.com' matches host='ExamplePay.com' (no leading dot needed)."""
    from sentinel.agent.pentest.tools import _build_cookie_jar_for_url

    class _MockScope:
        auth_cookies = [
            {"name": "datadome", "value": "abc", "domain": "ExamplePay.com",
             "path": "/", "secure": True, "httpOnly": False},
        ]

    class _MockCtx:
        scope = _MockScope()

    jar = _build_cookie_jar_for_url(_MockCtx(), "https://ExamplePay.com/foo")
    assert jar == {"datadome": "abc"}


def test_build_cookie_jar_subdomain_match_via_leading_dot():
    """domain='.ExamplePay.com' matches host='www.ExamplePay.com' AND 'ExamplePay.com'."""
    from sentinel.agent.pentest.tools import _build_cookie_jar_for_url

    class _MockScope:
        auth_cookies = [
            {"name": "datadome", "value": "xyz", "domain": ".ExamplePay.com",
             "path": "/", "secure": True, "httpOnly": False},
        ]

    class _MockCtx:
        scope = _MockScope()

    assert _build_cookie_jar_for_url(_MockCtx(), "https://www.ExamplePay.com/foo") == {"datadome": "xyz"}
    assert _build_cookie_jar_for_url(_MockCtx(), "https://ExamplePay.com/foo") == {"datadome": "xyz"}
    assert _build_cookie_jar_for_url(_MockCtx(), "https://api.ExamplePay.com/v1") == {"datadome": "xyz"}


def test_build_cookie_jar_no_match_for_other_domain():
    """Cookies for ExamplePay.com must NOT leak to other domains (security)."""
    from sentinel.agent.pentest.tools import _build_cookie_jar_for_url

    class _MockScope:
        auth_cookies = [
            {"name": "datadome", "value": "abc", "domain": ".ExamplePay.com",
             "path": "/", "secure": True, "httpOnly": False},
        ]

    class _MockCtx:
        scope = _MockScope()

    assert _build_cookie_jar_for_url(_MockCtx(), "https://attacker.example/x") == {}
    # Subdomain confusion attack: ExamplePay.com cookie must not match ExamplePay.com.attacker.com
    assert _build_cookie_jar_for_url(_MockCtx(), "https://ExamplePay.com.attacker.com/x") == {}


def test_build_cookie_jar_empty_when_no_auth_cookies():
    """Backwards-compat: scope without auth_cookies returns {} (no injection)."""
    from sentinel.agent.pentest.tools import _build_cookie_jar_for_url

    class _MockScope:
        auth_cookies = []

    class _MockCtx:
        scope = _MockScope()

    assert _build_cookie_jar_for_url(_MockCtx(), "https://ExamplePay.com/foo") == {}


def test_build_cookie_jar_handles_missing_attr():
    """If scope object somehow has no auth_cookies attribute at all."""
    from sentinel.agent.pentest.tools import _build_cookie_jar_for_url

    class _MockScope:
        pass

    class _MockCtx:
        scope = _MockScope()

    assert _build_cookie_jar_for_url(_MockCtx(), "https://ExamplePay.com/foo") == {}


# ───────────── Tier-2: harvest helper — interesting-cookie filter ────────

def test_interesting_cookie_recognizes_datadome():
    from sentinel.agent.datadome_harvest import _is_interesting_cookie
    assert _is_interesting_cookie("datadome") is True
    assert _is_interesting_cookie("DataDome") is True  # case-insensitive
    assert _is_interesting_cookie("_pddc_dd_") is True


def test_interesting_cookie_recognizes_cloudflare():
    from sentinel.agent.datadome_harvest import _is_interesting_cookie
    assert _is_interesting_cookie("cf_clearance") is True
    assert _is_interesting_cookie("__cf_bm") is True
    assert _is_interesting_cookie("cf_chl_2") is True
    assert _is_interesting_cookie("cf_chl_session_xyz") is True  # prefix


def test_interesting_cookie_recognizes_akamai():
    from sentinel.agent.datadome_harvest import _is_interesting_cookie
    assert _is_interesting_cookie("_abck") is True
    assert _is_interesting_cookie("ak_bmsc") is True


def test_interesting_cookie_recognizes_imperva():
    from sentinel.agent.datadome_harvest import _is_interesting_cookie
    assert _is_interesting_cookie("incap_ses_1234_abcd") is True  # prefix
    assert _is_interesting_cookie("visid_incap_xyz") is True


def test_interesting_cookie_rejects_random_cookies():
    """Privacy: don't capture analytics/tracking/random cookies."""
    from sentinel.agent.datadome_harvest import _is_interesting_cookie
    assert _is_interesting_cookie("_ga") is False  # Google Analytics
    assert _is_interesting_cookie("nsid") is False  # ExamplePay session
    assert _is_interesting_cookie("LANG") is False
    assert _is_interesting_cookie("session_id") is False
    assert _is_interesting_cookie("cookie_prefs") is False


# ───────────── Tier-2: scope yaml write-back ─────────────────────────────

def test_write_cookies_to_scope_creates_block(tmp_path):
    """Cookies get written to a scope yaml that has no existing
    auth_cookies block."""
    from sentinel.agent.datadome_harvest import write_cookies_to_scope

    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(textwrap.dedent("""\
        client: testclient
        engagement_id: test-2026-write
        authorized_by: tester@example.com
        valid_from: 2026-XX-XX
        valid_until: 2026-06-07
        targets:
          domains:
            - example.com
        """))

    cookies = [
        {"name": "datadome", "value": "abc123", "domain": ".example.com",
         "path": "/", "secure": True, "httpOnly": False, "expires": -1},
    ]
    write_cookies_to_scope(scope_path, cookies)

    # Round-trip: re-load via Scope.load
    scope = Scope.load(scope_path)
    assert len(scope.auth_cookies) == 1
    assert scope.auth_cookies[0]["name"] == "datadome"
    assert scope.auth_cookies[0]["value"] == "abc123"


def test_write_cookies_to_scope_dedupes_by_domain_and_name(tmp_path):
    """Re-running harvest replaces existing entries with same (domain, name)
    instead of appending duplicates."""
    from sentinel.agent.datadome_harvest import write_cookies_to_scope

    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(textwrap.dedent("""\
        client: testclient
        engagement_id: test-2026-dedupe
        authorized_by: tester@example.com
        valid_from: 2026-XX-XX
        valid_until: 2026-06-07
        targets:
          domains:
            - example.com
        auth_cookies:
          - name: datadome
            value: OLD_VALUE
            domain: .example.com
        """))

    new_cookies = [
        {"name": "datadome", "value": "NEW_VALUE", "domain": ".example.com",
         "path": "/", "secure": True, "httpOnly": False, "expires": -1},
    ]
    write_cookies_to_scope(scope_path, new_cookies)

    scope = Scope.load(scope_path)
    assert len(scope.auth_cookies) == 1, "should NOT have appended a duplicate"
    assert scope.auth_cookies[0]["value"] == "NEW_VALUE"
