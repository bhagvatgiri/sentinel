"""Tests for the short-lived-token refresh engine."""

import base64
import json
import time

import pytest

from sentinel.agent.pentest import token_refresher as tr


def _make_jwt(exp: int) -> str:
    """Minimal unsigned-ish JWT with the given exp claim (header.payload.sig)."""
    header = base64.urlsafe_b64encode(b'{"alg":"EdDSA","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": 61812354, "exp": exp, "identity": "x@example.com"}).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def test_jwt_exp_decodes():
    exp = int(time.time()) + 300
    assert tr._jwt_exp(_make_jwt(exp)) == exp


def test_jwt_exp_non_jwt_returns_none():
    assert tr._jwt_exp("not-a-jwt") is None
    assert tr._jwt_exp("") is None
    assert tr._jwt_exp("a.b") is None  # only 1 dot


def test_seconds_remaining_tracks_access_token():
    exp = int(time.time()) + 200
    r = tr.TokenRefresher(
        host="www.ExampleMarket.com",
        refresh_url="https://www.ExampleMarket.com/account/settings/account",
        initial_jar={"__Secure-access-token": _make_jwt(exp)},
    )
    rem = r.seconds_remaining()
    assert 190 <= rem <= 200


def test_matches_host_and_subdomains():
    r = tr.TokenRefresher(
        host="ExampleMarket.com",
        refresh_url="https://www.ExampleMarket.com/x",
        initial_jar={"__Secure-access-token": _make_jwt(int(time.time()) + 300)},
    )
    assert r.matches("https://ExampleMarket.com/foo")
    assert r.matches("https://www.ExampleMarket.com/bar")
    assert r.matches("https://api.ExampleMarket.com/graphql")
    assert not r.matches("https://evil.com/")
    assert not r.matches("https://notwhatnot.com/")


def test_auth_headers_only_when_configured():
    base = dict(
        host="www.ExampleMarket.com",
        refresh_url="https://www.ExampleMarket.com/x",
        initial_jar={"__Secure-access-token": _make_jwt(int(time.time()) + 300)},
    )
    assert tr.TokenRefresher(**base).auth_headers() == {}
    r = tr.TokenRefresher(auth_header_name="authorization", auth_header_value="Cookie", **base)
    assert r.auth_headers() == {"authorization": "Cookie"}


@pytest.mark.asyncio
async def test_ensure_fresh_noop_when_token_valid():
    # Token valid well beyond margin → ensure_fresh must NOT make a network call.
    r = tr.TokenRefresher(
        host="www.ExampleMarket.com",
        refresh_url="https://invalid.invalid/should-not-be-called",
        initial_jar={"__Secure-access-token": _make_jwt(int(time.time()) + 300)},
        margin_sec=60,
    )
    # If it tried to hit the invalid URL it would raise/return False; valid → True
    assert await r.ensure_fresh() is True
    assert r.refresh_count == 0


def test_registry_lookup_and_clear():
    tr.clear_refreshers()
    r = tr.TokenRefresher(
        host="www.ExampleMarket.com",
        refresh_url="https://www.ExampleMarket.com/x",
        initial_jar={"__Secure-access-token": _make_jwt(int(time.time()) + 300)},
    )
    tr.register_refresher(r)
    assert tr.get_refresher_for_url("https://www.ExampleMarket.com/services/graphql") is r
    assert tr.get_refresher_for_url("https://other.com/") is None
    tr.clear_refreshers()
    assert tr.get_refresher_for_url("https://www.ExampleMarket.com/x") is None


def test_build_from_scope_requires_config():
    class FakeScope:
        auth_refresh = {}
        auth_cookies = []
    assert tr.build_from_scope(FakeScope()) == []

    class FakeScope2:
        auth_refresh = {"refresh_url": "https://www.ExampleMarket.com/account/settings/account",
                        "host": "www.ExampleMarket.com", "auth_header_name": "authorization",
                        "auth_header_value": "Cookie"}
        auth_cookies = [{"name": "__Secure-access-token", "value": _make_jwt(int(time.time()) + 300)}]
    tr.clear_refreshers()
    built = tr.build_from_scope(FakeScope2())
    assert len(built) == 1
    r = built[0]
    assert r.host == "www.ExampleMarket.com"
    assert r.name == "primary"  # single dict defaults to primary
    assert r.auth_headers() == {"authorization": "Cookie"}
    tr.clear_refreshers()


def test_build_from_scope_multi_account_bola():
    """auth_refresh as a list[dict] → attacker + victim sessions, both
    registered, first is the default; account selector routes to each."""
    jwt = _make_jwt(int(time.time()) + 300)
    class FakeScope:
        auth_refresh = [
            {"name": "primary", "host": "www.ExampleMarket.com",
             "refresh_url": "https://www.ExampleMarket.com/account/settings/account",
             "auth_header_name": "authorization", "auth_header_value": "Cookie"},
            {"name": "victim", "host": "www.ExampleMarket.com",
             "refresh_url": "https://www.ExampleMarket.com/account/settings/account",
             "auth_header_name": "authorization", "auth_header_value": "Cookie"},
        ]
        # No cookie_file → fall back to auth_cookies for the seed (both share
        # this in the test; in production each has its own cookie_file).
        auth_cookies = [{"name": "__Secure-access-token", "value": jwt}]
    tr.clear_refreshers()
    built = tr.build_from_scope(FakeScope())
    assert len(built) == 2
    assert {r.name for r in built} == {"primary", "victim"}
    # Default (no account) routes to primary
    d = tr.get_refresher_for_url("https://www.ExampleMarket.com/services/graphql")
    assert d is not None and d.name == "primary"
    # Explicit account routes to the named session
    v = tr.get_refresher_for_url("https://www.ExampleMarket.com/services/graphql", account="victim")
    assert v is not None and v.name == "victim"
    # Unknown account → None (caller surfaces an error)
    assert tr.get_refresher_for_url("https://www.ExampleMarket.com/x", account="nope") is None
    # Account that exists but wrong host → None
    assert tr.get_refresher_for_url("https://evil.com/", account="victim") is None
    tr.clear_refreshers()
