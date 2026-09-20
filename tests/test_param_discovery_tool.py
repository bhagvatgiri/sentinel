"""Smoke tests for B5 — hidden parameter discovery."""

from __future__ import annotations

from sentinel.agent.pentest.param_discovery_tool import (
    _HIGH_VALUE_PARAMS,
    ALL_TOOLS,
)


def test_all_tools_export():
    assert isinstance(ALL_TOOLS, list)
    assert len(ALL_TOOLS) == 1
    assert ALL_TOOLS[0].name == "discover_hidden_params"


def test_wordlist_starts_with_high_signal_params():
    """The first 30 entries should include the most-likely-to-hit auth
    bypass + debug toggle params."""
    first_30 = set(_HIGH_VALUE_PARAMS[:30])
    must_have = {"admin", "is_admin", "role", "debug", "test"}
    missing = must_have - first_30
    assert not missing, f"high-value params missing from first 30: {missing}"


def test_wordlist_size_at_least_100():
    """Defensive: wordlist must be large enough that wordlist_size=100
    actually has 100 entries to use."""
    assert len(_HIGH_VALUE_PARAMS) >= 100


def test_wordlist_no_duplicates():
    assert len(_HIGH_VALUE_PARAMS) == len(set(_HIGH_VALUE_PARAMS))


def test_wordlist_covers_idor_fuel():
    """ID-lookup params (id, user_id, etc.) feed IDOR finding hypotheses."""
    idor_fuel = {"id", "user_id", "uid", "account_id", "owner_id"}
    found = idor_fuel & set(_HIGH_VALUE_PARAMS)
    assert len(found) >= 4, f"too few IDOR-fuel params (got {found})"


def test_wordlist_covers_ssrf_fuel():
    ssrf_fuel = {"url", "callback", "redirect", "next", "src", "uri"}
    found = ssrf_fuel & set(_HIGH_VALUE_PARAMS)
    assert len(found) >= 4, f"too few SSRF-fuel params (got {found})"


def test_event_styles_register_param_events():
    from sentinel.web.event_styles import EVENT_STYLES
    assert "hidden_params_scan" in EVENT_STYLES
    assert "hidden_param_found" in EVENT_STYLES
