"""Smoke tests for B11 — CORS misconfig scanner.

Tests pure functions (_classify_response, scenarios list, vuln class
registration). Live network probes are not tested here.
"""

from __future__ import annotations

from sentinel.agent.pentest.cors_tool import (
    _classify_response,
    _corsy_available,
    _SCENARIOS,
    ALL_TOOLS,
)


def test_all_tools_export():
    assert isinstance(ALL_TOOLS, list)
    assert len(ALL_TOOLS) == 2
    names = {t.name for t in ALL_TOOLS}
    assert "test_cors_misconfig" in names
    assert "scan_cors_full" in names


def test_scenarios_cover_11_classes():
    """Defensive: the 11+ scenario count is the value prop."""
    assert len(_SCENARIOS) >= 11
    names = {s[0] for s in _SCENARIOS}
    assert "origin_reflection" in names
    assert "null_origin" in names
    assert "trusted_insecure_scheme" in names
    assert "third_party_subdomain" in names


def test_corsy_available_returns_pair():
    available, msg = _corsy_available()
    assert isinstance(available, bool)
    assert isinstance(msg, str)


# ───────── _classify_response ─────────

def test_no_acao_means_no_misconfig():
    is_mc, reason = _classify_response("origin_reflection",
                                        "https://attacker.example", None, None)
    assert is_mc is False
    assert "no ACAO" in reason


def test_origin_reflection_with_creds_is_misconfig():
    is_mc, reason = _classify_response(
        "origin_reflection",
        "https://attacker-test.example",
        "https://attacker-test.example",   # ACAO reflects
        "true",                              # ACAC: true
    )
    assert is_mc is True
    assert "credentials" in reason.lower() or "creds" in reason.lower()


def test_origin_reflection_without_creds_is_still_misconfig():
    """Reflection without creds is still a CORS issue (cross-origin
    read of public endpoint). Maybe lower severity but still flagged."""
    is_mc, reason = _classify_response(
        "origin_reflection",
        "https://attacker-test.example",
        "https://attacker-test.example",
        None,
    )
    assert is_mc is True
    assert "no creds" in reason.lower() or "no creds" in reason or "cross-origin" in reason.lower()


def test_null_origin_misconfig():
    is_mc, reason = _classify_response(
        "null_origin", "null", "null", None,
    )
    assert is_mc is True
    assert "null" in reason.lower()


def test_explicit_allowlist_not_misconfig():
    """Server returning ACAO=https://trusted.example.com is FINE — that's
    a deliberate allowlist, not a misconfig."""
    is_mc, reason = _classify_response(
        "origin_reflection",
        "https://attacker.example",
        "https://trusted-frontend.example",  # NOT what we sent
        "true",
    )
    assert is_mc is False
    assert "no misconfig" in reason or "allowlist" in reason


def test_wildcard_with_credentials_is_misconfig():
    """ACAO=* with ACAC=true is a spec violation (browsers may still honor
    it). Always flag."""
    is_mc, reason = _classify_response(
        "origin_reflection", "https://attacker.example",
        "*", "true",
    )
    assert is_mc is True
    assert "Allow-Origin=*" in reason or "wildcard" in reason.lower()


def test_wildcard_without_credentials_not_misconfig():
    """ACAO=* without ACAC is generally fine — public APIs use this."""
    is_mc, reason = _classify_response(
        "origin_reflection", "https://attacker.example", "*", None,
    )
    assert is_mc is False


def test_acao_case_insensitive_match():
    """Origin matching should ignore case (some servers normalize)."""
    is_mc, _ = _classify_response(
        "origin_reflection",
        "https://Attacker.Example",
        "HTTPS://ATTACKER.EXAMPLE",
        "true",
    )
    assert is_mc is True


def test_vuln_class_cors_registered():
    """The new vuln:cors class must appear in VULN_CLASSES so the
    pipeline includes it in Phase 2/3."""
    from sentinel.agent.pentest.vuln_classes import VULN_CLASSES, SLUG_TO_CLASS
    cors_class = next((c for c in VULN_CLASSES if c.slug == "cors"), None)
    assert cors_class is not None, "cors class not registered in VULN_CLASSES"
    assert cors_class.display == "CORS Misconfiguration"
    assert cors_class.default_cwe == "CWE-942"
    assert "cors" in SLUG_TO_CLASS


def test_cors_focus_block_in_vuln_prompts():
    """The vuln_prompts.py must have a per-class focus block for cors."""
    from sentinel.agent.pentest import vuln_prompts
    src = open(vuln_prompts.__file__).read()
    assert '"cors":' in src
    assert "Origin reflection" in src or "origin reflect" in src.lower()


def test_event_styles_register_cors_events():
    from sentinel.web.event_styles import EVENT_STYLES
    for kind in ("cors_probed", "cors_full_scan", "cors_misconfig_found"):
        assert kind in EVENT_STYLES
        assert EVENT_STYLES[kind]["group"] == "tool"
