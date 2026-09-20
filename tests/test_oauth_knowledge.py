"""Tier 3 #7 — OAuth knowledge patterns + brain seeds are present and wired."""
from __future__ import annotations

from sentinel.agent.pentest import oauth_knowledge as ok


def test_test_patterns_cover_core_rfc_clauses():
    p = ok.OAUTH_TEST_PATTERNS.lower()
    for needle in ("redirect_uri", "state", "pkce", "refresh-token rotation",
                   "rfc 9700", "noauth", "mix-up"):
        assert needle in p, f"OAUTH_TEST_PATTERNS missing {needle!r}"


def test_test_patterns_reference_the_new_tools():
    p = ok.OAUTH_TEST_PATTERNS
    assert "oauth_install_app" in p
    assert "oauth_rfc_audit" in p or "oauth_refresh_replay" in p


def test_brain_seed_topics_non_empty_and_oauth():
    assert len(ok.OAUTH_BRAIN_SEED_TOPICS) >= 5
    assert all(isinstance(t, str) and t for t in ok.OAUTH_BRAIN_SEED_TOPICS)
    joined = " ".join(ok.OAUTH_BRAIN_SEED_TOPICS).lower()
    assert "oauth" in joined and "9700" in joined


def test_patterns_injected_into_auth_focus_block():
    """The auth vuln-agent focus block must carry the test-for-X checklist."""
    from sentinel.agent.pentest.vuln_prompts import _FOCUS_BLOCKS
    auth = _FOCUS_BLOCKS["auth"]
    assert "test-for-X checklist" in auth or "redirect_uri validation" in auth
    # Tier-1 refresh-rotation guidance still present (not clobbered)
    assert "RFC 6749 §10.4" in auth or "oauth_install_app" in auth
