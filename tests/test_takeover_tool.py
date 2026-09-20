"""Smoke tests for B6/B14 — subdomain takeover probe.

Tests the pure functions (signature matching). Network-side functions
(_resolve_cname, _fetch_apex_body) are not exercised here — they're
covered by integration tests with a controlled DNS/HTTP fixture.
"""

from __future__ import annotations

from sentinel.agent.pentest.takeover_tool import (
    _FINGERPRINTS,
    _match_signatures,
)


def test_fingerprints_table_is_populated():
    """Defensive — the table is the value prop of this tool. Confirm it has
    the major service classes that drive H1 bounties."""
    assert len(_FINGERPRINTS) >= 30
    services = {svc for _, _, svc in _FINGERPRINTS}
    # The recurring high-bounty services must be present.
    must_have = {
        "GitHub Pages", "Heroku", "AWS S3",
        "Shopify", "Tumblr", "Vercel", "Netlify",
    }
    missing = must_have - {s.split(" (")[0] for s in services}
    assert not missing, f"missing fingerprint entries: {missing}"


def test_match_returns_empty_for_unrelated_cname():
    """Apex CNAME pointing at a non-fingerprinted host should produce no match."""
    assert _match_signatures(["www.example.com"]) == []
    assert _match_signatures([]) == []


def test_match_detects_github_pages():
    matches = _match_signatures(["org-name.github.io"])
    assert len(matches) >= 1
    assert any("GitHub Pages" in svc for _, _, svc in matches)


def test_match_detects_heroku():
    matches = _match_signatures(["app-name.herokuapp.com"])
    assert any("Heroku" in svc for _, _, svc in matches)


def test_match_detects_s3_bucket():
    matches = _match_signatures(["bucket-name.s3.amazonaws.com"])
    services = {svc for _, _, svc in matches}
    assert any("S3" in svc for svc in services)


def test_match_detects_shopify():
    matches = _match_signatures(["mystore.myshopify.com"])
    assert any("Shopify" in svc for _, _, svc in matches)


def test_match_detects_azure_web():
    matches = _match_signatures(["app.azurewebsites.net"])
    assert any("Azure" in svc for _, _, svc in matches)


def test_match_detects_vercel():
    matches = _match_signatures(["app.vercel.app"])
    assert any("Vercel" in svc for _, _, svc in matches)


def test_match_walks_full_chain():
    """If CNAME chain is multi-hop, ALL hops are matched, not just the first."""
    chain = ["alias.example.com", "stage.herokuapp.com"]
    matches = _match_signatures(chain)
    assert any("Heroku" in svc for _, _, svc in matches)


def test_match_dedupes_within_a_single_chain():
    """If the same (pattern, marker, service) tuple is hit twice across the
    chain, only one match — but distinct marker variants for the same service
    are kept (they're different signatures, not redundant). The fingerprint
    table has 2 Heroku entries with different markers ('No such app' vs
    'no-such-app'), so a 2-CNAME chain that's all Heroku produces 2 matches."""
    chain = ["alias.herokuapp.com", "stage.herokuapp.com"]
    matches = _match_signatures(chain)
    distinct_tuples = {(p, m, s) for p, m, s in matches}
    # 2 distinct fingerprint tuples for Heroku → 2 unique matches after dedup
    assert len(distinct_tuples) == len(matches), "dedup left duplicates"
    assert len(matches) == 2  # both heroku marker variants kept


def test_all_tools_export():
    from sentinel.agent.pentest.takeover_tool import ALL_TOOLS
    assert isinstance(ALL_TOOLS, list)
    assert len(ALL_TOOLS) >= 1
    for t in ALL_TOOLS:
        assert hasattr(t, "name")
