"""WAF bypass intelligence — token regex matching + technique enumeration."""

from __future__ import annotations

from sentinel.agent.pentest.bypass_tool import (
    _BYPASS_TECHNIQUES, _TOKEN_PATTERNS, _TOKEN_PROBE_PATHS,
    _walk_for_tokens, _root_url,
)


def test_vercel_protection_bypass_token_is_recognized():
    body = '"x-vercel-protection-bypass": "abcDEF12345tokenXYZ_long_enough"'
    hits = []
    for kind, pat in _TOKEN_PATTERNS:
        for m in pat.finditer(body):
            hits.append((kind, m.group(1)))
    assert any(k == "vercel_protection_bypass" for k, _ in hits)


def test_cloudflare_bypass_token_is_recognized():
    body = "__cf_bypass=cf123456789abcdef"
    found = False
    for kind, pat in _TOKEN_PATTERNS:
        if kind == "cloudflare_bypass" and pat.search(body):
            found = True
    assert found


def test_aws_waf_token_is_recognized():
    body = 'x-amzn-waf-token: "wafabcdef0123456789TOKEN"'
    hits = [k for k, p in _TOKEN_PATTERNS if p.search(body)]
    assert "aws_waf_token" in hits


def test_techniques_list_is_exactly_six():
    assert len(_BYPASS_TECHNIQUES) == 6
    assert "header_smuggling" in _BYPASS_TECHNIQUES
    assert "vercel_token" in _BYPASS_TECHNIQUES
    assert "cloudflare_worker_direct" in _BYPASS_TECHNIQUES


def test_probe_paths_cover_common_token_locations():
    # robots/sitemap/manifest are non-negotiable.
    assert "/robots.txt" in _TOKEN_PROBE_PATHS
    assert "/sitemap.xml" in _TOKEN_PROBE_PATHS
    assert "/manifest.json" in _TOKEN_PROBE_PATHS
    # Next.js paths catch React/SSR apps where tokens leak in __NEXT_DATA__.
    assert any("_next/" in p for p in _TOKEN_PROBE_PATHS)


def test_walk_for_tokens_finds_nested_json_keys():
    findings: list[dict] = []
    doc = {
        "build": {
            "x-vercel-protection-bypass": "tok_super_secret_value_12345",
            "version": "1.0",
        },
        "irrelevant": [{"deploy-token": "another_secret_token_67890"}],
    }
    _walk_for_tokens(doc, "/manifest.json", "https://x/manifest.json", findings)
    kinds = {f["kind"] for f in findings}
    # Both the top-level and the nested-list match should appear.
    assert any("x-vercel-protection-bypass" in k for k in kinds)
    assert any("deploy-token" in k for k in kinds)


def test_root_url_strips_path_and_query():
    assert _root_url("https://example.com/foo/bar?a=1") == "https://example.com"
    assert _root_url("http://example.com:8080/x") == "http://example.com:8080"
