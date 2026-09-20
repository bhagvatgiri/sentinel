"""Curated tech-stack recipe library — Phase B."""

from __future__ import annotations

from sentinel.agent.pentest.tech_recipes import (
    TECH_RECIPES, all_aliases, all_techs, lookup,
)


def test_inventory_covers_critical_stacks():
    """The recipes that motivated this feature must exist."""
    must_have = [
        "wordpress", "litespeed", "nginx", "apache", "iis",
        "spring", "django", "rails", "laravel",
        "next.js", "react", "vue", "angular",
        "graphql",
        "cloudflare", "vercel", "akamai", "aws-cloudfront",
        "auth0", "okta",
    ]
    missing = [t for t in must_have if t not in TECH_RECIPES]
    assert not missing, f"missing critical recipes: {missing}"


def test_every_recipe_has_required_fields():
    for tech, r in TECH_RECIPES.items():
        for field in ("recon", "vuln_focus", "corpus_queries"):
            assert field in r, f"{tech!r} missing field {field!r}"
            assert isinstance(r[field], list), f"{tech!r}.{field} should be list"
            assert r[field], f"{tech!r}.{field} should not be empty"


def test_lookup_direct_hit():
    r = lookup("wordpress")
    assert r is not None
    assert any("wpscan" in cmd for cmd in r["recon"])


def test_lookup_case_insensitive():
    assert lookup("WordPress") is lookup("wordpress")
    assert lookup("LITESPEED") is lookup("litespeed")


def test_lookup_alias_resolves_to_canonical():
    assert lookup("openlitespeed") is TECH_RECIPES["litespeed"]
    assert lookup("nextjs") is TECH_RECIPES["next.js"]
    assert lookup("spring boot") is TECH_RECIPES["spring"]
    assert lookup("ror") is TECH_RECIPES["rails"]


def test_lookup_substring_fallback():
    """Fingerprinting often returns 'WordPress 6.4.2' — should still resolve."""
    r = lookup("WordPress 6.4.2")
    assert r is TECH_RECIPES["wordpress"]
    r = lookup("LiteSpeed/8.1.4")
    assert r is TECH_RECIPES["litespeed"]


def test_lookup_returns_none_for_unknown():
    assert lookup("totally-fake-stack-xyz") is None


def test_lookup_handles_empty():
    assert lookup("") is None
    assert lookup("   ") is None


def test_litespeed_has_cve_reference():
    """The motivating example: LiteSpeed Cache CVE-2024-28000."""
    r = lookup("litespeed")
    blob = " ".join(r["vuln_focus"]).lower()
    assert "cve-2024-28000" in blob or "litespeed" in blob


def test_no_alias_loops():
    """Aliases must resolve to canonical names that exist."""
    for alias, canonical in all_aliases().items():
        assert canonical in TECH_RECIPES, (
            f"alias {alias!r} → {canonical!r} but {canonical!r} not in TECH_RECIPES"
        )


def test_all_techs_returns_sorted_list():
    techs = all_techs()
    assert techs == sorted(techs)
    assert len(techs) == len(TECH_RECIPES)
