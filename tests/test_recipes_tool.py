"""recon_recipes MCP tool — Phase B."""

from __future__ import annotations

import asyncio

from sentinel.agent.pentest.recipes_tool import recon_recipes, ALL_TOOLS


def _call(args: dict) -> dict:
    """Invoke the @tool-decorated handler. The SDK wraps it in a callable
    object; the underlying fn is exposed at .handler."""
    handler = recon_recipes.handler if hasattr(recon_recipes, "handler") else recon_recipes
    if asyncio.iscoroutinefunction(handler):
        return asyncio.run(handler(args))
    return handler(args)


def _text(result: dict) -> str:
    return result.get("content", [{}])[0].get("text", "")


def test_returns_recipe_for_known_tech():
    out = _call({"tech": "wordpress"})
    text = _text(out)
    assert "Recipe: wordpress" in text
    assert "wpscan" in text
    assert "corpus_search" in text  # mentions follow-up step


def test_returns_recipe_for_alias():
    out = _call({"tech": "openlitespeed"})
    text = _text(out)
    assert "Recipe:" in text
    assert "litespeed" in text.lower() or "lscache" in text.lower()


def test_no_recipe_falls_back_with_helpful_message():
    out = _call({"tech": "totally-fake-xyz"})
    text = _text(out)
    assert "No curated recipe" in text
    assert "request_brain_research" in text
    assert "corpus_search" in text


def test_empty_tech_returns_error():
    out = _call({"tech": ""})
    text = _text(out)
    assert text.startswith("ERROR:")
    assert out.get("is_error") is True


def test_substring_fingerprint_resolves():
    """Fingerprinted as 'WordPress 6.4.2' should still get the wordpress recipe."""
    out = _call({"tech": "WordPress 6.4.2"})
    text = _text(out)
    assert "Recipe:" in text
    assert "wpscan" in text


def test_all_tools_export():
    assert recon_recipes in ALL_TOOLS
    assert len(ALL_TOOLS) == 1
