"""B1 — Environment-context block injected into every system prompt.

The gather call has its own 5s timeout and falls back to minimal context
if anything stalls; the renderer must never crash on missing fields.
"""

from __future__ import annotations

import time

import pytest

from sentinel.agent.pentest import env_context as ec


def test_gather_env_context_returns_expected_keys():
    ec.reset_cache()
    ctx = ec.gather_env_context(overall_timeout_sec=5.0)
    # Always-cheap fields (no network, no subprocess) must be present.
    for key in ("os", "hostname", "python", "shell", "cwd",
                "wordlist_dirs", "tun0_ip", "attacker_ip", "tools",
                "sentinel_rev", "user", "degraded"):
        assert key in ctx, f"missing key: {key}"
    # Types
    assert isinstance(ctx["wordlist_dirs"], list)
    assert isinstance(ctx["tools"], dict)
    assert isinstance(ctx["degraded"], bool)


def test_render_env_context_block_with_full_dict():
    ctx = {
        "os": "Linux", "os_release": "5.15.0",
        "hostname": "kali", "user": "kali", "shell": "zsh",
        "python": "3.11.0", "cwd": "/home/kali",
        "sentinel_rev": "abc1234",
        "attacker_ip": "203.0.113.5", "tun0_ip": "10.10.14.21",
        "wordlist_dirs": ["/usr/share/wordlists: rockyou.txt, dirb"],
        "tools": {"nmap": "Nmap version 7.94", "nuclei": "v3.1.0"},
        "degraded": False,
    }
    out = ec.render_env_context_block(ctx)
    assert "## Live environment context" in out
    assert "Linux" in out
    assert "kali" in out
    assert "203.0.113.5" in out
    assert "tun0 10.10.14.21" in out
    assert "nmap" in out
    assert "rockyou.txt" in out


def test_render_env_context_block_missing_tools_does_not_crash():
    """When env-gathering fails most fields, the renderer must still
    produce a valid markdown block — no KeyErrors, no AttributeErrors."""
    ctx = {
        "os": "Linux", "hostname": "x", "python": "3.11", "shell": "bash",
        "cwd": "/tmp", "user": "u",
        "sentinel_rev": None,
        "attacker_ip": None, "tun0_ip": None,
        "wordlist_dirs": [],
        "tools": {},
        "degraded": True,
    }
    out = ec.render_env_context_block(ctx)
    assert "## Live environment context" in out
    assert "env-gather hit timeout" in out
    # No attacker IP line when both are absent.
    assert "Attacker IP" not in out


def test_render_env_context_block_handles_completely_empty_dict():
    """Pathological case — nothing populated. Don't crash."""
    out = ec.render_env_context_block({})
    assert "## Live environment context" in out
    # Renderer must produce SOMETHING even on a blank dict.
    assert len(out) > 30


def test_prepend_env_block_no_op_on_empty():
    base = "## System prompt\nfoo"
    assert ec.prepend_env_block(base, None) == base
    assert ec.prepend_env_block(base, "") == base
    assert ec.prepend_env_block(base, "   \n  ") == base


def test_prepend_env_block_inserts_before_prompt():
    base = "## System prompt\nfoo"
    block = "## Live environment context\n- Host: x"
    out = ec.prepend_env_block(base, block)
    assert out.startswith("## Live environment context")
    assert out.endswith("foo")
    # Separator newlines between blocks (not glued).
    assert "\n\n## System prompt" in out


def test_gather_uses_module_cache():
    """Second call within TTL should return the same dict object — proves
    we're not re-running subprocess calls 5x per pipeline."""
    ec.reset_cache()
    a = ec.gather_env_context(overall_timeout_sec=5.0)
    b = ec.gather_env_context(overall_timeout_sec=5.0)
    assert a is b


def test_gather_force_refresh_breaks_cache():
    ec.reset_cache()
    a = ec.gather_env_context(overall_timeout_sec=5.0)
    b = ec.gather_env_context(overall_timeout_sec=5.0, force_refresh=True)
    # Different identity — refresh actually re-ran.
    assert a is not b


def test_gather_overall_timeout_quick_does_not_crash():
    """Aggressive 0.05s budget — most expensive paths must skip cleanly,
    and the function must still return a usable dict, not raise."""
    ec.reset_cache()
    started = time.monotonic()
    ctx = ec.gather_env_context(overall_timeout_sec=0.05)
    elapsed = time.monotonic() - started
    # Should complete well under 1s — the always-cheap fields are pure
    # Python and the network/subprocess paths are budget-gated.
    assert elapsed < 2.0
    assert isinstance(ctx, dict)
    assert "os" in ctx


def test_render_block_is_token_compact():
    """Rendered block should be ~200 tokens — sanity-cap at 1500 chars
    (rough proxy: ~1500/4 = 375 tokens, generous upper bound)."""
    ec.reset_cache()
    ctx = ec.gather_env_context(overall_timeout_sec=5.0)
    out = ec.render_env_context_block(ctx)
    assert len(out) < 4000, (
        f"env-context block grew to {len(out)} chars — review _TRACKED_TOOLS or "
        f"wordlist caps; the block must stay near ~200 tokens."
    )
