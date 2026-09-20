"""Tier 2 (2026-XX-XX) — vuln:race / exploit:race wiring tests.

These guard the three contracts that must hold for the race-conditions
vuln class to actually fire in the autonomous pipeline:

  1. VULN_CLASSES has the `race` entry (with CWE-362 + the long summary).
  2. _FOCUS_BLOCKS["race"] is non-empty (otherwise render_vuln_prompt
     would KeyError when the pipeline tries to build the prompt).
  3. ModelRouter routes vuln:race + exploit:race to Opus via the
     vuln:/exploit: prefix fallback in `_apply_anthropic_baseline`.

Plus the scope-field contract: race_test_concurrent_max is opt-in, defaults
to None (tool's built-in 50 wins), and is validated at scope-load time.
"""

from __future__ import annotations


def test_race_is_in_vuln_classes():
    from sentinel.agent.pentest.vuln_classes import VULN_CLASSES, SLUG_TO_CLASS
    slugs = [v.slug for v in VULN_CLASSES]
    assert "race" in slugs, f"race slug missing from VULN_CLASSES; got {slugs}"
    cls = SLUG_TO_CLASS["race"]
    assert cls.default_cwe == "CWE-362"
    assert cls.display == "Race Conditions / TOCTOU"
    # Summary should describe the burst-detection technique
    assert "concurrent" in cls.summary.lower() or "burst" in cls.summary.lower()
    assert "TOCTOU" in cls.summary or "race" in cls.summary.lower()


def test_vuln_classes_count_grew_to_17():
    """Regression guard — the class count is meant to grow only when a new
    class is intentionally added (each new class adds a vuln + exploit
    phase pair, which is real model-spend on every run)."""
    from sentinel.agent.pentest.vuln_classes import VULN_CLASSES
    assert len(VULN_CLASSES) == 17, (
        f"VULN_CLASSES count changed unexpectedly: {len(VULN_CLASSES)} "
        f"(was 16 before 'novel' zero-day class added 2026-XX-XX; 15 before "
        f"'race' 2026-XX-XX). If you added or removed a class, update this."
    )


def test_race_focus_block_exists_and_is_meaningful():
    from sentinel.agent.pentest.vuln_prompts import _FOCUS_BLOCKS
    assert "race" in _FOCUS_BLOCKS, "race focus block missing"
    block = _FOCUS_BLOCKS["race"]
    assert isinstance(block, str) and len(block) > 500
    # Must mention the burst tool by name so the agent picks it up
    assert "race_request" in block
    # Must describe the candidate endpoint patterns
    assert "wallet" in block.lower() or "balance" in block.lower()
    assert "promo" in block.lower() or "coupon" in block.lower()
    # Must describe the state-diff signal definition
    assert "state" in block.lower() and "diff" in block.lower()
    # Must call out the rate-limit-as-defense OOS trap
    assert "rate" in block.lower() and "limit" in block.lower()


def test_render_vuln_prompt_includes_race_focus():
    """Building the actual prompt for the race class must not KeyError
    and must inline the focus block."""
    from sentinel.agent.pentest.vuln_classes import SLUG_TO_CLASS
    from sentinel.agent.pentest.vuln_prompts import render_vuln_prompt

    cls = SLUG_TO_CLASS["race"]
    out = render_vuln_prompt(
        cls,
        client="acme",
        engagement_id="2026-test",
        target="https://example.com",
        workspace="/tmp/ws",
        audit_log="/tmp/audit.jsonl",
        max_pages=10,
        max_turns=20,
        max_budget_usd=5.0,
    )
    assert isinstance(out, str) and len(out) > 1000
    assert "race_request" in out
    # The class display name should be in the prompt header
    assert "Race Conditions" in out or "TOCTOU" in out


def test_model_router_routes_vuln_race_to_opus():
    from sentinel.agent.model_router import ModelRouter
    router = ModelRouter()
    model = router.phase_model("vuln:race")
    assert "opus" in model.lower(), f"vuln:race should route to opus, got {model}"


def test_model_router_routes_exploit_race_to_opus():
    from sentinel.agent.model_router import ModelRouter
    router = ModelRouter()
    model = router.phase_model("exploit:race")
    assert "opus" in model.lower(), f"exploit:race should route to opus, got {model}"


# ---- scope-field contract ----------------------------------------------


def test_scope_race_test_concurrent_max_defaults_to_none(tmp_path):
    """Default scope.yaml (no race_test_concurrent_max key) must load
    with the field at None — back-compat, tool's built-in 50 applies."""
    from sentinel.core.scope import Scope
    yaml_text = """
client: acme
engagement_id: 2026-test
authorized_by: jack@acme.com
valid_from: 2026-01-01
valid_until: 2030-01-01
targets:
  domains: [example.com]
"""
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml_text)
    s = Scope.load(scope_path)
    assert s.race_test_concurrent_max is None


def test_scope_race_test_concurrent_max_accepts_valid_int(tmp_path):
    from sentinel.core.scope import Scope
    yaml_text = """
client: acme
engagement_id: 2026-test
authorized_by: jack@acme.com
valid_from: 2026-01-01
valid_until: 2030-01-01
targets:
  domains: [example.com]
race_test_concurrent_max: 75
"""
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml_text)
    s = Scope.load(scope_path)
    assert s.race_test_concurrent_max == 75


def test_scope_race_test_concurrent_max_zero_disables(tmp_path):
    """0 is the documented opt-out — race testing disabled entirely."""
    from sentinel.core.scope import Scope
    yaml_text = """
client: acme
engagement_id: 2026-test
authorized_by: jack@acme.com
valid_from: 2026-01-01
valid_until: 2030-01-01
targets:
  domains: [example.com]
race_test_concurrent_max: 0
"""
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml_text)
    s = Scope.load(scope_path)
    assert s.race_test_concurrent_max == 0


def test_scope_race_test_concurrent_max_rejects_over_ceiling(tmp_path):
    """> 100 must fail loud at scope-load time (operator typo guard)."""
    import pytest
    from sentinel.core.scope import Scope, ScopeError
    yaml_text = """
client: acme
engagement_id: 2026-test
authorized_by: jack@acme.com
valid_from: 2026-01-01
valid_until: 2030-01-01
targets:
  domains: [example.com]
race_test_concurrent_max: 500
"""
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml_text)
    with pytest.raises(ScopeError, match="race_test_concurrent_max"):
        Scope.load(scope_path)


def test_scope_race_test_concurrent_max_rejects_negative(tmp_path):
    import pytest
    from sentinel.core.scope import Scope, ScopeError
    yaml_text = """
client: acme
engagement_id: 2026-test
authorized_by: jack@acme.com
valid_from: 2026-01-01
valid_until: 2030-01-01
targets:
  domains: [example.com]
race_test_concurrent_max: -1
"""
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml_text)
    with pytest.raises(ScopeError, match="race_test_concurrent_max"):
        Scope.load(scope_path)


def test_scope_race_test_concurrent_max_rejects_non_int(tmp_path):
    """String / float must NOT silently coerce — this is security-relevant."""
    import pytest
    from sentinel.core.scope import Scope, ScopeError
    yaml_text = """
client: acme
engagement_id: 2026-test
authorized_by: jack@acme.com
valid_from: 2026-01-01
valid_until: 2030-01-01
targets:
  domains: [example.com]
race_test_concurrent_max: "50"
"""
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml_text)
    with pytest.raises(ScopeError, match="race_test_concurrent_max"):
        Scope.load(scope_path)


def test_pipeline_vuln_phase_includes_race_tool():
    """The vuln phase tool list must include race_request — otherwise
    vuln:race fires but the agent has no burst tool to call."""
    import re
    from pathlib import Path
    src = Path("sentinel/agent/pentest/pipeline.py").read_text()
    # Look at the _run_vuln_phase tool-list region — it's the block ending
    # with handoff_tool('retester', source_phase=f"vuln:{cls.slug}").
    # The simplest contract: p_race.ALL_TOOLS appears in the tool palette
    # both for exploit AND vuln. Count of p_race.ALL_TOOLS occurrences in
    # the file should be at least 2 now.
    occurrences = len(re.findall(r"\bp_race\.ALL_TOOLS\b", src))
    assert occurrences >= 2, (
        f"p_race.ALL_TOOLS expected to appear in BOTH vuln-phase and "
        f"exploit-phase tool palettes; found {occurrences} occurrence(s)."
    )
