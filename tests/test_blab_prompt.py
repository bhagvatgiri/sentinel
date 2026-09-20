"""B2 — Business-Logic Abuse Backlog (BLAB) prompt section.

Every Phase 2 vuln-class prompt must enumerate 10–15 abuse hypotheses
with the 5-field BLAB shape before deep probing. Test that the BLAB
section is rendered for every supported class and that the template
carries all 5 required fields.
"""

from __future__ import annotations

import pytest

from sentinel.agent.pentest.vuln_classes import VULN_CLASSES
from sentinel.agent.pentest.vuln_prompts import (
    _BLAB_SECTION,
    _BLACKBOX_SPECTER_SECTION,
    render_vuln_prompt,
)


_REQUIRED_BLAB_FIELDS = (
    "Preconditions:",
    "Abuse idea:",
    "Validate:",
    "Success signal:",
    "Impact:",
)


def test_blab_section_constant_has_all_five_fields():
    for field in _REQUIRED_BLAB_FIELDS:
        assert field in _BLAB_SECTION, f"BLAB section missing required field: {field}"


def test_blab_section_demands_10_to_15_hypotheses():
    """The number range must be in the prompt — that's the directive."""
    text = _BLAB_SECTION
    assert "10" in text and "15" in text, (
        "BLAB prompt must specify the 10–15 hypothesis count range."
    )


def test_blab_section_writes_per_class_deliverable():
    """The blab_<slug>.md filename must be in the section so the agent
    knows where to write — the {slug} placeholder is filled per render."""
    assert "blab_{slug}.md" in _BLAB_SECTION


def test_blackbox_specter_section_has_six_fields():
    for field in ("Hypothesis:", "Source:", "Flow:", "Sink:",
                  "Confirmation:", "Evidence:"):
        assert field in _BLACKBOX_SPECTER_SECTION, (
            f"BLACKBOX_SPECTER section missing field: {field}"
        )


def test_all_twelve_vuln_classes_render_blab_section():
    """Every supported vuln class must include the BLAB scaffold."""
    assert len(VULN_CLASSES) == 12, (
        f"Expected 12 vuln classes, got {len(VULN_CLASSES)} — update test if "
        f"the class list intentionally changed."
    )
    for cls in VULN_CLASSES:
        prompt = render_vuln_prompt(
            cls, client="acme", engagement_id="test-001",
            target="https://test.example.com", workspace="/tmp/ws",
            audit_log="/tmp/audit.jsonl",
            max_pages=10, max_turns=20, max_budget_usd=1.0,
        )
        # BLAB filename gets the slug substituted in.
        assert f"blab_{cls.slug}.md" in prompt, (
            f"vuln class {cls.slug} prompt missing BLAB filename"
        )
        # Each of the 5 BLAB fields landed.
        for field in _REQUIRED_BLAB_FIELDS:
            assert field in prompt, (
                f"vuln class {cls.slug} prompt missing BLAB field: {field}"
            )
        # BLACKBOX_SPECTER scaffold is also in every class prompt (B3).
        for field in ("Hypothesis:", "Source:", "Flow:", "Sink:",
                      "Confirmation:", "Evidence:"):
            assert field in prompt, (
                f"vuln class {cls.slug} prompt missing BLACKBOX_SPECTER field: {field}"
            )


def test_render_vuln_prompt_with_env_block_prepends_correctly():
    """B1 + B2 integration — env block prefix doesn't displace BLAB."""
    cls = VULN_CLASSES[0]
    env_block = "## Live environment context\n- Host: kali"
    out = render_vuln_prompt(
        cls, client="c", engagement_id="e", target="https://t",
        workspace="/w", audit_log="/a",
        max_pages=10, max_turns=20, max_budget_usd=1.0,
        env_context_block=env_block,
    )
    assert out.startswith("## Live environment context")
    # BLAB still in the rendered output.
    assert "Business-Logic Abuse Backlog" in out
    assert "Abuse idea:" in out


def test_render_vuln_prompt_without_env_block_unchanged():
    """When env_context_block is omitted, prompt starts at the original
    template heading — backwards compat for older callers."""
    cls = VULN_CLASSES[0]
    out = render_vuln_prompt(
        cls, client="c", engagement_id="e", target="https://t",
        workspace="/w", audit_log="/a",
        max_pages=10, max_turns=20, max_budget_usd=1.0,
    )
    # Without env block, the prompt starts at the legacy template's
    # first line (the "You are Sentinel's Phase 2..." sentence).
    assert out.startswith("You are Sentinel's Phase 2 vulnerability-analysis agent")
