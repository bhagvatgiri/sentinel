"""Tests for the pentest-tool-selection skill loader and prompt injection.

Covers T5S-01:
- Test A: load_tool_selection_skill() returns a non-empty, frontmatter-free body.
- Test B: render_vuln_prompt, render_exploit_prompt, and render_recon_prompt each
  contain the tool-selection guidance phrase.

All tests are hermetic — no network, no filesystem writes.
"""

import pytest

from sentinel.agent.pentest.skill_loader import load_tool_selection_skill
from sentinel.agent.pentest.vuln_classes import VULN_CLASSES
from sentinel.agent.pentest.vuln_prompts import render_vuln_prompt
from sentinel.agent.pentest.exploit_prompts import render_exploit_prompt
from sentinel.agent.pentest.prompt import render_recon_prompt


# ---------------------------------------------------------------------------
# Shared render kwargs
# ---------------------------------------------------------------------------

_KW = dict(
    client="test-client",
    engagement_id="test-eng-001",
    target="https://x.test",
    workspace="/tmp/test-workspace",
    audit_log="/tmp/test.audit.jsonl",
    max_pages=10,
    max_turns=10,
    max_budget_usd=1.0,
)


# ---------------------------------------------------------------------------
# Test A — loader
# ---------------------------------------------------------------------------

class TestSkillLoader:
    """Verify load_tool_selection_skill() loader contract."""

    def test_returns_nonempty_string(self):
        body = load_tool_selection_skill()
        assert isinstance(body, str)
        assert len(body) > 0, "Expected non-empty skill body"

    def test_contains_tool_first_phrase(self):
        body = load_tool_selection_skill()
        assert "TOOL-FIRST" in body, "Distinctive phrase 'TOOL-FIRST' missing from skill body"

    def test_frontmatter_stripped_no_delimiter(self):
        body = load_tool_selection_skill()
        first_line = body.split("\n")[0]
        assert first_line.strip() != "---", (
            "First line of body is a frontmatter delimiter — frontmatter was not stripped"
        )

    def test_frontmatter_key_not_leaked(self):
        body = load_tool_selection_skill()
        assert "name: pentest-tool-selection" not in body, (
            "Frontmatter key 'name: pentest-tool-selection' leaked into skill body"
        )

    def test_cached_returns_same_object(self):
        """lru_cache means repeated calls return the exact same string object."""
        b1 = load_tool_selection_skill()
        b2 = load_tool_selection_skill()
        # Either the same object (cached) or equal value — both are acceptable;
        # different objects with the same value would still satisfy the spec.
        assert b1 == b2


# ---------------------------------------------------------------------------
# Test B — injection into all three rendered prompts
# ---------------------------------------------------------------------------

class TestSkillInjectionIntoPrompts:
    """Verify that all three phase prompts carry the tool-selection block."""

    def test_vuln_prompt_contains_tool_first(self):
        rendered = render_vuln_prompt(VULN_CLASSES[0], **_KW)
        assert "TOOL-FIRST" in rendered, (
            "render_vuln_prompt output missing 'TOOL-FIRST' tool-selection phrase"
        )

    def test_vuln_prompt_contains_mandatory_header(self):
        rendered = render_vuln_prompt(VULN_CLASSES[0], **_KW)
        assert "Tool selection (MANDATORY" in rendered, (
            "render_vuln_prompt output missing '## Tool selection (MANDATORY' header"
        )

    def test_exploit_prompt_contains_tool_first(self):
        rendered = render_exploit_prompt(VULN_CLASSES[0], **_KW)
        assert "TOOL-FIRST" in rendered, (
            "render_exploit_prompt output missing 'TOOL-FIRST' tool-selection phrase"
        )

    def test_exploit_prompt_contains_mandatory_header(self):
        rendered = render_exploit_prompt(VULN_CLASSES[0], **_KW)
        assert "Tool selection (MANDATORY" in rendered, (
            "render_exploit_prompt output missing '## Tool selection (MANDATORY' header"
        )

    def test_recon_prompt_contains_tool_first(self):
        rendered = render_recon_prompt(**_KW)
        assert "TOOL-FIRST" in rendered, (
            "render_recon_prompt output missing 'TOOL-FIRST' tool-selection phrase"
        )

    def test_recon_prompt_contains_mandatory_header(self):
        rendered = render_recon_prompt(**_KW)
        assert "Tool selection (MANDATORY" in rendered, (
            "render_recon_prompt output missing '## Tool selection (MANDATORY' header"
        )

    def test_all_three_contain_run_tools_not_curl(self):
        """Alternative distinctive phrase from the injected header."""
        rendered_vuln = render_vuln_prompt(VULN_CLASSES[0], **_KW)
        rendered_exploit = render_exploit_prompt(VULN_CLASSES[0], **_KW)
        rendered_recon = render_recon_prompt(**_KW)
        for name, rendered in [
            ("vuln", rendered_vuln),
            ("exploit", rendered_exploit),
            ("recon", rendered_recon),
        ]:
            assert "run tools, not curl" in rendered, (
                f"render_{name}_prompt output missing 'run tools, not curl'"
            )


# ---------------------------------------------------------------------------
# Test C — production wiring (regression guard)
# ---------------------------------------------------------------------------
# The recon skill injection is only real if the PIPELINE renders its recon
# system prompt through render_recon_prompt(). An earlier pass added the helper
# but left pipeline.py formatting the raw RECON_PROMPT constant directly, so the
# recon agent never saw the block (tests passed because they called the helper
# directly). These guards assert the production callsite uses the helper.

class TestPipelineWiring:
    """Guard against the recon prompt regressing to the raw constant."""

    def _pipeline_source(self) -> str:
        import inspect
        import sentinel.agent.pentest.pipeline as pipeline
        return inspect.getsource(pipeline)

    def test_pipeline_uses_render_recon_prompt(self):
        assert "render_recon_prompt(" in self._pipeline_source(), (
            "pipeline.py must build the recon system prompt via "
            "render_recon_prompt() so the tool-selection block is injected"
        )

    def test_pipeline_does_not_format_raw_recon_prompt(self):
        assert "RECON_PROMPT.format" not in self._pipeline_source(), (
            "pipeline.py formats the raw RECON_PROMPT constant — this bypasses "
            "the tool-selection injection. Use render_recon_prompt() instead."
        )
