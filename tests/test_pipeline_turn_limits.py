"""Regression guard: pipeline phase turn limits are sane for the work each phase does.

Caught during live ExampleChat scan when verify-phase-03 (PoC sandbox) kept hitting
'Reached maximum number of turns (3)' — too tight for authenticated PoC gen.
"""
from __future__ import annotations
import pytest


def test_poc_sandbox_max_turns_is_configurable_and_default_at_least_30():
    """The PoC sandbox (verify-phase-03) max_turns should be a config field, default >= 30."""
    from sentinel.agent.pentest.pipeline import PipelineConfig
    cfg = PipelineConfig(target="https://example.com", scope_path="/tmp/scope.yaml")
    assert hasattr(cfg, "poc_sandbox_max_turns"), (
        "PipelineConfig must expose poc_sandbox_max_turns config field"
    )
    assert cfg.poc_sandbox_max_turns >= 30, (
        f"PoC sandbox max_turns too tight: {cfg.poc_sandbox_max_turns} — needs >= 30 "
        f"for multi-step authenticated PoC generation"
    )


def test_chain_max_steps_per_chain_at_least_25():
    """Chain attacks need enough steps to construct multi-stage exploits."""
    from sentinel.agent.pentest.pipeline import PipelineConfig
    cfg = PipelineConfig(target="https://example.com", scope_path="/tmp/scope.yaml")
    assert cfg.chain_max_steps_per_chain >= 25, (
        f"chain_max_steps_per_chain={cfg.chain_max_steps_per_chain} too tight for "
        f"multi-stage chain construction — needs >= 25"
    )


def test_pipeline_no_hardcoded_max_turns_3():
    """Sanity check: no lingering hardcoded max_turns=3 in pipeline.py.

    The previous code had max_turns=3 hardcoded for the PoC sandbox phase,
    which broke live PoCs. This test guards against regressing to a hardcoded value.
    """
    import inspect
    from sentinel.agent.pentest import pipeline
    src = inspect.getsource(pipeline)
    # Find any naked `max_turns=3,` or `max_turns=3 ` patterns
    import re
    # Match "max_turns=3" only when followed by , or whitespace or comment marker
    matches = re.findall(r"max_turns\s*=\s*3\s*[,\)\s#]", src)
    assert not matches, (
        f"Found {len(matches)} lingering hardcoded max_turns=3 — these should "
        f"be config-driven via self.cfg.<phase>_max_turns. Matches: {matches[:3]}"
    )
