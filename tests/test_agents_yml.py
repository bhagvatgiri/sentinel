"""B5 — Declarative parallel-agent config (agents.yml).

Operator declares per-phase model + prompt addendum overrides in YAML
without a code change. Default behavior MUST be unchanged when no
agents.yml is present — Sentinel still works without one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agent.pentest import agents_yml as ay


# ---- parse_agents_yml -----------------------------------------------------

def test_parse_empty_yields_empty_config():
    cfg = ay.parse_agents_yml("")
    assert cfg.is_empty()


def test_parse_minimal_two_overrides():
    text = """
parallel_agents:
  - name: bug_bounter
    phase: vuln:idor
    model: claude-sonnet-4-6
  - name: deep_recon
    phase: recon
    prompt: "Focus on cloud-metadata SSRF surfaces"
"""
    cfg = ay.parse_agents_yml(text)
    assert not cfg.is_empty()
    assert cfg.for_phase("vuln:idor").model == "claude-sonnet-4-6"  # explicit yml value, not router default
    assert cfg.for_phase("vuln:idor").name == "bug_bounter"
    assert "Focus on cloud-metadata" in cfg.for_phase("recon").prompt_addendum


def test_parse_unified_context_flag():
    text = """
parallel_agents:
  - name: x
    phase: report
    unified_context: true
"""
    cfg = ay.parse_agents_yml(text)
    assert cfg.for_phase("report").unified_context is True


def test_parse_unknown_phase_raises_loudly():
    """Typo in phase name must fail — silently dropping it would let the
    operator's intent never apply, hard to debug."""
    text = """
parallel_agents:
  - name: x
    phase: vulnerability_scan      # not a real Sentinel phase
    model: x
"""
    with pytest.raises(ValueError, match="not a known Sentinel phase"):
        ay.parse_agents_yml(text)


def test_parse_missing_required_keys():
    with pytest.raises(ValueError, match="name is required"):
        ay.parse_agents_yml("parallel_agents:\n  - phase: recon\n")
    with pytest.raises(ValueError, match="phase is required"):
        ay.parse_agents_yml("parallel_agents:\n  - name: x\n")


def test_parse_bad_top_level_type():
    with pytest.raises(ValueError, match="must be a mapping"):
        ay.parse_agents_yml("- just: a list")


def test_parse_recognizes_dynamic_phase_prefixes():
    text = """
parallel_agents:
  - {name: a, phase: "vuln:auth"}
  - {name: b, phase: "exploit:idor"}
  - {name: c, phase: "chain_execute:admin_session_takeover"}
"""
    cfg = ay.parse_agents_yml(text)
    assert cfg.for_phase("vuln:auth").name == "a"
    assert cfg.for_phase("exploit:idor").name == "b"
    assert cfg.for_phase("chain_execute:admin_session_takeover").name == "c"


# ---- load_agents_yml -----------------------------------------------------

def test_load_finds_workspace_first(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (ws / "agents.yml").write_text(
        "parallel_agents:\n  - {name: from_ws, phase: report, model: m1}\n"
    )
    (cwd / "agents.yml").write_text(
        "parallel_agents:\n  - {name: from_cwd, phase: report, model: m2}\n"
    )
    cfg = ay.load_agents_yml(ws, cwd)
    # First match wins — workspace.
    assert cfg.for_phase("report").name == "from_ws"
    assert cfg.source_path == ws / "agents.yml"


def test_load_returns_empty_when_no_file(tmp_path):
    cfg = ay.load_agents_yml(tmp_path)
    assert cfg.is_empty()


def test_load_falls_back_to_cwd_when_workspace_empty(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "agents.yml").write_text(
        "parallel_agents:\n  - {name: from_cwd, phase: recon}\n"
    )
    cfg = ay.load_agents_yml(ws, cwd)
    assert cfg.for_phase("recon").name == "from_cwd"
    assert cfg.source_path == cwd / "agents.yml"


# ---- merge_into_pipeline_config ------------------------------------------

class _FakeCfg:
    def __init__(self):
        self.model_router = None
        self.model = None


def test_merge_no_op_on_empty():
    cfg = _FakeCfg()
    ay.merge_into_pipeline_config(cfg, ay.AgentsYmlConfig())
    # No model_router was created — completely untouched.
    assert cfg.model_router is None
    assert not getattr(cfg, "_phase_addendums", None)


def test_merge_applies_per_phase_model_override():
    cfg = _FakeCfg()
    yml = ay.parse_agents_yml(
        "parallel_agents:\n"
        "  - {name: x, phase: 'vuln:idor', model: claude-opus-4-7}\n"
    )
    ay.merge_into_pipeline_config(cfg, yml)
    assert cfg.model_router is not None
    # Overridden phase comes back with the new model.
    assert cfg.model_router.phase_model("vuln:idor") == "claude-opus-4-7"
    # Other phases untouched (default Sonnet).
    other = cfg.model_router.phase_model("recon")
    assert "opus" not in other.lower() or other.lower().startswith("claude-sonnet")


def test_merge_applies_prompt_addendum():
    cfg = _FakeCfg()
    yml = ay.parse_agents_yml(
        "parallel_agents:\n"
        "  - {name: x, phase: report, prompt_addendum: 'Be concise.'}\n"
    )
    ay.merge_into_pipeline_config(cfg, yml)
    assert getattr(cfg, "_phase_addendums") == {"report": "Be concise."}


def test_merge_precedence_yml_over_defaults():
    """When agents.yml sets a model for a phase, the merged ModelRouter
    returns the YAML model, not the registered default."""
    cfg = _FakeCfg()
    yml = ay.parse_agents_yml(
        "parallel_agents:\n"
        "  - {name: r, phase: report, model: my-special-model}\n"
    )
    ay.merge_into_pipeline_config(cfg, yml)
    assert cfg.model_router.phase_model("report") == "my-special-model"
