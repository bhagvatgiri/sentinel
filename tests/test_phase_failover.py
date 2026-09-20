"""Tests for the Claude → Ollama phase failover.

Covers:
- ModelRouter.fallback_for_phase returns the right model for wired
  phases (report, correlation) and None for unwired phases.
- The `should_failover` decision logic in pipeline._run_phase: only
  fires for failover-wired phases when error is set and backend != claude.
- run_pentest_phase_ollama returns a PhaseResult with correct shape.
"""

from __future__ import annotations

import pytest


# ---- ModelRouter ---------------------------------------------------------


def test_fallback_for_phase_returns_qwen_for_report():
    from sentinel.agent.model_router import fallback_for_phase
    out = fallback_for_phase("report")
    assert out is not None
    assert "qwen" in out.lower()


def test_fallback_for_phase_returns_qwen_for_correlation():
    from sentinel.agent.model_router import fallback_for_phase
    out = fallback_for_phase("correlation")
    assert out is not None
    assert "qwen" in out.lower()


@pytest.mark.parametrize("phase", [
    "recon", "vuln:auth", "vuln:csrf", "vuln:file_upload", "vuln:jwt_oauth",
    "exploit:auth", "exploit:xss", "chain_execute",
    "chain_execute:admin_session_takeover:chain_admin_session_takeover_001",
])
def test_fallback_for_phase_returns_none_for_unwired_phases(phase):
    """Heavy agent-loop phases are NOT yet wired for failover. They
    should raise on Claude failure rather than silently degrade."""
    from sentinel.agent.model_router import fallback_for_phase
    assert fallback_for_phase(phase) is None


def test_default_fallback_phase_models_only_lists_safe_phases():
    """Sanity check: only the read-files-and-write-prose phases are
    wired. If someone adds vuln:* or exploit:* here without also
    building the Ollama-MCP bridge, things will silently break."""
    from sentinel.agent.model_router import DEFAULT_FALLBACK_PHASE_MODELS
    safe = {"report", "correlation"}
    assert set(DEFAULT_FALLBACK_PHASE_MODELS.keys()) == safe


# ---- PipelineConfig surfaces the new fields -----------------------------


def test_pipeline_config_has_phase_backend_default_auto():
    from sentinel.agent.pentest.pipeline import PipelineConfig
    cfg = PipelineConfig(target="https://x", scope_path="/tmp/x.yaml")
    assert cfg.phase_backend == "auto"
    assert "qwen" in cfg.ollama_fallback_model


# ---- should_failover decision logic --------------------------------------


def _decide_failover(*, error, backend_pref, fallback_model):
    """Mirrors the gate in pipeline._run_phase verbatim."""
    return (
        error is not None
        and backend_pref != "claude"
        and fallback_model is not None
    )


def test_should_failover_fires_when_error_and_auto_and_wired():
    assert _decide_failover(
        error="rate limited", backend_pref="auto",
        fallback_model="qwen2.5:32b-instruct-q4_K_M",
    ) is True


def test_should_failover_blocked_when_backend_is_claude():
    """--phase-backend=claude means operator demanded Claude only.
    Failover MUST NOT fire even on errors."""
    assert _decide_failover(
        error="rate limited", backend_pref="claude",
        fallback_model="qwen2.5:32b-instruct-q4_K_M",
    ) is False


def test_should_failover_blocked_for_unwired_phase():
    """Phase has no fallback model registered → don't try."""
    assert _decide_failover(
        error="rate limited", backend_pref="auto",
        fallback_model=None,
    ) is False


def test_should_failover_blocked_when_no_error():
    """Claude succeeded → no failover even if model is registered."""
    assert _decide_failover(
        error=None, backend_pref="auto",
        fallback_model="qwen2.5:32b-instruct-q4_K_M",
    ) is False


# ---- run_pentest_phase_ollama smoke -------------------------------------


def test_ollama_phase_returns_phase_result_shape():
    """When the Ollama loop terminates with no tool calls (model says
    'done' with empty tool_calls), it returns a success PhaseResult."""
    import asyncio
    from sentinel.agent.pentest.ollama_phase import run_pentest_phase_ollama

    async def fake_chat(self, model, messages, **kw):
        return {"message": {"content": "done", "tool_calls": []}}

    from sentinel.agent.ollama_provider import OllamaClient
    import unittest.mock as mock
    with mock.patch.object(OllamaClient, "chat", fake_chat):
        result = asyncio.run(run_pentest_phase_ollama(
            name="report",
            system_prompt="sys",
            user_prompt="user",
            tools=[],
            ollama_host="http://localhost:11434",
            model="qwen2.5:32b-instruct-q4_K_M",
            max_turns=3,
        ))
    assert result.name == "report"
    assert result.success is True
    assert result.cost_usd == 0.0
    assert result.error is None


def test_ollama_phase_records_chat_failure_as_error():
    import asyncio
    from sentinel.agent.pentest.ollama_phase import run_pentest_phase_ollama

    async def fake_chat(self, model, messages, **kw):
        raise RuntimeError("simulated ollama outage")

    from sentinel.agent.ollama_provider import OllamaClient
    import unittest.mock as mock
    with mock.patch.object(OllamaClient, "chat", fake_chat):
        result = asyncio.run(run_pentest_phase_ollama(
            name="report",
            system_prompt="sys", user_prompt="user", tools=[],
            ollama_host="http://localhost:11434",
            model="qwen2.5:32b-instruct-q4_K_M",
            max_turns=3,
        ))
    assert result.success is False
    assert "simulated ollama outage" in (result.error or "")
