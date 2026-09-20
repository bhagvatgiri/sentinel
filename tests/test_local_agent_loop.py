"""Tests for the local-agent loop hardening (2026-XX-XX juice-shop spike):

- agentic-loop-discipline skill loads (frontmatter-stripped, non-empty).
- run_pentest_phase_ollama's narration guard: a no-tool-call turn nudges the
  model to continue instead of ending the phase, and only finishes for real once
  write_deliverable was called (or the nudges are exhausted).
"""

from __future__ import annotations

import types

import pytest

from sentinel.agent.pentest import ollama_phase
from sentinel.agent.pentest.skill_loader import (
    load_loop_discipline_skill,
    load_skill,
)


# ---------------------------------------------------------------------------
# Skill loader
# ---------------------------------------------------------------------------

class TestLoopDisciplineSkill:
    def test_loads_nonempty(self):
        body = load_loop_discipline_skill()
        assert body
        assert "every turn must end with a tool call" in body.lower()
        assert "write_deliverable" in body

    def test_frontmatter_stripped(self):
        body = load_loop_discipline_skill()
        assert body.splitlines()[0].strip() != "---"
        assert "name: agentic-loop-discipline" not in body

    def test_generic_loader_missing_returns_empty(self):
        assert load_skill("does-not-exist-xyz") == ""


# ---------------------------------------------------------------------------
# Narration guard in the Ollama phase loop
# ---------------------------------------------------------------------------

def _msg(content="", tool_calls=None):
    return {"message": {"content": content, "tool_calls": tool_calls or []}}


def _tool(name, handler):
    return types.SimpleNamespace(name=name, handler=handler)


@pytest.fixture
def patched(monkeypatch):
    """Patch build_tools_payload (skip schema gen) and OllamaClient (scripted)."""
    monkeypatch.setattr(ollama_phase, "build_tools_payload", lambda tools: [])

    state = {"responses": [], "chat_calls": 0, "deliverable_calls": 0}

    class FakeClient:
        def __init__(self, host=None):
            pass

        async def chat(self, **kwargs):
            state["chat_calls"] += 1
            if state["responses"]:
                return state["responses"].pop(0)
            return _msg(content="")  # default: no-tool (e.g. the forced-write call)

    monkeypatch.setattr(ollama_phase, "OllamaClient", FakeClient)
    return state


@pytest.mark.asyncio
async def test_nudges_then_finishes_after_deliverable(patched):
    """No-tool turn 1 → nudge (not quit); turn 2 calls write_deliverable;
    turn 3 no-tool → legitimate finish."""
    async def write_deliverable(args):
        patched["deliverable_calls"] += 1
        return {"content": [{"type": "text", "text": "ok"}]}

    patched["responses"] = [
        _msg(content="Next, let's check robots.txt."),                 # turn 1: narrate
        _msg(tool_calls=[{"function": {"name": "write_deliverable",
                                       "arguments": {"path": "d.md"}}}]),  # turn 2: act
        _msg(content="Done."),                                          # turn 3: finish
    ]

    result = await ollama_phase.run_pentest_phase_ollama(
        name="recon",
        system_prompt="sys",
        user_prompt="go",
        tools=[_tool("write_deliverable", write_deliverable)],
        ollama_host="http://x",
        model="qwen2.5:32b-instruct-q4_K_M",
        max_turns=10,
    )

    assert patched["chat_calls"] == 3, "turn-1 no-tool must NOT end the phase"
    assert patched["deliverable_calls"] == 1
    assert result.success is True


@pytest.mark.asyncio
async def test_repetition_guard_refuses_duplicate(patched):
    """The same (tool, args) called twice: the second is refused, not executed."""
    calls = {"http_get": 0}

    async def http_get(args):
        calls["http_get"] += 1
        return {"content": [{"type": "text", "text": "Status: 200"}]}

    async def write_deliverable(args):
        patched["deliverable_calls"] += 1
        patched["last_filename"] = args.get("filename")
        return {"content": [{"type": "text", "text": "written"}]}

    url = "http://localhost:3000/admin"
    patched["responses"] = [
        _msg(tool_calls=[{"function": {"name": "http_get", "arguments": {"url": url}}}]),
        _msg(tool_calls=[{"function": {"name": "http_get", "arguments": {"url": url}}}]),  # dup
    ]

    result = await ollama_phase.run_pentest_phase_ollama(
        name="recon", system_prompt="sys", user_prompt="go",
        tools=[_tool("http_get", http_get),
               _tool("write_deliverable", write_deliverable)],
        ollama_host="http://x", model="m", max_turns=2,
    )

    assert calls["http_get"] == 1, "duplicate http_get must be refused, not re-run"
    assert result.success is True


@pytest.mark.asyncio
async def test_forced_synth_deliverable_when_model_wont_write(patched):
    """Model never writes a deliverable; the forced-write + synth fallback
    guarantees one is produced (filename recon_deliverable.md)."""
    async def write_deliverable(args):
        patched["deliverable_calls"] += 1
        patched["last_filename"] = args.get("filename")
        patched["last_content"] = args.get("content", "")
        return {"content": [{"type": "text", "text": "written"}]}

    # All prose, never a tool call → nudges exhausted → loop ends → forced-write
    # chat returns no tool call → synth fallback writes the deliverable.
    patched["responses"] = [_msg(content="blah") for _ in range(6)]

    result = await ollama_phase.run_pentest_phase_ollama(
        name="recon", system_prompt="sys", user_prompt="go",
        tools=[_tool("write_deliverable", write_deliverable)],
        ollama_host="http://x", model="m", max_turns=4,
    )

    assert result.success is True
    assert patched["deliverable_calls"] == 1, "synth must write exactly one deliverable"
    assert patched["last_filename"] == "recon_deliverable.md"
    assert "auto-synthesized" in patched.get("last_content", "")
