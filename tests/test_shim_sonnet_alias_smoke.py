"""COST-03 regression test — gate against the expensive Sonnet alias.

This test gates the anthropic-shim's `MODEL_ALIASES['claude-sonnet-4-6']` entry
against regressing back to the expensive `Qwen/Qwen3.5-397B-A17B` value. That
alias billed 25-40% MORE than the Anthropic Sonnet baseline on the 2026-XX-XX
parity bench (see `.planning/phases/02-siliconflow-qwen-235b-parity-benchmark/
post-mortem/2026-XX-XX-cost-finding.md`).

The replacement primary alias is `Qwen/Qwen3.6-35B-A3B` (3B-active MoE, newer
Qwen3.6 generation). Manual SiliconFlow probe on 2026-XX-XX returned:

    HTTP 200 + finish_reason=tool_calls + arguments='{"input": "ok"}'

confirming the model is enabled on the operator's account and produces real
tool-call output when given an Anthropic-shaped tools payload.

Documented fallbacks (in order — try Qwen3.6-35B-A3B first; if a future
account state breaks it, the runbook is: try these in order):

    1. Qwen/Qwen3-30B-A3B-Instruct-2507
    2. deepseek-ai/DeepSeek-V3.2

Test coverage:

  Test 1 — `test_sonnet_alias_is_qwen3_6_35b_a3b_or_fallback`
           Asserts MODEL_ALIASES['claude-sonnet-4-6']['model'] is one of the
           three documented candidates (primary or fallback). Hard-asserts it
           is NOT the expensive Qwen3.5-397B-A17B.
  Test 2 — `test_sonnet_alias_extra_body_unchanged`
           Asserts extra_body.enable_thinking is False (must use `is False`,
           not `== False`, because Python's `bool` subclasses `int`).
  Test 3 — `test_other_aliases_unchanged`
           Asserts Opus + Haiku aliases are untouched. Those tiers performed
           well on the 2026-XX-XX bench and any regression here is a bug.
  Test 4 — `test_shim_alias_smoke_live` (marked @pytest.mark.integration)
           Live HTTP POST to 127.0.0.1:4002/v1/messages with a tools-enabled
           payload. Asserts response is HTTP 200 + at least one tool_use block
           with a non-empty input. Gates the alias change against shipping
           a model that resolves but can't drive the agent loop.

Import strategy: the shim filename is hyphenated (`anthropic-shim.py`) so
`import anthropic_shim` does NOT work. We load it via importlib.util at
module scope.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest


# ---- Shim module loader (hyphenated filename) ----------------------------

_SHIM_PATH = Path(__file__).resolve().parent.parent / "tools" / "serving" / "anthropic-shim.py"


def _load_shim_module():
    """Load tools/serving/anthropic-shim.py as a module (hyphenated filename
    means normal `import` doesn't work). Cached on the function attribute so
    repeated calls don't re-exec the module."""
    cached = getattr(_load_shim_module, "_cached", None)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location("anthropic_shim", str(_SHIM_PATH))
    assert spec is not None and spec.loader is not None, f"cannot load {_SHIM_PATH}"
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so internal imports (if any) can find it.
    sys.modules["anthropic_shim"] = mod
    spec.loader.exec_module(mod)
    _load_shim_module._cached = mod  # type: ignore[attr-defined]
    return mod


# Documented candidate aliases. Primary first, fallbacks in priority order.
ACCEPTABLE_SONNET_ALIASES = (
    "Qwen/Qwen3.6-35B-A3B",
    "Qwen/Qwen3-30B-A3B-Instruct-2507",
    "deepseek-ai/DeepSeek-V3.2",
)

# Explicit deny — the expensive alias this plan removed.
FORBIDDEN_SONNET_ALIAS = "Qwen/Qwen3.5-397B-A17B"


# ---- Unit tests ----------------------------------------------------------


def test_sonnet_alias_is_qwen3_6_35b_a3b_or_fallback():
    """COST-03 gate: claude-sonnet-4-6 must point at one of the documented
    cheaper alternatives and must NOT point at the expensive Qwen3.5-397B-A17B."""
    mod = _load_shim_module()
    aliases = mod.MODEL_ALIASES
    assert "claude-sonnet-4-6" in aliases, (
        "claude-sonnet-4-6 missing from MODEL_ALIASES — "
        "shim cannot translate Sonnet calls"
    )
    chosen = aliases["claude-sonnet-4-6"]["model"]
    assert chosen != FORBIDDEN_SONNET_ALIAS, (
        f"REGRESSION: claude-sonnet-4-6 points at the expensive "
        f"{FORBIDDEN_SONNET_ALIAS}. See COST-03 / "
        f"2026-XX-XX-cost-finding.md — that alias billed 25-40% MORE "
        f"than the Sonnet baseline."
    )
    assert chosen in ACCEPTABLE_SONNET_ALIASES, (
        f"claude-sonnet-4-6 points at {chosen!r}, which is not one of the "
        f"three documented candidates {ACCEPTABLE_SONNET_ALIASES}. If a new "
        f"alias is needed, add it to ACCEPTABLE_SONNET_ALIASES here + the "
        f"post-mortem runbook."
    )


def test_sonnet_alias_extra_body_unchanged():
    """The agent loop assumes enable_thinking=False on the Sonnet alias to
    keep per-call latency manageable (extended thinking adds 1000+ tokens
    per turn). Must use `is False`, not `== False` — bool is int in Python."""
    mod = _load_shim_module()
    extra = mod.MODEL_ALIASES["claude-sonnet-4-6"].get("extra_body") or {}
    assert extra.get("enable_thinking") is False, (
        f"claude-sonnet-4-6 extra_body.enable_thinking must be exactly False "
        f"(got {extra.get('enable_thinking')!r})"
    )


def test_other_aliases_unchanged():
    """Opus + Haiku tiers performed well on the 2026-XX-XX bench. Any change
    to those aliases is out of scope for COST-03 and must come with its own
    parity bench."""
    mod = _load_shim_module()
    aliases = mod.MODEL_ALIASES
    assert aliases["claude-opus-4-7"]["model"] == "deepseek-ai/DeepSeek-R1", (
        f"claude-opus-4-7 alias regressed — expected deepseek-ai/DeepSeek-R1, "
        f"got {aliases['claude-opus-4-7']['model']!r}"
    )
    assert aliases["claude-haiku-4-5"]["model"] == "Qwen/Qwen3-Coder-30B-A3B-Instruct", (
        f"claude-haiku-4-5 alias regressed — expected "
        f"Qwen/Qwen3-Coder-30B-A3B-Instruct, "
        f"got {aliases['claude-haiku-4-5']['model']!r}"
    )


# ---- Live integration smoke test (gated) ---------------------------------

_SHIM_URL = "http://127.0.0.1:4002"


def _shim_is_up(timeout_s: float = 2.0) -> bool:
    """Return True if the anthropic-shim is responding at 127.0.0.1:4002."""
    try:
        with urllib.request.urlopen(f"{_SHIM_URL}/v1/models", timeout=timeout_s) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


@pytest.mark.integration
def test_shim_alias_smoke_live():
    """Live gate: POST a tool-call payload through the running shim and
    require a real `tool_use` block with a non-empty `input`.

    A pass proves: (a) the alias resolves on SiliconFlow, (b) the model
    actually emits tool_calls when given an Anthropic tools payload, (c)
    the shim's Anthropic→OpenAI→Anthropic translation chain is intact for
    the new alias.

    Skipped (NOT failed) when the shim isn't running, so the default unit
    suite doesn't error if the operator hasn't started the shim. Run the
    integration suite explicitly: `pytest -m integration`.
    """
    if not _shim_is_up():
        pytest.skip(
            "Shim not up at 127.0.0.1:4002. Start with "
            "`bash tools/serving/start-anthropic-shim.sh --bg` and re-run."
        )

    payload: dict[str, Any] = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 300,
        "system": "You are a test reviewer. Use the echo tool with input='ok'.",
        "tools": [{
            "name": "echo",
            "description": "Echo a string",
            "input_schema": {
                "type": "object",
                "properties": {"input": {"type": "string"}},
                "required": ["input"],
            },
        }],
        "messages": [
            {"role": "user", "content": "Please call echo with input=ok."},
        ],
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{_SHIM_URL}/v1/messages",
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": "dummy",
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=60.0) as r:
        assert r.status == 200, f"shim returned HTTP {r.status}"
        resp_body = r.read().decode("utf-8", errors="replace")

    # The shim's /v1/messages streams Anthropic SSE events (NOT a single
    # JSON envelope). Walk the event stream and reconstruct the tool_use
    # block from `content_block_start` + `content_block_delta`(partial_json)
    # frames — same pattern the claude_agent_sdk uses.
    tool_use_name: str | None = None
    tool_use_id: str | None = None
    tool_use_input_buf = ""
    stop_reason: str | None = None
    saw_message_start = False

    for raw_line in resp_body.splitlines():
        line = raw_line.strip()
        if not line.startswith("data:"):
            continue
        payload_str = line[len("data:"):].strip()
        if not payload_str or payload_str == "[DONE]":
            continue
        try:
            evt = json.loads(payload_str)
        except json.JSONDecodeError:
            continue
        etype = evt.get("type")
        if etype == "message_start":
            saw_message_start = True
        elif etype == "content_block_start":
            cb = evt.get("content_block") or {}
            if cb.get("type") == "tool_use":
                tool_use_name = cb.get("name")
                tool_use_id = cb.get("id")
        elif etype == "content_block_delta":
            delta = evt.get("delta") or {}
            if delta.get("type") == "input_json_delta":
                tool_use_input_buf += delta.get("partial_json") or ""
        elif etype == "message_delta":
            d = evt.get("delta") or {}
            stop_reason = d.get("stop_reason") or stop_reason

    assert saw_message_start, (
        f"shim SSE stream missing message_start event. Preview: "
        f"{resp_body[:400]}"
    )
    assert tool_use_name is not None, (
        f"shim response contained NO tool_use content_block_start. "
        f"Stop reason: {stop_reason!r}. Preview: {resp_body[:600]}"
    )
    assert tool_use_name == "echo", (
        f"tool_use name mismatch — expected 'echo', got {tool_use_name!r}"
    )
    assert tool_use_id, "tool_use block missing id"

    # Reconstruct the input dict from the accumulated partial_json deltas.
    assert tool_use_input_buf, (
        "shim emitted tool_use block but NO input_json_delta frames — "
        "Qwen empty-args bug (BUG-01) may have regressed for the new alias."
    )
    try:
        tu_input = json.loads(tool_use_input_buf)
    except json.JSONDecodeError as e:
        pytest.fail(
            f"tool_use input_json_delta accumulator is not valid JSON: {e}\n"
            f"---\n{tool_use_input_buf!r}"
        )
    assert isinstance(tu_input, dict) and tu_input, (
        f"tool_use input is empty or non-dict (got {tu_input!r})"
    )
    assert any(v for v in tu_input.values()), (
        f"tool_use input has only empty/falsy values: {tu_input!r}"
    )
    assert stop_reason == "tool_use", (
        f"stop_reason was {stop_reason!r}, expected 'tool_use'"
    )
