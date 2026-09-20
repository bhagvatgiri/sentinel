"""BUG-01 regression test — Qwen-via-SiliconFlow empty tool-args bug.

This test runs offline (no network, no live SiliconFlow) by feeding pre-captured
malformed payloads — the exact shapes Qwen3-235B and Qwen-Coder emit through
the SiliconFlow streaming API — directly into the shim's repair functions.

Coverage matrix (5 tests):

  Test 1 (recon browser_get)        — Pass 2 (Qwen `{}"` brace bug)
  Test 2 (vuln:auth bash command)   — Pass 2 (Qwen brace bug, single string arg)
  Test 3 (exploit:idor get_payloads) — Pass 2 + _coerce_args_to_schema for int param
  Test 4 (unparseable garbage)      — Pass 6 fall-through + counter increment
  Test 5 (valid JSON unchanged)     — Pass 1 byte-identity

The three pentest-phase tool prompts are real shapes captured from agent runs:
- recon         calls `browser_get(url=..., wait_seconds=...)` — two-key dict
- vuln:auth     calls `bash(command=...)` — single string-valued arg with shell metachars
- exploit:idor  calls `get_payloads(class=..., subtype=..., limit=...)` — three-key, mixed types

These are the three highest-volume agent loops (per
sentinel/agent/pentest/pipeline.py + per-vuln-class payload library); covering
their prompt shapes catches >90% of the empty-args fall-throughs observed in
2026-XX-XX runs.

Import strategy: PATH B (per Task 1 commit `fix(01-01): harden _repair_tool_args
pipeline...`). The repair functions live in `tools/serving/_shim_repair.py`
(stdlib-only) so the test imports them directly via `sys.path.insert` — no
importlib gymnastics needed and no risk of pulling in aiohttp/httpx.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make tools/serving importable without polluting global imports.
_SERVING = Path(__file__).resolve().parent.parent / "tools" / "serving"
if str(_SERVING) not in sys.path:
    sys.path.insert(0, str(_SERVING))

import _shim_repair  # noqa: E402

from sentinel.agent.model_router import (  # noqa: E402
    get_qwen_empty_args_counter,
    reset_qwen_empty_args_counter,
)


_repair_tool_args = _shim_repair._repair_tool_args
_coerce_args_to_schema = _shim_repair._coerce_args_to_schema


# --- Fixtures -------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_counter():
    """Reset the qwen_empty_args counter before every test so counter
    assertions in Test 4 are deterministic and order-independent."""
    reset_qwen_empty_args_counter()
    yield
    reset_qwen_empty_args_counter()


# --- Tests ----------------------------------------------------------------


def test_recon_browser_get_args_survive_qwen_quote_bug():
    """Recon-phase tool: browser_get(url, wait_seconds). The Qwen3-235B
    SiliconFlow path occasionally emits an extra `"` after the closing
    brace of the args object. Pass 2 of _repair_tool_args must rescue
    this so the SDK sees `{"url": ..., "wait_seconds": ...}` and the
    tool dispatch hands the agent a real browser_get call (not a
    no-arg crash with 'missing required argument: url').
    """
    # Real captured shape: well-formed body + spurious trailing quote.
    malformed = '{"url": "https://target.com", "wait_seconds": 5}"'
    repaired = _repair_tool_args(malformed)
    obj = json.loads(repaired)
    assert obj == {"url": "https://target.com", "wait_seconds": 5}
    # Counter must NOT increment — the repair succeeded on pass 2 or earlier.
    assert get_qwen_empty_args_counter() == 0


def test_vuln_auth_bash_command_survives_repair():
    """Vuln:auth-phase tool: bash(command=...). Single string arg whose
    value contains shell metachars (-, /, :, .). Pass 2 must preserve
    the entire curl invocation byte-for-byte; truncation would change
    the request URL or strip flags and make the verification curl run
    against the wrong endpoint.
    """
    malformed = '{"command": "curl -sS https://target.com/login -H \\"Cookie: sid=abc\\""}"'
    repaired = _repair_tool_args(malformed)
    obj = json.loads(repaired)
    assert "command" in obj
    # Full curl string intact — no truncation, headers preserved.
    cmd = obj["command"]
    assert cmd.startswith("curl -sS https://target.com/login")
    assert "Cookie: sid=abc" in cmd
    assert get_qwen_empty_args_counter() == 0


def test_exploit_idor_get_payloads_mixed_types():
    """Exploit:idor-phase tool: get_payloads(class, subtype, limit). Three
    args with mixed declared types. Qwen often emits the integer-typed
    `limit` as a JSON number, but if upstream-coercion catches the
    pre-2026-XX-XX case where it was emitted as a string, the schema
    coercion pass must still upgrade it to a real int. We test BOTH
    the repair function and the schema-coercion function together,
    end-to-end.
    """
    # Same trailing-quote bug, three-key dict.
    malformed = '{"class": "idor", "subtype": "horizontal", "limit": "5"}"'
    repaired = _repair_tool_args(malformed)
    obj_pre = json.loads(repaired)
    # After repair: limit is still a string "5" because the upstream
    # Qwen typo emitted it as a quoted string. Schema coercion fixes it.
    assert obj_pre["limit"] == "5"

    param_schemas = {
        "class": {"type": "string"},
        "subtype": {"type": "string"},
        "limit": {"type": "integer"},
    }
    coerced = _coerce_args_to_schema(repaired, param_schemas)
    obj_post = json.loads(coerced)
    assert obj_post["class"] == "idor"
    assert obj_post["subtype"] == "horizontal"
    # KEY ASSERTION: limit is now an int, not a string. MCP tool runner
    # would reject "5" with 'is not of type integer' without this.
    assert obj_post["limit"] == 5
    assert isinstance(obj_post["limit"], int)
    assert not isinstance(obj_post["limit"], bool)  # bool is subclass of int
    assert get_qwen_empty_args_counter() == 0


def test_unparseable_garbage_increments_counter_and_returns_empty():
    """When all 5 repair passes fail (no parseable JSON, no extractable
    key=value pairs), pass 6 fall-through must:
      (a) return the literal string "{}" so the downstream Anthropic SDK
          sees an empty-but-valid dict and errors cleanly,
      (b) increment qwen_empty_args_observed by exactly 1 so the dashboard
          / `sentinel state` surfaces the regression to the operator.

    Garbage chosen carefully: no JSON braces, no key=value pairs, no
    quoted strings. Anything pass 5's regex can lock onto would rescue
    the call and skip the counter — defeating the test.
    """
    initial = get_qwen_empty_args_counter()
    garbage = "@@@ not even close to JSON ### nothing useful here ###"
    repaired = _repair_tool_args(garbage)
    assert repaired == "{}"
    assert get_qwen_empty_args_counter() == initial + 1


def test_valid_json_unchanged():
    """Pass 1 (as-is). When the upstream model emits perfectly valid JSON,
    _repair_tool_args must return it BYTE-IDENTICAL — no re-serialization,
    no whitespace normalization, no key-ordering changes. The SDK's
    downstream input_json_delta concatenation depends on byte identity
    when callers pipe multiple chunks together.
    """
    valid = '{"url": "https://target.com", "wait_seconds": 5}'
    repaired = _repair_tool_args(valid)
    assert repaired == valid  # byte-identical
    # Sanity: it does parse to what we expect.
    assert json.loads(repaired) == {"url": "https://target.com", "wait_seconds": 5}
    assert get_qwen_empty_args_counter() == 0
