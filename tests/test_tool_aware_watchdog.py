"""Tests for the tool-aware streaming watchdog helper (2026-XX-XX).

The streaming watchdog in `_run_phase` must not mistake a long scanner's
legitimate silence (nuclei/ffuf running 60-300s with no intermediate stream
output) for a transport freeze. It tracks tool_use(+1)/tool_result(-1) blocks
via `_tool_delta`; while the net is > 0 a tool is mid-flight and a longer
tool-grace silence is allowed. `_tool_delta` is the testable core of that.
"""
from __future__ import annotations

from types import SimpleNamespace as NS

from sentinel.agent.pentest.pipeline import _tool_delta


class _ToolUseBlock:  # class-name substring "tooluse" is what _tool_delta matches
    pass


class _ToolResultBlock:
    pass


class _TextBlock:
    pass


def _msg(*block_types):
    return NS(content=[b() for b in block_types])


def test_tool_use_increments():
    assert _tool_delta(_msg(_ToolUseBlock)) == 1


def test_parallel_tool_uses_count_each():
    assert _tool_delta(_msg(_ToolUseBlock, _ToolUseBlock, _ToolUseBlock)) == 3


def test_tool_result_decrements():
    assert _tool_delta(_msg(_ToolResultBlock)) == -1


def test_text_and_unknown_blocks_are_neutral():
    assert _tool_delta(_msg(_TextBlock)) == 0
    assert _tool_delta(_msg(_TextBlock, _TextBlock)) == 0


def test_mixed_message_nets_correctly():
    # an assistant turn that emits text + 2 tool calls
    assert _tool_delta(_msg(_TextBlock, _ToolUseBlock, _ToolUseBlock)) == 2


def test_none_or_missing_content_is_safe():
    assert _tool_delta(NS(content=None)) == 0
    assert _tool_delta(NS()) == 0


def test_use_then_result_balances_to_zero():
    """A tool_use followed by its tool_result nets 0 → watchdog returns to the
    tight step_timeout once the tool finishes (so real post-tool freezes are
    still caught fast)."""
    pending = 0
    pending += _tool_delta(_msg(_ToolUseBlock))      # tool starts
    assert pending == 1
    pending += _tool_delta(_msg(_ToolResultBlock))   # tool returns
    assert pending == 0
