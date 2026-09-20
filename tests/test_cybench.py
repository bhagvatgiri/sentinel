"""D8 — Cybench / AutoPenBench replay tests.

Asserts:
- Task index loaded (Cybench 38 + AutoPenBench 29).
- assert_ctf_mode raises in production / BBP, allows CTF / LAB.
- grade_output recognizes flag pattern.
- Mock LLM replay verifies pass-rate plumbing.
"""

from __future__ import annotations

import pytest

from sentinel.benchmark import cybench
from sentinel.benchmark.cybench import (
    CTFModeRequiredError, CybenchTask, assert_ctf_mode,
    grade_output, replay_task, run,
)
from sentinel.core.engagement_mode import EngagementMode


def test_task_index_size():
    """38 Cybench + 29 AutoPenBench = 67 tasks."""
    assert len(cybench.CYBENCH_TASKS) == 67


def test_cybench_subset_count():
    n = sum(1 for t in cybench.CYBENCH_TASKS if t.suite == "cybench")
    assert n == 38


def test_autopenbench_subset_count():
    n = sum(1 for t in cybench.CYBENCH_TASKS if t.suite == "autopenbench")
    assert n == 29


def test_mode_gate_refuses_production():
    with pytest.raises(CTFModeRequiredError):
        assert_ctf_mode(EngagementMode.PRODUCTION)


def test_mode_gate_refuses_bbp():
    with pytest.raises(CTFModeRequiredError):
        assert_ctf_mode(EngagementMode.BBP)


def test_mode_gate_allows_ctf():
    assert_ctf_mode(EngagementMode.CTF)
    assert_ctf_mode(EngagementMode.LAB)


def test_mode_gate_accepts_string_input():
    with pytest.raises(CTFModeRequiredError):
        assert_ctf_mode("production")
    assert_ctf_mode("ctf")
    assert_ctf_mode("lab")


def test_grade_output_matches_flag_pattern():
    t = cybench.CYBENCH_TASKS[0]
    assert grade_output(t, "got it: flag{proof_of_pwn}") is True
    assert grade_output(t, "couldn't crack it") is False
    assert grade_output(t, "") is False


def test_replay_with_winning_runner():
    t = cybench.CYBENCH_TASKS[0]
    res = replay_task(
        t,
        runner=lambda task: {
            "deliverable": "After exploiting the bug: flag{abcdef123456}",
            "n_tool_calls": 7,
        },
    )
    assert res["passed"] is True
    assert res["n_tool_calls"] == 7


def test_replay_with_losing_runner():
    t = cybench.CYBENCH_TASKS[0]
    res = replay_task(
        t,
        runner=lambda task: {"deliverable": "no flag"},
    )
    assert res["passed"] is False


def test_run_returns_aggregate_with_per_suite_breakdown():
    """Run with default stub (always-fails) — pass_rate 0 but the
    plumbing for the by_suite breakdown still populates."""
    res = run(mode="ctf", max_tasks=10)
    assert res["benchmark"] == "cybench"
    assert res["n_tasks"] == 10
    assert res["pass_rate"] == 0.0
    assert "by_suite" in res
    assert all(
        s in {"cybench", "autopenbench"} for s in res["by_suite"]
    )


def test_run_in_non_ctf_mode_refuses():
    with pytest.raises(CTFModeRequiredError):
        run(mode="production")


def test_run_with_custom_runner_records_passes():
    """Runner returns a flag for half the tasks → pass_rate ≈ 0.5."""
    counter = {"i": 0}

    def alternating_runner(task):
        counter["i"] += 1
        if counter["i"] % 2 == 0:
            return {"deliverable": "flag{half_alternation}"}
        return {"deliverable": "miss"}

    res = run(mode="ctf", runner=alternating_runner, max_tasks=10)
    assert res["n_tasks"] == 10
    assert 0.4 <= res["pass_rate"] <= 0.6
