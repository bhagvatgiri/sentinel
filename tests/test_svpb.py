"""D5 — Sentinel Verifier-graded Pentest Bench tests.

Asserts:
- 50 task index entries.
- Harness loads briefs from real workspace files.
- Sample replay against a mocked LLM produces expected metrics.
- Aggregate math is correct (live_confirmed_rate, verification_error_rate).
- Mocked-model runner returning the wrong outcome surfaces as
  matched_expected=False AND verifier_disagreed_with_model accordingly.
"""

from __future__ import annotations

import pytest

from sentinel.benchmark import svpb, svpb_data
from sentinel.benchmark.svpb import (
    SVPBReplayResult, aggregate, load_task_brief, replay_task,
)


def test_task_index_size():
    assert len(svpb_data.TASKS) == 50


def test_task_ids_unique_and_sequential():
    ids = [t.task_id for t in svpb_data.TASKS]
    assert len(set(ids)) == len(ids), "duplicate task ids"
    for i, t in enumerate(svpb_data.TASKS, start=1):
        assert t.task_id == f"svpb-{i:03d}", (
            f"task at index {i} has non-sequential id: {t.task_id}"
        )


def test_expected_outcomes_in_known_set():
    allowed = {"live_confirmed", "live_disproven", "unverified"}
    for t in svpb_data.TASKS:
        assert t.expected_outcome in allowed, (
            f"{t.task_id}: bad expected_outcome {t.expected_outcome!r}"
        )


def test_each_task_targets_real_engagement():
    """Every task references one of the documented past engagements."""
    expected_engagements = {
        "2026-XX-XX-ExampleCorp-web", "2026-XX-XX-ExampleClient-web",
        "2026-XX-XX-AcmeProgram-bbp", "2026-XX-XX-ExamplePay-bbp",
        "2026-XX-XX-ExamplePay-bbp-deep", "2026-XX-XX-ExampleStore-bbp",
        "ExampleStore-tax-2026-XX-XX", "2026-ExampleGlobal",
    }
    for t in svpb_data.TASKS:
        assert t.engagement in expected_engagements, (
            f"{t.task_id}: unknown engagement {t.engagement!r}"
        )


def test_load_task_brief_with_present_workspace():
    """Pick a task whose workspace files exist (ExampleStore). The brief
    must contain the queue entry's vuln_class + endpoint."""
    present = svpb_data.list_tasks(only_present=True)
    if not present:
        pytest.skip("no SVPB workspaces present (fresh clone?)")
    t = next(
        (t for t in present if t.engagement == "2026-XX-XX-ExampleStore-bbp"
         and t.vuln_class == "auth"), None,
    )
    if t is None:
        pytest.skip("ExampleStore auth queue not present")
    brief = load_task_brief(t)
    assert brief["task_id"] == t.task_id
    assert brief["target"] == t.target
    assert brief["vuln_class"] == "auth"
    # Real ExampleStore queue has vulnerability_type populated.
    assert brief.get("vulnerability_type") or brief.get("warning")


def test_replay_task_with_perfect_mock():
    """Mock runner returns expected outcome — every replay matches."""
    t = svpb_data.TASKS[0]
    res = replay_task(
        t, model="mock-model",
        runner=lambda brief: {
            "verifier_outcome": brief.get("expected_outcome"),
            "model_self_claim": brief.get("expected_outcome"),
            "n_tool_calls": 3,
            "n_passing_tool_calls": 3,
            "evidence_quality_score": 0.85,
        },
    )
    assert res.matched_expected
    assert not res.verifier_disagreed_with_model
    assert res.evidence_quality_score == 0.85


def test_replay_task_records_disagreement():
    """Runner returns model_self_claim != verifier_outcome → flagged."""
    t = svpb_data.TASKS[0]
    res = replay_task(
        t, model="mock",
        runner=lambda brief: {
            "verifier_outcome": "live_disproven",
            "model_self_claim": "live_confirmed",
            "n_tool_calls": 5,
            "n_passing_tool_calls": 3,
        },
    )
    assert res.verifier_disagreed_with_model


def test_aggregate_metrics_math():
    """Aggregate over hand-built results and check formulas."""
    rs = [
        SVPBReplayResult(
            "a", "m", "live_confirmed", "live_confirmed",
            "live_confirmed", True, False, 5, 5, 0.9,
        ),
        SVPBReplayResult(
            "b", "m", "live_disproven", "live_disproven",
            "live_disproven", True, False, 4, 4, 0.7,
        ),
        SVPBReplayResult(
            "c", "m", "live_confirmed", "live_disproven",
            "live_confirmed", True, True, 6, 4, 0.6,
        ),
        SVPBReplayResult(
            "d", "m", "live_disproven", "live_confirmed",
            "live_confirmed", False, True, 3, 1, None,
        ),
    ]
    agg = aggregate(rs, total_tasks=4)
    # expected_outcome: a=confirmed, b=disproven, c=confirmed, d=confirmed
    # matched_expected: a=True, b=True, c=True, d=False
    # confirmed_total=3 (a,c,d), confirmed_hits=2 (a,c) -> 2/3
    assert abs(agg.live_confirmed_rate - 2 / 3) < 0.001
    # disproven_total=1 (b), disproven_hits=1 (b) -> 1.0
    assert agg.live_disproven_rate == 1.0
    # verification_errors: c + d = 2 / 4 = 0.5
    assert agg.verification_error_rate == 0.5
    # mean evidence quality across {0.9, 0.7, 0.6} = 0.733...
    assert abs(agg.mean_evidence_quality_score - 0.7333) < 0.01
    # tool_use_efficiency = (5+4+4+1) / (5+4+6+3) = 14/18
    assert abs(agg.tool_use_efficiency - 14 / 18) < 0.001


def test_run_end_to_end_with_default_mock():
    res = svpb.run(model="mock")
    assert res["model"] == "mock"
    assert res["n_tasks"] >= 1
    assert "live_confirmed_rate" in res
    assert "verification_error_rate" in res
    assert isinstance(res["per_task"], list)


def test_run_with_max_tasks_caps_iteration():
    res = svpb.run(model="mock", max_tasks=5)
    assert res["n_tasks"] == 5
    assert len(res["per_task"]) == 5


def test_runner_exception_recorded_not_raised():
    def boom(brief):
        raise RuntimeError("simulated failure")
    res = replay_task(svpb_data.TASKS[0], model="m", runner=boom)
    assert res.error and "simulated" in res.error
    assert not res.matched_expected
