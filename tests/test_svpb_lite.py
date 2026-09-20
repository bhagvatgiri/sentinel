"""D6 — SVPB-Lite open subset tests.

Asserts:
- 10 tasks indexed.
- Each task references an existing scope yaml + workspace.
- Replay end-to-end with the stub runner returns sane metrics.
- Determinism: same seed → same output.
- Provenance block carries the scope yaml + seed for re-runners.
"""

from __future__ import annotations

import pytest

from sentinel.benchmark import svpb_lite, svpb_lite_data


def test_index_size_is_10():
    assert len(svpb_lite_data.TASKS) == 10


def test_each_task_unique_id():
    ids = [t.task_id for t in svpb_lite_data.TASKS]
    assert len(set(ids)) == len(ids)


def test_each_task_has_program_label():
    for t in svpb_lite_data.TASKS:
        assert t.program, f"{t.task_id} missing program label"


def test_each_task_references_existing_scope_yaml():
    """Spec requirement: SVPB-Lite scope yamls reference real, public
    BBP programs. The yaml file must be on disk in this repo."""
    for t in svpb_lite_data.TASKS:
        assert t.scope_yaml_path.exists(), (
            f"{t.task_id}: scope yaml missing at {t.scope_yaml_path}"
        )


def test_each_task_references_existing_workspace():
    for t in svpb_lite_data.TASKS:
        assert t.workspace_path.exists(), (
            f"{t.task_id}: workspace missing at {t.workspace_path}"
        )


def test_run_with_default_stub_returns_sane_metrics():
    res = svpb_lite.run(model="stub-model")
    assert res["benchmark"] == "svpb_lite"
    assert res["n_tasks"] >= 1
    assert res["n_completed"] >= 1
    assert 0.0 <= res["live_confirmed_rate"] <= 1.0
    assert 0.0 <= res["live_disproven_rate"] <= 1.0
    assert 0.0 <= res["verification_error_rate"] <= 1.0


def test_provenance_block_present_and_complete():
    res = svpb_lite.run(model="stub")
    assert "provenance" in res
    for entry in res["provenance"]:
        assert "task_id" in entry
        assert "program" in entry
        assert "scope_yaml" in entry
        assert "seed" in entry


def test_seeded_runner_is_deterministic():
    """Same model + same seed → same output. The reproducibility
    contract that makes SVPB-Lite publishable."""
    a = svpb_lite.run(model="m1")
    b = svpb_lite.run(model="m1")
    # Strip aggregates that don't depend on seed (just compare per-task).
    a_per = [(p["task_id"], p["matched"], p["n_tool_calls"]) for p in a["per_task"]]
    b_per = [(p["task_id"], p["matched"], p["n_tool_calls"]) for p in b["per_task"]]
    assert a_per == b_per


def test_seeds_unique_across_tasks():
    """Each task's seed is unique — otherwise two tasks would produce
    identical mock outputs and the determinism guarantee can't be
    inspected per-task."""
    seeds = [t.seed for t in svpb_lite_data.TASKS]
    assert len(set(seeds)) == len(seeds)
