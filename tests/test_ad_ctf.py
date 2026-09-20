"""D9 — A&D CTF scenario tests.

Asserts:
- 10 scenarios indexed.
- Mode gate refuses production / BBP.
- Both red_teamer + blue_teamer agents register.
- Mock run produces a constraint matrix with all three tiers.
"""

from __future__ import annotations

import pytest

from sentinel.benchmark import ad_ctf
from sentinel.benchmark.ad_ctf import (
    ADScenario, ScenarioReplayResult, both_agents_registered,
    replay_scenario, run,
)
from sentinel.benchmark.cybench import CTFModeRequiredError
from sentinel.core.engagement_mode import EngagementMode


def test_scenario_index_size():
    assert len(ad_ctf.SCENARIOS) == 10


def test_each_scenario_well_formed():
    for s in ad_ctf.SCENARIOS:
        assert s.scenario_id
        assert s.flag_pattern
        assert s.blue_signal_pattern
        assert s.red_objective
        assert s.blue_objective


def test_mode_gate_refuses_production():
    with pytest.raises(CTFModeRequiredError):
        run(mode="production")
    with pytest.raises(CTFModeRequiredError):
        run(mode="bbp")


def test_mode_gate_allows_ctf_and_lab():
    a = run(mode="ctf", max_scenarios=2)
    b = run(mode="lab", max_scenarios=2)
    assert a["benchmark"] == "ad_ctf"
    assert b["benchmark"] == "ad_ctf"


def test_both_agents_register():
    """Spec requirement: red_teamer + blue_teamer both register."""
    red_ok, blue_ok = both_agents_registered()
    assert red_ok, "red_teamer module failed to import"
    assert blue_ok, "blue_teamer module failed to import"


def test_replay_scenario_with_winning_red():
    s = ad_ctf.SCENARIOS[0]

    def runner(scenario):
        return {
            "red_payload": "owned: flag{ad-001-test}",
            "blue_rule": "no relevant detection",
        }

    res = replay_scenario(s, runner=runner)
    assert res.red_won is True
    assert res.constraint_lab is True


def test_replay_scenario_blue_detection_blocks_operational():
    """When blue catches red, the operational constraint should fail
    (red won, but the defense was active — operational reproducibility
    requires red wins THROUGH the defense)."""
    s = ad_ctf.SCENARIOS[0]

    def runner(scenario):
        return {
            "red_payload": "got: flag{ad-001}",
            "blue_rule": f"sigma: {scenario.name}.detection alert",
        }

    res = replay_scenario(s, runner=runner)
    assert res.red_won is True
    assert res.blue_detected is True
    assert res.constraint_lab is True
    assert res.constraint_operational is False
    assert res.constraint_complete is False


def test_run_produces_full_constraint_matrix():
    res = run(mode="ctf")
    assert "constraint_matrix" in res
    cm = res["constraint_matrix"]
    for tier in ("lab", "operational", "complete"):
        assert tier in cm
    assert "constraint_rates" in res
    assert "blue_detection_rate" in res


def test_run_with_max_scenarios_caps_iteration():
    res = run(mode="ctf", max_scenarios=3)
    assert res["n_scenarios"] == 3
    assert len(res["per_scenario"]) == 3
