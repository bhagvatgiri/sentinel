"""BENCH-07 regression tests — cost accounting + cost-delta math.

Hermetic tests for `sentinel.benchmark.cost_accounting`:

  - `cost_summary_for_run(run)` — per-phase + per-model + per-run totals.
  - `cost_delta(baseline_run, candidate_run)` — absolute + percent reduction
    + per-phase deltas + pass/partial/fail verdict.
  - `verdict_for_cost(percent_reduction)` — threshold gates at 80% / 50%.

Plus a harness integration test that confirms `run_parity_eval` embeds
`cost_summary` into each run AND `cost_delta` into each suite AND emits a
top-level `verdict_overall`.

NO live SiliconFlow, NO docker, NO juice-shop instance.
`_invoke_scan_autonomous` is monkeypatched via the `invoke_fn` kwarg so the
harness orchestration logic is tested in isolation.

Test contract (10 tests):

  Test 1: cost_summary_for_run — single phase, single call, single model.
  Test 2: cost_summary_for_run — multi-phase + multi-model breakdown.
  Test 3: cost_summary_for_run — unknown model contributes 0 to cost
          but tokens still tallied in totals.
  Test 4: cost_delta — 80% reduction → verdict='pass'.
  Test 5: cost_delta — 50% reduction → verdict='partial'.
  Test 6: cost_delta — 30% reduction → verdict='fail'.
  Test 7: cost_delta — candidate more expensive than baseline → 'fail'.
  Test 8: cost_delta — per-phase delta dict has all phase keys + correct math.
  Test 9: run_parity_eval — eval JSON has runs[].cost_summary AND
          suites[].cost_delta AND verdict_overall.
  Test 10: Eval JSON schema_version bumped to '1.2'.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.benchmark.cost_accounting import (
    COST_THRESHOLDS,
    cost_delta,
    cost_summary_for_run,
    verdict_for_cost,
)
from sentinel.benchmark.pricing import compute_call_cost_usd
from sentinel.benchmark.parity_eval import (
    EVAL_JSON_SCHEMA_VERSION,
    run_parity_eval,
)
from sentinel.core.scope import AuditLog


_REPO_ROOT = Path(__file__).resolve().parent.parent
_BENCH_SCOPE = _REPO_ROOT / "bench" / "juice-shop" / "scope.yaml"


# ---- Fixtures -----------------------------------------------------------


@pytest.fixture
def tmp_scope(tmp_path):
    """Copy bench/juice-shop/scope.yaml into tmp + rewrite engagement_id.

    Audit logs land in tmp_path under `.audit-bench-test.jsonl` so the
    real bench engagement's audit chain is untouched by the integration
    test (Test 9).
    """
    dest = tmp_path / "scope.yaml"
    text = _BENCH_SCOPE.read_text()
    text = text.replace(
        "engagement_id: bench-juice-shop", "engagement_id: bench-test"
    ).replace(
        "client: bench-juice-shop", "client: bench-test"
    )
    dest.write_text(text)
    return dest


def _mk_run(*, profile: str, phases: list[dict]) -> dict:
    """Build a minimal per-run dict matching the v1.2 schema's shape, just
    enough for cost-accounting math. Tests pass synthetic phases."""
    return {
        "profile": profile,
        "model_aliases_used": {},
        "workspace_path": "/tmp/test-workspace",
        "suite_name": "test-suite",
        "target_url": "http://127.0.0.1:3000",
        "scope_engagement_id": "test-engagement",
        "phases": phases,
        "total_input_tokens": sum(
            c.get("input_tokens", 0)
            for ph in phases for c in ph.get("llm_calls", [])
        ),
        "total_output_tokens": sum(
            c.get("output_tokens", 0)
            for ph in phases for c in ph.get("llm_calls", [])
        ),
        "qwen_empty_args_observed_delta": 0,
    }


# ---- Test 1: single-phase single-call -----------------------------------


def test_cost_summary_single_phase_single_call():
    """One phase, one LLM call. Verify totals + per_phase + per_model
    breakdowns ALL agree and equal compute_call_cost_usd's return value.
    """
    run = _mk_run(
        profile="anthropic-baseline",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "claude-sonnet-4-6",
                        "input_tokens": 1_000_000,
                        "output_tokens": 500_000,
                        "wall_clock_ms": 1234,
                    },
                ],
            },
        ],
    )
    summary = cost_summary_for_run(run)

    expected_cost = compute_call_cost_usd(
        "claude-sonnet-4-6", 1_000_000, 500_000
    )
    assert summary["total_input_tokens"] == 1_000_000
    assert summary["total_output_tokens"] == 500_000
    assert summary["total_cost_usd"] == pytest.approx(expected_cost, rel=1e-9)
    # Per-phase breakdown.
    assert "recon" in summary["per_phase"]
    assert summary["per_phase"]["recon"]["input_tokens"] == 1_000_000
    assert summary["per_phase"]["recon"]["output_tokens"] == 500_000
    assert summary["per_phase"]["recon"]["cost_usd"] == pytest.approx(
        expected_cost, rel=1e-9
    )
    # Per-model breakdown.
    assert "claude-sonnet-4-6" in summary["per_model"]
    assert summary["per_model"]["claude-sonnet-4-6"]["cost_usd"] == pytest.approx(
        expected_cost, rel=1e-9
    )


# ---- Test 2: multi-phase multi-model ------------------------------------


def test_cost_summary_multi_phase_multi_model():
    """Two phases, three calls mixing sonnet + opus. Verify per_phase +
    per_model breakdowns sum correctly to total_cost_usd.
    """
    run = _mk_run(
        profile="anthropic-baseline",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "claude-sonnet-4-6",
                        "input_tokens": 500_000,
                        "output_tokens": 200_000,
                        "wall_clock_ms": 1000,
                    },
                    {
                        "model": "claude-haiku-4-5",
                        "input_tokens": 100_000,
                        "output_tokens": 50_000,
                        "wall_clock_ms": 200,
                    },
                ],
            },
            {
                "name": "correlation",
                "llm_calls": [
                    {
                        "model": "claude-opus-4-7",
                        "input_tokens": 300_000,
                        "output_tokens": 150_000,
                        "wall_clock_ms": 2500,
                    },
                ],
            },
        ],
    )
    summary = cost_summary_for_run(run)

    sonnet_cost = compute_call_cost_usd(
        "claude-sonnet-4-6", 500_000, 200_000
    )
    haiku_cost = compute_call_cost_usd(
        "claude-haiku-4-5", 100_000, 50_000
    )
    opus_cost = compute_call_cost_usd(
        "claude-opus-4-7", 300_000, 150_000
    )
    expected_total = sonnet_cost + haiku_cost + opus_cost

    assert summary["total_input_tokens"] == 900_000
    assert summary["total_output_tokens"] == 400_000
    assert summary["total_cost_usd"] == pytest.approx(expected_total, rel=1e-9)

    # Per-phase: recon = sonnet + haiku; correlation = opus.
    assert summary["per_phase"]["recon"]["cost_usd"] == pytest.approx(
        sonnet_cost + haiku_cost, rel=1e-9
    )
    assert summary["per_phase"]["recon"]["input_tokens"] == 600_000
    assert summary["per_phase"]["correlation"]["cost_usd"] == pytest.approx(
        opus_cost, rel=1e-9
    )
    assert summary["per_phase"]["correlation"]["input_tokens"] == 300_000

    # Per-model: all three present, costs match.
    assert summary["per_model"]["claude-sonnet-4-6"]["cost_usd"] == pytest.approx(
        sonnet_cost, rel=1e-9
    )
    assert summary["per_model"]["claude-haiku-4-5"]["cost_usd"] == pytest.approx(
        haiku_cost, rel=1e-9
    )
    assert summary["per_model"]["claude-opus-4-7"]["cost_usd"] == pytest.approx(
        opus_cost, rel=1e-9
    )


# ---- Test 3: unknown model costs 0, tokens still counted ----------------


def test_cost_summary_unknown_model_costs_zero():
    """An unknown model alias contributes 0.0 to total_cost_usd (matches
    pricing.compute_call_cost_usd's defensive default — never fabricate
    dollar values). Its tokens DO contribute to total_input/output_tokens.
    """
    run = _mk_run(
        profile="anthropic-baseline",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "not-a-real-model",
                        "input_tokens": 1_000_000,
                        "output_tokens": 500_000,
                        "wall_clock_ms": 1000,
                    },
                ],
            },
        ],
    )
    summary = cost_summary_for_run(run)

    assert summary["total_cost_usd"] == 0.0
    # Tokens still counted regardless of pricing availability.
    assert summary["total_input_tokens"] == 1_000_000
    assert summary["total_output_tokens"] == 500_000
    # Per-model entry exists with zero cost.
    assert "not-a-real-model" in summary["per_model"]
    assert summary["per_model"]["not-a-real-model"]["cost_usd"] == 0.0


# ---- Test 4: 80% reduction is pass --------------------------------------


def test_cost_delta_80_percent_reduction_is_pass():
    """Baseline cost $9.00, candidate cost $1.80 → 80% reduction → verdict 'pass'.

    Input_tokens chosen so total_cost_usd is an EXACT decimal value via the
    documented pricing (no rounding-error edge cases at the threshold).
    Baseline: 3M sonnet input × $3/M = $9.00.
    Candidate: 3.6M qwen input × $0.50/M = $1.80.
    """
    baseline_run = _mk_run(
        profile="anthropic-baseline",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "claude-sonnet-4-6",
                        "input_tokens": 3_000_000,
                        "output_tokens": 0,
                        "wall_clock_ms": 1,
                    },
                ],
            },
        ],
    )
    candidate_run = _mk_run(
        profile="siliconflow-qwen-235b",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "Qwen/Qwen3-235B-A22B-Instruct-2507",
                        "input_tokens": 3_600_000,
                        "output_tokens": 0,
                        "wall_clock_ms": 1,
                    },
                ],
            },
        ],
    )

    delta = cost_delta(baseline_run, candidate_run)

    assert delta["baseline_total_usd"] == pytest.approx(9.0, rel=1e-6)
    assert delta["candidate_total_usd"] == pytest.approx(1.80, rel=1e-6)
    assert delta["absolute_delta_usd"] == pytest.approx(7.20, rel=1e-6)
    assert delta["percent_reduction"] == pytest.approx(80.0, rel=1e-6)
    assert delta["verdict"] == "pass"


# ---- Test 5: 50% reduction is partial -----------------------------------


def test_cost_delta_50_percent_reduction_is_partial():
    """Baseline $9, candidate $4.50 → 50% reduction → verdict 'partial'.

    Baseline: 3M sonnet input × $3/M = $9.00.
    Candidate: 9M qwen input × $0.50/M = $4.50.
    """
    baseline_run = _mk_run(
        profile="anthropic-baseline",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "claude-sonnet-4-6",
                        "input_tokens": 3_000_000,
                        "output_tokens": 0,
                        "wall_clock_ms": 1,
                    },
                ],
            },
        ],
    )
    candidate_run = _mk_run(
        profile="siliconflow-qwen-235b",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "Qwen/Qwen3-235B-A22B-Instruct-2507",
                        "input_tokens": 9_000_000,
                        "output_tokens": 0,
                        "wall_clock_ms": 1,
                    },
                ],
            },
        ],
    )
    delta = cost_delta(baseline_run, candidate_run)
    assert delta["baseline_total_usd"] == pytest.approx(9.0, rel=1e-6)
    assert delta["candidate_total_usd"] == pytest.approx(4.50, rel=1e-6)
    assert delta["percent_reduction"] == pytest.approx(50.0, rel=1e-6)
    assert delta["verdict"] == "partial"


# ---- Test 6: 30% reduction is fail --------------------------------------


def test_cost_delta_30_percent_reduction_is_fail():
    """Baseline $9, candidate $6.30 → 30% reduction → verdict 'fail'.
    The cost-delta threshold is hard: anything below 50% is 'fail', because
    the whole point of the Qwen experiment is dramatic per-token savings.

    Baseline: 3M sonnet input × $3/M = $9.00.
    Candidate: 12.6M qwen input × $0.50/M = $6.30.
    """
    baseline_run = _mk_run(
        profile="anthropic-baseline",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "claude-sonnet-4-6",
                        "input_tokens": 3_000_000,
                        "output_tokens": 0,
                        "wall_clock_ms": 1,
                    },
                ],
            },
        ],
    )
    candidate_run = _mk_run(
        profile="siliconflow-qwen-235b",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "Qwen/Qwen3-235B-A22B-Instruct-2507",
                        "input_tokens": 12_600_000,
                        "output_tokens": 0,
                        "wall_clock_ms": 1,
                    },
                ],
            },
        ],
    )
    delta = cost_delta(baseline_run, candidate_run)
    assert delta["baseline_total_usd"] == pytest.approx(9.0, rel=1e-6)
    assert delta["candidate_total_usd"] == pytest.approx(6.30, rel=1e-6)
    assert delta["percent_reduction"] == pytest.approx(30.0, rel=1e-6)
    assert delta["verdict"] == "fail"


# ---- Test 7: candidate more expensive -----------------------------------


def test_cost_delta_candidate_more_expensive_is_fail():
    """Baseline $6, candidate $12 → candidate is 100% MORE expensive
    (percent_reduction = -100.0) → verdict 'fail'. The reduction is
    NEGATIVE; the formula still produces a comparable number.

    Baseline: 2M sonnet input × $3/M = $6.00.
    Candidate: 24M qwen input × $0.50/M = $12.00.
    """
    baseline_run = _mk_run(
        profile="anthropic-baseline",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "claude-sonnet-4-6",
                        "input_tokens": 2_000_000,
                        "output_tokens": 0,
                        "wall_clock_ms": 1,
                    },
                ],
            },
        ],
    )
    candidate_run = _mk_run(
        profile="siliconflow-qwen-235b",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "Qwen/Qwen3-235B-A22B-Instruct-2507",
                        "input_tokens": 24_000_000,
                        "output_tokens": 0,
                        "wall_clock_ms": 1,
                    },
                ],
            },
        ],
    )
    delta = cost_delta(baseline_run, candidate_run)
    assert delta["baseline_total_usd"] == pytest.approx(6.0, rel=1e-6)
    assert delta["candidate_total_usd"] == pytest.approx(12.0, rel=1e-6)
    assert delta["absolute_delta_usd"] == pytest.approx(-6.0, rel=1e-6)
    assert delta["percent_reduction"] == pytest.approx(-100.0, rel=1e-6)
    assert delta["verdict"] == "fail"


# ---- Test 8: per-phase delta breakdown ---------------------------------


def test_cost_delta_per_phase_breakdown():
    """Two phases on both sides; per_phase_delta has entries for both with
    correct absolute + percent deltas.

    All token counts integer-exact under the documented pricing:
      Recon baseline: 2M × $3/M = $6 (sonnet).
      Recon candidate: 2.4M × $0.50/M = $1.20 (qwen).
      Correlation baseline: 1M × $3/M = $3 (sonnet).
      Correlation candidate: 1.2M × $0.50/M = $0.60 (qwen).
    Both phases come out to 80% reduction.
    """
    baseline_run = _mk_run(
        profile="anthropic-baseline",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "claude-sonnet-4-6",
                        "input_tokens": 2_000_000,
                        "output_tokens": 0,
                        "wall_clock_ms": 1,
                    },
                ],
            },
            {
                "name": "correlation",
                "llm_calls": [
                    {
                        "model": "claude-sonnet-4-6",
                        "input_tokens": 1_000_000,
                        "output_tokens": 0,
                        "wall_clock_ms": 1,
                    },
                ],
            },
        ],
    )
    candidate_run = _mk_run(
        profile="siliconflow-qwen-235b",
        phases=[
            {
                "name": "recon",
                "llm_calls": [
                    {
                        "model": "Qwen/Qwen3-235B-A22B-Instruct-2507",
                        "input_tokens": 2_400_000,
                        "output_tokens": 0,
                        "wall_clock_ms": 1,
                    },
                ],
            },
            {
                "name": "correlation",
                "llm_calls": [
                    {
                        "model": "Qwen/Qwen3-235B-A22B-Instruct-2507",
                        "input_tokens": 1_200_000,
                        "output_tokens": 0,
                        "wall_clock_ms": 1,
                    },
                ],
            },
        ],
    )
    delta = cost_delta(baseline_run, candidate_run)

    assert set(delta["per_phase_delta"].keys()) == {"recon", "correlation"}
    # Recon: baseline 6 → candidate 1.2; delta 4.8; 80% reduction.
    recon = delta["per_phase_delta"]["recon"]
    assert recon["baseline_usd"] == pytest.approx(6.0, rel=1e-6)
    assert recon["candidate_usd"] == pytest.approx(1.20, rel=1e-6)
    assert recon["delta_usd"] == pytest.approx(4.80, rel=1e-6)
    assert recon["percent_reduction"] == pytest.approx(80.0, rel=1e-6)
    # Correlation: baseline 3 → candidate 0.6; 80% reduction.
    corr = delta["per_phase_delta"]["correlation"]
    assert corr["baseline_usd"] == pytest.approx(3.0, rel=1e-6)
    assert corr["candidate_usd"] == pytest.approx(0.60, rel=1e-6)
    assert corr["percent_reduction"] == pytest.approx(80.0, rel=1e-6)


# ---- Test 9: harness embeds cost_summary + cost_delta + verdict_overall


def _mock_invoke_with_costs(per_profile_tokens: dict[str, tuple[int, int, str]]):
    """Return a fake invoke_fn that yields synthetic llm_calls populated.

    per_profile_tokens maps profile → (input_tokens, output_tokens, model_alias).
    The returned per-run dict has one phase ('recon') with one call.
    """
    def _invoke(*, target, scope_path, profile, suite, extra_args=None):
        inp, out, model = per_profile_tokens[profile]
        return {
            "profile": profile,
            "model_aliases_used": {"claude-sonnet-4-6": model},
            "workspace_path": f"/tmp/test-{profile}",
            "subprocess_exit_code": 0,
            "phases": [
                {
                    "name": "recon",
                    "started_at": "2026-XX-XXT00:00:00Z",
                    "completed_at": "2026-XX-XXT00:00:01Z",
                    "exit_code": 0,
                    "llm_calls": [
                        {
                            "model": model,
                            "input_tokens": inp,
                            "output_tokens": out,
                            "wall_clock_ms": 1234,
                        },
                    ],
                    "tool_calls": [],
                    "emitted_finding_fingerprints": [],
                    "emitted_findings": [],
                },
            ],
            "total_input_tokens": inp,
            "total_output_tokens": out,
            "qwen_empty_args_observed_delta": 0,
        }
    return _invoke


def test_run_parity_eval_embeds_cost_summary_in_eval_json(
    tmp_scope, tmp_path
):
    """Full harness invocation (with mocked invoke_fn):
    - Each run dict in eval_json['runs'] has a `cost_summary` key.
    - eval_json['suites'][<suite>] has a `cost_delta` key.
    - Top-level eval_json['verdict_overall'] is set.
    """
    output_dir = tmp_path / "runs"
    # Baseline: 3M sonnet input × $3/M = $9. Candidate: 3.6M qwen × $0.50/M = $1.80.
    # → 80% reduction → cost verdict 'pass'.
    invoke_fn = _mock_invoke_with_costs({
        "anthropic-baseline": (3_000_000, 0, "claude-sonnet-4-6"),
        "siliconflow-qwen-235b": (
            3_600_000, 0, "Qwen/Qwen3-235B-A22B-Instruct-2507"
        ),
    })

    result = run_parity_eval(
        suite="juice-shop",
        baseline_profile="anthropic-baseline",
        candidate_profile="siliconflow-qwen-235b",
        scope_path=str(tmp_scope),
        output_dir=output_dir,
        invoke_fn=invoke_fn,
    )

    # Each run has cost_summary.
    for run in result["runs"]:
        assert "cost_summary" in run, (
            f"run for {run.get('profile')} missing cost_summary; "
            f"keys: {sorted(run.keys())}"
        )
        cs = run["cost_summary"]
        assert "total_cost_usd" in cs
        assert "per_phase" in cs
        assert "per_model" in cs
        assert "total_input_tokens" in cs
        assert "total_output_tokens" in cs

    # Suite-level cost_delta exists.
    assert "suites" in result, sorted(result.keys())
    assert "juice-shop" in result["suites"]
    suite_data = result["suites"]["juice-shop"]
    assert "cost_delta" in suite_data
    cd = suite_data["cost_delta"]
    assert cd["verdict"] == "pass"
    assert cd["percent_reduction"] == pytest.approx(80.0, rel=1e-4)

    # Per-suite verdict aggregation present.
    assert "verdict" in suite_data

    # Top-level verdict_overall present.
    assert "verdict_overall" in result
    assert result["verdict_overall"] in ("pass", "partial", "fail")


# ---- Test 10: schema_version bumped to '1.2' -----------------------------


def test_eval_json_schema_version_bumped_to_1_2():
    """Plan 02-03 bumps the schema constant from '1.1' (Plan 02-02) to '1.2'.
    Plan 02-04's dashboard reads this constant to detect v1.2+ shape.
    """
    assert EVAL_JSON_SCHEMA_VERSION == "1.2", (
        f"expected schema version '1.2', got {EVAL_JSON_SCHEMA_VERSION!r}"
    )
    assert isinstance(EVAL_JSON_SCHEMA_VERSION, str)


# ---- Bonus: verdict_for_cost edge cases (boundary tests) ---------------


def test_verdict_for_cost_at_thresholds():
    """Boundary values: exactly at pass and partial thresholds.

    COST_THRESHOLDS['pass'] = 80.0  → exactly 80% is 'pass' (>=).
    COST_THRESHOLDS['partial'] = 50.0 → exactly 50% is 'partial' (>=).
    """
    assert verdict_for_cost(80.0) == "pass"
    assert verdict_for_cost(79.999) == "partial"
    assert verdict_for_cost(50.0) == "partial"
    assert verdict_for_cost(49.999) == "fail"
    assert verdict_for_cost(0.0) == "fail"
    assert verdict_for_cost(-50.0) == "fail"
    # Constants exposed.
    assert COST_THRESHOLDS["pass"] == 80.0
    assert COST_THRESHOLDS["partial"] == 50.0
