"""Cost accounting + cost-delta math for the parity benchmark (BENCH-07).

This module turns a per-run dict (the runs[i] entries written by
`sentinel.benchmark.parity_eval.run_parity_eval`) into:

  - A `cost_summary_for_run` aggregator (per-phase + per-model + per-run
    totals in USD), grounded in `sentinel.benchmark.pricing.PROFILE_PRICING`.
  - A `cost_delta` comparator (baseline vs candidate — absolute USD delta,
    percent reduction, per-phase deltas, and a pass/partial/fail verdict).
  - A `verdict_for_cost` threshold gate (≥80% → pass, ≥50% → partial,
    below → fail).

Cost-delta contract:

    A 'pass' verdict on cost-delta is the central success criterion for
    Phase 2 (SiliconFlow Qwen 235B vs Anthropic baseline). The whole
    point of the benchmark is dramatic per-token savings — anything less
    than 80% reduction means the operator should NOT flip the default
    profile to Qwen 235B (Plan 02-04's --apply-default-switch flow gates
    on this verdict).

Token-source contract:

    The per-call token counts come from `run['phases'][].llm_calls[i]
    .input_tokens / .output_tokens`. These are the LIVE token counts the
    LLM API returned (captured by the agent loop's existing
    `llm_call_completed` event handler), NOT character-count estimates.
    See `sentinel/agent/event_log.py` for the upstream capture point.

Unknown model handling:

    `compute_call_cost_usd` returns 0.0 + warning log for unknown model
    aliases (defensive default — never fabricate dollar values).
    `cost_summary_for_run` inherits this: unknown-model calls count
    toward total_input/output_tokens but contribute $0 to cost. The
    operator sees an incomplete-accounting warning in their logs and
    can add the missing model to PROFILE_PRICING.

Hermetic: this module does no I/O. Tests pass synthetic dicts; the
harness (parity_eval.run_parity_eval) calls these functions on its
in-memory run dicts before writing the eval JSON.
"""

from __future__ import annotations

import logging
from typing import Any

from sentinel.benchmark.pricing import compute_call_cost_usd


log = logging.getLogger(__name__)


# ---- Threshold constants ------------------------------------------------

# Percent-reduction thresholds for cost-delta verdict. The 'pass' bar at
# 80% matches Phase 2's BENCH-07 success criterion in REQUIREMENTS.md.
COST_THRESHOLDS: dict[str, float] = {
    "pass": 80.0,
    "partial": 50.0,
}


# ---- Per-run cost summary ----------------------------------------------


def cost_summary_for_run(run: dict) -> dict:
    """Aggregate per-phase + per-model + per-run cost from a single run dict.

    Walks `run['phases'][].llm_calls[]`. For each call, looks up the
    model alias in `pricing.PROFILE_PRICING` via `compute_call_cost_usd`
    and accumulates input/output tokens + USD cost. Unknown models
    contribute 0.0 cost (with a warning log from compute_call_cost_usd)
    but their tokens still count toward total_input/output_tokens.

    Args:
        run: A per-run dict (matches runs[i] schema in parity_eval).
            Must have a 'phases' list; each phase must have an 'llm_calls'
            list; each call must have 'model', 'input_tokens',
            'output_tokens' keys.

    Returns:
        Dict with:
            total_input_tokens:  int  — sum across all calls.
            total_output_tokens: int  — sum across all calls.
            total_cost_usd:      float — sum of per-call USD costs.
            per_phase:  dict[phase_name, {input_tokens, output_tokens,
                                          cost_usd}]
            per_model:  dict[model_alias, {input_tokens, output_tokens,
                                           cost_usd}]
    """
    total_input = 0
    total_output = 0
    total_cost = 0.0
    per_phase: dict[str, dict[str, Any]] = {}
    per_model: dict[str, dict[str, Any]] = {}

    for phase in run.get("phases", []):
        phase_name = phase.get("name", "<unnamed>")
        phase_entry = per_phase.setdefault(
            phase_name,
            {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
        )

        for call in phase.get("llm_calls", []):
            model = call.get("model", "")
            inp = int(call.get("input_tokens", 0) or 0)
            out = int(call.get("output_tokens", 0) or 0)
            cost = compute_call_cost_usd(model, inp, out)

            total_input += inp
            total_output += out
            total_cost += cost

            phase_entry["input_tokens"] += inp
            phase_entry["output_tokens"] += out
            phase_entry["cost_usd"] += cost

            model_entry = per_model.setdefault(
                model,
                {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
            )
            model_entry["input_tokens"] += inp
            model_entry["output_tokens"] += out
            model_entry["cost_usd"] += cost

    return {
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_cost_usd": total_cost,
        "per_phase": per_phase,
        "per_model": per_model,
    }


# ---- Per-suite cost delta ----------------------------------------------


def _per_phase_summary(run: dict) -> dict[str, dict[str, float]]:
    """Internal helper — extract per-phase cost from a run's cost_summary
    (computing it on the fly if not already present). Returns
    {phase_name: {input_tokens, output_tokens, cost_usd}}.
    """
    cs = run.get("cost_summary")
    if cs is None:
        cs = cost_summary_for_run(run)
    return cs.get("per_phase", {})


def cost_delta(baseline_run: dict, candidate_run: dict) -> dict:
    """Compare two runs of the same suite (different profiles).

    Pulls cost_summary from each run (computing on the fly via
    cost_summary_for_run if either is missing). Returns absolute +
    percent reduction + per-phase breakdown + verdict.

    Percent_reduction formula:
        (baseline_total_usd - candidate_total_usd) / baseline_total_usd * 100

    A positive percent_reduction means the candidate is cheaper (the
    expected direction for Phase 2's SiliconFlow vs Anthropic comparison).
    A negative value means the candidate is MORE expensive than the baseline.

    Args:
        baseline_run: per-run dict for the baseline profile (typically
            anthropic-baseline).
        candidate_run: per-run dict for the candidate profile (typically
            siliconflow-qwen-235b).

    Returns:
        Dict with:
            baseline_total_usd:  float
            candidate_total_usd: float
            absolute_delta_usd:  float — baseline_total - candidate_total
                                          (positive = savings).
            percent_reduction:   float — (delta / baseline) * 100, or 0.0
                                          if baseline_total <= 0.
            per_phase_delta: dict[phase_name, {baseline_usd, candidate_usd,
                                               delta_usd, percent_reduction}]
            verdict: 'pass' | 'partial' | 'fail' (via verdict_for_cost).
    """
    # Compute (or reuse) cost_summary for both sides.
    baseline_cs = baseline_run.get("cost_summary") or cost_summary_for_run(
        baseline_run
    )
    candidate_cs = candidate_run.get("cost_summary") or cost_summary_for_run(
        candidate_run
    )

    baseline_total = float(baseline_cs.get("total_cost_usd", 0.0))
    candidate_total = float(candidate_cs.get("total_cost_usd", 0.0))
    absolute_delta = baseline_total - candidate_total
    if baseline_total > 0:
        percent_reduction = (absolute_delta / baseline_total) * 100.0
    else:
        percent_reduction = 0.0

    # Per-phase delta — union of phase keys from both sides.
    baseline_per_phase = _per_phase_summary(baseline_run)
    candidate_per_phase = _per_phase_summary(candidate_run)
    all_phase_names = set(baseline_per_phase.keys()) | set(
        candidate_per_phase.keys()
    )

    per_phase_delta: dict[str, dict[str, float]] = {}
    for phase_name in all_phase_names:
        b_phase = baseline_per_phase.get(phase_name, {})
        c_phase = candidate_per_phase.get(phase_name, {})
        b_usd = float(b_phase.get("cost_usd", 0.0))
        c_usd = float(c_phase.get("cost_usd", 0.0))
        d_usd = b_usd - c_usd
        pct = (d_usd / b_usd) * 100.0 if b_usd > 0 else 0.0
        per_phase_delta[phase_name] = {
            "baseline_usd": b_usd,
            "candidate_usd": c_usd,
            "delta_usd": d_usd,
            "percent_reduction": pct,
        }

    return {
        "baseline_total_usd": baseline_total,
        "candidate_total_usd": candidate_total,
        "absolute_delta_usd": absolute_delta,
        "percent_reduction": percent_reduction,
        "per_phase_delta": per_phase_delta,
        "verdict": verdict_for_cost(percent_reduction),
    }


# ---- Verdict thresholding ----------------------------------------------


def verdict_for_cost(percent_reduction: float) -> str:
    """Return 'pass' / 'partial' / 'fail' based on percent_reduction.

    Thresholds (COST_THRESHOLDS):
      percent_reduction >= 80.0 → 'pass'
      percent_reduction >= 50.0 → 'partial'
      otherwise                  → 'fail'

    Negative reductions (candidate MORE expensive) always fall to 'fail'.
    """
    if percent_reduction >= COST_THRESHOLDS["pass"]:
        return "pass"
    if percent_reduction >= COST_THRESHOLDS["partial"]:
        return "partial"
    return "fail"


__all__ = [
    "COST_THRESHOLDS",
    "cost_summary_for_run",
    "cost_delta",
    "verdict_for_cost",
]
