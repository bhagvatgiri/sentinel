"""Fix 2 (C4) — Cost-cap pre-phase predictive check.

The live ExampleChat scan was launched with `--max-cost-usd 10` but actual spend
reached $13.08 (a 30% overshoot). Reason: the existing
`_check_cost_cap` only compares `_scan_spend_usd >= max_budget_per_scan_usd`
AFTER a phase completes. If $9 already spent and the next phase costs $4+,
the cap is blown before the next between-phase check fires.

Fix: a PREDICTIVE check that estimates the next phase's cost based on a
rolling average of phases run so far (with a 50% safety margin) and aborts
BEFORE entering the phase if `cumulative + estimated >= cap`.

Heuristic:
    avg_cost = self._scan_spend_usd / max(self._phases_completed, 1)
    next_phase_estimate = avg_cost * 1.5

Tests are fully hermetic — no SDK, no shim, no network. They drive the
helper method directly with synthetic state.
"""

from __future__ import annotations

import pytest

from sentinel.agent.pentest.pipeline import (
    CostCapTripped,
    PentestPipeline,
    PipelineConfig,
)


def _build_pipeline(
    *,
    cost_cap_strict: bool = True,
    max_budget_per_scan_usd: float = 10.0,
    scan_spend_usd: float = 0.0,
    phases_completed: int = 0,
) -> PentestPipeline:
    cfg = PipelineConfig(
        target="http://example.test",
        scope_path="/nonexistent.yaml",
        max_budget_per_scan_usd=max_budget_per_scan_usd,
        cost_cap_strict=cost_cap_strict,
    )
    p = PentestPipeline(cfg)
    p._scan_spend_usd = scan_spend_usd
    p._phases_completed = phases_completed
    return p


# ---- Test 1: predictive helper exists ------------------------------------


def test_predict_next_phase_estimate_uses_running_average():
    """Estimate = running-avg-cost-per-phase * 1.5 safety margin.

    With $9 spent over 5 phases, avg = $1.80, est_next = $2.70.
    """
    p = _build_pipeline(scan_spend_usd=9.0, phases_completed=5)
    est = p._estimate_next_phase_cost_usd()
    assert est == pytest.approx(9.0 / 5 * 1.5, rel=1e-3), (
        f"expected 1.5× rolling avg, got ${est:.4f}"
    )


def test_predict_next_phase_estimate_zero_when_no_phases_completed():
    """First phase has no history — estimate is 0 (don't pre-abort phase 0)."""
    p = _build_pipeline(scan_spend_usd=0.0, phases_completed=0)
    est = p._estimate_next_phase_cost_usd()
    assert est == 0.0


# ---- Test 2: pre-phase predictive check fires when estimate would exceed -


def test_cost_cap_prephase_predicts_overshoot_in_strict_mode():
    """Strict mode: cumulative=$9, est_next=$2.70, cap=$10. $9 + $2.70 = $11.70 ≥ $10
    → returns CostCapTripped sentinel BEFORE the phase runs.
    """
    p = _build_pipeline(
        cost_cap_strict=True,
        max_budget_per_scan_usd=10.0,
        scan_spend_usd=9.0,
        phases_completed=5,
    )
    tripped = p._check_cost_cap_prephase(
        phase_name="exploit:jwt_oauth",
        phases_completed=5,
        phases_total=20,
    )
    assert tripped is not None
    assert isinstance(tripped, CostCapTripped)
    assert tripped.scan_spend_usd == pytest.approx(9.0)
    assert tripped.cap_usd == pytest.approx(10.0)
    assert tripped.phase_at_trip == "exploit:jwt_oauth"


def test_cost_cap_prephase_returns_none_when_estimate_under_cap():
    """Cumulative + estimate well below cap → returns None (phase allowed)."""
    p = _build_pipeline(
        cost_cap_strict=True,
        max_budget_per_scan_usd=10.0,
        scan_spend_usd=2.0,
        phases_completed=4,
    )
    # avg = 0.5, est_next = 0.75. 2.0 + 0.75 = 2.75 << 10.0
    tripped = p._check_cost_cap_prephase(
        phase_name="vuln:xss",
        phases_completed=4,
        phases_total=20,
    )
    assert tripped is None


def test_cost_cap_prephase_returns_none_when_cost_cap_strict_off():
    """Soft mode (cost_cap_strict=False) must NOT pre-abort.

    Predictive aborts only fire when the operator explicitly opted into
    --max-cost-usd (cost_cap_strict=True). Otherwise we preserve the
    existing soft-skip-then-fall-through behavior.
    """
    p = _build_pipeline(
        cost_cap_strict=False,
        max_budget_per_scan_usd=10.0,
        scan_spend_usd=9.5,
        phases_completed=5,
    )
    tripped = p._check_cost_cap_prephase(
        phase_name="exploit:jwt_oauth",
        phases_completed=5,
        phases_total=20,
    )
    assert tripped is None


def test_cost_cap_prephase_returns_none_when_no_phases_yet():
    """First phase: no history, estimate=0, no pre-abort possible even strict."""
    p = _build_pipeline(
        cost_cap_strict=True,
        max_budget_per_scan_usd=10.0,
        scan_spend_usd=0.0,
        phases_completed=0,
    )
    tripped = p._check_cost_cap_prephase(
        phase_name="recon",
        phases_completed=0,
        phases_total=20,
    )
    assert tripped is None


# ---- Test 3: live-scan exact scenario ($13 overshoot of $10 cap) ---------


def test_cost_cap_prephase_would_have_caught_live_slack_overshoot():
    """Regression for the live ExampleChat scan: $10 cap, $13.08 actual.

    If the scan reached $9.00 over 5 phases (avg=$1.80) and the next phase
    would have cost $2-4, the predictive check must fire and prevent the
    overshoot. Documents the lower-bound fix expected from this change.
    """
    p = _build_pipeline(
        cost_cap_strict=True,
        max_budget_per_scan_usd=10.0,
        scan_spend_usd=9.0,
        phases_completed=5,
    )
    tripped = p._check_cost_cap_prephase(
        phase_name="exploit:idor",
        phases_completed=5,
        phases_total=20,
    )
    assert tripped is not None, (
        "predictive check failed to fire — live ExampleChat-style overshoot would still occur"
    )
