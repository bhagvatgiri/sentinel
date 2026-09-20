"""evaluate_novelty_gate — the single pure-function the pipeline calls between
verify-phase-03 drain and pre-correlation (Plan 05-04, NOVEL-05 + NOVEL-06).

Combines three gates into one decision so the pipeline's _run_novelty_sweep
has a single call site to consult per finding:

  1. INDEX_EMPTY     — operator hasn't run `sentinel novelty refresh-index`,
                        index_size == 0; no escalation is possible.
  2. WRONG_EVIDENCE_STATE — finding.evidence_state isn't in the scope's
                        allowlist (default: ["verified"], preserves the
                        VERIFY-08 contract).
  3. BELOW_THRESHOLD  — novelty_score < scope.novelty_threshold (default 0.75).
  4. COST_CAP_HEADROOM_EXHAUSTED — scan_spend + est_escalation_cost would
                        cross max_cost_usd; preserves Plan 03-02 COST-01.
  5. PROCEED          — all gates pass; pipeline calls render_escalation_prompt
                        next.

The gate is INTENTIONALLY pure (no IO, no side-effects). All audit-log writes
and event_log emits happen in the pipeline call site so the gate stays
unit-testable with simple fakes.

Order of checks matters for operator-readable reasons:
  1. INDEX_EMPTY first — short-circuits everything (no novelty signal possible).
  2. WRONG_EVIDENCE_STATE next — cheaper than threshold check; if the state
     is wrong we don't care about the score.
  3. BELOW_THRESHOLD — the score-vs-threshold comparison.
  4. COST_CAP_HEADROOM_EXHAUSTED — last because it's the most subtle (depends
     on cumulative pipeline state, not the finding alone).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Decision enum + result dataclass
# ---------------------------------------------------------------------------


class EscalationDecision(str, Enum):
    """Five terminal decisions evaluate_novelty_gate can return.

    The string values double as audit-log payload keys (operator-readable
    when grepping `.audit-<engagement>.jsonl`).
    """

    PROCEED = "proceed"
    BELOW_THRESHOLD = "below_threshold"
    WRONG_EVIDENCE_STATE = "wrong_evidence_state"
    COST_CAP_HEADROOM_EXHAUSTED = "cost_cap_headroom_exhausted"
    INDEX_EMPTY = "index_empty"


@dataclass(frozen=True)
class GateResult:
    """Decision + operator-readable explanation.

    Frozen so the pipeline can't accidentally mutate after the gate returns
    (we want the audit-event payload to reflect exactly what the gate
    decided, not a downstream-modified copy).
    """

    decision: EscalationDecision
    reason: str


# ---------------------------------------------------------------------------
# The pure function
# ---------------------------------------------------------------------------


def evaluate_novelty_gate(
    finding,  # noqa: ANN001 — Finding type avoids circular import
    scope,    # noqa: ANN001 — Scope type avoids circular import
    *,
    index_size: int,
    scan_spend_usd: float,
    max_cost_usd: Optional[float],
    est_escalation_cost_usd: float = 0.05,
) -> GateResult:
    """Single combined gate for novelty escalation.

    Args:
        finding: sentinel.core.findings.Finding. Reads novelty_score +
            evidence_state. The novelty_score field's range invariant
            ([0.0, 1.0]) is enforced by Finding.__post_init__; we don't
            re-validate here.
        scope: sentinel.core.scope.Scope. Reads novelty_threshold +
            escalate_on_evidence_states.
        index_size: CorpusIndex.size — number of corpus rows. 0 means the
            operator never ran `sentinel novelty refresh-index`; gate
            short-circuits with INDEX_EMPTY.
        scan_spend_usd: Current cumulative pipeline spend (Plan 03-02
            COST-01 state). Caller passes the value snapshotted just
            before this gate fires.
        max_cost_usd: Plan 03-02 --max-cost-usd cap. None means unbounded
            (operator omitted the flag); the cost-cap check is skipped
            entirely in that case.
        est_escalation_cost_usd: Per-escalation Sonnet-tier LLM call
            estimate. Default 0.05 reflects a single ~2k-token round-trip
            at the SiliconFlow Qwen3.6-35B-A3B alias's published rates;
            operators with a different cost profile can override this
            constant in a future scope.yaml extension (TODO: Plan 05-05+).

    Returns:
        GateResult(decision=..., reason=...) where decision is one of the
        five EscalationDecision values and reason is a single operator-
        readable sentence suitable for the audit-event payload.
    """
    # ---- Gate 1: INDEX_EMPTY -----------------------------------------------
    if index_size <= 0:
        return GateResult(
            decision=EscalationDecision.INDEX_EMPTY,
            reason=(
                "novelty index is empty (size=0) — operator must run "
                "`sentinel novelty refresh-index` before escalation is possible"
            ),
        )

    # ---- Gate 2: WRONG_EVIDENCE_STATE --------------------------------------
    # Normalize evidence_state to its string value for comparison against the
    # scope's allowlist (which holds string values, not enum members).
    state_value = (
        finding.evidence_state.value
        if hasattr(finding.evidence_state, "value")
        else str(finding.evidence_state)
    )
    allowlist = list(scope.escalate_on_evidence_states or [])
    # Normalize allowlist entries the same way the scope loader does
    # (hyphen vs underscore for `manual-required` / `manual_required`).
    normalized_allowlist = {
        (entry.lower().strip() if isinstance(entry, str) else str(entry))
        for entry in allowlist
    }
    normalized_state = state_value.lower().strip()
    # Also accept the underscore alias matching the scope-loader normalization.
    if normalized_state == "manual-required":
        normalized_state_alt = "manual_required"
    elif normalized_state == "manual_required":
        normalized_state_alt = "manual-required"
    else:
        normalized_state_alt = normalized_state
    if (normalized_state not in normalized_allowlist
            and normalized_state_alt not in normalized_allowlist):
        return GateResult(
            decision=EscalationDecision.WRONG_EVIDENCE_STATE,
            reason=(
                f"evidence_state {state_value!r} not in allowlist "
                f"{sorted(normalized_allowlist)}"
            ),
        )

    # ---- Gate 3: BELOW_THRESHOLD -------------------------------------------
    score = float(getattr(finding, "novelty_score", 0.0))
    threshold = float(getattr(scope, "novelty_threshold", 0.75))
    if score < threshold:
        return GateResult(
            decision=EscalationDecision.BELOW_THRESHOLD,
            reason=(
                f"novelty_score {score:.4f} below threshold {threshold:.4f}"
            ),
        )

    # ---- Gate 4: COST_CAP_HEADROOM_EXHAUSTED -------------------------------
    if max_cost_usd is not None:
        projected_spend = float(scan_spend_usd) + float(est_escalation_cost_usd)
        if projected_spend > float(max_cost_usd):
            headroom = max(0.0, float(max_cost_usd) - float(scan_spend_usd))
            return GateResult(
                decision=EscalationDecision.COST_CAP_HEADROOM_EXHAUSTED,
                reason=(
                    f"headroom ${headroom:.4f} below estimated escalation cost "
                    f"${est_escalation_cost_usd:.4f} at cap ${max_cost_usd:.4f} "
                    f"(scan_spend ${scan_spend_usd:.4f})"
                ),
            )

    # ---- All gates passed -> PROCEED ---------------------------------------
    return GateResult(
        decision=EscalationDecision.PROCEED,
        reason=(
            f"novelty_score {score:.4f} >= threshold {threshold:.4f}, "
            f"evidence_state {state_value!r} in allowlist, "
            f"index_size {index_size}, "
            f"cost-cap headroom available"
        ),
    )
