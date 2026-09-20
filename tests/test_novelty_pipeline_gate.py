"""NOVEL-05 + NOVEL-06 pipeline gate tests (Plan 05-04, Task 2).

Pins evaluate_novelty_gate's five-state decision matrix and the AuditLog
hash-chain invariant for the three new event kinds.

Gate decision tests (1-6 + an unbounded variant):

  Test 1 — PROCEED: score above threshold, evidence_state allowed, non-empty
    index, cost-cap headroom available -> GateResult(decision=PROCEED, reason=...)
  Test 2 — BELOW_THRESHOLD: novelty_score < scope.novelty_threshold
  Test 3 — WRONG_EVIDENCE_STATE: evidence_state not in the allowlist
  Test 4 — INDEX_EMPTY: index_size == 0 short-circuits regardless of score
  Test 5 — COST_CAP_HEADROOM_EXHAUSTED: scan_spend + est_escalation > max_cost
  Test 6 — PROCEED with max_cost_usd=None: unbounded mode skips the cost-cap
    check entirely

Test 7 — Audit chain integrity (CLAUDE.md safety-boundary #2):
  Write one of each of the three new event kinds to a real AuditLog file
  in tmp_path; AuditLog.verify(path) must return (True, None). The new
  event kinds are arbitrary strings the existing AuditLog.write API
  accepts; this pins that adding them does NOT break the hash chain.

All tests hermetic — zero live LLM, zero live Chroma, zero pipeline boot.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.core.findings import EvidenceState, Finding, Severity
from sentinel.core.scope import AuditLog


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    novelty_score: float = 0.85,
    evidence_state: EvidenceState = EvidenceState.VERIFIED,
) -> Finding:
    """Compact Finding factory mirroring test_finding_novelty_score_field."""
    return Finding(
        title="SQL injection in /admin",
        description="Parameter id reflects into raw SQL; UNION-based extraction proven.",
        severity=Severity.HIGH,
        scanner="vuln:sqli",
        target="https://example.com",
        novelty_score=novelty_score,
        evidence_state=evidence_state,
    )


class _FakeScope:
    """Minimal scope stand-in. Plan 05-04 reads only novelty_threshold +
    escalate_on_evidence_states off scope; rest is irrelevant for the gate."""

    def __init__(
        self,
        *,
        novelty_threshold: float = 0.75,
        escalate_on_evidence_states: list = None,
    ):
        self.novelty_threshold = novelty_threshold
        self.escalate_on_evidence_states = (
            escalate_on_evidence_states if escalate_on_evidence_states is not None
            else ["verified"]
        )


# ---------------------------------------------------------------------------
# Gate decision matrix
# ---------------------------------------------------------------------------


def test_evaluate_gate_proceeds_when_score_above_threshold_and_state_allowed():
    """Happy path — score >= threshold, state allowed, index non-empty,
    headroom present -> PROCEED."""
    from sentinel.agent.novelty import (
        EscalationDecision,
        GateResult,
        evaluate_novelty_gate,
    )

    finding = _make_finding(novelty_score=0.85)
    scope = _FakeScope(novelty_threshold=0.75)
    result = evaluate_novelty_gate(
        finding,
        scope,
        index_size=100,
        scan_spend_usd=1.0,
        max_cost_usd=10.0,
    )
    assert isinstance(result, GateResult)
    assert result.decision == EscalationDecision.PROCEED
    assert isinstance(result.reason, str) and result.reason  # non-empty


def test_evaluate_gate_blocks_below_threshold():
    """novelty_score 0.30 below scope.novelty_threshold 0.75 -> BELOW_THRESHOLD."""
    from sentinel.agent.novelty import EscalationDecision, evaluate_novelty_gate

    finding = _make_finding(novelty_score=0.30)
    scope = _FakeScope(novelty_threshold=0.75)
    result = evaluate_novelty_gate(
        finding,
        scope,
        index_size=100,
        scan_spend_usd=1.0,
        max_cost_usd=10.0,
    )
    assert result.decision == EscalationDecision.BELOW_THRESHOLD
    # Reason names the score + threshold so the audit-event decline line is
    # operator-readable (no need to cross-reference scope file).
    assert "0.3" in result.reason or "0.30" in result.reason
    assert "0.75" in result.reason


def test_evaluate_gate_blocks_wrong_evidence_state():
    """Finding evidence_state UNREPRODUCIBLE not in allowlist -> WRONG_EVIDENCE_STATE."""
    from sentinel.agent.novelty import EscalationDecision, evaluate_novelty_gate

    finding = _make_finding(
        novelty_score=0.85,
        evidence_state=EvidenceState.UNREPRODUCIBLE,
    )
    scope = _FakeScope(escalate_on_evidence_states=["verified"])
    result = evaluate_novelty_gate(
        finding,
        scope,
        index_size=100,
        scan_spend_usd=1.0,
        max_cost_usd=10.0,
    )
    assert result.decision == EscalationDecision.WRONG_EVIDENCE_STATE
    # Reason mentions the unallowed state + the allowlist.
    assert "unreproducible" in result.reason.lower()


def test_evaluate_gate_blocks_empty_index():
    """index_size 0 short-circuits regardless of score -> INDEX_EMPTY."""
    from sentinel.agent.novelty import EscalationDecision, evaluate_novelty_gate

    finding = _make_finding(novelty_score=0.99)
    scope = _FakeScope()
    result = evaluate_novelty_gate(
        finding,
        scope,
        index_size=0,
        scan_spend_usd=0.0,
        max_cost_usd=10.0,
    )
    assert result.decision == EscalationDecision.INDEX_EMPTY


def test_evaluate_gate_blocks_when_cost_cap_headroom_exhausted():
    """scan_spend + est_escalation_cost > max_cost -> COST_CAP_HEADROOM_EXHAUSTED."""
    from sentinel.agent.novelty import EscalationDecision, evaluate_novelty_gate

    finding = _make_finding(novelty_score=0.85)
    scope = _FakeScope()
    result = evaluate_novelty_gate(
        finding,
        scope,
        index_size=100,
        scan_spend_usd=9.99,
        max_cost_usd=10.00,
        # 9.99 + 0.05 = 10.04 > 10.00 cap -> blocks.
        est_escalation_cost_usd=0.05,
    )
    assert result.decision == EscalationDecision.COST_CAP_HEADROOM_EXHAUSTED
    # Reason cites the cap + the estimated cost so the audit log is
    # self-explanatory at incident-review time.
    assert "10" in result.reason


def test_evaluate_gate_proceeds_when_no_max_cost():
    """max_cost_usd=None (operator omitted --max-cost-usd) -> cost check skipped."""
    from sentinel.agent.novelty import EscalationDecision, evaluate_novelty_gate

    finding = _make_finding(novelty_score=0.85)
    scope = _FakeScope()
    result = evaluate_novelty_gate(
        finding,
        scope,
        index_size=100,
        scan_spend_usd=1_000_000.0,  # unbounded -> doesn't matter
        max_cost_usd=None,
    )
    assert result.decision == EscalationDecision.PROCEED


# ---------------------------------------------------------------------------
# Test 7 — Audit chain integrity (CLAUDE.md safety-boundary #2 invariant)
# ---------------------------------------------------------------------------


def test_audit_chain_remains_valid_with_all_three_novelty_events(tmp_path: Path):
    """Writing all three new event kinds to a real AuditLog preserves the
    hash chain. AuditLog.verify(path) must return (True, None).

    This is the load-bearing CLAUDE.md safety-boundary #2 invariant: the
    audit log is the legal artifact. Adding new event kinds (arbitrary
    strings the existing AuditLog.write API already accepts) must NOT
    break the chain.
    """
    audit_path = tmp_path / "audit-test.jsonl"
    audit = AuditLog(audit_path)

    # Emit the genesis scope_loaded entry so the chain has a real first
    # entry (matches the production Scope.load pattern).
    audit.write("scope_loaded", {
        "engagement_id": "test-novelty-eng",
        "client": "test-client",
    }, mode="production")

    # Plan 05-04's three new event kinds with realistic payload shapes.
    audit.write("novelty_score_computed", {
        "engagement_id": "test-novelty-eng",
        "finding_fingerprint": "abc123def4567890",
        "novelty_score": 0.87,
        "evidence_state": "verified",
    }, mode="production")
    audit.write("novel_finding_escalated", {
        "engagement_id": "test-novelty-eng",
        "finding_fingerprint": "abc123def4567890",
        "novelty_score": 0.87,
        "nearest_corpus_match": {
            "chunk_id": "owasp-asvs-v4.0-1.2.3",
            "source": "owasp",
            "title": "ASVS Authentication",
            "cosine_distance": 0.42,
            "url": "https://owasp.org/asvs/v4.0/#1.2.3",
        },
    }, mode="production")
    audit.write("novel_finding_evidence_captured", {
        "engagement_id": "test-novelty-eng",
        "finding_fingerprint": "abc123def4567890",
        "novelty_score": 0.87,
        "verifier_evidence_path": "/tmp/workspaces/eng-001/verification/abc123def4567890",
    }, mode="production")

    ok, err = AuditLog.verify(audit_path)
    assert ok, f"hash chain broken after writing novelty events: {err}"
    assert err is None
