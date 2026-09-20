"""Adversarial-validation gate — proof-model fork (2026-XX-XX).

The Evidence-Grade gate (sentinel/agent/pentest/adversarial_validation.py) must
enforce the doctrine WITHOUT nuking legitimately-verified classic findings.

Two valid proof models:
  P1 — a registered Phase-2.5 class verifier deterministically reproduced the
       finding (entry['verification'] with a summary). Classic classes
       (idor/sqli/xss/ssrf/auth) prove impact this way.
  P2 — the differential variant/control contract (vuln:novel / logic classes).

A finding with P1 must NOT be forced to carry the P2 contract fields — that
regression downgraded every verifier-confirmed finding to recon_inferred (a
false negative worse than the false positive the doctrine prevents). But rule 4
(documented-by-design, CASE B) and rule 5's true-positive (a second control
actually found behind the break, CASE A) STILL apply on top of P1.
"""

from __future__ import annotations

import asyncio

import pytest

from sentinel.agent.pentest import adversarial_validation as av
from sentinel.core.findings import EvidenceState


def _gate(entry: dict, vuln_class: str, state: EvidenceState = EvidenceState.LIVE_CONFIRMED):
    return asyncio.run(
        av.gate_finding(
            entry, vuln_class, current_state=state, scope_mode="production",
        )
    )


def test_verifier_reproduced_classic_finding_survives_gate():
    """P1: a Phase-2.5-verified IDOR (cross-account PII read) must STAY
    live_confirmed — the verifier reproduced the impact, so the gate must not
    demand the novel-class variant/control contract fields."""
    entry = {
        "ID": "IDOR-01",
        "vulnerability_type": "IDOR cross-account read",
        "evidence_state": "live_confirmed",
        "verification": {
            "summary": "Read victim order #1002 with attacker session; "
                       "response carried victim PII (name, email, address).",
            "evidence": {"attacker_status": 200, "leaked": ["email", "address"]},
        },
    }
    out = _gate(entry, "idor")
    assert out.new_evidence_state == EvidenceState.LIVE_CONFIRMED
    assert out.passed is True
    assert out.reasons == []


def test_documented_by_design_downgrades_even_with_verifier(monkeypatch):
    """CASE B: a verifier-reproduced behavior that is spec-permitted (ExampleChat
    confidential-client refresh grace) must STILL downgrade — rule 4 applies on
    top of a verifier reproduction."""
    entry = {
        "ID": "JWT-01",
        "vulnerability_type": "refresh token rotation grace 12h",
        "client_type": "confidential",
        "evidence_state": "live_confirmed",
        "is_spec_permitted": True,  # set upstream by is_documented_by_design
        "verification": {"summary": "old refresh token still valid 12h after rotation"},
    }
    out = _gate(entry, "jwt")
    assert out.new_evidence_state == EvidenceState.LIVE_DISPROVEN


def test_bare_signal_without_verifier_is_downgraded():
    """CASE A: a finding marked live_confirmed with NO verifier reproduction and
    NO adversarial contract is a bare signal — it must not survive as confirmed.
    (This is the auth-gate-code-bug-but-never-proved-bypass case.)"""
    entry = {
        "ID": "AUTH-09",
        "vulnerability_type": "auth gate code bug",
        "evidence_state": "live_confirmed",
    }
    out = _gate(entry, "auth")
    assert out.new_evidence_state != EvidenceState.LIVE_CONFIRMED
    assert out.passed is False


def test_verifier_bypass_with_second_control_found_is_held():
    """CASE A true-positive ("100 floors"): a verifier reached protected
    functionality, but a SECOND control was found behind the one it broke — the
    bypass is not proven, so it must be held for manual review (not confirmed)."""
    entry = {
        "ID": "AUTH-10",
        "vulnerability_type": "auth bypass",
        "evidence_state": "live_confirmed",
        "verification": {"summary": "reached /admin past the first gate"},
        "adversarial": {"second_control_found": True},
    }
    out = _gate(entry, "auth")
    assert out.new_evidence_state == EvidenceState.MANUAL_VERIFICATION_REQUIRED


def test_gate_is_monotonic_down_never_promotes():
    """The gate may only HOLD or DOWNGRADE; it must never raise a weaker state
    up to a confirmed one, even with a perfect-looking contract."""
    entry = {
        "ID": "X-1",
        "evidence_state": "recon_inferred",
        "verification": {"summary": "looks confirmed"},
        "adversarial": {
            "realized_impact": "full account takeover",
            "impact_evidence_ref": "evidence/x.json",
            "chain_layers": [{"name": "gate", "proven": True}],
            "ruled_out_alternatives": ["a", "b", "c"],
            "variant_resp_hash": "aaa", "control_resp_hash": "bbb",
            "mechanism": "because reasons",
        },
    }
    out = _gate(entry, "novel", state=EvidenceState.RECON_INFERRED)
    assert out.new_evidence_state == EvidenceState.RECON_INFERRED


def test_by_design_matches_vulnerability_type_field():
    """Regression (2026-XX-XX dry run): the documented-by-design canonical match
    reads _entry_text, which must include the `vulnerability_type` field — the
    canonical queue-entry field name across this codebase. Omitting it silently
    defeated CASE B on entries that carry the vuln name only there."""
    entry = {
        "ID": "JWT-VT",
        "vulnerability_type": "OAuth refresh token rotation grace window 12h",
        "client_type": "confidential",
    }
    by_design, evidence = asyncio.run(
        av.is_documented_by_design(entry, "jwt", corpus_search=None)
    )
    assert by_design is True, f"expected canonical by-design match, got {evidence!r}"
    # and the gate downgrades it end-to-end (CASE B)
    out = _gate(entry, "jwt")
    assert out.new_evidence_state == EvidenceState.LIVE_DISPROVEN


def test_ctf_mode_is_pass_through():
    """Flag-capture modes never apply doctrine downgrades — every hypothesis
    advances."""
    entry = {"ID": "F-1", "evidence_state": "live_confirmed"}
    out = asyncio.run(
        av.gate_finding(
            entry, "auth", current_state=EvidenceState.LIVE_CONFIRMED,
            scope_mode="ctf",
        )
    )
    assert out.new_evidence_state == EvidenceState.LIVE_CONFIRMED
    assert out.passed is True
