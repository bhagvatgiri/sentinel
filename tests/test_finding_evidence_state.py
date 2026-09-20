"""VERIFY-01 — EvidenceState Phase 3 extension + Finding.destructive_classifier_match.

Pins the contract that:

1.  The Phase 2.5 evidence_state taxonomy (recon_inferred, live_confirmed,
    live_disproven, requires_test_credentials, requires_two_accounts,
    manual_verification_required, verification_error) remains intact — adding
    Phase 3 values is purely additive.
2.  The Phase 3 spelling values (`verified`, `unreproducible`, `manual-required`,
    `pending`) carry the EXACT strings the requirement spec calls for, including
    the hyphen in `manual-required`.
3.  `EvidenceState.from_string` tolerates the snake_case alias
    `manual_required` (maps to MANUAL_REQUIRED) while preserving the legacy
    `manual_verification_required` → MANUAL_VERIFICATION_REQUIRED mapping.
4.  Finding carries an optional `destructive_classifier_match: dict | None` field
    that round-trips through `to_dict`.
5.  The `__post_init__` reproduces_complete invariant is untouched.
"""

from __future__ import annotations

import pytest

from sentinel.core.findings import EvidenceState, Finding, Severity, Status


# ---------------------------------------------------------------------------
# EvidenceState enum extension
# ---------------------------------------------------------------------------


def test_evidence_state_phase3_values_exist():
    """Phase 3 verifier values present with the exact strings from the spec."""
    assert EvidenceState.VERIFIED.value == "verified"
    assert EvidenceState.UNREPRODUCIBLE.value == "unreproducible"
    assert EvidenceState.MANUAL_REQUIRED.value == "manual-required"  # hyphen, not underscore
    assert EvidenceState.PENDING.value == "pending"


def test_evidence_state_phase2_5_values_preserved():
    """All seven existing Phase 2.5 values still present and unchanged."""
    assert EvidenceState.RECON_INFERRED.value == "recon_inferred"
    assert EvidenceState.LIVE_CONFIRMED.value == "live_confirmed"
    assert EvidenceState.LIVE_DISPROVEN.value == "live_disproven"
    assert EvidenceState.REQUIRES_TEST_CREDENTIALS.value == "requires_test_credentials"
    assert EvidenceState.REQUIRES_TWO_ACCOUNTS.value == "requires_two_accounts"
    assert EvidenceState.MANUAL_VERIFICATION_REQUIRED.value == "manual_verification_required"
    assert EvidenceState.VERIFICATION_ERROR.value == "verification_error"


def test_evidence_state_from_string_handles_new_values():
    """from_string accepts each Phase 3 spelling, including snake_case alias."""
    assert EvidenceState.from_string("verified") is EvidenceState.VERIFIED
    assert EvidenceState.from_string("unreproducible") is EvidenceState.UNREPRODUCIBLE
    assert EvidenceState.from_string("manual-required") is EvidenceState.MANUAL_REQUIRED
    assert EvidenceState.from_string("manual_required") is EvidenceState.MANUAL_REQUIRED
    assert EvidenceState.from_string("pending") is EvidenceState.PENDING


def test_evidence_state_from_string_back_compat():
    """Legacy Phase 2.5 strings still resolve to their original enum values."""
    assert EvidenceState.from_string("live_confirmed") is EvidenceState.LIVE_CONFIRMED
    assert EvidenceState.from_string("live_disproven") is EvidenceState.LIVE_DISPROVEN
    assert EvidenceState.from_string("recon_inferred") is EvidenceState.RECON_INFERRED
    # The legacy spelling MUST stay distinct from the new MANUAL_REQUIRED —
    # back-compat means the older value keeps mapping to its own enum entry.
    assert (
        EvidenceState.from_string("manual_verification_required")
        is EvidenceState.MANUAL_VERIFICATION_REQUIRED
    )
    assert EvidenceState.from_string("requires_test_credentials") is EvidenceState.REQUIRES_TEST_CREDENTIALS
    assert EvidenceState.from_string("requires_two_accounts") is EvidenceState.REQUIRES_TWO_ACCOUNTS
    assert EvidenceState.from_string("verification_error") is EvidenceState.VERIFICATION_ERROR


def test_evidence_state_from_string_unknown_returns_default():
    """Unknown strings fall back to RECON_INFERRED (existing default)."""
    assert EvidenceState.from_string("not-a-state") is EvidenceState.RECON_INFERRED
    assert EvidenceState.from_string("") is EvidenceState.RECON_INFERRED
    assert EvidenceState.from_string(None) is EvidenceState.RECON_INFERRED


def test_evidence_state_from_string_case_and_whitespace_tolerant():
    """Mixed case + surrounding whitespace are stripped (existing behavior)."""
    assert EvidenceState.from_string("  VERIFIED  ") is EvidenceState.VERIFIED
    assert EvidenceState.from_string("Manual-Required") is EvidenceState.MANUAL_REQUIRED
    assert EvidenceState.from_string("  manual_required") is EvidenceState.MANUAL_REQUIRED


# ---------------------------------------------------------------------------
# Finding dataclass — destructive_classifier_match + Phase 3 evidence_state
# ---------------------------------------------------------------------------


def _make_finding(**overrides) -> Finding:
    base = dict(
        title="t",
        description="d",
        severity=Severity.LOW,
        scanner="s",
        target="t",
    )
    base.update(overrides)
    return Finding(**base)


def test_finding_default_destructive_match_is_none():
    """A freshly constructed finding has no classifier match attached."""
    f = _make_finding()
    assert f.destructive_classifier_match is None


def test_finding_with_destructive_match_round_trips_through_to_dict():
    """to_dict serializes the classifier payload as-is + emits enum .value."""
    match = {"pattern": "sql_drop_table", "rationale": "PoC contains DROP TABLE"}
    f = _make_finding(
        evidence_state=EvidenceState.MANUAL_REQUIRED,
        destructive_classifier_match=match,
    )
    d = f.to_dict()
    assert d["destructive_classifier_match"] == match
    assert d["destructive_classifier_match"]["pattern"] == "sql_drop_table"
    assert d["evidence_state"] == "manual-required"


def test_finding_accepts_phase3_evidence_state():
    """All four Phase 3 enum values can be assigned to a Finding directly."""
    for state in (
        EvidenceState.VERIFIED,
        EvidenceState.UNREPRODUCIBLE,
        EvidenceState.MANUAL_REQUIRED,
        EvidenceState.PENDING,
    ):
        f = _make_finding(evidence_state=state)
        assert f.evidence_state is state


def test_finding_post_init_invariant_unchanged():
    """The reproduces_complete belt-and-suspenders check still fires when one weaker leg is False."""
    # Happy path: all three legs True.
    _make_finding(
        reproduces_complete=True,
        reproduces_in_lab=True,
        reproduces_under_operational=True,
    )
    # Operational missing -> raise.
    with pytest.raises(ValueError, match="reproduces_complete"):
        _make_finding(
            reproduces_complete=True,
            reproduces_in_lab=True,
            reproduces_under_operational=False,
        )
    # Lab missing -> raise.
    with pytest.raises(ValueError, match="reproduces_complete"):
        _make_finding(
            reproduces_complete=True,
            reproduces_in_lab=False,
            reproduces_under_operational=True,
        )


def test_finding_to_dict_round_trip_preserves_evidence_state_value():
    """Each of the 11 EvidenceState values serializes to its `.value` string.

    PDF / dashboard / Obsidian renderers depend on this — they consume the
    string form, not the enum. A new value added without to_dict awareness
    would break the deliverable pipeline silently.
    """
    expected = {
        EvidenceState.RECON_INFERRED: "recon_inferred",
        EvidenceState.LIVE_CONFIRMED: "live_confirmed",
        EvidenceState.LIVE_DISPROVEN: "live_disproven",
        EvidenceState.REQUIRES_TEST_CREDENTIALS: "requires_test_credentials",
        EvidenceState.REQUIRES_TWO_ACCOUNTS: "requires_two_accounts",
        EvidenceState.MANUAL_VERIFICATION_REQUIRED: "manual_verification_required",
        EvidenceState.VERIFICATION_ERROR: "verification_error",
        EvidenceState.VERIFIED: "verified",
        EvidenceState.UNREPRODUCIBLE: "unreproducible",
        EvidenceState.MANUAL_REQUIRED: "manual-required",
        EvidenceState.PENDING: "pending",
    }
    assert len(expected) == 11  # tripwire: matches the documented taxonomy size
    for state, expected_value in expected.items():
        f = _make_finding(evidence_state=state)
        d = f.to_dict()
        assert d["evidence_state"] == expected_value, (
            f"to_dict serialization drift: {state} -> {d['evidence_state']!r} "
            f"(expected {expected_value!r})"
        )


def test_finding_destructive_match_default_round_trip_preserves_none():
    """When no match attached, the to_dict dict explicitly carries None (not missing)."""
    f = _make_finding()
    d = f.to_dict()
    assert "destructive_classifier_match" in d
    assert d["destructive_classifier_match"] is None


def test_finding_status_serialization_still_works():
    """Sanity: to_dict serialization of status survived the dataclass edit."""
    f = _make_finding(status=Status.CONFIRMED)
    d = f.to_dict()
    assert d["status"] == "confirmed"
