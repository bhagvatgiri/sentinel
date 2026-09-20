"""Tests for the Phase 3.5 chain executor — Goal taxonomy, chain
enumeration, and per-goal goal_satisfied predicates.

All goals are detection-mode. The predicates refuse to fire success
without the right evidence (canary callbacks, ≤3 record reads, rollback
for cleanup_required goals, test-mode credentials for payment goal).
"""

from __future__ import annotations

import pytest

from sentinel.agent.pentest.chain_executor import (
    GOALS, SLUG_TO_GOAL, DEFAULT_CLI_GOALS, validate_goal_slugs,
    chains_for_goal, ChainState, StepRecord, RCE_CANARY_COMMANDS,
    ChainContext, set_context, get_context,
)
from sentinel.agent.pentest.primitives import Primitive, PrimitiveType


# ---- registry shape ------------------------------------------------------


def test_eight_goals_registered():
    assert len(GOALS) == 8
    slugs = {g.slug for g in GOALS}
    assert slugs == {
        "admin_session_takeover", "pii_exfil", "lateral_to_internal_service",
        "session_fixation_or_hijack", "rce", "persistent_backdoor_admin",
        "audit_log_tamper", "payment_flow_bypass",
    }


def test_default_cli_goals_are_universal_detection():
    """Default-on goals must be ones that work against any engagement
    without operator-supplied test credentials."""
    for slug in DEFAULT_CLI_GOALS:
        g = SLUG_TO_GOAL[slug]
        assert g.requires_scope_field is None, (
            f"{slug} requires {g.requires_scope_field} — shouldn't be default"
        )
        assert not g.cleanup_required, (
            f"{slug} requires cleanup — shouldn't be default-on"
        )


def test_validate_goal_slugs_separates_known_unknown():
    ok, bad = validate_goal_slugs(["rce", "fake", "pii_exfil", "  ", "admin_session_takeover"])
    assert {g.slug for g in ok} == {"rce", "pii_exfil", "admin_session_takeover"}
    assert bad == ["fake"]


# ---- goal_satisfied predicates -------------------------------------------


def _state(**kw) -> ChainState:
    base = dict(chain_id="c1", goal_slug="x", target_url="https://x")
    base.update(kw)
    return ChainState(**base)


def test_admin_session_takeover_satisfied_only_with_token_and_admin_200():
    g = SLUG_TO_GOAL["admin_session_takeover"]
    assert g.goal_satisfied(_state()) is False
    assert g.goal_satisfied(_state(captured_session_token="t", captured_admin_path_status=403)) is False
    assert g.goal_satisfied(_state(captured_session_token="t", captured_admin_path_status=200)) is True


def test_pii_exfil_satisfied_at_three_records_not_two():
    g = SLUG_TO_GOAL["pii_exfil"]
    assert g.goal_satisfied(_state(pii_records_read=2)) is False
    assert g.goal_satisfied(_state(pii_records_read=3)) is True
    assert g.goal_satisfied(_state(pii_records_read=10)) is True  # cap is enforced upstream


def test_lateral_requires_response_bytes():
    g = SLUG_TO_GOAL["lateral_to_internal_service"]
    assert g.goal_satisfied(_state(internal_probe_succeeded=True)) is False  # no body
    assert g.goal_satisfied(_state(
        internal_probe_succeeded=True, internal_probe_response="ami-0123",
    )) is True


def test_session_fixation_requires_token_and_canary_callback():
    g = SLUG_TO_GOAL["session_fixation_or_hijack"]
    assert g.goal_satisfied(_state(captured_session_token="t")) is False
    assert g.goal_satisfied(_state(js_canary_callback_received=True)) is False
    assert g.goal_satisfied(_state(
        captured_session_token="t", js_canary_callback_received=True,
    )) is True


def test_rce_satisfied_via_either_canary_proof():
    g = SLUG_TO_GOAL["rce"]
    assert g.goal_satisfied(_state()) is False
    assert g.goal_satisfied(_state(rce_canary_response="uid=33(www-data)")) is True
    assert g.goal_satisfied(_state(rce_canary_dns_received=True)) is True


def test_persistent_backdoor_requires_marker_AND_rollback_AND_confirmation():
    g = SLUG_TO_GOAL["persistent_backdoor_admin"]
    assert g.cleanup_required is True
    # marker without rollback → no
    assert g.goal_satisfied(_state(persistence_marker="sentinel-canary-c1")) is False
    # rollback claimed but not confirmed → no
    assert g.goal_satisfied(_state(
        persistence_marker="sentinel-canary-c1", persistence_rolled_back=True,
    )) is False
    # full triple → yes
    assert g.goal_satisfied(_state(
        persistence_marker="sentinel-canary-c1",
        persistence_rolled_back=True,
        persistence_rollback_confirmed=True,
    )) is True


def test_audit_log_tamper_blocked_when_requires_human_cleanup():
    g = SLUG_TO_GOAL["audit_log_tamper"]
    assert g.cleanup_required is True
    # rolled back → ok
    assert g.goal_satisfied(_state(log_marker="m", log_rolled_back=True)) is True
    # requires_human_cleanup overrides → never satisfied
    assert g.goal_satisfied(_state(
        log_marker="m", log_rolled_back=True, requires_human_cleanup=True,
    )) is False


def test_payment_flow_bypass_requires_test_mode_and_no_charge():
    g = SLUG_TO_GOAL["payment_flow_bypass"]
    assert g.requires_scope_field == "payment_test_mode"
    # test_mode not used → never satisfied
    assert g.goal_satisfied(_state(payment_order_state_paid=True,
                                   payment_charge_recorded_in_provider=False)) is False
    # test_mode used + paid + no charge → satisfied
    assert g.goal_satisfied(_state(
        payment_test_mode_used=True,
        payment_order_state_paid=True,
        payment_charge_recorded_in_provider=False,
    )) is True
    # test_mode used + paid BUT charge present → no (it actually charged)
    assert g.goal_satisfied(_state(
        payment_test_mode_used=True,
        payment_order_state_paid=True,
        payment_charge_recorded_in_provider=True,
    )) is False
    # requires_test_credentials flag → no
    assert g.goal_satisfied(_state(
        payment_test_mode_used=True, payment_order_state_paid=True,
        payment_charge_recorded_in_provider=False,
        requires_test_credentials=True,
    )) is False


# ---- chain enumeration ---------------------------------------------------


def _prim(class_slug, finding_id, pt, conf="high") -> Primitive:
    return Primitive(
        class_slug=class_slug, finding_id=finding_id, primitive_type=pt,
        description="x", confidence=conf,
    )


def test_chains_for_goal_caps_at_max_chains():
    goal = SLUG_TO_GOAL["admin_session_takeover"]
    # Plenty of relevant primitives.
    prims = [
        _prim("auth", f"AUTH-{i}", PrimitiveType.SESSION_TOKEN) for i in range(10)
    ] + [
        _prim("xss", f"XSS-{i}", PrimitiveType.JS_EXEC_BROWSER_CTX) for i in range(10)
    ]
    chains = chains_for_goal(goal, prims, max_chains=3)
    assert len(chains) == 3


def test_chains_for_goal_returns_empty_when_no_relevant_primitives():
    goal = SLUG_TO_GOAL["lateral_to_internal_service"]
    prims = [_prim("xss", "X", PrimitiveType.JS_EXEC_BROWSER_CTX)]  # not relevant
    assert chains_for_goal(goal, prims) == []


def test_chains_for_goal_ranks_higher_confidence_first():
    goal = SLUG_TO_GOAL["pii_exfil"]
    prims = [
        _prim("idor", "low", PrimitiveType.ARBITRARY_OBJECT_READ, conf="low"),
        _prim("idor", "high", PrimitiveType.ARBITRARY_OBJECT_READ, conf="high"),
    ]
    chains = chains_for_goal(goal, prims)
    # Highest-rank chain leads.
    leading_terminal_id = chains[0].primitives[-1].finding_id
    assert leading_terminal_id == "high"


def test_chains_uses_session_token_as_precursor_for_object_read():
    """SESSION_TOKEN → ARBITRARY_OBJECT_READ is in _TYPE_EDGES; if a
    SESSION_TOKEN primitive is available, the enumerator should produce
    a 2-step chain that uses it as a precursor for an object-read."""
    goal = SLUG_TO_GOAL["pii_exfil"]
    prims = [
        _prim("auth", "AUTH-1", PrimitiveType.SESSION_TOKEN),
        _prim("idor", "IDOR-1", PrimitiveType.ARBITRARY_OBJECT_READ),
    ]
    chains = chains_for_goal(goal, prims)
    # At least one chain has the 2-step shape.
    two_step = [c for c in chains if c.length == 2]
    assert two_step, f"expected a 2-step chain, got: {[(c.chain_id, [p.finding_id for p in c.primitives]) for c in chains]}"
    assert two_step[0].primitives[0].primitive_type == PrimitiveType.SESSION_TOKEN
    assert two_step[0].primitives[1].primitive_type == PrimitiveType.ARBITRARY_OBJECT_READ


# ---- ChainContext + RCE canary allowlist ---------------------------------


def test_chain_context_set_and_get(tmp_path):
    ctx = ChainContext(primitives=[], target_url="https://x",
                       workspace=str(tmp_path), evidence_path=str(tmp_path / "e.md"))
    set_context(ctx)
    assert get_context() is ctx
    set_context(None)  # type: ignore[arg-type]


def test_rce_canary_command_set_does_not_include_destructive():
    """Sanity check the curated allowlist — never contains destructive
    or exfil utilities."""
    forbidden = {"rm", "wget", "curl", "nc", "chmod", "ncat", "bash", "sh",
                 "python", "perl", "ruby", "kill", "shutdown", "reboot",
                 "mkfs", "dd"}
    for cmd in RCE_CANARY_COMMANDS:
        first_token = cmd.split()[0]
        assert first_token not in forbidden, (
            f"{cmd!r} starts with destructive command {first_token!r}"
        )
