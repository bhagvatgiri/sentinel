"""Locks the evidence_state gating contract across the four places it
must be honored: vuln prompts, exploit prompts, report prompt, and chain
prompt — plus the auth verifier's `emit()` keyword that crashed the
ExampleStore-tax 2026-XX-XX scan.

Cheap structural canaries: if anyone deletes the gating section from a
prompt, the matching test fires before the next scan ships an
over-claimed report.
"""

from __future__ import annotations

import asyncio
from unittest import mock

import pytest

from sentinel.core.findings import EvidenceState
from sentinel.agent.pentest import verifier_tool
from sentinel.agent.pentest.verifiers import auth as auth_verifier


# --------------------------------------------------------------------------
# Bug 1 — auth verifier emit() must not collide on `kind`
# --------------------------------------------------------------------------


def test_auth_verifier_emit_does_not_collide_on_kind(monkeypatch, tmp_path):
    """The ExampleStore-tax 2026-XX-XX scan crashed all 8 auth entries with
    `TypeError: VerificationContext.emit() got multiple values for
    argument 'kind'`. Regression test — the dispatch emit must use a
    different keyword than `kind` (which is the first positional arg of
    `VerificationContext.emit`).
    """

    fake_scope = mock.MagicMock()
    fake_scope.authorize_url.return_value = None
    workspace = tmp_path / "ws"
    (workspace / "deliverables" / "verification" / "auth").mkdir(parents=True)

    captured: list[tuple[str, dict]] = []

    def capture_emit(kind: str, **payload) -> None:
        captured.append((kind, payload))

    ctx = verifier_tool.VerificationContext(
        scope=fake_scope,
        target="https://www.example.invalid",
        workspace_dir=workspace,
        vuln_class="auth",
        queue_entry={
            "ID": "AUTH-VULN-01",
            "vulnerability_type": "Some open redirect via returnUrl",
            "exploitation_hypothesis": "Attacker URL captures assertion",
            "notes": "openid.return_to assertion capture",
            "source_endpoint": "GET /ExampleStore/signinRedirect",
        },
        entry_id="AUTH-VULN-01",
        evidence_dir=workspace / "deliverables" / "verification" / "auth",
        auth_credentials=[],
        research_headers={},
        event_emit=capture_emit,
    )

    # Stub httpx so we don't actually network. We only care that the
    # dispatcher gets through `ctx.emit(...)` without TypeError.
    class _FakeResp:
        status_code = 200
        headers: dict = {}
        text = "no body"

    async def fake_get(self, url, headers=None):
        return _FakeResp()

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    # Run the verifier — must not raise.
    asyncio.run(auth_verifier.verify(ctx))

    dispatch_emits = [c for c in captured if c[0] == "verify_auth_dispatch"]
    assert dispatch_emits, "verify_auth_dispatch should have been emitted"
    payload = dispatch_emits[0][1]
    assert "entry_kind" in payload, (
        "auth verifier must emit `entry_kind`, not `kind` — `kind` is the "
        "first positional arg of VerificationContext.emit and collides"
    )
    assert "kind" not in payload, (
        "auth verifier must NOT emit a `kind` keyword — it shadows the "
        "positional arg of VerificationContext.emit"
    )


# --------------------------------------------------------------------------
# Bug 2 — report prompt must mention evidence_state gating
# --------------------------------------------------------------------------


def test_report_prompt_gates_on_evidence_state():
    """The ExampleStore-tax 2026-XX-XX scan's report agent re-promoted
    verifier-disproven entries as Critical findings because
    `report_prompt.py` had zero references to `evidence_state`. Cheap
    canary: if the gating section is removed, this fires.
    """
    from sentinel.agent.pentest.report_prompt import render_report_prompt

    rendered = render_report_prompt(
        client="test", engagement_id="t-1", target="https://t.invalid",
        workspace="/tmp/ws", max_turns=20, max_budget_usd=1.0,
    )

    # The gating section must exist
    assert "evidence_state" in rendered, (
        "report_prompt must instruct the agent to gate findings on "
        "evidence_state — otherwise it re-promotes disproven entries"
    )
    assert "live_confirmed" in rendered
    assert "live_disproven" in rendered
    # And it must specifically tell the agent NOT to include disproven
    # entries in the headline Findings table:
    assert "DO NOT include in Findings table" in rendered, (
        "report_prompt must explicitly forbid putting disproven entries "
        "in the Findings table"
    )


# --------------------------------------------------------------------------
# Bug 3 — chain prompt must mention evidence_state gating
# --------------------------------------------------------------------------


def test_chain_prompt_gates_on_evidence_state():
    """Chain executor must not compose chains from disproven primitives.
    Same canary pattern as report_prompt.
    """
    from sentinel.agent.pentest.chain_prompt import render_chain_prompt
    from sentinel.agent.pentest.chain_executor import GOALS

    # Pick any goal to render a real prompt
    goal = next(iter(GOALS))

    rendered = render_chain_prompt(
        goal=goal, chain_id="test-chain-1",
        chain_primitives=[], all_primitives=[],
        target="https://t.invalid", client="test",
        engagement_id="t-1", workspace="/tmp/ws", audit_log="/tmp/audit",
    )

    assert "evidence_state" in rendered, (
        "chain_prompt must instruct the agent to gate primitives on "
        "evidence_state — otherwise it stacks disproven claims"
    )
    assert "live_confirmed" in rendered
    assert "live_disproven" in rendered
    assert "abandon" in rendered.lower(), (
        "chain_prompt must instruct the agent to ABANDON chains whose "
        "primitives are not live_confirmed"
    )
