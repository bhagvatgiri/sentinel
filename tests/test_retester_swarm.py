"""Wave 2 / A3 — Retester swarm tests.

Asserted properties:
  - Vuln agent's reasoning is preserved across the handoff (transcript
    continuity in HandoffContext).
  - Retester verdict updates the queue entry's `evidence_state`.
  - Round-trip cap (3) prevents infinite ping-pong.
  - AuditLog records every handoff (request + handback).
  - Verdicts map cleanly: confirmed → live_confirmed, disproven →
    live_disproven, blocked → manual_verification_required.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from sentinel.agent.pentest.handoff import HandoffContext, set_handoff_context
from sentinel.agent.pentest.retester_agent import (
    MAX_ROUND_TRIPS,
    RetesterTripCounter,
    RetesterVerdict,
    apply_verdict_to_queue,
    reason_to_state,
    retest_entry,
)
from sentinel.core.findings import EvidenceState


# ---- Stubs ------------------------------------------------------------

class _StubAuditLog:
    def __init__(self):
        self.writes: list[tuple[str, dict]] = []

    def write(self, kind: str, payload: dict) -> None:
        self.writes.append((kind, dict(payload)))


class _StubScope:
    """Minimal scope that pretends every URL is in scope. The retester
    only needs scope.authorize_url + .auth_credentials access."""
    auth_credentials: list[dict] = []
    research_headers: dict = {}
    engagement_id = "test"
    client = "test"

    def authorize_url(self, url: str) -> str:
        return url

    def authorize_repo(self, repo: str) -> str:
        return repo


# ---- Helpers ----------------------------------------------------------

def _write_queue(workspace: Path, vuln_class: str, entries: list[dict]) -> Path:
    deliv = workspace / "deliverables"
    deliv.mkdir(parents=True, exist_ok=True)
    path = deliv / f"{vuln_class}_exploitation_queue.json"
    path.write_text(json.dumps({"vulnerabilities": entries}, indent=2))
    return path


def _read_queue(workspace: Path, vuln_class: str) -> list[dict]:
    path = workspace / "deliverables" / f"{vuln_class}_exploitation_queue.json"
    return json.loads(path.read_text()).get("vulnerabilities") or []


# ---- Tests: reason_to_state mapping -----------------------------------

def test_reason_to_state_confirmed():
    assert reason_to_state("confirmed") == EvidenceState.LIVE_CONFIRMED
    assert reason_to_state("verified") == EvidenceState.LIVE_CONFIRMED


def test_reason_to_state_disproven():
    assert reason_to_state("disproven") == EvidenceState.LIVE_DISPROVEN
    assert reason_to_state("falsified") == EvidenceState.LIVE_DISPROVEN


def test_reason_to_state_blocked():
    assert reason_to_state("blocked") == EvidenceState.REQUIRES_TEST_CREDENTIALS
    assert reason_to_state("two_accounts") == EvidenceState.REQUIRES_TWO_ACCOUNTS


def test_reason_to_state_unknown_falls_back():
    assert reason_to_state("garbage") == EvidenceState.MANUAL_VERIFICATION_REQUIRED
    assert reason_to_state("") == EvidenceState.MANUAL_VERIFICATION_REQUIRED


# ---- Tests: trip counter ----------------------------------------------

def test_trip_counter_bumps():
    c = RetesterTripCounter()
    assert c.bump("auth", "AUTH-01") == 1
    assert c.bump("auth", "AUTH-01") == 2
    assert c.bump("auth", "AUTH-02") == 1  # different entry, separate count
    assert c.get("auth", "AUTH-01") == 2


def test_trip_counter_at_cap():
    c = RetesterTripCounter()
    for _ in range(MAX_ROUND_TRIPS):
        c.bump("auth", "AUTH-01")
    assert c.at_cap("auth", "AUTH-01")


# ---- Tests: apply_verdict_to_queue ------------------------------------

def test_apply_verdict_writes_state(tmp_path: Path):
    _write_queue(tmp_path, "auth", [
        {"ID": "AUTH-VULN-01", "evidence_state": "recon_inferred"},
    ])
    verdict = RetesterVerdict(
        vuln_class="auth", entry_id="AUTH-VULN-01",
        state=EvidenceState.LIVE_CONFIRMED,
        summary="Reproduced via timing differential 5.1s",
        reason="confirmed",
    )
    assert apply_verdict_to_queue(workspace_dir=tmp_path, verdict=verdict)
    entries = _read_queue(tmp_path, "auth")
    assert entries[0]["evidence_state"] == "live_confirmed"
    assert entries[0]["retester_history"]
    assert entries[0]["retester_history"][0]["reason"] == "confirmed"


def test_apply_verdict_appends_history_on_repeat(tmp_path: Path):
    _write_queue(tmp_path, "auth", [
        {"ID": "AUTH-VULN-01", "evidence_state": "recon_inferred"},
    ])
    v1 = RetesterVerdict(
        vuln_class="auth", entry_id="AUTH-VULN-01",
        state=EvidenceState.LIVE_DISPROVEN,
        summary="Trip 1: payload not reflected", reason="disproven",
    )
    v2 = RetesterVerdict(
        vuln_class="auth", entry_id="AUTH-VULN-01",
        state=EvidenceState.LIVE_CONFIRMED,
        summary="Trip 2: cookie-flush bypass works", reason="confirmed",
    )
    apply_verdict_to_queue(workspace_dir=tmp_path, verdict=v1)
    apply_verdict_to_queue(workspace_dir=tmp_path, verdict=v2)
    entries = _read_queue(tmp_path, "auth")
    assert len(entries[0]["retester_history"]) == 2
    # Final state is the LATEST verdict.
    assert entries[0]["evidence_state"] == "live_confirmed"


def test_apply_verdict_missing_queue(tmp_path: Path):
    verdict = RetesterVerdict(
        vuln_class="auth", entry_id="AUTH-VULN-01",
        state=EvidenceState.LIVE_CONFIRMED,
        summary="x", reason="confirmed",
    )
    assert not apply_verdict_to_queue(workspace_dir=tmp_path, verdict=verdict)


# ---- Tests: retest_entry round-trip cap -------------------------------

def test_retest_entry_round_trip_cap_forces_manual(tmp_path: Path):
    """After MAX_ROUND_TRIPS cycles on the same entry, the next retest
    forces manual_verification_required without re-running the verifier.
    """
    _write_queue(tmp_path, "auth", [
        {"ID": "AUTH-VULN-01", "evidence_state": "recon_inferred",
         "vulnerability_type": "missing rate-limit"},
    ])
    h_ctx = HandoffContext()
    set_handoff_context(h_ctx)
    audit = _StubAuditLog()
    counter = RetesterTripCounter()
    # Pre-populate at the cap.
    for _ in range(MAX_ROUND_TRIPS):
        counter.bump("auth", "AUTH-VULN-01")

    entry = _read_queue(tmp_path, "auth")[0]
    verdict = asyncio.run(retest_entry(
        scope=_StubScope(),  # type: ignore[arg-type]
        target="https://target.example.com",
        workspace_dir=tmp_path,
        vuln_class="auth",
        entry=entry,
        source_phase="vuln:auth",
        handoff_ctx=h_ctx,
        trip_counter=counter,
        audit_writer=audit,
    ))

    assert verdict.reason == "forced_cap"
    assert verdict.state == EvidenceState.MANUAL_VERIFICATION_REQUIRED
    set_handoff_context(None)


def test_retest_entry_records_handoff_in_transcript(tmp_path: Path):
    """The retester must append a tool message to the handoff transcript
    so subsequent phases can read what was decided."""
    _write_queue(tmp_path, "auth", [
        {"ID": "AUTH-VULN-01", "evidence_state": "recon_inferred",
         "vulnerability_type": "missing rate-limit"},
    ])
    h_ctx = HandoffContext()
    h_ctx.append({"role": "user", "content": "vuln agent reasoning"})
    h_ctx.append({"role": "assistant",
                  "content": "Found a missing rate-limit. Verify."})
    set_handoff_context(h_ctx)
    audit = _StubAuditLog()
    counter = RetesterTripCounter()
    counter.bump("auth", "AUTH-VULN-01")
    counter.bump("auth", "AUTH-VULN-01")
    counter.bump("auth", "AUTH-VULN-01")
    counter.bump("auth", "AUTH-VULN-01")  # over cap → forced

    entry = _read_queue(tmp_path, "auth")[0]
    asyncio.run(retest_entry(
        scope=_StubScope(),  # type: ignore[arg-type]
        target="https://target.example.com",
        workspace_dir=tmp_path,
        vuln_class="auth",
        entry=entry,
        source_phase="vuln:auth",
        handoff_ctx=h_ctx,
        trip_counter=counter,
        audit_writer=audit,
    ))

    # The user/assistant turns the vuln agent left should still be
    # present (preserved across the handoff).
    assert h_ctx.transcript[0]["role"] == "user"
    assert h_ctx.transcript[1]["role"] == "assistant"
    assert "rate-limit" in h_ctx.transcript[1]["content"]
    # The retester wrote a tool turn back to the transcript.
    assert any(m.get("role") == "tool" for m in h_ctx.transcript)
    set_handoff_context(None)


def test_retest_entry_audits_verdict(tmp_path: Path):
    _write_queue(tmp_path, "auth", [
        {"ID": "AUTH-VULN-01", "evidence_state": "recon_inferred"},
    ])
    h_ctx = HandoffContext()
    set_handoff_context(h_ctx)
    audit = _StubAuditLog()
    counter = RetesterTripCounter()

    entry = _read_queue(tmp_path, "auth")[0]
    asyncio.run(retest_entry(
        scope=_StubScope(),  # type: ignore[arg-type]
        target="https://target.example.com",
        workspace_dir=tmp_path,
        vuln_class="auth",
        entry=entry,
        source_phase="vuln:auth",
        handoff_ctx=h_ctx,
        trip_counter=counter,
        audit_writer=audit,
    ))
    assert any(k == "retester_verdict" for k, _ in audit.writes)
    set_handoff_context(None)


def test_retest_entry_nonexistent_class_blocks(tmp_path: Path):
    """When no per-class verifier is registered for the slug, retester
    must hand back with a `blocked` reason — not crash."""
    _write_queue(tmp_path, "no_such_class", [
        {"ID": "NOSUCH-01", "evidence_state": "recon_inferred"},
    ])
    h_ctx = HandoffContext()
    set_handoff_context(h_ctx)
    audit = _StubAuditLog()
    counter = RetesterTripCounter()

    entry = _read_queue(tmp_path, "no_such_class")[0]
    verdict = asyncio.run(retest_entry(
        scope=_StubScope(),  # type: ignore[arg-type]
        target="https://target.example.com",
        workspace_dir=tmp_path,
        vuln_class="no_such_class",
        entry=entry,
        source_phase="vuln:no_such_class",
        handoff_ctx=h_ctx,
        trip_counter=counter,
        audit_writer=audit,
    ))
    assert verdict.reason == "blocked"
    set_handoff_context(None)
