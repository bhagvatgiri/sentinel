"""NOVEL-05 + NOVEL-06 data-layer tests (Plan 05-04, Task 1).

Pins the six load-bearing data surfaces wired in Plan 05-04 Task 1:

  * NovelFindingEvidence dataclass (Test 1) — six fields preserved on
    construction; the cross-plan identity record linking a Phase 3 PoC bundle
    to a Plan 05-03 escalation result.
  * Round-trip serialization (Test 2) — to_dict / from_dict survive
    json.dumps -> json.loads cleanly. Plan 05-05 reads NovelFindingEvidence
    instances off RunReport.novel_findings for dashboard rendering; if
    round-trip drops a field the chip vocabulary silently degrades.
  * RunReport.novel_findings default (Test 3) — empty list default preserves
    every existing pipeline call site that constructs RunReport(scope=...)
    without novel_findings (Phases 1-4.5 backward-compat).
  * RunReport.novel_findings accepts a list (Test 4) — explicit assignment of
    NovelFindingEvidence instances preserves identity through the dataclass
    attribute.
  * Scope.novelty_threshold default (Test 5) — 0.75 matches NOVEL-04 spec;
    operator overrides via scope.yaml.
  * Scope.novelty_threshold override (Test 6) — yaml override parses to the
    documented attribute name.
  * Scope.novelty_threshold range validation (Test 7) — out-of-range raises
    ScopeError (CLAUDE.md safety-boundary #2: scope file is the legal artifact;
    a typo'd 1.5 must fail loud at load time, not silently disable escalation).
  * Scope.escalate_on_evidence_states (Test 8) — default ["verified"] preserves
    VERIFY-08 contract; operator opt-in to manual_required works.
  * EVENT_STYLES registration (Test 9) — all three new event kinds registered
    with group="phase" + chip + label (Plan 05-05 dashboard consumes these).
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from sentinel.core.scope import Scope, ScopeError


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _scope_yaml(tmp_path: Path, **overrides) -> Path:
    """Minimal valid scope.yaml; test override via kwargs."""
    today = date.today()
    data = {
        "client": "test-client",
        "engagement_id": "test-novelty-001",
        "authorized_by": "test@example.com",
        "valid_from": (today - timedelta(days=1)).isoformat(),
        "valid_until": (today + timedelta(days=30)).isoformat(),
        "targets": {"domains": ["example.com"]},
    }
    data.update(overrides)
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def _sample_evidence(**overrides):
    """Build a sample NovelFindingEvidence with all six fields populated."""
    from sentinel.agent.novelty import NovelFindingEvidence

    base = dict(
        finding_fingerprint="abc123def4567890",
        novelty_score=0.87,
        nearest_corpus_match={
            "chunk_id": "owasp-asvs-v4.0-1.2.3",
            "source": "owasp",
            "title": "ASVS Authentication",
            "cosine_distance": 0.42,
            "text_preview": "Verify that the application uses a single ...",
            "url": "https://owasp.org/asvs/v4.0/#1.2.3",
        },
        exploit_chain={
            "input": "?id=1 UNION SELECT pw FROM users--",
            "behavior": "Server returned hashed password column in response body.",
            "impact": "Full credential disclosure across user table.",
        },
        verifier_evidence_path="/tmp/workspaces/eng-001/verification/abc123def4567890",
        captured_at="2026-XX-XXT10:30:00+00:00",
    )
    base.update(overrides)
    return NovelFindingEvidence(**base)


# ---------------------------------------------------------------------------
# Test 1 — NovelFindingEvidence construction preserves all six fields
# ---------------------------------------------------------------------------


def test_novel_finding_evidence_construction():
    """Build a NovelFindingEvidence with all 6 fields; assert preservation."""
    evidence = _sample_evidence()
    assert evidence.finding_fingerprint == "abc123def4567890"
    assert evidence.novelty_score == 0.87
    assert evidence.nearest_corpus_match["source"] == "owasp"
    assert evidence.nearest_corpus_match["cosine_distance"] == 0.42
    assert evidence.exploit_chain["input"].startswith("?id=1 UNION")
    assert evidence.exploit_chain["behavior"].startswith("Server returned")
    assert evidence.exploit_chain["impact"].startswith("Full credential")
    assert evidence.verifier_evidence_path == "/tmp/workspaces/eng-001/verification/abc123def4567890"
    assert evidence.captured_at == "2026-XX-XXT10:30:00+00:00"


# ---------------------------------------------------------------------------
# Test 2 — to_dict / from_dict round-trip through json.dumps + json.loads
# ---------------------------------------------------------------------------


def test_novel_finding_evidence_to_dict_round_trip():
    """to_dict -> json.dumps -> json.loads -> from_dict yields equivalent record."""
    from sentinel.agent.novelty import NovelFindingEvidence

    original = _sample_evidence()
    encoded = json.dumps(original.to_dict())
    decoded = json.loads(encoded)
    restored = NovelFindingEvidence.from_dict(decoded)

    assert restored.finding_fingerprint == original.finding_fingerprint
    assert restored.novelty_score == original.novelty_score
    assert restored.nearest_corpus_match == original.nearest_corpus_match
    assert restored.exploit_chain == original.exploit_chain
    assert restored.verifier_evidence_path == original.verifier_evidence_path
    assert restored.captured_at == original.captured_at


# ---------------------------------------------------------------------------
# Test 3 — RunReport.novel_findings defaults to empty list (backward-compat)
# ---------------------------------------------------------------------------


def test_run_report_default_novel_findings_is_empty():
    """Constructing RunReport with no novel_findings kwarg yields an empty list."""
    from sentinel.core.orchestrator import RunReport

    # Pass scope=None — Phases 1-4.5 backward-compat: the field's default
    # factory must produce a fresh empty list per instance (not a shared one).
    r1 = RunReport(scope=None)  # type: ignore[arg-type]
    r2 = RunReport(scope=None)  # type: ignore[arg-type]
    assert r1.novel_findings == []
    assert r2.novel_findings == []
    # Default factory produces distinct list instances (no aliasing).
    r1.novel_findings.append("sentinel")
    assert r2.novel_findings == []


# ---------------------------------------------------------------------------
# Test 4 — RunReport.novel_findings accepts a list of NovelFindingEvidence
# ---------------------------------------------------------------------------


def test_run_report_accepts_novel_findings_list():
    """Explicit assignment of NovelFindingEvidence instances preserves them."""
    from sentinel.core.orchestrator import RunReport

    e1 = _sample_evidence(finding_fingerprint="fp1111111111aaaa")
    e2 = _sample_evidence(finding_fingerprint="fp2222222222bbbb", novelty_score=0.91)
    r = RunReport(scope=None, novel_findings=[e1, e2])  # type: ignore[arg-type]
    assert len(r.novel_findings) == 2
    assert r.novel_findings[0].finding_fingerprint == "fp1111111111aaaa"
    assert r.novel_findings[1].novelty_score == 0.91


# ---------------------------------------------------------------------------
# Test 5 — Scope.novelty_threshold default = 0.75 (NOVEL-04 spec)
# ---------------------------------------------------------------------------


def test_scope_novelty_threshold_default_is_zero_point_seven_five(tmp_path: Path):
    """Scope.load on a minimal yaml yields novelty_threshold == 0.75."""
    scope = Scope.load(_scope_yaml(tmp_path))
    assert scope.novelty_threshold == 0.75


# ---------------------------------------------------------------------------
# Test 6 — Scope.novelty_threshold override via yaml
# ---------------------------------------------------------------------------


def test_scope_novelty_threshold_override_via_yaml(tmp_path: Path):
    """Operator override `novelty_threshold: 0.5` parses to the attribute."""
    scope = Scope.load(_scope_yaml(tmp_path, novelty_threshold=0.5))
    assert scope.novelty_threshold == 0.5


# ---------------------------------------------------------------------------
# Test 7 — Out-of-range raises ScopeError (CLAUDE.md safety-boundary #2)
# ---------------------------------------------------------------------------


def test_scope_novelty_threshold_out_of_range_raises(tmp_path: Path):
    """novelty_threshold > 1.0 raises ScopeError mentioning the valid range."""
    with pytest.raises(ScopeError) as exc_info:
        Scope.load(_scope_yaml(tmp_path, novelty_threshold=1.5))
    assert "novelty_threshold" in str(exc_info.value)
    assert "[0.0, 1.0]" in str(exc_info.value)

    with pytest.raises(ScopeError) as exc_info:
        Scope.load(_scope_yaml(tmp_path, novelty_threshold=-0.1))
    assert "novelty_threshold" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 8 — Scope.escalate_on_evidence_states default + override
# ---------------------------------------------------------------------------


def test_scope_escalate_on_evidence_states_default(tmp_path: Path):
    """Default = ["verified"] (preserves VERIFY-08 verified_only contract).

    Operator opt-in to ["verified", "manual_required"] for offline workflows
    parses cleanly. Unknown evidence_state values raise ScopeError so a typo
    doesn't silently disable escalation.
    """
    # Default — only "verified" is in the allowlist.
    scope = Scope.load(_scope_yaml(tmp_path))
    assert scope.escalate_on_evidence_states == ["verified"]

    # Operator opt-in to manual_required.
    scope2 = Scope.load(_scope_yaml(
        tmp_path,
        escalate_on_evidence_states=["verified", "manual_required"],
    ))
    assert scope2.escalate_on_evidence_states == ["verified", "manual_required"]


# ---------------------------------------------------------------------------
# Test 9 — All three new EVENT_STYLES entries registered with group="phase"
# ---------------------------------------------------------------------------


def test_event_styles_register_all_three_novelty_kinds():
    """Plan 05-04 registers three new event kinds for Plan 05-05's dashboard.

    Every kind is in `phase` group so the dashboard renders them next to
    phase_started / phase_completed in the phase panel.
    """
    from sentinel.web.event_styles import EVENT_STYLES

    expected_kinds = [
        "novelty_score_computed",
        "novel_finding_escalated",
        "novel_finding_evidence_captured",
    ]
    for kind in expected_kinds:
        assert kind in EVENT_STYLES, f"missing EVENT_STYLES entry: {kind}"
        style = EVENT_STYLES[kind]
        assert style["group"] == "phase", (
            f"{kind} must be in group=phase (got {style['group']!r})"
        )
        assert style["chip"], f"{kind} missing chip"
        assert style["label"], f"{kind} missing label"
        assert style["icon"], f"{kind} missing icon"
