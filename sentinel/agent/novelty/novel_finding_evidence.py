"""NovelFindingEvidence dataclass (Plan 05-04, NOVEL-05).

The structured zero-day candidate record produced by the Plan 05-04 pipeline
escalation gate (`sentinel.agent.pentest.pipeline._run_novelty_sweep`) for
every finding that:

  * has a novelty_score at or above the configured scope.novelty_threshold,
  * has an evidence_state in the configured scope.escalate_on_evidence_states
    allowlist (default: ["verified"] — preserves the VERIFY-08 contract),
  * still has cost-cap headroom for the Sonnet-tier LLM escalation call, and
  * returns a JSON exploit-chain payload that validates against
    EXPLOIT_CHAIN_SCHEMA (Plan 05-03).

One NovelFindingEvidence instance lands per successful escalation. They
propagate into `RunReport.novel_findings` so Plan 05-05's dashboard and
report renderers can surface them to the operator.

Six fields (cross-plan identity record):

  finding_fingerprint     : Finding.fingerprint() — the FROZEN dedup key,
                            so a NovelFindingEvidence always traces back
                            unambiguously to the underlying Finding even
                            after the run JSON has been reloaded from disk.
  novelty_score           : Plan 05-01 field value (range [0.0, 1.0]).
  nearest_corpus_match    : dict with the IndexEntry-equivalent fields
                            {chunk_id, source, title, cosine_distance,
                             text_preview, url} pulled from
                            CorpusIndex.nearest() (Plan 05-02). Stored as a
                            dict instead of a dataclass so it round-trips
                            through json.dumps without per-type adapters.
  exploit_chain           : dict {"input", "behavior", "impact"} —
                            the validated triple from Plan 05-03's
                            validate_exploit_chain(...).
  verifier_evidence_path  : Optional[str] path to the Phase 3 evidence
                            bundle (workspaces/<eng>/verification/<fp>/).
                            None when the bundle wasn't found at escalation
                            time (e.g. verify-phase-03 ran in dry mode).
  captured_at             : ISO-8601 UTC timestamp the escalation closed.

Round-trip contract (Plan 05-04 Task 1 Test 2): to_dict / from_dict survives
json.dumps -> json.loads cleanly. Plan 05-05 reads these off the dashboard's
loaded RunReport JSON; if round-trip drops a field the chip vocabulary
silently degrades.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NovelFindingEvidence:
    """One escalated zero-day candidate.

    Frozen-by-convention (we don't pass `frozen=True` because the dataclass
    is small and a future schema-version bump may need to mutate one field;
    callers MUST NOT mutate after construction).
    """

    finding_fingerprint: str
    novelty_score: float
    nearest_corpus_match: dict = field(default_factory=dict)
    exploit_chain: dict = field(default_factory=dict)
    verifier_evidence_path: Optional[str] = None
    captured_at: str = ""

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict.

        Explicit per-field copy (not asdict) so the nested dicts
        (`nearest_corpus_match`, `exploit_chain`) are shallow-copied —
        callers that mutate the result post-serialization don't accidentally
        mutate the original dataclass state.
        """
        return {
            "finding_fingerprint": self.finding_fingerprint,
            "novelty_score": float(self.novelty_score),
            "nearest_corpus_match": dict(self.nearest_corpus_match or {}),
            "exploit_chain": dict(self.exploit_chain or {}),
            "verifier_evidence_path": self.verifier_evidence_path,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NovelFindingEvidence":
        """Reconstitute from a dict (typically post-json.loads).

        Missing optional fields fall back to the dataclass defaults so a
        forward-rev JSON written by Plan 05-05+ that drops `verifier_evidence_path`
        still loads on a Plan 05-04-only reader (best-effort backward-compat).
        """
        return cls(
            finding_fingerprint=str(data["finding_fingerprint"]),
            novelty_score=float(data["novelty_score"]),
            nearest_corpus_match=dict(data.get("nearest_corpus_match") or {}),
            exploit_chain=dict(data.get("exploit_chain") or {}),
            verifier_evidence_path=data.get("verifier_evidence_path"),
            captured_at=str(data.get("captured_at") or ""),
        )
