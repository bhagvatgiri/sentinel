"""Finding data model — the canonical shape for everything scanners emit."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_string(cls, s: Optional[str]) -> "Severity":
        if not s:
            return cls.INFO
        s = s.lower().strip()
        mapping = {
            "info": cls.INFO,
            "informational": cls.INFO,
            "note": cls.INFO,
            "low": cls.LOW,
            "minor": cls.LOW,
            "warning": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "important": cls.HIGH,
            "error": cls.HIGH,
            "critical": cls.CRITICAL,
            "severe": cls.CRITICAL,
        }
        return mapping.get(s, cls.INFO)


class Status(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    FALSE_POSITIVE = "false_positive"
    CONFIRMED = "confirmed"
    REMEDIATED = "remediated"


class EvidenceState(str, Enum):
    """Tracks how well a finding has been live-verified.

    Phase 2 vuln-analysis agents always emit `recon_inferred` — they observed
    a hint of a bug from RP-layer signals (header reflection, missing flag,
    timing differential) but never reproduced the full attack chain.

    Phase 2.5 (Live Verification) is the only path that promotes an entry to
    `live_confirmed`. If verification fails or can't run safely, the entry
    moves to one of the explicit "blocked" states and Phase 3 skips it.

    This guards against the W1 over-trust gap: queue entries become finding
    claims downstream, and unverified inferences shouldn't reach H1 reports.
    """

    RECON_INFERRED = "recon_inferred"           # Phase 2 default
    LIVE_CONFIRMED = "live_confirmed"           # Phase 2.5 reproduced the bug
    LIVE_DISPROVEN = "live_disproven"           # Phase 2.5 ran the proof; bug did NOT reproduce
    REQUIRES_TEST_CREDENTIALS = "requires_test_credentials"
    REQUIRES_TWO_ACCOUNTS = "requires_two_accounts"
    MANUAL_VERIFICATION_REQUIRED = "manual_verification_required"
    VERIFICATION_ERROR = "verification_error"

    # Phase 3 verification terminology (VERIFY-01). Coexists with the Phase 2.5
    # values above — Plan 03-05's pipeline gate translates between taxonomies
    # at the correlation-input filter. Plan 03-04's sandbox writes VERIFIED /
    # UNREPRODUCIBLE / MANUAL_REQUIRED depending on classifier verdict +
    # subprocess outcome; PENDING is the default state before the sandbox runs.
    VERIFIED = "verified"
    UNREPRODUCIBLE = "unreproducible"
    MANUAL_REQUIRED = "manual-required"   # hyphen per VERIFY-01 spec; from_string also accepts snake_case
    PENDING = "pending"

    @classmethod
    def from_string(cls, s: Optional[str]) -> "EvidenceState":
        if not s:
            return cls.RECON_INFERRED
        normalized = s.lower().strip()
        # Phase 3 spelling tolerance: 'manual-required' is the canonical value
        # (matches the requirement spec verbatim); 'manual_required' is the
        # snake_case alias for callers that normalize hyphen->underscore.
        if normalized == "manual_required":
            return cls.MANUAL_REQUIRED
        try:
            return cls(normalized)
        except ValueError:
            return cls.RECON_INFERRED


@dataclass
class PocStep:
    """One manual-reproduction step for a finding (Phase 4 / POC-01).

    Phase 3 produces a machine-runnable PoC inside an evidence bundle
    (`workspaces/<engagement>/verification/<fingerprint>/{poc.sh|poc.py,
    stdout.log, exit_code.txt, screenshot.png}`). Phase 4 reformats that
    bundle into operator-readable numbered steps — one PocStep per
    discrete reproduction action — so the operator can paste them verbatim into
    a HackerOne report's "Steps to Reproduce" section.

    Field shape (frozen by POC-01):

      step_number      1-indexed ascending order within a finding's list
      description      one-sentence human summary of what the step does;
                       Phase 4 renderers (markdown, PDF, Obsidian) consume
                       it verbatim — they do NOT re-generate it
      command          the runnable bash/curl/python — multi-line allowed
                       (a single python script body is one PocStep whose
                       command spans the whole file)
      expected_output  the slice of stdout the operator should observe
                       (empty string is allowed; Phase 3 may capture a
                       genuinely empty stdout)
      screenshot_path  absolute on-disk path to the bundle's screenshot.png
                       when one was captured (Playwright PoCs only); the
                       Optional[str] type — NOT Path — keeps JSON round-trip
                       trivial. Renderers in Plans 04-02/03/04 convert to
                       Path on consumption when they need filesystem access.
    """

    step_number: int
    description: str
    command: str
    expected_output: str
    screenshot_path: Optional[str] = None


@dataclass
class Finding:
    """A single security finding from any scanner."""

    title: str
    description: str
    severity: Severity
    scanner: str  # e.g. "semgrep", "gitleaks", "osv-scanner"
    target: str  # repo path, URL, file path
    location: Optional[str] = None  # file:line or URL path
    cwe: Optional[str] = None
    cve: Optional[str] = None
    cvss: Optional[float] = None
    references: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    status: Status = Status.NEW
    remediation: Optional[str] = None
    # Devops-ready ticket fields, populated by the PoC enricher post-triage:
    # - impact: 1-2 sentence "what happens if exploited"
    # - proof_of_concept: copy-pasteable curl/dig/openssl that demonstrates the issue
    # - expected_output: what a vulnerable target's output literally looks like
    # - validation: copy-pasteable command that returns "FIXED" output after remediation
    impact: Optional[str] = None
    proof_of_concept: Optional[str] = None
    expected_output: Optional[str] = None
    validation: Optional[str] = None
    triage_notes: Optional[str] = None
    # Live-verification tracking (Phase 2.5). Defaults to recon_inferred for
    # any finding emitted by Phase 2 vuln-analysis agents. Phase 2.5 promotes
    # to live_confirmed only after reproducing the attack chain end-to-end.
    evidence_state: EvidenceState = EvidenceState.RECON_INFERRED
    # Phase 3 destructive-PoC classifier payload (VERIFY-02). When the PoC
    # classifier (`sentinel.agent.poc.classifier.classify_destructive`)
    # flags this finding's PoC as destructive, this dict carries the
    # pattern name + rationale. None when no destructive verdict applies.
    # Shape: {"pattern": "<name>", "rationale": "<text>"}
    destructive_classifier_match: Optional[dict] = None
    # Wave 4 / A5 — constraint-aware severity gradation (paper 2510.17521).
    # A finding may pass the weak Lab condition yet fail Operational or
    # Complete. Reporting renders three columns so the deliverable is honest
    # about which constraints each finding actually clears:
    #   reproduces_in_lab           — any state, no constraints (live_confirmed
    #                                 implies True)
    #   reproduces_under_operational — service uptime maintained AND probe did
    #                                 not push >5% error rate (non-destructive)
    #   reproduces_complete          — operational + Sentinel synthesised a
    #                                 remediation patch that, applied to a
    #                                 fixture, blocks the same probe. Wave 4
    #                                 leaves this False with a TODO; Wave 7
    #                                 may automate patch synthesis.
    reproduces_in_lab: bool = False
    reproduces_under_operational: bool = False
    reproduces_complete: bool = False
    # Wave 4 / A6 — per-finding ATT&CK + CAPEC tags (paper 2510.17521 Tables
    # 10-12). Populated by sentinel.core.attack_mapper.infer_attack_capec()
    # in the triage path; default empty so non-pentest scanners (which don't
    # always emit a vuln-class slug) don't carry stale tags.
    attack_technique_ids: list[str] = field(default_factory=list)
    capec_ids: list[str] = field(default_factory=list)
    # Phase 4 / POC-01 — structured reproduction steps. Default [] so
    # findings emitted before the Phase 4 renderer runs (and legacy
    # run JSONs written before Phase 4 landed) round-trip cleanly with
    # no extra coercion at the call site.
    poc_steps: list["PocStep"] = field(default_factory=list)
    # Phase 5 / NOVEL-01 — novelty score against pre-embedded Chroma corpus +
    # NVD CVE feed (Plan 05-02 populates the index; Plan 05-03 computes the
    # score). Range [0.0, 1.0]: 0 = matches existing CWE/CVE/writeup exactly;
    # 1 = no semantic match. Default 0.0 preserves backward-compat for legacy
    # run JSONs (Phases 1-4.5) which round-trip through Finding(**data) without
    # a novelty_score key. Fingerprint is FROZEN: novelty_score is NOT in
    # fingerprint() input (see test_finding_fingerprint_unchanged_by_novelty_score).
    novelty_score: float = 0.0
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        # Belt-and-suspenders invariant: a "Complete" repro must clear Lab
        # AND Operational by definition. This guards against logic bugs in
        # verifiers / future patch-synthesis automation that flip Complete
        # without backing it with the weaker conditions.
        if self.reproduces_complete and not (
            self.reproduces_in_lab and self.reproduces_under_operational
        ):
            raise ValueError(
                "Finding invariant violated: reproduces_complete=True requires "
                "reproduces_in_lab=True AND reproduces_under_operational=True "
                f"(title={self.title!r})"
            )
        # Phase 4 / POC-01 — coerce list[dict] poc_steps entries (which is
        # what `json.load` will hand us from a serialized run JSON) into
        # list[PocStep] so callers downstream always see real dataclass
        # instances. Already-typed PocStep entries pass through untouched.
        coerced: list[PocStep] = []
        for entry in self.poc_steps or []:
            if isinstance(entry, PocStep):
                coerced.append(entry)
            elif isinstance(entry, dict):
                coerced.append(PocStep(**entry))
            else:
                raise TypeError(
                    f"poc_steps entry must be PocStep or dict, "
                    f"got {type(entry).__name__}"
                )
        self.poc_steps = coerced
        # NOVEL-01 — novelty_score range invariant. Plan 05-03's scorer is the
        # canonical producer (cosine-distance-derived in [0.0, 1.0]); out-of-band
        # callers that hand-construct a Finding must respect the range so the
        # Plan 05-05 dashboard chip vocabulary (novelty-high >= 0.75, novelty-medium
        # 0.5-0.75, otherwise none) and Plan 05-04 escalation gate (novelty_score
        # >= threshold) stay deterministic.
        if not (0.0 <= float(self.novelty_score) <= 1.0):
            raise ValueError(
                "Finding invariant violated: novelty_score must be in [0.0, 1.0], "
                f"got {self.novelty_score!r} (title={self.title!r})"
            )

    def fingerprint(self) -> str:
        """Stable hash for deduplication across scanners and runs."""
        key = f"{self.scanner}|{self.target}|{self.location or ''}|{self.title}|{self.cwe or ''}|{self.cve or ''}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        d["evidence_state"] = self.evidence_state.value
        # destructive_classifier_match is already a dict-or-None (or absent on
        # older Findings deserialized from disk), so asdict above already
        # carries it through. The explicit assignment is documentation
        # insurance — downstream renderers (PDF, dashboard, Obsidian) read
        # this key by name and the round-trip test pins it to a known shape.
        d["destructive_classifier_match"] = self.destructive_classifier_match
        # NOVEL-01 — explicit float cast guarantees the on-disk value is a
        # JSON-safe float (not numpy.float32 or Decimal from a third-party
        # scorer); legacy round-trip stays deterministic.
        d["novelty_score"] = float(self.novelty_score)
        d["fingerprint"] = self.fingerprint()
        return d
