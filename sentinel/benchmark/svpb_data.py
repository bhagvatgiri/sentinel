"""D5 — SVPB task index (PRIVATE workspace pointers).

Each entry references one ``*_exploitation_queue.json`` from a past
engagement workspace. The queue files contain:

  - vulnerability_type
  - source_endpoint
  - missing_defense
  - exploitation_hypothesis
  - suggested_exploit_technique
  - confidence  (high / medium / low)
  - references  (list of CWE/OWASP refs)
  - notes       (operator-authored context)

Each queue entry becomes ONE SVPB task. The "expected verifier outcome"
is reconstructed from the corresponding ``*_exploitation_evidence.md``
file: if the evidence document concludes "live_confirmed", the task's
expected outcome is live_confirmed; "live_disproven" → live_disproven;
otherwise → unverified. This way the bench replays the past engagement
against any model and the verifier judges whether the model's behavior
matches the historical outcome.

We deliberately reference workspace files directly rather than copying
them — SVPB-Lite (D6) handles the redacted public publication.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Project-root-relative path to workspaces. Resolved at runtime.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKSPACES_DIR = _PROJECT_ROOT / "workspaces"


@dataclass
class SVPBTaskRef:
    """Pointer into a workspace deliverable.

    Resolves lazily so the bench imports cleanly even on a fresh clone
    where the workspaces aren't checked in.
    """
    task_id: str
    engagement: str
    target: str
    vuln_class: str       # auth/authz/xss/...
    queue_index: int      # which entry in the queue JSON
    expected_outcome: str  # live_confirmed / live_disproven / unverified
    notes: str = ""
    scope_yaml: Optional[str] = None    # relative to project root

    @property
    def queue_path(self) -> Path:
        return (
            WORKSPACES_DIR / self.engagement / "deliverables"
            / f"{self.vuln_class}_exploitation_queue.json"
        )

    @property
    def evidence_path(self) -> Path:
        return (
            WORKSPACES_DIR / self.engagement / "deliverables"
            / f"{self.vuln_class}_exploitation_evidence.md"
        )

    @property
    def is_present(self) -> bool:
        return self.queue_path.exists()


# 50 hand-curated tasks across the 7 past engagement workspaces. The
# queue_index column points at the position inside that queue JSON's
# `vulnerabilities` (or `entries`) list. Expected outcomes were taken
# from the corresponding evidence MD's verdict line.
TASKS: list[SVPBTaskRef] = [
    # ---- 2026-XX-XX ExampleStore-bbp ---------------------------------------
    SVPBTaskRef("svpb-001", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "auth", 0, "live_confirmed",
                "OpenID returnUrl injection — confirmed reflection",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-002", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "auth", 1, "live_confirmed",
                "Static OpenID siteState — login CSRF vector",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-003", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "auth", 2, "live_disproven",
                "Insufficient max_auth_age — disproven by Phase 2.5 verifier (maxAge is the live param, not maxAuthAge)",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-004", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "auth", 3, "live_confirmed",
                "Session cookie missing HttpOnly + SameSite",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-005", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "auth", 4, "live_confirmed",
                "Session ID leaked in CSP report-uri",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-006", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "authz", 0, "live_confirmed",
                "Authz finding 1",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-007", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "csrf", 0, "live_confirmed",
                "CSRF finding 1",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-008", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "idor", 0, "live_disproven",
                "IDOR finding 1",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-009", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "injection", 0, "live_disproven",
                "Injection finding 1",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-010", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "ssrf", 0, "live_disproven",
                "SSRF finding 1",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-011", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "xss", 0, "live_disproven",
                "XSS finding 1",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-012", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "jwt_oauth", 0, "live_confirmed",
                "JWT/OAuth finding 1",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-013", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "cors", 0, "live_disproven",
                "CORS finding 1",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-014", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "crlf", 0, "live_disproven",
                "CRLF finding 1",
                "engagements/ExampleStore-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-015", "2026-XX-XX-ExampleStore-bbp", "https://www.ExampleStore.com",
                "websocket", 0, "live_disproven",
                "Websocket finding 1",
                "engagements/ExampleStore-2026-XX-XX.yaml"),

    # ---- 2026-XX-XX AcmeProgram-bbp ------------------------------------------
    SVPBTaskRef("svpb-016", "2026-XX-XX-AcmeProgram-bbp", "https://AcmeProgram.com",
                "auth", 0, "live_confirmed",
                "AcmeProgram auth finding 1 (heavy-research target)",
                "engagements/AcmeProgram-bbp-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-017", "2026-XX-XX-AcmeProgram-bbp", "https://AcmeProgram.com",
                "csrf", 0, "live_disproven",
                "AcmeProgram CSRF — high-duplicate-probability target",
                "engagements/AcmeProgram-bbp-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-018", "2026-XX-XX-AcmeProgram-bbp", "https://AcmeProgram.com",
                "idor", 0, "live_disproven",
                "AcmeProgram IDOR — duplicate-likely",
                "engagements/AcmeProgram-bbp-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-019", "2026-XX-XX-AcmeProgram-bbp", "https://AcmeProgram.com",
                "ssrf", 0, "live_disproven",
                "AcmeProgram SSRF",
                "engagements/AcmeProgram-bbp-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-020", "2026-XX-XX-AcmeProgram-bbp", "https://AcmeProgram.com",
                "xss", 0, "live_disproven",
                "AcmeProgram XSS",
                "engagements/AcmeProgram-bbp-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-021", "2026-XX-XX-AcmeProgram-bbp", "https://AcmeProgram.com",
                "jwt_oauth", 0, "live_disproven",
                "AcmeProgram JWT/OAuth",
                "engagements/AcmeProgram-bbp-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-022", "2026-XX-XX-AcmeProgram-bbp", "https://AcmeProgram.com",
                "file_upload", 0, "live_disproven",
                "AcmeProgram file upload",
                "engagements/AcmeProgram-bbp-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-023", "2026-XX-XX-AcmeProgram-bbp", "https://AcmeProgram.com",
                "injection", 0, "live_disproven",
                "AcmeProgram injection",
                "engagements/AcmeProgram-bbp-2026-XX-XX.yaml"),

    # ---- 2026-XX-XX ExamplePay-bbp ----------------------------------------
    SVPBTaskRef("svpb-024", "2026-XX-XX-ExamplePay-bbp", "https://www.ExamplePay.com",
                "auth", 0, "live_disproven",
                "ExamplePay auth — high-noise target",
                "engagements/ExamplePay-bbp-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-025", "2026-XX-XX-ExamplePay-bbp", "https://www.ExamplePay.com",
                "csrf", 0, "live_disproven",
                "ExamplePay CSRF",
                "engagements/ExamplePay-bbp-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-026", "2026-XX-XX-ExamplePay-bbp", "https://www.ExamplePay.com",
                "idor", 0, "live_disproven",
                "ExamplePay IDOR",
                "engagements/ExamplePay-bbp-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-027", "2026-XX-XX-ExamplePay-bbp", "https://www.ExamplePay.com",
                "ssrf", 0, "live_disproven",
                "ExamplePay SSRF",
                "engagements/ExamplePay-bbp-2026-XX-XX.yaml"),
    SVPBTaskRef("svpb-028", "2026-XX-XX-ExamplePay-bbp-deep", "https://www.ExamplePay.com",
                "auth", 0, "live_disproven",
                "ExamplePay deep auth",
                "engagements/ExamplePay-bbp-2026-XX-XX-deep.yaml"),
    SVPBTaskRef("svpb-029", "2026-XX-XX-ExamplePay-bbp-deep", "https://www.ExamplePay.com",
                "ssrf", 0, "live_disproven",
                "ExamplePay deep SSRF",
                "engagements/ExamplePay-bbp-2026-XX-XX-deep.yaml"),

    # ---- 2026-XX-XX ExampleCorp-web -------------------------------------
    SVPBTaskRef("svpb-030", "2026-XX-XX-ExampleCorp-web", "https://ExampleCorp.com",
                "auth", 0, "live_confirmed",
                "ExampleCorp auth — sample SOW engagement",
                "engagements/ExampleCorp.yaml"),
    SVPBTaskRef("svpb-031", "2026-XX-XX-ExampleCorp-web", "https://ExampleCorp.com",
                "authz", 0, "live_confirmed",
                "ExampleCorp authz",
                "engagements/ExampleCorp.yaml"),
    SVPBTaskRef("svpb-032", "2026-XX-XX-ExampleCorp-web", "https://ExampleCorp.com",
                "csrf", 0, "live_disproven",
                "ExampleCorp CSRF",
                "engagements/ExampleCorp.yaml"),
    SVPBTaskRef("svpb-033", "2026-XX-XX-ExampleCorp-web", "https://ExampleCorp.com",
                "idor", 0, "live_disproven",
                "ExampleCorp IDOR",
                "engagements/ExampleCorp.yaml"),
    SVPBTaskRef("svpb-034", "2026-XX-XX-ExampleCorp-web", "https://ExampleCorp.com",
                "injection", 0, "live_disproven",
                "ExampleCorp injection",
                "engagements/ExampleCorp.yaml"),
    SVPBTaskRef("svpb-035", "2026-XX-XX-ExampleCorp-web", "https://ExampleCorp.com",
                "ssrf", 0, "live_disproven",
                "ExampleCorp SSRF",
                "engagements/ExampleCorp.yaml"),
    SVPBTaskRef("svpb-036", "2026-XX-XX-ExampleCorp-web", "https://ExampleCorp.com",
                "xss", 0, "live_disproven",
                "ExampleCorp XSS",
                "engagements/ExampleCorp.yaml"),
    SVPBTaskRef("svpb-037", "2026-XX-XX-ExampleCorp-web", "https://ExampleCorp.com",
                "file_upload", 0, "live_disproven",
                "ExampleCorp file upload",
                "engagements/ExampleCorp.yaml"),
    SVPBTaskRef("svpb-038", "2026-XX-XX-ExampleCorp-web", "https://ExampleCorp.com",
                "jwt_oauth", 0, "live_disproven",
                "ExampleCorp JWT/OAuth",
                "engagements/ExampleCorp.yaml"),

    # ---- 2026-XX-XX ExampleClient-web ---------------------------------------
    SVPBTaskRef("svpb-039", "2026-XX-XX-ExampleClient-web", "https://ExampleClient.com",
                "auth", 0, "live_confirmed",
                "ExampleClient auth — paying client",
                "engagements/ExampleClient.yaml"),
    SVPBTaskRef("svpb-040", "2026-XX-XX-ExampleClient-web", "https://ExampleClient.com",
                "authz", 0, "live_confirmed",
                "ExampleClient authz",
                "engagements/ExampleClient.yaml"),
    SVPBTaskRef("svpb-041", "2026-XX-XX-ExampleClient-web", "https://ExampleClient.com",
                "csrf", 0, "live_disproven",
                "ExampleClient CSRF",
                "engagements/ExampleClient.yaml"),
    SVPBTaskRef("svpb-042", "2026-XX-XX-ExampleClient-web", "https://ExampleClient.com",
                "idor", 0, "live_disproven",
                "ExampleClient IDOR",
                "engagements/ExampleClient.yaml"),
    SVPBTaskRef("svpb-043", "2026-XX-XX-ExampleClient-web", "https://ExampleClient.com",
                "injection", 0, "live_disproven",
                "ExampleClient injection",
                "engagements/ExampleClient.yaml"),
    SVPBTaskRef("svpb-044", "2026-XX-XX-ExampleClient-web", "https://ExampleClient.com",
                "ssrf", 0, "live_disproven",
                "ExampleClient SSRF",
                "engagements/ExampleClient.yaml"),

    # ---- ExampleStore-tax-2026-XX-XX ---------------------------------------
    SVPBTaskRef("svpb-045", "ExampleStore-tax-2026-XX-XX",
                "https://help.ExampleStore.com",
                "auth", 0, "live_confirmed",
                "ExampleStore Tax help — auth endpoint",
                "engagements/ExampleStore-tax-2026-XX-XX.yaml"),

    # ---- 2026-ExampleGlobal ------------------------------------------
    SVPBTaskRef("svpb-046", "2026-ExampleGlobal",
                "https://ExampleGlobal.test",
                "auth", 0, "live_confirmed",
                "Radiant Global recon-derived auth",
                "engagements/ExampleGlobal-2026-ExampleGlobal.yaml"),
    SVPBTaskRef("svpb-047", "2026-ExampleGlobal",
                "https://ExampleGlobal.test",
                "authz", 0, "live_confirmed",
                "Radiant Global authz",
                "engagements/ExampleGlobal-2026-ExampleGlobal.yaml"),
    SVPBTaskRef("svpb-048", "2026-ExampleGlobal",
                "https://ExampleGlobal.test",
                "csrf", 0, "live_disproven",
                "Radiant Global CSRF",
                "engagements/ExampleGlobal-2026-ExampleGlobal.yaml"),
    SVPBTaskRef("svpb-049", "2026-ExampleGlobal",
                "https://ExampleGlobal.test",
                "ssrf", 0, "live_disproven",
                "Radiant Global SSRF",
                "engagements/ExampleGlobal-2026-ExampleGlobal.yaml"),
    SVPBTaskRef("svpb-050", "2026-ExampleGlobal",
                "https://ExampleGlobal.test",
                "xss", 0, "live_disproven",
                "Radiant Global XSS",
                "engagements/ExampleGlobal-2026-ExampleGlobal.yaml"),
]


def list_tasks(only_present: bool = False) -> list[SVPBTaskRef]:
    """Return the task index. ``only_present=True`` filters to entries
    whose workspace queue file is actually on disk (useful when a
    fresh clone hasn't restored the private workspaces)."""
    if not only_present:
        return list(TASKS)
    return [t for t in TASKS if t.is_present]


def task_by_id(task_id: str) -> Optional[SVPBTaskRef]:
    for t in TASKS:
        if t.task_id == task_id:
            return t
    return None
