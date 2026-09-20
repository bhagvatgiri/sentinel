"""D6 — SVPB-Lite open task index.

The 10 tasks in this list MUST satisfy:

  1. Target is a PUBLIC bug-bounty program with prior authorization in
     this repo's engagements/ directory (so anyone with a Claude API
     key can re-run and the run is legally clean).
  2. Scope yaml + audit chain already exist in engagements/.
  3. The expected_outcome is reproducible — i.e. the verifier story or
     evidence file is committed so re-runners can compare.
  4. No personal-research targets, no client SOWs, no NDA-protected
     content.

This is the published surface — what makes Sentinel "the only OSS
pentest framework with reproducible end-to-end benchmarks." The
research/svpb-lite-publish/ directory ships a README pointing at this
list + the scope yamls + scoring instructions.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKSPACES_DIR = _PROJECT_ROOT / "workspaces"
ENGAGEMENTS_DIR = _PROJECT_ROOT / "engagements"


@dataclass
class SVPBLiteTask:
    task_id: str
    program: str          # bug-bounty platform program name
    target: str
    vuln_class: str
    queue_index: int
    expected_outcome: str
    notes: str
    scope_yaml: str       # relative to project root
    workspace: str        # relative to workspaces/
    seed: int = 0         # deterministic seed for the replay runner

    @property
    def scope_yaml_path(self) -> Path:
        return _PROJECT_ROOT / self.scope_yaml

    @property
    def workspace_path(self) -> Path:
        return WORKSPACES_DIR / self.workspace

    @property
    def queue_path(self) -> Path:
        return (
            self.workspace_path / "deliverables"
            / f"{self.vuln_class}_exploitation_queue.json"
        )


# ---- the 10 published tasks ----------------------------------------------

# All 10 reference public BBP targets where Sentinel ran with explicit
# H1 / Bugcrowd / Synack authorization. Re-runners must hold their own
# program authorization to re-execute against the live target — but the
# scope yaml, the recon brief, and the expected verifier outcome are
# all in this repo, so a research-only re-execution against a similar
# target is straightforward.
TASKS: list[SVPBLiteTask] = [
    SVPBLiteTask(
        "svpbl-001", "HackerOne — ExampleStore",
        "https://www.ExampleStore.com",
        "auth", 0, "live_confirmed",
        "OpenID returnUrl reflection — confirmed via signinRedirect chain",
        "engagements/ExampleStore-2026-XX-XX.yaml",
        "2026-XX-XX-ExampleStore-bbp", seed=1,
    ),
    SVPBLiteTask(
        "svpbl-002", "HackerOne — ExampleStore",
        "https://www.ExampleStore.com",
        "auth", 1, "live_confirmed",
        "Static OpenID siteState — login CSRF vector",
        "engagements/ExampleStore-2026-XX-XX.yaml",
        "2026-XX-XX-ExampleStore-bbp", seed=2,
    ),
    SVPBLiteTask(
        "svpbl-003", "HackerOne — ExampleStore",
        "https://www.ExampleStore.com",
        "auth", 2, "live_disproven",
        "max_auth_age over-claim — Phase 2.5 verifier disproved (maxAge "
        "is the live param, not maxAuthAge)",
        "engagements/ExampleStore-2026-XX-XX.yaml",
        "2026-XX-XX-ExampleStore-bbp", seed=3,
    ),
    SVPBLiteTask(
        "svpbl-004", "HackerOne — ExampleStore",
        "https://www.ExampleStore.com",
        "auth", 3, "live_confirmed",
        "Session cookie missing HttpOnly + SameSite",
        "engagements/ExampleStore-2026-XX-XX.yaml",
        "2026-XX-XX-ExampleStore-bbp", seed=4,
    ),
    SVPBLiteTask(
        "svpbl-005", "HackerOne — ExampleStore (tax sub-program)",
        "https://help.ExampleStore.com",
        "auth", 0, "live_confirmed",
        "ExampleStore Tax help portal auth-flow finding",
        "engagements/ExampleStore-tax-2026-XX-XX.yaml",
        "ExampleStore-tax-2026-XX-XX", seed=5,
    ),
    SVPBLiteTask(
        "svpbl-006", "HackerOne — AcmeProgram",
        "https://AcmeProgram.com",
        "auth", 0, "live_confirmed",
        "AcmeProgram auth — heavy-research target, novelty-checked finding",
        "engagements/AcmeProgram-bbp-2026-XX-XX.yaml",
        "2026-XX-XX-AcmeProgram-bbp", seed=6,
    ),
    SVPBLiteTask(
        "svpbl-007", "HackerOne — AcmeProgram",
        "https://AcmeProgram.com",
        "csrf", 0, "live_disproven",
        "AcmeProgram CSRF — high-duplicate-probability, verifier disproved",
        "engagements/AcmeProgram-bbp-2026-XX-XX.yaml",
        "2026-XX-XX-AcmeProgram-bbp", seed=7,
    ),
    SVPBLiteTask(
        "svpbl-008", "HackerOne — ExamplePay",
        "https://www.ExamplePay.com",
        "auth", 0, "live_disproven",
        "ExamplePay auth — high-noise target, verifier disproved",
        "engagements/ExamplePay-bbp-2026-XX-XX.yaml",
        "2026-XX-XX-ExamplePay-bbp", seed=8,
    ),
    SVPBLiteTask(
        "svpbl-009", "HackerOne — ExamplePay (deep mode)",
        "https://www.ExamplePay.com",
        "ssrf", 0, "live_disproven",
        "ExamplePay deep SSRF — verifier disproved",
        "engagements/ExamplePay-bbp-2026-XX-XX-deep.yaml",
        "2026-XX-XX-ExamplePay-bbp-deep", seed=9,
    ),
    SVPBLiteTask(
        "svpbl-010", "Sentinel public testbed",
        "https://ExampleGlobal.test",
        "auth", 0, "live_confirmed",
        "Radiant Global testbed — recon-derived auth finding",
        "engagements/ExampleGlobal-2026-ExampleGlobal.yaml",
        "2026-ExampleGlobal", seed=10,
    ),
]


def list_tasks(only_present: bool = False) -> list[SVPBLiteTask]:
    if not only_present:
        return list(TASKS)
    return [
        t for t in TASKS
        if t.scope_yaml_path.exists() and t.workspace_path.exists()
    ]


def task_by_id(task_id: str) -> Optional[SVPBLiteTask]:
    for t in TASKS:
        if t.task_id == task_id:
            return t
    return None
