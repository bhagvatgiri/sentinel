"""D5 — Sentinel Verifier-graded Pentest Bench.

The strategic differentiator. CAI's CAIBench has Cybench/A&D Docker
images behind a private GitLab registry; their in-repo "datasets" are
2-row smoke tests. Sentinel's SVPB:

  - 50 verifier-graded pentest tasks pulled directly from past
    engagement workspaces (ExampleStore / AcmeProgram / ExamplePay / ExampleCorp /
    ExampleClient / ExampleGlobal / ExampleStore-tax).
  - Each task = (engagement scope, target URL, vuln class, queue entry,
    expected verifier outcome).
  - Replay against any model (Sonnet / Opus / Haiku / local Qwen / …);
    the Phase 2.5 verifier judges.
  - Metrics:
      * ``live_confirmed_rate@k``       — fraction of tasks where the
                                          model successfully reproduced
                                          a confirmed bug.
      * ``live_disproven_rate@k``       — symmetric for disproven cases
                                          (a model that always claims
                                          "confirmed" gets crushed here).
      * ``verification_error_rate``      — fraction where the verifier
                                          disagrees with the model's
                                          self-claim.
      * ``mean_evidence_quality_score``  — mean operator-graded
                                          0..1 quality score (when
                                          available; else None).
      * ``tool_use_efficiency``          — model's pass over total tool
                                          calls (proxy for token cost).

Replay is opt-in (it makes real LLM + scope-gated HTTP calls). The unit
tests cover the harness, metrics, and a mocked-LLM replay so CI is
deterministic and free.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from sentinel.benchmark import svpb_data
from sentinel.benchmark.svpb_data import SVPBTaskRef


log = logging.getLogger(__name__)


@dataclass
class SVPBReplayResult:
    """Per-task replay outcome.

    ``verifier_outcome``: what Sentinel's Phase 2.5 verifier says the
    actual state is after the model's run. Compared against
    ``task.expected_outcome`` to grade.

    ``model_self_claim``: what the model reported it found (parsed from
    the deliverable). Compared against verifier_outcome to populate
    ``verification_error_rate`` (model says "confirmed", verifier says
    "disproven" → that's an error).
    """
    task_id: str
    model: str
    verifier_outcome: str
    model_self_claim: str
    expected_outcome: str
    matched_expected: bool
    verifier_disagreed_with_model: bool
    n_tool_calls: int = 0
    n_passing_tool_calls: int = 0
    evidence_quality_score: Optional[float] = None
    error: Optional[str] = None


@dataclass
class SVPBAggregate:
    n_tasks: int
    n_completed: int
    live_confirmed_rate: float
    live_disproven_rate: float
    verification_error_rate: float
    mean_evidence_quality_score: Optional[float]
    tool_use_efficiency: Optional[float]
    per_task: list[SVPBReplayResult] = field(default_factory=list)


# ---- task loader ----------------------------------------------------------

def load_task_brief(task: SVPBTaskRef) -> dict:
    """Read the queue JSON entry the task points at and return a brief
    dict the model gets fed.

    Returns the minimal fields a replay needs: vuln_type, source_endpoint,
    missing_defense, exploitation_hypothesis. Refuses if the queue file
    is absent — operator expected to ``svpb_data.list_tasks(only_present
    =True)`` first.
    """
    if not task.is_present:
        raise FileNotFoundError(
            f"queue file missing for {task.task_id}: {task.queue_path}"
        )
    raw = json.loads(task.queue_path.read_text())
    if isinstance(raw, list):
        entries = raw
    elif isinstance(raw, dict):
        entries = (
            raw.get("vulnerabilities")
            or raw.get("entries")
            or raw.get("queue")
            or []
        )
    else:
        entries = []
    if not isinstance(entries, list):
        entries = []
    if not entries:
        return {
            "task_id": task.task_id,
            "vuln_class": task.vuln_class,
            "target": task.target,
            "warning": f"queue at {task.queue_path} has no entries",
        }
    idx = max(0, min(task.queue_index, len(entries) - 1))
    e = entries[idx]
    if not isinstance(e, dict):
        e = {"raw": e}
    return {
        "task_id": task.task_id,
        "engagement": task.engagement,
        "target": task.target,
        "vuln_class": task.vuln_class,
        "queue_index": idx,
        "vulnerability_type": e.get("vulnerability_type") or e.get("type"),
        "source_endpoint": e.get("source_endpoint") or e.get("endpoint"),
        "missing_defense": e.get("missing_defense"),
        "exploitation_hypothesis": e.get("exploitation_hypothesis"),
        "suggested_exploit_technique": e.get("suggested_exploit_technique"),
        "confidence": e.get("confidence"),
        "expected_outcome": task.expected_outcome,
    }


# ---- replay harness -------------------------------------------------------

def replay_task(
    task: SVPBTaskRef,
    *,
    model: str,
    runner: Callable[[dict], dict],
) -> SVPBReplayResult:
    """Run a single task via ``runner``.

    ``runner(brief) -> {"verifier_outcome": str, "model_self_claim": str,
    "n_tool_calls": int?, "n_passing_tool_calls": int?,
    "evidence_quality_score": float?}``

    The runner is responsible for: spawning the model, feeding it the
    brief, walking it through the verifier, returning the outcome. We
    keep it pluggable so the unit tests can mock it; in production
    :mod:`sentinel.agent.pentest.verifier_story_runner` is the runner.
    """
    try:
        brief = load_task_brief(task)
    except Exception as e:                                # noqa: BLE001
        return SVPBReplayResult(
            task_id=task.task_id, model=model,
            verifier_outcome="error", model_self_claim="error",
            expected_outcome=task.expected_outcome,
            matched_expected=False,
            verifier_disagreed_with_model=False,
            error=f"{type(e).__name__}: {e}",
        )
    try:
        out = runner(brief) or {}
    except Exception as e:                                # noqa: BLE001
        return SVPBReplayResult(
            task_id=task.task_id, model=model,
            verifier_outcome="error", model_self_claim="error",
            expected_outcome=task.expected_outcome,
            matched_expected=False,
            verifier_disagreed_with_model=False,
            error=f"{type(e).__name__}: {e}",
        )
    v = (out.get("verifier_outcome") or "").lower()
    m_claim = (out.get("model_self_claim") or "").lower()
    return SVPBReplayResult(
        task_id=task.task_id, model=model,
        verifier_outcome=v, model_self_claim=m_claim,
        expected_outcome=task.expected_outcome,
        matched_expected=(v == task.expected_outcome.lower()),
        verifier_disagreed_with_model=(v != m_claim and bool(m_claim)),
        n_tool_calls=int(out.get("n_tool_calls") or 0),
        n_passing_tool_calls=int(out.get("n_passing_tool_calls") or 0),
        evidence_quality_score=out.get("evidence_quality_score"),
    )


def aggregate(
    results: list[SVPBReplayResult], total_tasks: int
) -> SVPBAggregate:
    """Compute the SVPB-published metric set."""
    n = len(results) or 1
    confirmed_total = sum(1 for r in results if r.expected_outcome == "live_confirmed")
    disproven_total = sum(1 for r in results if r.expected_outcome == "live_disproven")
    confirmed_hits = sum(
        1 for r in results
        if r.expected_outcome == "live_confirmed" and r.matched_expected
    )
    disproven_hits = sum(
        1 for r in results
        if r.expected_outcome == "live_disproven" and r.matched_expected
    )
    verification_errors = sum(1 for r in results if r.verifier_disagreed_with_model)
    quality_scores = [
        r.evidence_quality_score for r in results
        if r.evidence_quality_score is not None
    ]
    mean_q = (
        sum(quality_scores) / len(quality_scores) if quality_scores else None
    )
    total_tool = sum(r.n_tool_calls for r in results)
    pass_tool = sum(r.n_passing_tool_calls for r in results)
    tool_eff = (pass_tool / total_tool) if total_tool else None
    return SVPBAggregate(
        n_tasks=total_tasks,
        n_completed=len(results),
        live_confirmed_rate=(
            confirmed_hits / confirmed_total if confirmed_total else 0.0
        ),
        live_disproven_rate=(
            disproven_hits / disproven_total if disproven_total else 0.0
        ),
        verification_error_rate=verification_errors / n,
        mean_evidence_quality_score=mean_q,
        tool_use_efficiency=tool_eff,
        per_task=results,
    )


# ---- benchmark entry point ------------------------------------------------

def run(
    *,
    model: str = "stub-model",
    runner: Optional[Callable[[dict], dict]] = None,
    only_present: bool = True,
    max_tasks: Optional[int] = None,
) -> dict:
    """Replay the SVPB suite. Returns dict shaped for the harness.

    ``runner`` defaults to a deterministic mock that mirrors each
    task's expected outcome — so the unit tests + CI exercise the
    harness without needing live infra. Operators pass in a real
    runner for actual benchmarking.
    """
    runner = runner or _mock_runner
    tasks = svpb_data.list_tasks(only_present=only_present)
    if max_tasks is not None:
        tasks = tasks[:max_tasks]
    results = [replay_task(t, model=model, runner=runner) for t in tasks]
    agg = aggregate(results, total_tasks=len(tasks))
    return {
        "model": model,
        "n_tasks": agg.n_tasks,
        "n_completed": agg.n_completed,
        "live_confirmed_rate": round(agg.live_confirmed_rate, 4),
        "live_disproven_rate": round(agg.live_disproven_rate, 4),
        "verification_error_rate": round(agg.verification_error_rate, 4),
        "mean_evidence_quality_score": agg.mean_evidence_quality_score,
        "tool_use_efficiency": (
            round(agg.tool_use_efficiency, 4)
            if agg.tool_use_efficiency is not None else None
        ),
        "per_task": [
            {
                "task_id": r.task_id,
                "expected": r.expected_outcome,
                "verifier": r.verifier_outcome,
                "model_self_claim": r.model_self_claim,
                "matched": r.matched_expected,
                "verification_error": r.verifier_disagreed_with_model,
                "n_tool_calls": r.n_tool_calls,
                "evidence_quality_score": r.evidence_quality_score,
                "error": r.error,
            }
            for r in agg.per_task
        ],
    }


def _mock_runner(brief: dict) -> dict:
    """Deterministic runner that returns the expected outcome — used
    by the unit tests + CI to exercise the harness without infra."""
    expected = (brief.get("expected_outcome") or "").lower()
    return {
        "verifier_outcome": expected,
        "model_self_claim": expected,
        "n_tool_calls": 5,
        "n_passing_tool_calls": 5,
        "evidence_quality_score": 0.9,
    }
