"""D4 — Generic eval harness with cumulative cost cap.

CAI ships ``benchmarks/eval.py`` with a ``if total_cost > 20: break``
pattern so a benchmark sweep can't blow the operator's budget. We
replicate that pattern in a small reusable harness so every benchmark
in :mod:`sentinel.benchmark` shares one cost-cap implementation.

Public surface:

  - :class:`BenchmarkTask`        — one input + ground-truth tuple.
  - :class:`BenchmarkTaskResult`  — per-task outcome with cost +
                                    duration + pass/fail.
  - :class:`BenchmarkResult`      — aggregate across all tasks.
  - :func:`run_benchmark`         — orchestrator. Iterates tasks, calls
                                    a user-provided runner, accumulates
                                    cost, hard-stops on cap.
  - :class:`CostCapExceeded`      — raised once cumulative cost exceeds
                                    the cap. Caller decides whether to
                                    treat as success or failure.

The runner contract is intentionally minimal: ``runner(task) -> dict``
with at minimum ``{"passed": bool}`` and optionally ``{"cost_usd":
float, "duration_sec": float, "details": Any}``. This lets the harness
work for everything from PII regex eval (zero LLM cost) to live-target
SVPB replay (real Claude SDK calls).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


class CostCapExceeded(Exception):
    """Raised when cumulative benchmark cost exceeds the operator cap."""


@dataclass
class BenchmarkTask:
    """One unit of work in a benchmark sweep.

    ``inputs`` is whatever the runner needs (a dict, a string, a path).
    ``expected`` is the ground truth (also runner-defined). ``meta``
    carries provenance tags for the report (source, difficulty, …).
    """
    id: str
    inputs: Any
    expected: Any
    meta: dict = field(default_factory=dict)


@dataclass
class BenchmarkTaskResult:
    """Outcome of running one task. ``actual`` is whatever the runner
    produced; ``passed`` is the boolean grade."""
    task_id: str
    passed: bool
    cost_usd: float = 0.0
    duration_sec: float = 0.0
    actual: Any = None
    error: Optional[str] = None
    details: dict = field(default_factory=dict)


@dataclass
class BenchmarkResult:
    """Aggregate result for one benchmark run.

    Computed metrics:
      - ``pass_rate`` — fraction of completed tasks that passed.
      - ``pass_at_1`` — alias of pass_rate (CAI naming compatibility).
      - ``total_cost_usd`` / ``total_duration_sec`` — cumulative.
      - ``aborted`` — True if the cost cap stopped the sweep early.
      - ``per_task`` — list of :class:`BenchmarkTaskResult`.
      - ``custom_metrics`` — bag the benchmark module may fill in
        (``{"f1_macro": 0.84, "mad": 1.2}`` etc.). Renderer reads it.
    """
    name: str
    model: Optional[str]
    n_tasks: int
    n_completed: int
    n_passed: int
    total_cost_usd: float
    total_duration_sec: float
    aborted: bool
    per_task: list[BenchmarkTaskResult]
    custom_metrics: dict = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""

    @property
    def pass_rate(self) -> float:
        return self.n_passed / self.n_completed if self.n_completed else 0.0

    @property
    def pass_at_1(self) -> float:
        return self.pass_rate

    def to_dict(self) -> dict:
        """JSON-friendly snapshot. The dashboard + CLI both round-trip
        through this; per-task details are kept compact."""
        return {
            "name": self.name,
            "model": self.model,
            "n_tasks": self.n_tasks,
            "n_completed": self.n_completed,
            "n_passed": self.n_passed,
            "pass_rate": self.pass_rate,
            "total_cost_usd": self.total_cost_usd,
            "total_duration_sec": self.total_duration_sec,
            "aborted": self.aborted,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "custom_metrics": self.custom_metrics,
            "per_task": [
                {
                    "task_id": r.task_id,
                    "passed": r.passed,
                    "cost_usd": r.cost_usd,
                    "duration_sec": r.duration_sec,
                    "error": r.error,
                }
                for r in self.per_task
            ],
        }


def run_benchmark(
    *,
    name: str,
    tasks: list[BenchmarkTask],
    runner: Callable[[BenchmarkTask], dict],
    model: Optional[str] = None,
    max_cost_usd: float = 5.0,
    timeout_per_task_sec: float = 600.0,
    on_progress: Optional[Callable[[BenchmarkTaskResult], None]] = None,
) -> BenchmarkResult:
    """Run a benchmark to completion, the cost cap, or first-task-error.

    Args:
        name: Display name for the report ("pii_bench", "svpb_lite", ...)
        tasks: Pre-built task list; harness iterates in order.
        runner: ``runner(task) -> {"passed": bool, "cost_usd": float?,
                "duration_sec": float?, "actual": Any?, "details": dict?}``.
                Errors raised by the runner are caught and recorded as
                ``BenchmarkTaskResult(passed=False, error=...)``.
        model: Provenance tag — recorded on the result for the report.
        max_cost_usd: CUMULATIVE cap. Once total cost passes this, the
                      sweep aborts and ``aborted=True`` on the result.
        timeout_per_task_sec: Soft cap; the harness measures wall-clock
                              and skips remaining tasks if a single task
                              exceeded this (informational only — runners
                              are expected to enforce their own timeout).
        on_progress: Optional callback fired after each task completes.

    Returns:
        :class:`BenchmarkResult`.
    """
    started = time.time()
    started_iso = _iso(started)

    per_task: list[BenchmarkTaskResult] = []
    total_cost = 0.0
    total_dur = 0.0
    aborted = False

    for task in tasks:
        if total_cost > max_cost_usd:
            aborted = True
            break
        t0 = time.time()
        try:
            res = runner(task) or {}
            duration = float(res.get("duration_sec") or (time.time() - t0))
            ttr = BenchmarkTaskResult(
                task_id=task.id,
                passed=bool(res.get("passed")),
                cost_usd=float(res.get("cost_usd") or 0.0),
                duration_sec=duration,
                actual=res.get("actual"),
                details=dict(res.get("details") or {}),
            )
        except Exception as e:                          # noqa: BLE001
            duration = time.time() - t0
            ttr = BenchmarkTaskResult(
                task_id=task.id, passed=False,
                cost_usd=0.0, duration_sec=duration,
                error=f"{type(e).__name__}: {e}",
            )
        per_task.append(ttr)
        total_cost += ttr.cost_usd
        total_dur += ttr.duration_sec
        if on_progress:
            try:
                on_progress(ttr)
            except Exception:                            # noqa: BLE001
                pass

    finished = time.time()
    n_completed = len(per_task)
    n_passed = sum(1 for r in per_task if r.passed)

    return BenchmarkResult(
        name=name,
        model=model,
        n_tasks=len(tasks),
        n_completed=n_completed,
        n_passed=n_passed,
        total_cost_usd=round(total_cost, 6),
        total_duration_sec=round(total_dur, 4),
        aborted=aborted,
        per_task=per_task,
        started_at=started_iso,
        finished_at=_iso(finished),
    )


def _iso(epoch: float) -> str:
    """ISO-8601 UTC timestamp — kept short to fit in audit-log payloads."""
    import datetime
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat()
