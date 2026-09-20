"""Sentinel benchmark suite (Wave 8).

Reproducible end-to-end benchmarks for the Sentinel pentest platform.

Sub-modules:

  - :mod:`pii_bench`  CyberPII-Bench port (838 → 78 unique pentest-log
                       PII annotations from CAI's MIT-licensed dataset).
                       Metric: precision/recall/F1/F2 (β=2 favors recall).
  - :mod:`cti_bench`  CTIBench MITRE-extract eval. Synthetic CTI excerpts
                       → ATT&CK technique extraction (F1-macro) + CVSS
                       scoring (MAD).
  - :mod:`mcq_bench`  SecEval/CyberMetric MCQ as RAG-regression test.
                       Cold LLM vs Sentinel-RAG-augmented LLM accuracy
                       delta.
  - :mod:`harness`    Generic eval harness with cumulative cost cap.
  - :mod:`svpb`       Sentinel Verifier-graded Pentest Bench. 50
                       verifier-graded pentest tasks derived from past
                       engagement workspaces.
  - :mod:`svpb_lite`  SVPB-Lite — open subset of 10 publishable tasks.
  - :mod:`cybench`    Cybench / AutoPenBench harness (CTF-only).
  - :mod:`ad_ctf`     A&D CTF scenarios from paper 2510.17521 (CTF-only,
                       red+blue parallel).

Each benchmark module exposes a ``run(...) -> BenchmarkResult`` entry
point compatible with :func:`sentinel.benchmark.harness.run_benchmark`.
"""

from sentinel.benchmark.harness import (  # noqa: E402
    BenchmarkResult,
    BenchmarkTask,
    BenchmarkTaskResult,
    CostCapExceeded,
    run_benchmark,
)


__all__ = [
    "BenchmarkResult",
    "BenchmarkTask",
    "BenchmarkTaskResult",
    "CostCapExceeded",
    "run_benchmark",
    "list_benchmarks",
]


def list_benchmarks() -> list[dict]:
    """Return a description of every registered benchmark.

    Used by the CLI (`sentinel benchmark list`) and the dashboard
    (/benchmark) to render a registry without needing to import every
    sub-module up-front.
    """
    return [
        {
            "name": "pii_bench",
            "module": "sentinel.benchmark.pii_bench",
            "metric": "F2 (β=2 — recall-favoring)",
            "mode": "production+ctf",
            "tasks": 78,
            "data": "CyberPII memory01_gold (MIT, ported from CAI)",
            "description": "Pentest-log PII span detection. CAI reports F1≈0.87.",
        },
        {
            "name": "cti_bench",
            "module": "sentinel.benchmark.cti_bench",
            "metric": "F1-macro (ATT&CK extraction) + MAD (CVSS)",
            "mode": "production+ctf",
            "tasks": 20,
            "data": "Synthetic CTI excerpts (Sentinel-authored)",
            "description": "ATT&CK/CWE extraction + CVSS score deviation.",
        },
        {
            "name": "mcq_bench",
            "module": "sentinel.benchmark.mcq_bench",
            "metric": "Accuracy delta (RAG vs cold)",
            "mode": "production+ctf",
            "tasks": 50,
            "data": "SecEval + CyberMetric MCQ subset (Sentinel-curated)",
            "description": "Demonstrates whether OWASP/MITRE corpus improves answers.",
        },
        {
            "name": "svpb",
            "module": "sentinel.benchmark.svpb",
            "metric": "live_confirmed_rate@k + verification_error_rate",
            "mode": "production",
            "tasks": 50,
            "data": "Past engagement workspaces (PRIVATE)",
            "description": "Verifier-graded replay against any model.",
        },
        {
            "name": "svpb_lite",
            "module": "sentinel.benchmark.svpb_lite",
            "metric": "live_confirmed_rate@k",
            "mode": "production",
            "tasks": 10,
            "data": "Public bug-bounty programs (REPRODUCIBLE)",
            "description": "Open SVPB subset — anyone with API key can re-run.",
        },
        {
            "name": "cybench",
            "module": "sentinel.benchmark.cybench",
            "metric": "pass-rate@1",
            "mode": "ctf",
            "tasks": 67,
            "data": "Cybench (38) + AutoPenBench (29) — public",
            "description": "CTF replays. Requires CTF-mode dangerous tools.",
        },
        {
            "name": "ad_ctf",
            "module": "sentinel.benchmark.ad_ctf",
            "metric": "constraint matrix (lab/operational/complete)",
            "mode": "ctf",
            "tasks": 10,
            "data": "A&D CTF scenarios (paper 2510.17521 public alts)",
            "description": "Red+blue parallel mode. CTF only.",
        },
        {
            "name": "parity_eval",
            "module": "sentinel.benchmark.parity_eval",
            "metric": "per-phase pass-rate + cost-delta vs anthropic baseline",
            "mode": "bench",
            "tasks": "varies (per suite)",
            "data": "bench/<suite>/canonical-vulns.yaml",
            "description":
                "SiliconFlow Qwen 235B vs Anthropic baseline parity benchmark "
                "(BENCH-05). Plan 02-01 ships juice-shop suite; 02-02/02-03 "
                "add DVWA + CTF-box.",
        },
    ]
