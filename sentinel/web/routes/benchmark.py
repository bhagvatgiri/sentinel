"""D7-D9 — Benchmark dashboard route.

Routes:
  GET /benchmarks                — registry view
  GET /benchmarks/<name>         — per-benchmark detail (last run + metric
                                    breakdown + per-task table)
  POST /benchmarks/<name>/run    — kick off a fresh stub run (no LLM
                                    cost) and persist the result JSON to
                                    runs/benchmark-<name>-<ts>.json

Historical runs read from ``runs/benchmark-*.json`` so the trendline
shows up across sessions.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from sentinel.benchmark import list_benchmarks


router = APIRouter()


_PROJECT_ROOT = Path(__file__).resolve().parents[3]
RUNS_DIR = _PROJECT_ROOT / "runs"


@router.get("/benchmarks", name="benchmarks_index")
def benchmarks_index(request: Request):
    """Registry + per-benchmark trendline of historical runs."""
    registry = list_benchmarks()
    trendlines = _load_trendlines()
    return request.app.state.templates.TemplateResponse(
        request, "benchmark.html",
        {
            "active_nav": "Benchmarks",
            "view": "index",
            "registry": registry,
            "trendlines": trendlines,
            "selected": None,
        },
    )


@router.get("/benchmarks/{name}", name="benchmarks_detail")
def benchmarks_detail(request: Request, name: str):
    registry = list_benchmarks()
    selected = next((b for b in registry if b["name"] == name), None)
    if selected is None:
        raise HTTPException(status_code=404, detail=f"unknown benchmark: {name}")
    trendlines = _load_trendlines()
    history = trendlines.get(name, [])
    last_run = history[-1] if history else None
    return request.app.state.templates.TemplateResponse(
        request, "benchmark.html",
        {
            "active_nav": "Benchmarks",
            "view": "detail",
            "registry": registry,
            "trendlines": trendlines,
            "selected": selected,
            "history": history,
            "last_run": last_run,
        },
    )


@router.post("/benchmarks/{name}/run", name="benchmarks_run")
def benchmarks_run(request: Request, name: str):
    """Kick off a stub-runner pass — no LLM cost, just exercises the
    harness. Real benchmarking goes via the CLI (``sentinel benchmark
    run``) which respects --max-budget."""
    registry = list_benchmarks()
    target = next((b for b in registry if b["name"] == name), None)
    if target is None:
        raise HTTPException(status_code=404, detail=f"unknown benchmark: {name}")
    try:
        result = _run_with_default_runner(name)
    except Exception as e:                                  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")

    # Persist for the trendline.
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    out_path = RUNS_DIR / f"benchmark-{name}-{ts}.json"
    out_path.write_text(json.dumps(result, indent=2))

    return benchmarks_detail(request, name)


def _run_with_default_runner(name: str) -> dict:
    """Dispatch to the named benchmark's run() with default args."""
    if name == "pii_bench":
        from sentinel.benchmark import pii_bench
        return pii_bench.run()
    if name == "cti_bench":
        from sentinel.benchmark import cti_bench
        return cti_bench.run()
    if name == "mcq_bench":
        from sentinel.benchmark import mcq_bench
        return mcq_bench.run()
    if name == "svpb":
        from sentinel.benchmark import svpb
        return svpb.run()
    if name == "svpb_lite":
        from sentinel.benchmark import svpb_lite
        return svpb_lite.run()
    if name == "cybench":
        from sentinel.benchmark import cybench
        return cybench.run(mode="ctf", max_tasks=5)
    if name == "ad_ctf":
        from sentinel.benchmark import ad_ctf
        return ad_ctf.run(mode="ctf")
    raise ValueError(f"no default runner wired for benchmark {name!r}")


def _load_trendlines() -> dict[str, list[dict]]:
    """Read every runs/benchmark-*.json file and bucket by benchmark
    name. Entries sorted by mtime ascending so the dashboard renders
    chronologically."""
    out: dict[str, list[dict]] = {}
    if not RUNS_DIR.exists():
        return out
    for p in sorted(RUNS_DIR.glob("benchmark-*.json"), key=lambda x: x.stat().st_mtime):
        try:
            data = json.loads(p.read_text())
        except Exception:                                   # noqa: BLE001
            continue
        # Try common name keys.
        bname = (
            data.get("benchmark") or data.get("name")
            or _name_from_filename(p.name)
        )
        if not bname:
            continue
        # Pick the headline metric per benchmark family.
        score = _headline_score(data)
        out.setdefault(bname, []).append({
            "ts": datetime.fromtimestamp(
                p.stat().st_mtime, timezone.utc
            ).isoformat(),
            "filename": p.name,
            "score": score,
            "model": data.get("model"),
            "raw": data,
        })
    return out


def _name_from_filename(filename: str) -> str:
    # benchmark-<name>-<ts>.json
    parts = filename.replace(".json", "").split("-")
    if len(parts) >= 3 and parts[0] == "benchmark":
        return "-".join(parts[1:-1])
    return ""


def _headline_score(data: dict) -> dict:
    """Pick the most-comparable metric from a benchmark result dict."""
    if "score" in data and isinstance(data["score"], dict):
        return {k: data["score"].get(k) for k in ("f1", "f2", "precision", "recall")}
    if "f1_macro" in data:
        return {"f1_macro": data["f1_macro"], "mad": data.get("mad")}
    if "rag_accuracy" in data:
        return {
            "rag_accuracy": data["rag_accuracy"],
            "cold_accuracy": data["cold_accuracy"],
            "delta": data["delta"],
        }
    if "live_confirmed_rate" in data:
        return {
            "live_confirmed_rate": data["live_confirmed_rate"],
            "live_disproven_rate": data["live_disproven_rate"],
            "verification_error_rate": data["verification_error_rate"],
        }
    if "pass_rate" in data:
        return {"pass_rate": data["pass_rate"]}
    if "constraint_matrix" in data:
        return {"constraint_matrix": data["constraint_matrix"]}
    return {}
