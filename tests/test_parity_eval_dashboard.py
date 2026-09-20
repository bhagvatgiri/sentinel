"""BENCH-10 regression tests — `/bench/parity-eval` FastAPI dashboard.

Hermetic FastAPI TestClient tests for the parity-eval dashboard surface
shipped by Plan 02-04 Task 2:

  - `GET  /bench/parity-eval`               — renders latest eval +
                                              current default profile.
  - `GET  /bench/parity-eval` Accept: JSON  — content-negotiates to JSON.
  - `POST /bench/parity-eval/reset-default` — calls reset_default + 303.
  - `POST /bench/parity-eval/run`           — kicks off run_parity_eval
                                              via BackgroundTasks (mocked).

All tests:
  - Monkeypatch `_RUNS_DIR` to a tmp directory so no test scans the
    operator's real `runs/` folder.
  - Monkeypatch `DEFAULT_PROFILE_STATE_PATH` to tmp so no test touches
    `~/.sentinel/`.
  - Mock the actual `run_parity_eval` call so POST /run doesn't fire a
    real benchmark.

No network, no docker, no shim, no live SiliconFlow.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


# Import lazily inside fixtures so collection errors surface as test
# failures (not module-load errors).


# ---- Fixtures -----------------------------------------------------------


def _build_synthetic_eval_json(*, verdict_overall: str = "pass") -> dict:
    """Build a v1.2 eval JSON with three suites (juice-shop, dvwa,
    ctf-box) and two profiles (anthropic-baseline + siliconflow-qwen-235b).

    Shape matches what `run_parity_eval` writes in Plan 02-03.
    """
    return {
        "schema_version": "1.2",
        "suite": "juice-shop,dvwa,ctf-box",
        "target": "http://127.0.0.1:3000",
        "scope_engagement_id": "bench-juice-shop",
        "baseline_profile": "anthropic-baseline",
        "candidate_profile": "siliconflow-qwen-235b",
        "started_at": "2026-XX-XXT12:00:00+00:00",
        "completed_at": "2026-XX-XXT12:30:00+00:00",
        "verdict_overall": verdict_overall,
        "markdown_report_path": "/tmp/qwen-parity-eval-2026-XX-XX-120000.md",
        "runs": [
            {
                "profile": "anthropic-baseline",
                "suite_name": "juice-shop",
                "target_url": "http://127.0.0.1:3000",
                "scope_engagement_id": "bench-juice-shop",
                "phases": [],
                "total_input_tokens": 100000,
                "total_output_tokens": 20000,
                "per_phase_verdicts": {"recon": "pass"},
                "cost_summary": {"total_usd": 1.0},
            },
            {
                "profile": "siliconflow-qwen-235b",
                "suite_name": "juice-shop",
                "target_url": "http://127.0.0.1:3000",
                "scope_engagement_id": "bench-juice-shop",
                "phases": [],
                "total_input_tokens": 100000,
                "total_output_tokens": 20000,
                "per_phase_verdicts": {"recon": "pass"},
                "cost_summary": {"total_usd": 0.15},
            },
            {"profile": "anthropic-baseline", "suite_name": "dvwa",
             "phases": [], "per_phase_verdicts": {}},
            {"profile": "siliconflow-qwen-235b", "suite_name": "dvwa",
             "phases": [], "per_phase_verdicts": {}},
            {"profile": "anthropic-baseline", "suite_name": "ctf-box",
             "phases": [], "per_phase_verdicts": {}},
            {"profile": "siliconflow-qwen-235b", "suite_name": "ctf-box",
             "phases": [], "per_phase_verdicts": {}},
        ],
        "suites": {
            "juice-shop": {
                "verdict": verdict_overall,
                "cost_delta": {
                    "baseline_usd": 1.0,
                    "candidate_usd": 0.15,
                    "delta_usd": -0.85,
                    "percent_reduction": 85.0,
                    "verdict": "pass",
                },
                "baseline_run_index": 0,
                "candidate_run_index": 1,
            },
            "dvwa": {
                "verdict": verdict_overall,
                "cost_delta": {"baseline_usd": 0.8, "candidate_usd": 0.12,
                                "delta_usd": -0.68,
                                "percent_reduction": 85.0,
                                "verdict": "pass"},
                "baseline_run_index": 2,
                "candidate_run_index": 3,
            },
            "ctf-box": {
                "verdict": verdict_overall,
                "cost_delta": {"baseline_usd": 0.6, "candidate_usd": 0.09,
                                "delta_usd": -0.51,
                                "percent_reduction": 85.0,
                                "verdict": "pass"},
                "baseline_run_index": 4,
                "candidate_run_index": 5,
            },
        },
    }


@pytest.fixture
def client_with_tmp_runs(tmp_path: Path, monkeypatch):
    """Hermetic TestClient — every filesystem read in the parity_eval
    route is redirected into `tmp_path`.

    Returns a tuple (client, runs_dir, state_path) so tests can write
    fixture files before asserting on the route's behavior.
    """
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    bench_dir = tmp_path / "bench" / "juice-shop"
    bench_dir.mkdir(parents=True, exist_ok=True)
    # Minimal scope.yaml — enough that the POST /run suite validation passes.
    (bench_dir / "scope.yaml").write_text(
        "client: bench-juice-shop\n"
        "engagement_id: bench-juice-shop\n"
        "authorized_by: jack+bench@local\n"
        "valid_from: 2026-XX-XX\n"
        "valid_until: 2030-12-31\n"
        "targets:\n"
        "  domains: [127.0.0.1, localhost]\n"
        "  ips: [127.0.0.1/32]\n"
    )
    state_path = tmp_path / "default.txt"

    # Monkeypatch BOTH the route's _RUNS_DIR AND the default_switch
    # state-file path BEFORE creating the app (the FastAPI dependency
    # graph is lazy, so imports inside route handlers pick up the patches).
    from sentinel.benchmark import default_switch as ds
    from sentinel.web.routes import parity_eval as pe_route
    monkeypatch.setattr(pe_route, "_RUNS_DIR", runs_dir)
    monkeypatch.setattr(pe_route, "_PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(ds, "DEFAULT_PROFILE_STATE_PATH", state_path)
    # POST /run validates suite names by checking bench/<name>/scope.yaml.
    # Set cwd so relative-path lookups land in tmp.
    monkeypatch.chdir(tmp_path)

    from sentinel.web.app import create_app
    app = create_app()
    with TestClient(app) as c:
        yield c, runs_dir, state_path


# ---- Tests --------------------------------------------------------------


def test_get_bench_parity_eval_returns_200_with_no_history(client_with_tmp_runs):
    """Empty runs/ → GET returns 200 + empty-state copy."""
    client, runs_dir, _state_path = client_with_tmp_runs
    r = client.get("/bench/parity-eval")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    body = r.text
    # The data-testid lets future regression tests target the panel.
    assert 'data-testid="parity-eval-panel"' in body
    # Empty-state copy. The exact wording is flexible; just check for the
    # "no run yet" sentinel.
    assert (
        "No parity eval runs yet" in body
        or "no parity eval" in body.lower()
        or "no runs yet" in body.lower()
    )


def test_get_bench_parity_eval_renders_latest_eval(client_with_tmp_runs):
    """Eval JSON + Markdown report present → response body contains the
    overall verdict + each suite name."""
    client, runs_dir, _state_path = client_with_tmp_runs
    eval_json = _build_synthetic_eval_json(verdict_overall="pass")
    (runs_dir / "bench-parity-2026-XX-XX-120000.json").write_text(
        json.dumps(eval_json, indent=2)
    )
    (runs_dir / "qwen-parity-eval-2026-XX-XX-120000.md").write_text(
        "# Qwen Parity Eval — 2026-XX-XX\n\n"
        "**Overall verdict:** pass\n\n"
        "## juice-shop\n"
        "Some details about juice-shop here.\n\n"
        "## dvwa\n"
        "Some details about dvwa here.\n\n"
        "## ctf-box\n"
        "Some details about ctf-box here.\n"
    )
    r = client.get("/bench/parity-eval")
    assert r.status_code == 200
    body = r.text
    assert "pass" in body.lower()
    assert "juice-shop" in body
    assert "dvwa" in body
    assert "ctf-box" in body


def test_get_bench_parity_eval_includes_current_default_profile(
    client_with_tmp_runs,
):
    """State file → response body shows the current default profile."""
    client, _runs_dir, state_path = client_with_tmp_runs
    state_path.write_text(
        "siliconflow-qwen-235b\n/tmp/eval.json\n2026-XX-XXT12:00:00+00:00\n",
        encoding="utf-8",
    )
    r = client.get("/bench/parity-eval")
    assert r.status_code == 200
    assert "siliconflow-qwen-235b" in r.text


def test_get_bench_parity_eval_accepts_json_negotiation(client_with_tmp_runs):
    """GET /bench/parity-eval with Accept: application/json → returns the
    latest eval JSON (not the HTML page)."""
    client, runs_dir, _state_path = client_with_tmp_runs
    eval_json = _build_synthetic_eval_json(verdict_overall="pass")
    (runs_dir / "bench-parity-2026-XX-XX-120000.json").write_text(
        json.dumps(eval_json, indent=2)
    )
    r = client.get(
        "/bench/parity-eval",
        headers={"Accept": "application/json"},
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    # The schema_version round-trips through the JSON surface.
    assert body.get("schema_version") == "1.2"
    assert body.get("verdict_overall") == "pass"


def test_post_bench_parity_eval_reset_default_calls_reset_and_redirects(
    client_with_tmp_runs,
):
    """State file present → POST /reset-default removes it + 303 redirect."""
    client, _runs_dir, state_path = client_with_tmp_runs
    state_path.write_text("siliconflow-qwen-235b\n", encoding="utf-8")
    assert state_path.exists()
    r = client.post(
        "/bench/parity-eval/reset-default",
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "/bench/parity-eval" in r.headers.get("location", "")
    assert not state_path.exists()


def test_post_bench_parity_eval_run_returns_202_with_job_id(
    client_with_tmp_runs, monkeypatch,
):
    """POST /run kicks off BackgroundTasks (mocked) and returns 202 + job_id."""
    client, _runs_dir, _state_path = client_with_tmp_runs

    # Mock run_parity_eval so the BackgroundTasks invocation does NOT spawn
    # a real benchmark. The route imports it lazily; we patch the module.
    called = {"yes": False}

    def _fake_run_parity_eval(**kwargs):
        called["yes"] = True
        return {"schema_version": "1.2", "runs": []}

    monkeypatch.setattr(
        "sentinel.benchmark.parity_eval.run_parity_eval",
        _fake_run_parity_eval,
    )

    r = client.post(
        "/bench/parity-eval/run",
        data={
            "suite": "juice-shop",
            "baseline": "anthropic-baseline",
            "candidate": "siliconflow-qwen-235b",
        },
    )
    assert r.status_code == 202
    body = r.json()
    assert "job_id" in body
    assert body["status"] == "queued"
    # job_id should be a uuid-ish string.
    assert isinstance(body["job_id"], str)
    assert len(body["job_id"]) >= 8


def test_post_bench_parity_eval_run_validates_suite_exists(client_with_tmp_runs):
    """POST /run with a suite that has no bench/<name>/scope.yaml → 400."""
    client, _runs_dir, _state_path = client_with_tmp_runs
    r = client.post(
        "/bench/parity-eval/run",
        data={
            "suite": "not-a-real-suite",
            "baseline": "anthropic-baseline",
            "candidate": "siliconflow-qwen-235b",
        },
    )
    assert r.status_code == 400
    body = r.json()
    assert "not-a-real-suite" in body.get("detail", "").lower() or \
        "scope.yaml" in body.get("detail", "").lower()


def test_nav_includes_benchmarks_pointing_at_bench_parity_eval(
    client_with_tmp_runs,
):
    """The base nav contains a `/bench/parity-eval` link labelled
    'Benchmarks' — UI parity surface for the CLI."""
    client, _runs_dir, _state_path = client_with_tmp_runs
    r = client.get("/")
    assert r.status_code == 200
    body = r.text
    assert "/bench/parity-eval" in body
    assert "Benchmarks" in body


def test_parity_eval_template_includes_cost_delta_when_present(
    client_with_tmp_runs,
):
    """Synthetic eval with percent_reduction=85.0 → rendered body shows '85'."""
    client, runs_dir, _state_path = client_with_tmp_runs
    eval_json = _build_synthetic_eval_json(verdict_overall="pass")
    (runs_dir / "bench-parity-2026-XX-XX-120000.json").write_text(
        json.dumps(eval_json, indent=2)
    )
    r = client.get("/bench/parity-eval")
    assert r.status_code == 200
    body = r.text
    # Cost-delta percent_reduction = 85.0 → "85" must appear in HTML.
    assert "85" in body
