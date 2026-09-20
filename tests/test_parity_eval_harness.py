"""BENCH-05 regression tests — parity_eval harness + pricing module.

Hermetic tests for the SiliconFlow Qwen 235B parity-benchmark harness.
NO live SiliconFlow calls, NO docker, NO Juice Shop instance required.
The `_invoke_scan_autonomous` step is monkeypatched via an `invoke_fn`
injection point so the harness orchestration logic is tested in
isolation from the real `subprocess.run` -> `sentinel scan-autonomous`
pipeline.

Test contract (7 tests):

  Test 1: `EVAL_JSON_SCHEMA_VERSION` is exported and equals '1.0'.
  Test 2: `compute_call_cost_usd('claude-sonnet-4-6', ...)` returns the
          expected dollar value derived from PROFILE_PRICING (floats
          with rate-card updates).
  Test 3: Same shape for `Qwen/Qwen3-235B-A22B-Instruct-2507` — confirms
          the SiliconFlow tier is in the pricing table.
  Test 4: Unknown model returns 0.0 and emits a warning log.
  Test 5: `run_parity_eval` writes versioned JSON to runs/bench-parity-*.json
          with the right schema_version, runs[] array length, and target URL.
  Test 6: `run_parity_eval` writes bench_parity_eval_started +
          bench_parity_eval_completed audit events, hash chain verifies.
  Test 7: Unknown candidate profile name → ValueError propagated from
          apply_model_profile; eval JSON is NOT written.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

import pytest

from sentinel.benchmark.parity_eval import (
    EVAL_JSON_SCHEMA_VERSION,
    run_parity_eval,
)
from sentinel.benchmark.pricing import (
    PROFILE_PRICING,
    compute_call_cost_usd,
)
from sentinel.core.scope import AuditLog


# ---- Helpers + fixtures -------------------------------------------------


_REPO_ROOT = Path(__file__).resolve().parent.parent
_BENCH_SCOPE = _REPO_ROOT / "bench" / "juice-shop" / "scope.yaml"


@pytest.fixture
def tmp_scope(tmp_path):
    """Copy bench/juice-shop/scope.yaml into tmp + rewrite engagement_id.

    Rewriting the engagement_id (bench-juice-shop → bench-test) makes the
    audit-log path land in tmp_path (`.audit-bench-test.jsonl`) so test
    runs don't pollute the real bench scope's audit chain. Domains + IPs
    stay loopback so authorize_url('http://127.0.0.1:3000') still passes.
    """
    dest = tmp_path / "scope.yaml"
    text = _BENCH_SCOPE.read_text()
    text = text.replace(
        "engagement_id: bench-juice-shop", "engagement_id: bench-test"
    ).replace(
        "client: bench-juice-shop", "client: bench-test"
    )
    dest.write_text(text)
    return dest


def _mock_invoke_returning(token_counts: dict[str, tuple[int, int]],
                            qwen_empty_args_delta: int = 0):
    """Return a fake invoke_fn that yields a canned per-profile dict.

    `token_counts` maps profile name → (input_tokens, output_tokens).
    The harness's contract is: invoke_fn(target=..., scope_path=...,
    profile=..., suite=...) → dict matching the runs[i] schema (profile,
    model_aliases_used, workspace_path, phases, total_input_tokens,
    total_output_tokens, qwen_empty_args_observed_delta).
    """
    def _invoke(*, target, scope_path, profile, suite):
        inp, out = token_counts.get(profile, (0, 0))
        return {
            "profile": profile,
            "model_aliases_used": {
                "claude-sonnet-4-6": (
                    "Qwen/Qwen3-235B-A22B-Instruct-2507"
                    if profile == "siliconflow-qwen-235b"
                    else "claude-sonnet-4-6"
                ),
                "claude-opus-4-7": (
                    "deepseek-ai/DeepSeek-R1"
                    if profile == "siliconflow-qwen-235b"
                    else "claude-opus-4-7"
                ),
                "claude-haiku-4-5": (
                    "Qwen/Qwen3-Coder-30B-A3B-Instruct"
                    if profile == "siliconflow-qwen-235b"
                    else "claude-haiku-4-5"
                ),
            },
            "workspace_path": f"workspaces/bench-{suite}-{profile}-fake-ts",
            "phases": [
                {
                    "name": "recon",
                    "started_at": "2026-XX-XXT00:00:00+00:00",
                    "completed_at": "2026-XX-XXT00:01:00+00:00",
                    "exit_code": 0,
                    "llm_calls": [
                        {"model": "claude-sonnet-4-6", "input_tokens": inp,
                         "output_tokens": out, "wall_clock_ms": 1234},
                    ],
                    "tool_calls": [
                        {"name": "browser_get",
                         "input_keys": ["url", "wait_seconds"], "ok": True},
                    ],
                    "emitted_finding_fingerprints": [],
                },
            ],
            "total_input_tokens": inp,
            "total_output_tokens": out,
            "qwen_empty_args_observed_delta": qwen_empty_args_delta,
        }
    return _invoke


# ---- Tests --------------------------------------------------------------


def test_eval_json_schema_version_constant():
    """The schema version is the contract Plans 02-02/02-03/02-04 read against.
    Plan 02-01 shipped v1.0; Plan 02-02 bumped to v1.1 (adds per-phase
    precision/recall/f1/verdict + per-run suite_name); Plan 02-03 bumps
    to v1.2 (adds runs[].cost_summary + suites[].cost_delta + verdict_overall
    + markdown_report_path). A breaking change without a version bump
    silently corrupts downstream readers.
    """
    assert EVAL_JSON_SCHEMA_VERSION == "1.2"
    assert isinstance(EVAL_JSON_SCHEMA_VERSION, str)


def test_compute_call_cost_usd_sonnet():
    """Sonnet pricing must round-trip: 1M input tokens + 500K output tokens
    × the documented per-million rate equals the function's return value.
    The expected value is derived from PROFILE_PRICING itself so the test
    floats with rate-card updates — we're asserting the function's math,
    not the rate-card numbers.
    """
    rates = PROFILE_PRICING["claude-sonnet-4-6"]
    expected = (
        (1_000_000 / 1_000_000) * rates["input_per_million_usd"]
        + (500_000 / 1_000_000) * rates["output_per_million_usd"]
    )
    actual = compute_call_cost_usd(
        "claude-sonnet-4-6", input_tokens=1_000_000, output_tokens=500_000
    )
    assert actual == pytest.approx(expected, rel=1e-9)
    # Sanity: Sonnet is not free.
    assert actual > 0


def test_compute_call_cost_usd_qwen_235b():
    """SiliconFlow Qwen3-235B-A22B-Instruct must be in PROFILE_PRICING.
    Plan 02-03's cost-delta math reads from this entry — if it's missing,
    cost-delta silently returns 0% reduction, masking the entire benchmark
    value proposition.
    """
    key = "Qwen/Qwen3-235B-A22B-Instruct-2507"
    assert key in PROFILE_PRICING, f"missing key {key} in PROFILE_PRICING"
    rates = PROFILE_PRICING[key]
    expected = (
        (2_000_000 / 1_000_000) * rates["input_per_million_usd"]
        + (1_000_000 / 1_000_000) * rates["output_per_million_usd"]
    )
    actual = compute_call_cost_usd(key, 2_000_000, 1_000_000)
    assert actual == pytest.approx(expected, rel=1e-9)
    assert actual > 0


def test_compute_call_cost_usd_unknown_model_returns_zero_and_warns(caplog):
    """Unknown model alias must return 0.0 (defensive default — don't
    fabricate dollar values for unknown models) and emit a warning log
    so the operator sees that their accounting is incomplete.
    """
    with caplog.at_level(logging.WARNING, logger="sentinel.benchmark.pricing"):
        result = compute_call_cost_usd("not-a-real-model", 1_000_000, 0)
    assert result == 0.0
    assert any("not-a-real-model" in rec.message for rec in caplog.records), (
        f"warning log should mention the model name; got: "
        f"{[r.message for r in caplog.records]}"
    )


def test_run_parity_eval_writes_versioned_json_to_runs_dir(
    tmp_scope, tmp_path, monkeypatch
):
    """End-to-end harness test (with the inner subprocess step mocked):
    given a valid scope + mocked invoke_fn, the harness writes a JSON
    file to <output_dir>/bench-parity-<date>.json containing
    schema_version, target, and a 2-element runs[] array with the right
    profile names.
    """
    output_dir = tmp_path / "runs"
    invoke_fn = _mock_invoke_returning({
        "anthropic-baseline": (10_000, 5_000),
        "siliconflow-qwen-235b": (10_000, 5_000),
    })

    result = run_parity_eval(
        suite="juice-shop",
        baseline_profile="anthropic-baseline",
        candidate_profile="siliconflow-qwen-235b",
        scope_path=str(tmp_scope),
        output_dir=output_dir,
        invoke_fn=invoke_fn,
    )

    # Schema version pinned to 1.2 (Plan 02-03 bump)
    assert result["schema_version"] == "1.2"
    assert result["suite"] == "juice-shop"
    # Target URL constructed from scope.yaml's first concrete domain (127.0.0.1)
    assert result["target"].startswith("http://127.0.0.1"), result["target"]
    # 2-element runs[] in baseline,candidate order
    assert len(result["runs"]) == 2
    assert result["runs"][0]["profile"] == "anthropic-baseline"
    assert result["runs"][1]["profile"] == "siliconflow-qwen-235b"
    # JSON written to disk
    json_files = list(output_dir.glob("bench-parity-*.json"))
    assert len(json_files) == 1, f"expected exactly 1 eval JSON, got {json_files}"
    on_disk = json.loads(json_files[0].read_text())
    assert on_disk["schema_version"] == "1.2"
    assert on_disk == result, "in-memory result and on-disk JSON must match"
    # Per-run shape — token totals propagated, finding fingerprints array exists.
    assert on_disk["runs"][0]["total_input_tokens"] == 10_000
    assert on_disk["runs"][0]["total_output_tokens"] == 5_000
    assert isinstance(
        on_disk["runs"][0]["phases"][0]["emitted_finding_fingerprints"], list
    )


def test_run_parity_eval_writes_audit_events(tmp_scope, tmp_path):
    """The harness's scope-gating + audit-event contract:
    bench_parity_eval_started fires BEFORE the per-profile invocations,
    bench_parity_eval_completed fires AFTER (with the eval JSON path).
    The full chain (scope_loaded + authorize + started + completed)
    must verify cleanly via AuditLog.verify — that's the legal artifact
    that proves what was actually run.
    """
    output_dir = tmp_path / "runs"
    invoke_fn = _mock_invoke_returning({
        "anthropic-baseline": (1, 1),
        "siliconflow-qwen-235b": (1, 1),
    })

    run_parity_eval(
        suite="juice-shop",
        baseline_profile="anthropic-baseline",
        candidate_profile="siliconflow-qwen-235b",
        scope_path=str(tmp_scope),
        output_dir=output_dir,
        invoke_fn=invoke_fn,
    )

    # Audit log lives next to the tmp_scope file as .audit-<engagement_id>.jsonl
    audit_path = tmp_scope.parent / ".audit-bench-test.jsonl"
    assert audit_path.exists(), f"audit log not found at {audit_path}"

    entries = [json.loads(line) for line in audit_path.read_text().splitlines()
               if line.strip()]
    events = [e["event"] for e in entries]
    assert "bench_parity_eval_started" in events, events
    assert "bench_parity_eval_completed" in events, events

    # The started event must include both profile names + the suite.
    started = next(e for e in entries if e["event"] == "bench_parity_eval_started")
    assert started["payload"]["suite"] == "juice-shop"
    assert started["payload"]["baseline_profile"] == "anthropic-baseline"
    assert started["payload"]["candidate_profile"] == "siliconflow-qwen-235b"

    # The completed event must include the eval JSON path.
    completed = next(e for e in entries
                      if e["event"] == "bench_parity_eval_completed")
    assert "eval_json_path" in completed["payload"]
    assert completed["payload"]["eval_json_path"].endswith(".json")

    # Hash chain verifies — no tampering.
    ok, err = AuditLog.verify(audit_path)
    assert ok, f"audit chain broken: {err}"


def test_run_parity_eval_refuses_unknown_profile(tmp_scope, tmp_path):
    """Unknown candidate profile → ValueError propagated from
    apply_model_profile. The eval JSON must NOT be written — a partial
    JSON file would corrupt downstream consumers that assume the file's
    presence means "the run completed".
    """
    output_dir = tmp_path / "runs"
    invoke_fn = _mock_invoke_returning({
        "anthropic-baseline": (1, 1),
    })

    with pytest.raises(ValueError) as excinfo:
        run_parity_eval(
            suite="juice-shop",
            baseline_profile="anthropic-baseline",
            candidate_profile="not-a-real-profile",
            scope_path=str(tmp_scope),
            output_dir=output_dir,
            invoke_fn=invoke_fn,
        )
    assert "not-a-real-profile" in str(excinfo.value)
    # No eval JSON should be on disk.
    assert not list(output_dir.glob("bench-parity-*.json")), (
        "harness must NOT write JSON on profile-resolution failure"
    )
