"""Bench cost-cap passthrough (COST-02) regression tests — Plan 03-02.

Contract:
  - `bench/<target>/scope.yaml` can declare a top-level `cost_cap_usd: <N>`
    field. The parity-eval harness reads it via `Scope.raw.get('cost_cap_usd')`
    at scope-load time and auto-appends `--max-cost-usd <N>` to the
    scan-autonomous subprocess argv for BOTH the baseline AND candidate
    profile runs per suite. A/B fairness is preserved: identical cap on
    both sides.
  - When the field is absent, no `--max-cost-usd` flag is appended (back-
    compat with pre-Plan-03-02 bench scopes that nothing was prior).
  - Non-numeric or non-positive values are rejected at scope-load time
    (T-03-02-05) — `ValueError` raised before any scan-autonomous subprocess
    spawn (cleaner failure than a runtime invalid-argv).
  - All three bench scope YAMLs ship with `cost_cap_usd: 5` as a defensive
    default per the 2026-XX-XX cost-finding post-mortem recommendation.

All tests hermetic: no shim, no docker, no network, no Claude SDK; the
subprocess.run call is monkeypatched in every test.
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock

import pytest
import yaml


# ---- Fixtures -------------------------------------------------------------


@pytest.fixture
def tmp_bench_scope_with_cap(tmp_path: Path) -> Path:
    """Write a minimal-but-valid scope.yaml with `cost_cap_usd: 5`."""
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        "client: bench-test\n"
        "engagement_id: bench-test-with-cap\n"
        "authorized_by: test@local\n"
        "valid_from: 2026-01-01\n"
        "valid_until: 2030-12-31\n"
        "cost_cap_usd: 5\n"
        "targets:\n"
        "  domains: [127.0.0.1]\n"
        "  ips: [127.0.0.1/32]\n"
        "rate_limits:\n"
        "  requests_per_second: 5\n"
    )
    return scope_path


@pytest.fixture
def tmp_bench_scope_without_cap(tmp_path: Path) -> Path:
    """Same shape but omits `cost_cap_usd`."""
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        "client: bench-test\n"
        "engagement_id: bench-test-no-cap\n"
        "authorized_by: test@local\n"
        "valid_from: 2026-01-01\n"
        "valid_until: 2030-12-31\n"
        "targets:\n"
        "  domains: [127.0.0.1]\n"
        "  ips: [127.0.0.1/32]\n"
        "rate_limits:\n"
        "  requests_per_second: 5\n"
    )
    return scope_path


def _make_recording_subprocess_run(record: list):
    """Build a subprocess.run replacement that records argv and returns 0."""
    def fake_run(argv, *args, **kwargs):
        record.append(list(argv))
        return CompletedProcess(args=argv, returncode=0, stdout="", stderr="")
    return fake_run


def _patch_subprocess_run(monkeypatch: pytest.MonkeyPatch, record: list) -> None:
    """Patch sentinel.benchmark.parity_eval.subprocess.run to record argv.

    Replaces the .run attribute on the imported subprocess module reference
    inside parity_eval. Safe — the module reference is restored at test
    teardown by monkeypatch.
    """
    from sentinel.benchmark import parity_eval as _pe
    monkeypatch.setattr(_pe.subprocess, "run", _make_recording_subprocess_run(record))


# ---- Test 1: scope with cap -> argv carries --max-cost-usd ---------------


def test_invoke_scan_autonomous_appends_max_cost_when_scope_has_field(
    monkeypatch: pytest.MonkeyPatch,
    tmp_bench_scope_with_cap: Path,
):
    """When _invoke_scan_autonomous receives a cost_cap_usd value, the spawned
    argv includes `--max-cost-usd 5` (or 5.0).
    """
    from sentinel.benchmark import parity_eval

    argv_record: list[list[str]] = []
    _patch_subprocess_run(monkeypatch, argv_record)

    parity_eval._invoke_scan_autonomous(
        target="http://127.0.0.1:3000",
        scope_path=str(tmp_bench_scope_with_cap),
        profile="siliconflow-qwen-235b",
        suite="juice-shop",
        cost_cap_usd=5.0,
    )
    assert len(argv_record) == 1
    argv = argv_record[0]
    assert "--max-cost-usd" in argv
    idx = argv.index("--max-cost-usd")
    # Value follows the flag; accept "5" or "5.0".
    value = argv[idx + 1]
    assert value in ("5", "5.0"), f"unexpected cap value: {value!r}"


# ---- Test 2: scope without cap -> no --max-cost-usd in argv --------------


def test_invoke_scan_autonomous_no_max_cost_flag_when_field_absent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_bench_scope_without_cap: Path,
):
    """When cost_cap_usd is None, argv must NOT contain --max-cost-usd
    (back-compat with pre-Plan-03-02 bench scopes).
    """
    from sentinel.benchmark import parity_eval

    argv_record: list[list[str]] = []
    _patch_subprocess_run(monkeypatch, argv_record)

    parity_eval._invoke_scan_autonomous(
        target="http://127.0.0.1:3000",
        scope_path=str(tmp_bench_scope_without_cap),
        profile="siliconflow-qwen-235b",
        suite="juice-shop",
        cost_cap_usd=None,
    )
    assert len(argv_record) == 1
    argv = argv_record[0]
    assert "--max-cost-usd" not in argv


# ---- Test 3: run_parity_eval threads cap identically to both profiles ----


def test_run_parity_eval_max_cost_uniform_per_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_bench_scope_with_cap: Path,
    tmp_path: Path,
):
    """run_parity_eval with a scope.yaml carrying cost_cap_usd: 5 must pass
    the SAME cap to both baseline AND candidate runs (A/B fairness)."""
    from sentinel.benchmark.parity_eval import run_parity_eval

    invocations: list[dict] = []

    def stub_invoke_fn(*, target, scope_path, profile, suite, cost_cap_usd=None,
                       extra_args=None, **kwargs):
        invocations.append({
            "profile": profile,
            "suite": suite,
            "cost_cap_usd": cost_cap_usd,
        })
        return {
            "profile": profile,
            "model_aliases_used": {},
            "workspace_path": str(tmp_path / f"workspaces/{suite}-{profile}"),
            "subprocess_exit_code": 0,
            "phases": [],
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "qwen_empty_args_observed_delta": 0,
        }

    result = run_parity_eval(
        suite="bench-test-suite",
        baseline_profile="anthropic-baseline",
        candidate_profile="siliconflow-qwen-235b",
        scope_path=str(tmp_bench_scope_with_cap),
        output_dir=tmp_path / "runs",
        invoke_fn=stub_invoke_fn,
    )
    # Both profiles invoked exactly once.
    assert len(invocations) == 2, invocations
    caps = [inv["cost_cap_usd"] for inv in invocations]
    profiles = [inv["profile"] for inv in invocations]
    assert set(profiles) == {"anthropic-baseline", "siliconflow-qwen-235b"}
    # Same cap on both sides — A/B fairness.
    assert caps[0] == caps[1] == 5.0, caps
    # Sanity-check the eval JSON still has both runs.
    assert len(result["runs"]) == 2


def test_run_parity_eval_no_cap_when_scope_omits_field(
    monkeypatch: pytest.MonkeyPatch,
    tmp_bench_scope_without_cap: Path,
    tmp_path: Path,
):
    """When the scope.yaml omits cost_cap_usd, cost_cap_usd=None is passed
    to invoke_fn — no --max-cost-usd flag appended to scan-autonomous argv."""
    from sentinel.benchmark.parity_eval import run_parity_eval

    invocations: list[dict] = []

    def stub_invoke_fn(*, target, scope_path, profile, suite, cost_cap_usd=None,
                       extra_args=None, **kwargs):
        invocations.append({"profile": profile, "cost_cap_usd": cost_cap_usd})
        return {
            "profile": profile,
            "model_aliases_used": {},
            "workspace_path": str(tmp_path / f"workspaces/{suite}-{profile}"),
            "subprocess_exit_code": 0,
            "phases": [],
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "qwen_empty_args_observed_delta": 0,
        }

    run_parity_eval(
        suite="bench-test-suite",
        baseline_profile="anthropic-baseline",
        candidate_profile="siliconflow-qwen-235b",
        scope_path=str(tmp_bench_scope_without_cap),
        output_dir=tmp_path / "runs",
        invoke_fn=stub_invoke_fn,
    )
    assert len(invocations) == 2
    caps = [inv["cost_cap_usd"] for inv in invocations]
    assert caps == [None, None], caps


# ---- Test 4: non-numeric cost_cap_usd is rejected ------------------------


def test_run_parity_eval_rejects_non_numeric_cost_cap_usd(
    tmp_path: Path,
):
    """A non-numeric value in cost_cap_usd raises ValueError (T-03-02-05)
    BEFORE any scan-autonomous subprocess is spawned."""
    from sentinel.benchmark.parity_eval import run_parity_eval

    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        "client: bench-test\n"
        "engagement_id: bench-test-bad-cap\n"
        "authorized_by: test@local\n"
        "valid_from: 2026-01-01\n"
        "valid_until: 2030-12-31\n"
        "cost_cap_usd: not-a-number\n"
        "targets:\n"
        "  domains: [127.0.0.1]\n"
        "  ips: [127.0.0.1/32]\n"
        "rate_limits:\n"
        "  requests_per_second: 5\n"
    )

    invocations: list = []

    def stub_invoke_fn(**kwargs):
        invocations.append(kwargs)
        raise AssertionError(
            "invoke_fn must not be called when cost_cap_usd is invalid"
        )

    with pytest.raises(ValueError) as exc_info:
        run_parity_eval(
            suite="bench-test-suite",
            baseline_profile="anthropic-baseline",
            candidate_profile="siliconflow-qwen-235b",
            scope_path=str(scope_path),
            output_dir=tmp_path / "runs",
            invoke_fn=stub_invoke_fn,
        )
    msg = str(exc_info.value).lower()
    assert "cost_cap_usd" in msg
    assert "numeric" in msg or "number" in msg
    assert len(invocations) == 0


# ---- Test 5: non-positive cost_cap_usd is rejected -----------------------


def test_run_parity_eval_rejects_non_positive_cost_cap_usd(
    tmp_path: Path,
):
    """cost_cap_usd: 0 (or negative) raises ValueError. T-03-02-01 + the
    same defense the CLI layer applies."""
    from sentinel.benchmark.parity_eval import run_parity_eval

    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        "client: bench-test\n"
        "engagement_id: bench-test-zero-cap\n"
        "authorized_by: test@local\n"
        "valid_from: 2026-01-01\n"
        "valid_until: 2030-12-31\n"
        "cost_cap_usd: 0\n"
        "targets:\n"
        "  domains: [127.0.0.1]\n"
        "  ips: [127.0.0.1/32]\n"
        "rate_limits:\n"
        "  requests_per_second: 5\n"
    )

    invocations: list = []

    def stub_invoke_fn(**kwargs):
        invocations.append(kwargs)
        raise AssertionError(
            "invoke_fn must not be called when cost_cap_usd is non-positive"
        )

    with pytest.raises(ValueError) as exc_info:
        run_parity_eval(
            suite="bench-test-suite",
            baseline_profile="anthropic-baseline",
            candidate_profile="siliconflow-qwen-235b",
            scope_path=str(scope_path),
            output_dir=tmp_path / "runs",
            invoke_fn=stub_invoke_fn,
        )
    msg = str(exc_info.value).lower()
    assert "cost_cap_usd" in msg
    assert "> 0" in msg or "positive" in msg
    assert len(invocations) == 0


# ---- Test 6: all three bench scope YAMLs ship with cost_cap_usd: 5 -------


def test_bench_scopes_have_cost_cap_5():
    """All three bench scope YAMLs (juice-shop, dvwa, ctf-box) ship with
    `cost_cap_usd: 5` — the defensive default per the 2026-XX-XX cost
    finding recommendation. Bench runs can no longer surprise the operator
    with $40+ scans (the post-mortem's $35-40 projected cost is now
    bounded at ~$5-7 per side).
    """
    repo_root = Path(__file__).parent.parent
    for suite in ("juice-shop", "dvwa", "ctf-box"):
        scope_path = repo_root / "bench" / suite / "scope.yaml"
        assert scope_path.is_file(), f"missing bench scope: {scope_path}"
        data = yaml.safe_load(scope_path.read_text())
        assert data.get("cost_cap_usd") == 5, (
            f"{suite}: expected cost_cap_usd=5, got {data.get('cost_cap_usd')!r}"
        )


# ---- Bonus: Scope.load doesn't choke on the new field --------------------


def test_scope_load_accepts_cost_cap_usd_field(
    tmp_bench_scope_with_cap: Path,
):
    """Scope.load must NOT fail when cost_cap_usd is in the YAML, AND the
    field must be accessible via scope.raw."""
    from sentinel.core.scope import Scope

    scope = Scope.load(
        str(tmp_bench_scope_with_cap),
        audit_log_path=str(tmp_bench_scope_with_cap.parent / ".audit-test.jsonl"),
    )
    assert scope.raw.get("cost_cap_usd") == 5
