"""Cost-cap (COST-01) regression tests — Plan 03-02.

Strict vs soft contract:
  - Default (no --max-cost-usd flag): `PipelineConfig.cost_cap_strict=False`.
    The existing line-1135 soft-budget check fires `phase_skipped_budget_exhausted`
    and falls through (no NEW phase starts but the check itself doesn't abort).
    Behavior is unchanged from prior Plan 03-01 wave.
  - Strict (operator passes --max-cost-usd N): `PipelineConfig.cost_cap_strict=True`
    AND `max_budget_per_scan_usd=N`. The between-phase guard now writes a
    `scan_aborted_cost_cap` audit event AND raises `CostCapAbort` so the
    outer `run()` terminates gracefully (no NEW phase starts after cap exceeded).

Contract is BEST-EFFORT: the check fires between phases, not mid-LLM-call.
A single very-expensive phase can overshoot by its own delta — documented inline
in the --max-cost-usd help text and the audit-event payload (`contract_note` field).

All tests hermetic: no shim, no docker, no network, no Claude SDK.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentinel.agent.pentest.pipeline import (
    CostCapAbort,
    CostCapTripped,
    PentestPipeline,
    PipelineConfig,
)


# ---- Helpers ------------------------------------------------------------


def _minimal_scope_yaml(tmp_path: Path, *, engagement_id: str = "test-cost-cap-eng") -> Path:
    """Write a minimal-but-valid scope YAML to tmp_path so Scope.load works.

    Not used directly by Tests 1-5 (those construct pipelines without loading
    a scope from disk) but kept here for Test 6 which needs the rejection to
    fire BEFORE scope load.
    """
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        "client: bench-test\n"
        f"engagement_id: {engagement_id}\n"
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


def _build_pipeline(*, cost_cap_strict: bool = False,
                     max_budget_per_scan_usd: float = 5.0) -> PentestPipeline:
    """Build a PentestPipeline with a minimal config.

    Constructs the pipeline object directly so we can drive the cost-cap helper
    method without actually running async phases. `target` and `scope_path` are
    set to placeholders since these tests never invoke `run()`.
    """
    cfg = PipelineConfig(
        target="http://example.test",
        scope_path="/nonexistent.yaml",
        max_budget_per_scan_usd=max_budget_per_scan_usd,
        cost_cap_strict=cost_cap_strict,
    )
    return PentestPipeline(cfg)


# ---- Test 1: default config has cost_cap_strict=False --------------------


def test_pipeline_config_default_cost_cap_strict_false():
    """`PipelineConfig()` default: cost_cap_strict=False, max_budget_per_scan_usd=100.0.

    Backward compat: any caller that constructs PipelineConfig without passing
    cost_cap_strict gets the existing soft-default behavior.
    """
    cfg = PipelineConfig(target="http://example.test", scope_path="/dev/null")
    assert cfg.cost_cap_strict is False
    assert cfg.max_budget_per_scan_usd == 100.0


# ---- Test 2: explicit max_cost_usd sets strict + cap ---------------------


def test_pipeline_config_explicit_max_cost_sets_strict():
    """When the CLI dispatch sets both fields, they persist on the config."""
    cfg = PipelineConfig(
        target="http://example.test",
        scope_path="/dev/null",
        max_budget_per_scan_usd=5.0,
        cost_cap_strict=True,
    )
    assert cfg.cost_cap_strict is True
    assert cfg.max_budget_per_scan_usd == 5.0


# ---- Test 3: soft-path no abort ------------------------------------------


def test_between_phase_check_does_not_abort_when_not_strict():
    """Soft default path — overshooting `max_budget_per_scan_usd` returns None.

    This is the existing line-1135 behavior preserved 1:1: the helper returns
    None even when over-cap, the caller emits `phase_skipped_budget_exhausted`,
    no abort.
    """
    pipeline = _build_pipeline(cost_cap_strict=False, max_budget_per_scan_usd=5.0)
    pipeline._scan_spend_usd = 6.0  # over the soft cap

    tripped = pipeline._check_cost_cap(
        phase_name="vuln:auth",
        phases_completed=3,
        phases_total=12,
    )
    # Soft path returns None — no abort — caller emits phase_skipped_budget_exhausted.
    assert tripped is None


# ---- Test 4: strict-path abort signal ------------------------------------


def test_between_phase_check_aborts_when_strict_and_cap_exceeded():
    """Strict path — overshooting returns a CostCapTripped sentinel with payload."""
    pipeline = _build_pipeline(cost_cap_strict=True, max_budget_per_scan_usd=5.0)
    pipeline._scan_spend_usd = 6.0  # over the strict cap

    tripped = pipeline._check_cost_cap(
        phase_name="vuln:auth",
        phases_completed=3,
        phases_total=12,
    )
    assert tripped is not None
    assert isinstance(tripped, CostCapTripped)
    assert tripped.scan_spend_usd == 6.0
    assert tripped.cap_usd == 5.0
    assert tripped.phase_at_trip == "vuln:auth"
    assert tripped.phases_completed == 3
    assert tripped.phases_total == 12


def test_between_phase_check_no_trip_when_strict_and_below_cap():
    """Strict path — below cap returns None (no false abort)."""
    pipeline = _build_pipeline(cost_cap_strict=True, max_budget_per_scan_usd=5.0)
    pipeline._scan_spend_usd = 4.99  # under the cap

    tripped = pipeline._check_cost_cap(
        phase_name="recon",
        phases_completed=1,
        phases_total=12,
    )
    assert tripped is None


# ---- Test 5: audit-log + event-log emission for cost-cap abort -----------


def test_cost_cap_abort_writes_audit_event(tmp_path: Path):
    """When the strict-path trip emits the abort, the audit-log entry has the
    documented payload shape (engagement_id, scan_spend_usd, cap_usd,
    phase_at_trip, phases_completed, phases_total) AND the event_log emits
    `scan_aborted_cost_cap` with the same fields.

    Drives `_emit_cost_cap_abort` directly with mock audit + event_log.
    """
    from sentinel.agent.pentest.pipeline import _emit_cost_cap_abort

    audit = MagicMock()
    event_log = MagicMock()
    tripped = CostCapTripped(
        scan_spend_usd=6.42,
        cap_usd=5.0,
        phase_at_trip="vuln:auth",
        phases_completed=3,
        phases_total=12,
    )
    _emit_cost_cap_abort(
        audit=audit,
        event_log=event_log,
        tripped=tripped,
        engagement_id="bench-test-eng",
        mode_value="bbp",
    )
    # AuditLog.write was called once with event="scan_aborted_cost_cap".
    assert audit.write.call_count == 1
    call_args = audit.write.call_args
    assert call_args[0][0] == "scan_aborted_cost_cap"
    payload = call_args[0][1]
    assert payload["engagement_id"] == "bench-test-eng"
    assert payload["scan_spend_usd"] == 6.42
    assert payload["cap_usd"] == 5.0
    assert payload["phase_at_trip"] == "vuln:auth"
    assert payload["phases_completed"] == 3
    assert payload["phases_total"] == 12
    # contract_note is the operator-facing reminder of the best-effort nature.
    assert "best-effort" in payload["contract_note"]
    # AuditLog mode kwarg is the engagement's mode value.
    assert call_args[1]["mode"] == "bbp"

    # event_log.emit was called with the same fields (flat kwargs).
    assert event_log.emit.call_count == 1
    elog_args = event_log.emit.call_args
    assert elog_args[0][0] == "scan_aborted_cost_cap"
    assert elog_args[1]["scan_spend_usd"] == 6.42
    assert elog_args[1]["cap_usd"] == 5.0
    assert elog_args[1]["phase_at_trip"] == "vuln:auth"


# ---- Test 6: CLI rejects non-positive --max-cost-usd ---------------------


def test_cli_rejects_non_positive_max_cost_usd(tmp_path: Path):
    """`sentinel scan-autonomous ... --max-cost-usd -1` exits 2 with a clear msg.

    Validation happens at the CLI dispatch level BEFORE the scope file is
    loaded — the nonexistent scope path is never opened.
    """
    # Use the module entrypoint so we don't depend on the sentinel wrapper
    # being installed in this test environment.
    proc = subprocess.run(
        [
            sys.executable, "-m", "sentinel.cli", "scan-autonomous",
            "http://example.test",
            "--scope", str(tmp_path / "nonexistent.yaml"),
            "--max-cost-usd", "-1",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 2, (
        f"expected exit code 2; got {proc.returncode}; stderr={proc.stderr[:1000]}"
    )
    combined = (proc.stderr + proc.stdout).lower()
    assert "must be > 0" in combined or "must be positive" in combined, (
        f"expected rejection message; stderr={proc.stderr[:1000]}; "
        f"stdout={proc.stdout[:500]}"
    )


def test_cli_rejects_zero_max_cost_usd(tmp_path: Path):
    """Zero is also rejected (boundary)."""
    proc = subprocess.run(
        [
            sys.executable, "-m", "sentinel.cli", "scan-autonomous",
            "http://example.test",
            "--scope", str(tmp_path / "nonexistent.yaml"),
            "--max-cost-usd", "0",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 2, (
        f"expected exit code 2; got {proc.returncode}; stderr={proc.stderr[:1000]}"
    )


# ---- Test 7: event_styles has the new entry ------------------------------


def test_event_styles_has_scan_aborted_cost_cap_entry():
    """`scan_aborted_cost_cap` is registered with chip=critical, group=pipeline.

    Without this, the dashboard renders the abort as a generic event chip,
    which violates the UI-parity contract.
    """
    from sentinel.web.event_styles import EVENT_STYLES

    assert "scan_aborted_cost_cap" in EVENT_STYLES
    entry = EVENT_STYLES["scan_aborted_cost_cap"]
    assert entry["chip"] == "critical"
    assert entry["group"] == "pipeline"
    # icon + label are also required for proper rendering.
    assert entry.get("icon"), "missing icon"
    assert entry.get("label"), "missing label"


# ---- Bonus: CostCapAbort is a RuntimeError subclass ----------------------


def test_cost_cap_abort_is_runtime_error():
    """`CostCapAbort` is a RuntimeError so callers can catch it consistently
    with PreflightRefused (also a RuntimeError subclass)."""
    assert issubclass(CostCapAbort, RuntimeError)
    err = CostCapAbort("test")
    assert isinstance(err, RuntimeError)
