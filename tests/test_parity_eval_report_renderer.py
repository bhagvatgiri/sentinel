"""BENCH-08 regression tests — Markdown parity-eval report renderer.

Hermetic tests for `sentinel.benchmark.report_renderer`:

  - `render_parity_report(eval_json)` -> str -- Markdown body.
  - `write_parity_report(eval_json, output_dir)` -> Path -- writes file +
    returns path.
  - `REPORT_TEMPLATE_VERSION = '1.0'` constant.

The renderer is the deliverable the operator reads when deciding whether to flip
the default profile to Qwen 235B. Plan 02-04's `/bench/parity-eval`
FastAPI route serves the EXACT file this module produces (no
re-rendering at the dashboard layer).

NO live SiliconFlow, NO docker. The harness integration test (Test 10)
uses an injected `invoke_fn`.

Test contract (10 tests):

  Test 1: render output includes the report header AND a top-line overall
          verdict marker.
  Test 2: render output has a `## <suite>` section for every suite in eval_json.
  Test 3: each suite section has a per-phase comparison Markdown table.
  Test 4: each suite section has a per-finding diff (only_baseline / only_candidate /
          both / neither sub-lists).
  Test 5: each suite section has a cost-summary table with baseline_usd /
          candidate_usd / delta_usd / percent_reduction / cost_verdict columns.
  Test 6: bottom of report has a roll-up table — per-phase weighted F1 across
          all suites for each profile.
  Test 7: bottom of report documents the F1 + cost verdict thresholds so the
          report is self-explanatory.
  Test 8: write_parity_report writes a file under runs/qwen-parity-eval-*.md.
  Test 9: missing verdict_overall (e.g. an older v1.1 JSON) renders without
          raising; falls back to 'unknown' verdict + warning section.
  Test 10: end-to-end harness invocation writes BOTH the JSON AND the
           Markdown report; Markdown contains suite headers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.benchmark.parity_eval import (
    EVAL_JSON_SCHEMA_VERSION,
    run_parity_eval,
)
from sentinel.benchmark.report_renderer import (
    REPORT_TEMPLATE_VERSION,
    render_parity_report,
    write_parity_report,
)


_REPO_ROOT = Path(__file__).resolve().parent.parent
_BENCH_SCOPE = _REPO_ROOT / "bench" / "juice-shop" / "scope.yaml"


# ---- Fixtures -----------------------------------------------------------


def _mk_phase(name: str,
              precision: float, recall: float, f1: float,
              verdict: str,
              matched_ids: list[str] | None = None,
              unmatched_ids: list[str] | None = None,
              calls: list[dict] | None = None) -> dict:
    """Build a minimal v1.2-shape phase dict for renderer testing."""
    return {
        "name": name,
        "started_at": "2026-XX-XXT00:00:00Z",
        "completed_at": "2026-XX-XXT00:00:01Z",
        "exit_code": 0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": len(matched_ids or []),
        "fp": 0,
        "fn": len(unmatched_ids or []),
        "matched_canonical_ids": matched_ids or [],
        "unmatched_canonical_ids": unmatched_ids or [],
        "verdict": verdict,
        "llm_calls": calls or [],
        "tool_calls": [],
        "emitted_finding_fingerprints": [],
    }


def _mk_run(suite_name: str, profile: str, phases: list[dict],
            cost_summary: dict | None = None) -> dict:
    return {
        "suite_name": suite_name,
        "profile": profile,
        "target_url": "http://127.0.0.1:3000",
        "scope_engagement_id": f"bench-{suite_name}",
        "workspace_path": f"workspaces/bench-{suite_name}-{profile}-20260514",
        "model_aliases_used": {},
        "phases": phases,
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "qwen_empty_args_observed_delta": 0,
        "cost_summary": cost_summary or {
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_cost_usd": 0.0,
            "per_phase": {},
            "per_model": {},
        },
    }


def _mk_suite_cost_delta(baseline_usd: float, candidate_usd: float,
                          verdict: str) -> dict:
    delta = baseline_usd - candidate_usd
    pct = (delta / baseline_usd) * 100.0 if baseline_usd > 0 else 0.0
    return {
        "baseline_total_usd": baseline_usd,
        "candidate_total_usd": candidate_usd,
        "absolute_delta_usd": delta,
        "percent_reduction": pct,
        "per_phase_delta": {},
        "verdict": verdict,
    }


@pytest.fixture
def synthetic_eval_json():
    """v1.2-shape eval JSON with 3 suites x 2 profiles x 2 phases.

    juice-shop: all phases pass, cost-delta pass  -> suite verdict pass.
    dvwa:       1 partial phase, cost-delta pass  -> suite verdict partial.
    ctf-box:    all phases pass, cost-delta partial -> suite verdict partial.

    Overall verdict: partial (mixed pass/partial).
    """
    runs = [
        # juice-shop / baseline
        _mk_run("juice-shop", "anthropic-baseline", [
            _mk_phase("recon", 1.0, 1.0, 1.0, "pass",
                     matched_ids=["js-recon-01"]),
            _mk_phase("vuln:xss", 1.0, 1.0, 1.0, "pass",
                     matched_ids=["js-xss-01"]),
        ]),
        # juice-shop / candidate
        _mk_run("juice-shop", "siliconflow-qwen-235b", [
            _mk_phase("recon", 1.0, 1.0, 1.0, "pass",
                     matched_ids=["js-recon-01"]),
            _mk_phase("vuln:xss", 1.0, 1.0, 1.0, "pass",
                     matched_ids=["js-xss-01"]),
        ]),
        # dvwa / baseline
        _mk_run("dvwa", "anthropic-baseline", [
            _mk_phase("vuln:injection", 1.0, 1.0, 1.0, "pass",
                     matched_ids=["dvwa-sqli-01"]),
            _mk_phase("vuln:xss", 1.0, 1.0, 1.0, "pass",
                     matched_ids=["dvwa-xss-reflected-01"]),
        ]),
        # dvwa / candidate (one partial)
        _mk_run("dvwa", "siliconflow-qwen-235b", [
            _mk_phase("vuln:injection", 0.7, 0.6, 0.65, "partial",
                     matched_ids=["dvwa-sqli-01"],
                     unmatched_ids=["dvwa-sqli-blind-01"]),
            _mk_phase("vuln:xss", 1.0, 1.0, 1.0, "pass",
                     matched_ids=["dvwa-xss-reflected-01"]),
        ]),
        # ctf-box / baseline
        _mk_run("ctf-box", "anthropic-baseline", [
            _mk_phase("exploit:injection", 1.0, 1.0, 1.0, "pass",
                     matched_ids=["ctf-s2045-01"]),
            _mk_phase("correlation", 1.0, 1.0, 1.0, "pass",
                     matched_ids=["ctf-correlation-01"]),
        ]),
        # ctf-box / candidate
        _mk_run("ctf-box", "siliconflow-qwen-235b", [
            _mk_phase("exploit:injection", 1.0, 1.0, 1.0, "pass",
                     matched_ids=["ctf-s2045-01"]),
            _mk_phase("correlation", 1.0, 1.0, 1.0, "pass",
                     matched_ids=["ctf-correlation-01"]),
        ]),
    ]

    suites_block = {
        "juice-shop": {
            "cost_delta": _mk_suite_cost_delta(10.0, 2.0, "pass"),
            "verdict": "pass",
            "baseline_run_index": 0,
            "candidate_run_index": 1,
        },
        "dvwa": {
            "cost_delta": _mk_suite_cost_delta(10.0, 2.0, "pass"),
            "verdict": "partial",  # partial because one phase is partial
            "baseline_run_index": 2,
            "candidate_run_index": 3,
        },
        "ctf-box": {
            "cost_delta": _mk_suite_cost_delta(10.0, 5.0, "partial"),
            "verdict": "partial",  # partial because cost-delta only partial
            "baseline_run_index": 4,
            "candidate_run_index": 5,
        },
    }

    return {
        "schema_version": "1.2",
        "suite": "juice-shop,dvwa,ctf-box",
        "target": "http://127.0.0.1:3000",
        "scope_engagement_id": "bench-juice-shop",
        "baseline_profile": "anthropic-baseline",
        "candidate_profile": "siliconflow-qwen-235b",
        "started_at": "2026-XX-XXT00:00:00Z",
        "completed_at": "2026-XX-XXT00:05:00Z",
        "runs": runs,
        "suites": suites_block,
        "verdict_overall": "partial",
    }


# ---- Test 1: header + overall verdict ----------------------------------


def test_render_report_includes_header_and_overall_verdict(synthetic_eval_json):
    """The rendered Markdown must have:
      - A top-level `# ` H1 header identifying it as the parity eval.
      - A bolded 'Overall verdict' marker line.
    """
    md = render_parity_report(synthetic_eval_json)

    # H1 header.
    assert md.startswith("# "), f"expected H1, got: {md[:80]!r}"
    # Title mentions the parity eval purpose.
    assert "parity" in md.lower() or "qwen" in md.lower(), (
        f"title should mention parity / qwen; first line: {md.splitlines()[0]!r}"
    )
    # Overall verdict line.
    assert "overall verdict" in md.lower()
    assert "partial" in md.lower()
    # Template version visible.
    assert REPORT_TEMPLATE_VERSION in md


# ---- Test 2: per-suite headers -----------------------------------------


def test_render_per_suite_section_present_for_each_suite(synthetic_eval_json):
    """Each suite gets a `## <suite>` H2 section. All 3 must appear."""
    md = render_parity_report(synthetic_eval_json)
    for suite_name in ("juice-shop", "dvwa", "ctf-box"):
        # H2 marker for the suite name.
        assert f"## {suite_name}" in md or f"## `{suite_name}`" in md, (
            f"missing H2 section for {suite_name!r}; "
            f"H2 headers found: "
            f"{[ln for ln in md.splitlines() if ln.startswith('## ')]}"
        )


# ---- Test 3: per-phase comparison table --------------------------------


def test_render_per_phase_comparison_table(synthetic_eval_json):
    """Each suite section has a Markdown table comparing baseline + candidate
    F1 + verdict per phase.

    A canonical Markdown table has:
      | header1 | header2 | ... |
      | --- | --- | ... |
      | row data | row data | ... |
    """
    md = render_parity_report(synthetic_eval_json)
    md_lower = md.lower()

    # Required column headers appear at least once each.
    for col in ("phase", "baseline_f1", "candidate_f1",
                 "baseline_verdict", "candidate_verdict"):
        assert col in md_lower, (
            f"per-phase table missing column {col!r}; "
            f"renderer output excerpt: {md[:500]!r}"
        )

    # At least one phase name appears (verifies the rows render).
    for phase_name in ("recon", "vuln:xss", "vuln:injection",
                        "exploit:injection", "correlation"):
        assert phase_name in md, f"missing phase row for {phase_name!r}"


# ---- Test 4: per-finding diff ------------------------------------------


def test_render_per_finding_diff_section(synthetic_eval_json):
    """Each suite section has a per-finding diff listing canonical-id buckets:
      - both (matched by baseline AND candidate)
      - only_baseline
      - only_candidate
      - neither
    """
    md = render_parity_report(synthetic_eval_json)
    md_lower = md.lower()

    # Diff section header / subsection marker.
    assert "per-finding diff" in md_lower or "finding diff" in md_lower

    # All four buckets named.
    for bucket in ("only_baseline", "only_candidate", "both", "neither"):
        assert bucket in md_lower, (
            f"diff section missing bucket {bucket!r}; "
            f"output excerpt: {md[md.lower().find('finding diff'):][:500]!r}"
        )

    # Concrete canonical ids from synthetic data appear in the diff.
    # dvwa has dvwa-sqli-blind-01 in only_baseline (candidate didn't match it).
    assert "dvwa-sqli-blind-01" in md, (
        "expected unmatched canonical id 'dvwa-sqli-blind-01' to appear in "
        "the dvwa per-finding diff (it's in the baseline matched set but "
        "candidate's unmatched_canonical_ids)."
    )


# ---- Test 5: cost-summary table ----------------------------------------


def test_render_cost_summary_table(synthetic_eval_json):
    """Each suite section has a cost-summary table including:
      baseline_usd, candidate_usd, delta_usd, percent_reduction, verdict.
    """
    md = render_parity_report(synthetic_eval_json)
    md_lower = md.lower()

    # Cost columns.
    for col in ("baseline_usd", "candidate_usd", "delta_usd",
                 "percent_reduction"):
        assert col in md_lower, (
            f"cost table missing column {col!r}; "
            f"output: {md[md.lower().find('cost'):][:500]!r}"
        )

    # Dollar values from synthetic data (juice-shop: $10 baseline, $2 candidate).
    # Renderer formats as e.g. '$10.00' or '10.0' - accept either.
    assert "10.0" in md or "10.00" in md, "expected baseline cost $10 to render"
    assert "2.0" in md or "2.00" in md, "expected candidate cost $2 to render"

    # Cost verdicts present.
    for v in ("pass", "partial"):
        assert v in md_lower


# ---- Test 6: roll-up table at bottom ----------------------------------


def test_render_summary_table_bottom(synthetic_eval_json):
    """Bottom of the report has a per-phase roll-up table showing weighted F1
    across all suites for each profile.
    """
    md = render_parity_report(synthetic_eval_json)
    md_lower = md.lower()

    # Roll-up / summary marker.
    assert ("summary" in md_lower or "roll" in md_lower
            or "weighted f1" in md_lower)

    # The two profile names appear in headers / rows.
    assert "anthropic-baseline" in md
    assert "siliconflow-qwen-235b" in md


# ---- Test 7: thresholds documented ------------------------------------


def test_render_thresholds_documented(synthetic_eval_json):
    """Bottom of the report includes the F1 + cost thresholds so the
    verdict logic is auditable from the report alone.

    F1: 0.95 (agentic pass), 0.85 (analytical pass), 0.50 (partial floor).
    Cost: 80% (pass), 50% (partial).
    """
    md = render_parity_report(synthetic_eval_json)

    # F1 thresholds — at least one of the three numeric markers appears.
    assert "0.95" in md or "95%" in md, "F1 agentic-pass threshold (0.95) missing"
    assert "0.85" in md or "85%" in md, "F1 analytical-pass threshold (0.85) missing"
    assert "0.5" in md or "50%" in md, "Partial floor (0.5 / 50%) missing"

    # Cost thresholds.
    assert "80%" in md or "80.0" in md, "Cost pass threshold (80%) missing"


# ---- Test 8: write_parity_report writes to disk -----------------------


def test_write_parity_report_writes_to_runs_dir(synthetic_eval_json, tmp_path):
    """write_parity_report writes a file under output_dir matching the
    naming pattern qwen-parity-eval-*.md and returns its path.
    """
    out_path = write_parity_report(synthetic_eval_json, output_dir=tmp_path)

    assert isinstance(out_path, Path)
    assert out_path.exists(), f"file not written at {out_path}"
    assert out_path.parent == tmp_path
    assert out_path.name.startswith("qwen-parity-eval-")
    assert out_path.suffix == ".md"

    body = out_path.read_text()
    # Sanity: file body equals the renderer's output (modulo trailing newline).
    rendered = render_parity_report(synthetic_eval_json)
    assert body == rendered or body == rendered + "\n"


# ---- Test 9: missing verdict_overall (older eval JSON) ----------------


def test_render_handles_missing_optional_fields_gracefully():
    """An eval JSON missing `verdict_overall` (e.g. an older v1.1 run before
    Plan 02-03 bumped the schema) renders without raising. The renderer
    falls back to 'unknown' for the missing verdict + emits a warning
    section in the report so operators see the version mismatch.
    """
    older_eval_json = {
        "schema_version": "1.1",
        "suite": "juice-shop",
        "target": "http://127.0.0.1:3000",
        "scope_engagement_id": "bench-juice-shop",
        "started_at": "2026-XX-XXT00:00:00Z",
        "completed_at": "2026-XX-XXT00:01:00Z",
        "runs": [],
        # NO 'suites', NO 'verdict_overall'.
    }
    # Must not raise.
    md = render_parity_report(older_eval_json)
    assert isinstance(md, str)
    assert len(md) > 0
    assert "unknown" in md.lower() or "warning" in md.lower()


# ---- Test 10: end-to-end harness writes BOTH JSON AND Markdown -------


@pytest.fixture
def tmp_scope(tmp_path):
    """Copy bench/juice-shop/scope.yaml into tmp + rewrite engagement_id."""
    dest = tmp_path / "scope.yaml"
    text = _BENCH_SCOPE.read_text()
    text = text.replace(
        "engagement_id: bench-juice-shop", "engagement_id: bench-test"
    ).replace(
        "client: bench-juice-shop", "client: bench-test"
    )
    dest.write_text(text)
    return dest


def _mock_invoke(*, target, scope_path, profile, suite, extra_args=None):
    """Minimal invoke_fn returning one phase with one llm_call.

    Costs land at 80% reduction so the suite verdict is 'pass' and the
    Markdown report renders the success path.
    """
    if profile == "anthropic-baseline":
        inp, out, model = 3_000_000, 0, "claude-sonnet-4-6"
    else:
        inp, out, model = 3_600_000, 0, "Qwen/Qwen3-235B-A22B-Instruct-2507"
    return {
        "profile": profile,
        "model_aliases_used": {"claude-sonnet-4-6": model},
        "workspace_path": f"/tmp/test-{profile}",
        "subprocess_exit_code": 0,
        "phases": [
            {
                "name": "recon",
                "started_at": "2026-XX-XXT00:00:00Z",
                "completed_at": "2026-XX-XXT00:00:01Z",
                "exit_code": 0,
                "llm_calls": [
                    {
                        "model": model,
                        "input_tokens": inp,
                        "output_tokens": out,
                        "wall_clock_ms": 1000,
                    },
                ],
                "tool_calls": [],
                "emitted_finding_fingerprints": [],
                "emitted_findings": [],
            },
        ],
        "total_input_tokens": inp,
        "total_output_tokens": out,
        "qwen_empty_args_observed_delta": 0,
    }


def test_run_parity_eval_writes_markdown_report_at_end(tmp_scope, tmp_path):
    """End-to-end: run_parity_eval writes BOTH `runs/bench-parity-<ts>.json`
    AND `runs/qwen-parity-eval-<ts>.md`. The Markdown contains the suite
    header AND the eval_json references its own companion via
    `markdown_report_path`.
    """
    output_dir = tmp_path / "runs"
    result = run_parity_eval(
        suite="juice-shop",
        baseline_profile="anthropic-baseline",
        candidate_profile="siliconflow-qwen-235b",
        scope_path=str(tmp_scope),
        output_dir=output_dir,
        invoke_fn=_mock_invoke,
    )

    # JSON written.
    json_files = list(output_dir.glob("bench-parity-*.json"))
    assert len(json_files) == 1, f"expected 1 JSON, got {json_files}"
    # Markdown written.
    md_files = list(output_dir.glob("qwen-parity-eval-*.md"))
    assert len(md_files) == 1, f"expected 1 Markdown, got {md_files}"

    md_body = md_files[0].read_text()
    assert "## juice-shop" in md_body
    assert "Overall verdict" in md_body or "overall verdict" in md_body.lower()

    # markdown_report_path embedded in eval_json + on-disk JSON.
    assert "markdown_report_path" in result
    assert result["markdown_report_path"] == str(md_files[0])
    on_disk = json.loads(json_files[0].read_text())
    assert on_disk["markdown_report_path"] == str(md_files[0])

    # Schema sanity.
    assert EVAL_JSON_SCHEMA_VERSION == "1.2"
