"""Markdown parity-eval report renderer (BENCH-08, Plan 02-03 Task 3).

Renders a v1.2-shape eval JSON (from `sentinel.benchmark.parity_eval`) into
a Markdown report the operator reads when deciding whether to flip the default
ModelRouter profile to Qwen 235B. The report is the file Plan 02-04's
`/bench/parity-eval` FastAPI route serves verbatim — no re-rendering at the
dashboard layer.

Public API:
    REPORT_TEMPLATE_VERSION: str  ('1.0')
    render_parity_report(eval_json: dict) -> str
    write_parity_report(eval_json: dict, *, output_dir: Path) -> Path

Report layout (top → bottom):
    # H1 title (mentions parity / qwen + overall verdict marker)
    Frontmatter (template version, suite, profiles, timestamps)
    Optional warning section (when eval_json is missing v1.2 fields)
    ## <suite-name> sections, one per suite:
        - per-phase comparison table (baseline vs candidate F1 + verdict)
        - per-finding diff (only_baseline / only_candidate / both / neither)
        - cost-summary table (baseline_usd / candidate_usd / delta_usd /
          percent_reduction / cost_verdict)
    ## Summary (roll-up across suites): per-phase weighted F1 per profile
    ## Thresholds (F1 + cost verdict cut-offs, for auditability)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


REPORT_TEMPLATE_VERSION = "1.0"


# ---- Helpers ------------------------------------------------------------


def _fmt_float(x: float | int | None, digits: int = 3) -> str:
    """Format a float with stable trailing zeros, or '-' if None."""
    if x is None:
        return "-"
    try:
        return f"{float(x):.{digits}f}"
    except (TypeError, ValueError):
        return str(x)


def _fmt_usd(x: float | int | None) -> str:
    if x is None:
        return "-"
    try:
        return f"${float(x):.2f}"
    except (TypeError, ValueError):
        return str(x)


def _fmt_pct(x: float | int | None) -> str:
    if x is None:
        return "-"
    try:
        return f"{float(x):.1f}%"
    except (TypeError, ValueError):
        return str(x)


def _phase_lookup(run: dict) -> dict[str, dict]:
    """Map phase-name -> phase dict for one run."""
    return {ph.get("name", ""): ph for ph in run.get("phases", []) if ph.get("name")}


def _all_phase_names_in_order(*runs: dict) -> list[str]:
    """Union of phase names across the given runs, preserving first-seen order."""
    seen: list[str] = []
    seen_set: set[str] = set()
    for run in runs:
        for ph in run.get("phases", []):
            name = ph.get("name", "")
            if name and name not in seen_set:
                seen.append(name)
                seen_set.add(name)
    return seen


def _bucket_findings(baseline_run: dict, candidate_run: dict) -> dict[str, list[str]]:
    """Sort canonical IDs into only_baseline / only_candidate / both / neither.

    Union across both runs (matched + unmatched). For each ID:
      - both: matched by baseline AND candidate
      - only_baseline: matched by baseline only
      - only_candidate: matched by candidate only
      - neither: appeared (as unmatched) on both sides but matched by neither
    """
    baseline_matched: set[str] = set()
    baseline_unmatched: set[str] = set()
    for ph in baseline_run.get("phases", []):
        baseline_matched.update(ph.get("matched_canonical_ids", []) or [])
        baseline_unmatched.update(ph.get("unmatched_canonical_ids", []) or [])

    candidate_matched: set[str] = set()
    candidate_unmatched: set[str] = set()
    for ph in candidate_run.get("phases", []):
        candidate_matched.update(ph.get("matched_canonical_ids", []) or [])
        candidate_unmatched.update(ph.get("unmatched_canonical_ids", []) or [])

    universe = (
        baseline_matched | baseline_unmatched | candidate_matched | candidate_unmatched
    )

    buckets: dict[str, list[str]] = {
        "both": [],
        "only_baseline": [],
        "only_candidate": [],
        "neither": [],
    }
    for cid in sorted(universe):
        b = cid in baseline_matched
        c = cid in candidate_matched
        if b and c:
            buckets["both"].append(cid)
        elif b and not c:
            buckets["only_baseline"].append(cid)
        elif c and not b:
            buckets["only_candidate"].append(cid)
        else:
            buckets["neither"].append(cid)
    return buckets


def _format_bucket_list(ids: list[str]) -> str:
    if not ids:
        return "_(none)_"
    return ", ".join(f"`{cid}`" for cid in ids)


def _weighted_f1_by_phase(
    runs: list[dict], profile: str
) -> dict[str, tuple[float, int]]:
    """Compute weighted F1 per phase across all runs of one profile.

    Weight = TP + FN (number of canonical expected items for the phase).
    Returns: {phase_name: (weighted_f1, total_weight)}. A phase with zero
    total weight is reported as f1=0.0.
    """
    sums: dict[str, list[float]] = {}
    weights: dict[str, int] = {}
    for run in runs:
        if run.get("profile") != profile:
            continue
        for ph in run.get("phases", []):
            name = ph.get("name", "")
            if not name:
                continue
            tp = int(ph.get("tp", 0) or 0)
            fn = int(ph.get("fn", 0) or 0)
            weight = tp + fn
            f1 = float(ph.get("f1", 0.0) or 0.0)
            sums.setdefault(name, []).append(f1 * weight)
            weights[name] = weights.get(name, 0) + weight
    result: dict[str, tuple[float, int]] = {}
    for name, values in sums.items():
        total_weight = weights.get(name, 0)
        if total_weight > 0:
            result[name] = (sum(values) / total_weight, total_weight)
        else:
            # Phase exists but no canonical expected — F1 is 0.0 by convention.
            result[name] = (0.0, 0)
    return result


# ---- Section renderers --------------------------------------------------


def _render_frontmatter(eval_json: dict, verdict_overall: str) -> list[str]:
    lines: list[str] = []
    suite = eval_json.get("suite", "(unknown)")
    baseline = eval_json.get("baseline_profile", "anthropic-baseline")
    candidate = eval_json.get("candidate_profile", "siliconflow-qwen-235b")
    started_at = eval_json.get("started_at", "")
    completed_at = eval_json.get("completed_at", "")
    schema_version = eval_json.get("schema_version", "?")

    lines.append(f"# Sentinel parity eval — Qwen 235B vs Anthropic baseline")
    lines.append("")
    lines.append(f"**Overall verdict:** `{verdict_overall}`")
    lines.append("")
    lines.append(f"- Suite(s): `{suite}`")
    lines.append(f"- Baseline profile: `{baseline}`")
    lines.append(f"- Candidate profile: `{candidate}`")
    lines.append(f"- Started at: `{started_at}`")
    lines.append(f"- Completed at: `{completed_at}`")
    lines.append(f"- Eval JSON schema: `{schema_version}`")
    lines.append(f"- Report template: `v{REPORT_TEMPLATE_VERSION}`")
    lines.append("")
    return lines


def _render_warning_section(missing: list[str]) -> list[str]:
    lines: list[str] = []
    lines.append("## Warning — schema fields missing")
    lines.append("")
    lines.append(
        "The eval JSON is missing fields the v1.2 renderer expects. The report "
        "falls back to `unknown` verdicts where applicable."
    )
    lines.append("")
    lines.append("Missing fields:")
    for f in missing:
        lines.append(f"- `{f}`")
    lines.append("")
    return lines


def _render_suite_section(
    suite_name: str,
    suite_block: dict,
    runs: list[dict],
    baseline_profile: str,
    candidate_profile: str,
) -> list[str]:
    lines: list[str] = []
    lines.append(f"## {suite_name}")
    lines.append("")
    suite_verdict = suite_block.get("verdict", "unknown")
    lines.append(f"**Suite verdict:** `{suite_verdict}`")
    lines.append("")

    baseline_idx = suite_block.get("baseline_run_index")
    candidate_idx = suite_block.get("candidate_run_index")

    baseline_run = runs[baseline_idx] if (
        baseline_idx is not None and 0 <= baseline_idx < len(runs)
    ) else {}
    candidate_run = runs[candidate_idx] if (
        candidate_idx is not None and 0 <= candidate_idx < len(runs)
    ) else {}

    # ---- Per-phase comparison table -------------------------------------
    lines.append("### Per-phase comparison")
    lines.append("")
    lines.append(
        "| phase | baseline_f1 | candidate_f1 | baseline_verdict | candidate_verdict |"
    )
    lines.append(
        "| --- | --- | --- | --- | --- |"
    )
    baseline_phases = _phase_lookup(baseline_run)
    candidate_phases = _phase_lookup(candidate_run)
    phase_order = _all_phase_names_in_order(baseline_run, candidate_run)
    for pname in phase_order:
        b = baseline_phases.get(pname, {})
        c = candidate_phases.get(pname, {})
        lines.append(
            f"| {pname} "
            f"| {_fmt_float(b.get('f1'))} "
            f"| {_fmt_float(c.get('f1'))} "
            f"| {b.get('verdict', '-')} "
            f"| {c.get('verdict', '-')} |"
        )
    lines.append("")

    # ---- Per-finding diff ------------------------------------------------
    lines.append("### Per-finding diff")
    lines.append("")
    buckets = _bucket_findings(baseline_run, candidate_run)
    lines.append(f"- **both** ({len(buckets['both'])}): "
                  f"{_format_bucket_list(buckets['both'])}")
    lines.append(f"- **only_baseline** ({len(buckets['only_baseline'])}): "
                  f"{_format_bucket_list(buckets['only_baseline'])}")
    lines.append(f"- **only_candidate** ({len(buckets['only_candidate'])}): "
                  f"{_format_bucket_list(buckets['only_candidate'])}")
    lines.append(f"- **neither** ({len(buckets['neither'])}): "
                  f"{_format_bucket_list(buckets['neither'])}")
    lines.append("")

    # ---- Cost summary table ---------------------------------------------
    lines.append("### Cost summary")
    lines.append("")
    cd = suite_block.get("cost_delta", {}) or {}
    baseline_usd = cd.get("baseline_total_usd")
    candidate_usd = cd.get("candidate_total_usd")
    delta_usd = cd.get("absolute_delta_usd")
    percent_reduction = cd.get("percent_reduction")
    cost_verdict = cd.get("verdict", "unknown")

    lines.append(
        "| baseline_usd | candidate_usd | delta_usd | percent_reduction | cost_verdict |"
    )
    lines.append("| --- | --- | --- | --- | --- |")
    lines.append(
        f"| {_fmt_usd(baseline_usd)} "
        f"| {_fmt_usd(candidate_usd)} "
        f"| {_fmt_usd(delta_usd)} "
        f"| {_fmt_pct(percent_reduction)} "
        f"| {cost_verdict} |"
    )
    lines.append("")

    return lines


def _render_summary_rollup(
    runs: list[dict], baseline_profile: str, candidate_profile: str
) -> list[str]:
    """Bottom roll-up: weighted F1 per phase across all suites, per profile."""
    lines: list[str] = []
    lines.append("## Summary roll-up — weighted F1 across all suites")
    lines.append("")
    lines.append(
        f"Weighted F1 per phase across every suite, for `{baseline_profile}` "
        f"(baseline) and `{candidate_profile}` (candidate). Weight per row "
        f"is the number of canonical-expected findings for that phase."
    )
    lines.append("")

    baseline_rollup = _weighted_f1_by_phase(runs, baseline_profile)
    candidate_rollup = _weighted_f1_by_phase(runs, candidate_profile)
    phase_names = sorted(set(baseline_rollup) | set(candidate_rollup))

    lines.append(
        f"| phase | {baseline_profile} weighted_f1 | "
        f"{candidate_profile} weighted_f1 | weight |"
    )
    lines.append("| --- | --- | --- | --- |")
    for pname in phase_names:
        b_f1, b_w = baseline_rollup.get(pname, (0.0, 0))
        c_f1, c_w = candidate_rollup.get(pname, (0.0, 0))
        # Same canonical set per phase across profiles, so weight is symmetric.
        weight = max(b_w, c_w)
        lines.append(
            f"| {pname} | {_fmt_float(b_f1)} | {_fmt_float(c_f1)} | {weight} |"
        )
    if not phase_names:
        lines.append("| _(no phases scored)_ | - | - | - |")
    lines.append("")
    return lines


def _render_thresholds_section() -> list[str]:
    lines: list[str] = []
    lines.append("## Thresholds (verdict cut-offs)")
    lines.append("")
    lines.append("**F1 thresholds (per-phase verdict, from `scoring.verdict_for_phase`):**")
    lines.append("")
    lines.append("- Agentic phases (recon, vuln:*, exploit:*, correlation, report) — "
                  "`pass` at F1 >= **0.95**.")
    lines.append("- Analytical phases (compliance overlay, PDF render) — "
                  "`pass` at F1 >= **0.85**.")
    lines.append("- Below 0.85 / 0.95 but above the partial floor (F1 >= **0.50** / **50%**) "
                  "→ `partial`. Below 0.50 → `fail`.")
    lines.append("")
    lines.append("**Cost-delta thresholds (per-suite verdict, from `cost_accounting.cost_delta`):**")
    lines.append("")
    lines.append("- `pass` iff candidate is at least **80%** cheaper than baseline "
                  "(percent_reduction >= 80.0).")
    lines.append("- `partial` iff candidate is at least **50%** cheaper "
                  "(percent_reduction >= 50.0) but below 80%.")
    lines.append("- `fail` otherwise (candidate not at least 50% cheaper).")
    lines.append("")
    return lines


# ---- Public API ---------------------------------------------------------


def render_parity_report(eval_json: dict) -> str:
    """Render a Markdown body for the given parity-eval JSON.

    Tolerates v1.1 / older-shape JSON missing v1.2 fields (`suites`,
    `verdict_overall`) — falls back to verdict `unknown` and emits a
    warning section. Never raises on missing optional fields.
    """
    # Pick up overall verdict; fall back when older eval JSON omits it.
    verdict_overall = eval_json.get("verdict_overall")
    suites_block = eval_json.get("suites")
    missing_fields: list[str] = []
    if verdict_overall is None:
        verdict_overall = "unknown"
        missing_fields.append("verdict_overall")
    if suites_block is None:
        suites_block = {}
        missing_fields.append("suites")

    runs = eval_json.get("runs", []) or []
    baseline_profile = eval_json.get("baseline_profile", "anthropic-baseline")
    candidate_profile = eval_json.get("candidate_profile", "siliconflow-qwen-235b")

    parts: list[str] = []
    parts.extend(_render_frontmatter(eval_json, verdict_overall))

    if missing_fields:
        parts.extend(_render_warning_section(missing_fields))

    # Per-suite sections, in iteration order of suites_block (insertion-stable
    # since Python 3.7).
    for suite_name, suite_block in suites_block.items():
        parts.extend(
            _render_suite_section(
                suite_name,
                suite_block,
                runs,
                baseline_profile,
                candidate_profile,
            )
        )

    # Bottom roll-up — always rendered so the report has a uniform shape
    # even when suites_block is empty.
    parts.extend(
        _render_summary_rollup(runs, baseline_profile, candidate_profile)
    )

    # Thresholds — always rendered (auditability).
    parts.extend(_render_thresholds_section())

    return "\n".join(parts)


def write_parity_report(eval_json: dict, *, output_dir: Path) -> Path:
    """Render and write the Markdown report; return the path written.

    Filename pattern: `qwen-parity-eval-<YYYY-MM-DD-HHMMSS>.md` (uses the
    eval JSON's `completed_at` when present, falls back to current UTC).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Prefer the eval JSON's completed_at timestamp so the Markdown filename
    # mirrors the companion JSON's bench-parity-<ts>.json suffix.
    ts_source = eval_json.get("completed_at") or eval_json.get("started_at")
    ts_str: str
    if ts_source:
        try:
            # Accept both '2026-XX-XXT00:00:00Z' and '2026-XX-XXT00:00:00+00:00'.
            cleaned = ts_source.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            ts_str = dt.strftime("%Y-%m-%d-%H%M%S")
        except (ValueError, TypeError):
            ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")
    else:
        ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")

    out_path = output_dir / f"qwen-parity-eval-{ts_str}.md"
    body = render_parity_report(eval_json)
    out_path.write_text(body)
    return out_path


__all__ = [
    "REPORT_TEMPLATE_VERSION",
    "render_parity_report",
    "write_parity_report",
]
