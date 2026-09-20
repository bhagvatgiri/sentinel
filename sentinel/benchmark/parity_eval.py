"""SiliconFlow Qwen 235B parity benchmark harness (BENCH-05).

This harness is the orchestrator behind `sentinel bench parity-eval`. It
runs the Sentinel autonomous pentest pipeline twice against a bench target
(once per model profile), captures per-phase outputs + tool calls +
per-call LLM token usage, and writes a structured eval JSON to
`runs/bench-parity-<date>.json` that downstream plans consume:

  Plan 02-02 adds per-phase F1 scoring (precision/recall against
              bench/<suite>/canonical-vulns.yaml).
  Plan 02-03 adds cost-delta accounting from sentinel.benchmark.pricing +
              Markdown report generator.
  Plan 02-04 adds the ModelRouter default-switch + dashboard view.

Eval JSON schema v1.1 (Plan 02-02 bump from v1.0):

    {
      "schema_version": "1.1",
      "suite": "<suite name OR comma-joined list>",
      "target": "<first-target URL>",         # back-compat — v1.0 readers
                                              # see a single URL even though
                                              # v1.1 may aggregate multiple
                                              # targets in runs[].
      "started_at": "<iso8601>",
      "completed_at": "<iso8601>",
      "runs": [                               # length = len(suites) * 2
        {
          "suite_name": "<suite>",            # NEW in v1.1
          "target_url": "<URL>",              # NEW in v1.1
          "scope_engagement_id": "<id>",      # NEW in v1.1 (was top-level)
          "profile": "<profile name>",
          "model_aliases_used": {<claude alias>: <resolved model>},
          "workspace_path": "<path>",
          "phases": [
            {
              "name": "<phase name>",
              "started_at": "<iso>",
              "completed_at": "<iso>",
              "exit_code": 0,
              "llm_calls": [...],
              "tool_calls":  [...],
              "emitted_findings": [...],       # NEW in v1.1 — full dicts
              "emitted_finding_fingerprints": [...],
              "precision": <float>,            # NEW in v1.1
              "recall":    <float>,            # NEW in v1.1
              "f1":        <float>,            # NEW in v1.1
              "tp":        <int>,              # NEW in v1.1
              "fp":        <int>,              # NEW in v1.1
              "fn":        <int>,              # NEW in v1.1
              "matched_canonical_ids":   [...], # NEW in v1.1
              "unmatched_canonical_ids": [...], # NEW in v1.1
              "verdict": "pass" | "partial" | "fail",  # NEW in v1.1
            }
          ],
          "per_phase_verdicts": {              # NEW in v1.1
            "<phase>": "pass" | "partial" | "fail",
            ...
          },
          "total_input_tokens": int,
          "total_output_tokens": int,
          "qwen_empty_args_observed_delta": int
        }
      ]
    }

Scope-gating: the harness loads the bench scope via `Scope.load()` (which
writes a `scope_loaded` audit entry) and `authorize_url`-validates the
constructed target URL before any profile is applied. The bench engagement's
`.audit-<engagement_id>.jsonl` records `bench_parity_eval_started` (before
the first invocation) and `bench_parity_eval_completed` (after both
invocations finish), with the hash chain preserved end-to-end.

Testability: `_invoke_scan_autonomous` is exposed as an injectable function
via the `invoke_fn` kwarg on `run_parity_eval`. Unit tests pass a canned
stub; production calls leave `invoke_fn=None` and the harness uses the
real subprocess-based implementation.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import yaml

from sentinel.agent.model_router import (
    MODEL_PROFILES,
    apply_model_profile,
    get_qwen_empty_args_counter,
)
from sentinel.benchmark.cost_accounting import (
    cost_delta as _cost_delta,
    cost_summary_for_run as _cost_summary_for_run,
)
from sentinel.benchmark.scoring import (
    score_phase,
    verdict_for_phase,
)
from sentinel.core.scope import Scope


log = logging.getLogger(__name__)


# Schema v1.2 (Plan 02-03 bump from v1.1): adds runs[].cost_summary,
# suites[].cost_delta, suites[].verdict, top-level verdict_overall,
# top-level markdown_report_path. Plan 02-04 reads against this version
# for the FastAPI /bench/parity-eval dashboard view.
EVAL_JSON_SCHEMA_VERSION = "1.2"

# Default port the OWASP Juice Shop docker-compose exposes. Overridable via
# the `bench_port` field on the scope's raw YAML if a future bench target
# wants a different default.
_DEFAULT_BENCH_PORT = 3000


# ---- Config dataclass ---------------------------------------------------


@dataclass
class ParityEvalConfig:
    """Configuration for a parity-eval run.

    `extra_scan_args` is forwarded into the `scan-autonomous` argv for both
    profiles, so an operator can pass through pipeline flags
    (--corpus-dir, --no-verify-before-exploit, --report-style ...) that
    aren't first-class fields on the dataclass.
    """
    suite: str
    scope_path: str
    baseline_profile: str = "anthropic-baseline"
    candidate_profile: str = "siliconflow-qwen-235b"
    output_dir: Path = field(default_factory=lambda: Path("runs"))
    extra_scan_args: list[str] = field(default_factory=list)


# ---- Target URL resolution ----------------------------------------------


def _resolve_target_url(scope: Scope) -> str:
    """Pick the first concrete URL we can construct from the scope's
    `targets.domains`. Wildcards (`*.example.com`) are skipped — they
    don't yield a concrete URL by themselves. Loopback domains map to
    the default bench port (3000 = Juice Shop, 4280 = DVWA, etc. —
    Plan 02-02/02-03 may extend this).
    """
    for d in scope.domains:
        if d.startswith("*."):
            continue
        # localhost / 127.0.0.1 → loopback bench port.
        if d in ("127.0.0.1", "localhost"):
            return f"http://{d}:{_DEFAULT_BENCH_PORT}"
        return f"https://{d}"
    # Fall back to IP CIDR's network address — only useful for the bench
    # case where the operator specified 127.0.0.1/32.
    for cidr in scope.ips:
        host = cidr.split("/")[0]
        if host in ("127.0.0.1", "localhost"):
            return f"http://{host}:{_DEFAULT_BENCH_PORT}"
    raise ValueError(
        f"could not resolve a concrete bench-target URL from scope "
        f"(domains={scope.domains}, ips={scope.ips})"
    )


# ---- Real subprocess-based invocation ------------------------------------


def _invoke_scan_autonomous(*, target: str,
                            scope_path: str,
                            profile: str,
                            suite: str,
                            extra_args: Optional[list[str]] = None,
                            cost_cap_usd: Optional[float] = None) -> dict:
    """Default invoke_fn — spawn a real `sentinel scan-autonomous` subprocess.

    Captures stdout / stderr / exit code. Walks the workspace post-run to
    extract per-phase outputs from `.completed_phases.json` and the
    structured event log. Token counts come from
    `runs/events-<job_id>.jsonl` entries of kind `llm_call_completed`
    (existing event kind; the harness does NOT introduce a new event type).

    Plan 03-02 (COST-02): when `cost_cap_usd` is non-None, appends
    `--max-cost-usd <N>` to the spawned argv. Value-validation
    (must be > 0, must be numeric) lives in `run_parity_eval` so the
    rejection fires BEFORE any subprocess spawn; this helper trusts
    the upstream validation and just passes the value through. Same
    cap is applied identically to baseline AND candidate runs by the
    caller so the A/B fairness contract is preserved.

    Returns the per-run shape (see runs[i] schema in the module docstring).
    This is the slow path that hits real docker + real LLM APIs; unit
    tests must inject a stub via the `invoke_fn` kwarg on run_parity_eval.
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    workspace_path = f"workspaces/bench-{suite}-{profile}-{ts}"
    argv = [
        "sentinel", "scan-autonomous", target,
        "--scope", scope_path,
        "--model-profile", profile,
        "--workspaces-root", str(Path(workspace_path).parent),
    ]
    if cost_cap_usd is not None:
        # Plan 03-02 (COST-02): pass-through to the strict-mode cap on the
        # spawned scan-autonomous. The cap is identical for both profiles
        # because run_parity_eval reads the field ONCE per suite and forwards
        # the same numeric value to every invoke_fn call.
        argv.extend(["--max-cost-usd", str(cost_cap_usd)])
    if extra_args:
        argv.extend(extra_args)

    pre_qwen_empty = get_qwen_empty_args_counter()
    started_at = datetime.now(timezone.utc).isoformat()
    log.info("parity_eval: invoking %s", " ".join(argv))
    proc = subprocess.run(argv, capture_output=True, text=True, check=False,
                           env=os.environ.copy())
    completed_at = datetime.now(timezone.utc).isoformat()
    post_qwen_empty = get_qwen_empty_args_counter()

    # Walk the workspace for per-phase outputs. The pipeline writes
    # .completed_phases.json + per-phase deliverables; the structured
    # event log is under runs/events-<job_id>.jsonl. If anything is
    # missing (subprocess failed early), we still return a valid shape
    # with what we have so the eval JSON isn't corrupted.
    phases: list[dict] = []
    completed_marker = Path(workspace_path) / ".completed_phases.json"
    if completed_marker.exists():
        try:
            completed_data = json.loads(completed_marker.read_text())
            for phase_name, ph in completed_data.items():
                phases.append({
                    "name": phase_name,
                    "started_at": ph.get("started_at", started_at),
                    "completed_at": ph.get("completed_at", completed_at),
                    "exit_code": int(ph.get("exit_code", 0)),
                    "llm_calls": ph.get("llm_calls", []),
                    "tool_calls": ph.get("tool_calls", []),
                    "emitted_finding_fingerprints":
                        ph.get("emitted_finding_fingerprints", []),
                })
        except (json.JSONDecodeError, OSError) as e:
            log.warning("parity_eval: couldn't parse %s: %s",
                         completed_marker, e)

    total_input = sum(c.get("input_tokens", 0)
                       for ph in phases for c in ph["llm_calls"])
    total_output = sum(c.get("output_tokens", 0)
                        for ph in phases for c in ph["llm_calls"])

    return {
        "profile": profile,
        "model_aliases_used": _model_aliases_for_profile(profile),
        "workspace_path": workspace_path,
        "subprocess_exit_code": proc.returncode,
        "phases": phases,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "qwen_empty_args_observed_delta": post_qwen_empty - pre_qwen_empty,
    }


def _model_aliases_for_profile(profile: str) -> dict[str, str]:
    """Static map of profile → which resolved model each Claude alias
    routes to. Mirrors `tools/serving/anthropic-shim.py:MODEL_ALIASES`.
    """
    if profile == "siliconflow-qwen-235b":
        return {
            "claude-sonnet-4-6": "Qwen/Qwen3-235B-A22B-Instruct-2507",
            "claude-opus-4-7":   "deepseek-ai/DeepSeek-R1",
            "claude-haiku-4-5":  "Qwen/Qwen3-Coder-30B-A3B-Instruct",
        }
    # Anthropic baseline — aliases resolve to themselves.
    return {
        "claude-sonnet-4-6": "claude-sonnet-4-6",
        "claude-opus-4-7":   "claude-opus-4-7",
        "claude-haiku-4-5":  "claude-haiku-4-5",
    }


# ---- Public entry-point --------------------------------------------------


def _normalize_suite_arg(suite: "str | list[str]") -> list[str]:
    """Normalize the `suite` argument into a list of suite names.

    Accepts:
      - 'juice-shop'                → ['juice-shop']
      - 'juice-shop,dvwa'           → ['juice-shop', 'dvwa']
      - 'juice-shop, dvwa, ctf-box' → ['juice-shop', 'dvwa', 'ctf-box']
      - ['juice-shop', 'dvwa']      → ['juice-shop', 'dvwa']

    Empty entries (consecutive commas, trailing comma) are dropped.
    """
    if isinstance(suite, str):
        if "," in suite:
            return [s.strip() for s in suite.split(",") if s.strip()]
        return [suite.strip()]
    if isinstance(suite, list):
        return [str(s).strip() for s in suite if str(s).strip()]
    raise TypeError(
        f"suite must be str or list[str], got {type(suite).__name__}"
    )


# ---- Plan 03-02 (COST-02) — cost_cap_usd extraction + validation -------


def _extract_cost_cap_usd(scope: "Scope") -> Optional[float]:
    """Read + validate the optional `cost_cap_usd` field from scope.raw.

    The field is permissive at the YAML layer (Scope.load doesn't strict-key
    so any new top-level field flows through `scope.raw`). This helper
    centralizes the read + coercion + validation so the same rules apply
    whether the harness is invoked by the CLI, the dashboard, or a direct
    Python caller.

    Returns:
      - None if the field is absent (back-compat with pre-Plan-03-02
        bench scopes; the harness skips appending --max-cost-usd to the
        scan-autonomous argv).
      - float(N) if the field is present and N is a positive numeric.

    Raises:
      - ValueError if the field is present but non-numeric (T-03-02-05).
      - ValueError if the field is present but <= 0 (T-03-02-01 — negative
        caps are always-satisfied; zero is a useless boundary). Both
        rejections fire BEFORE any scan-autonomous subprocess is spawned.

    Mirrors `sentinel/cli.py:_do_scan_autonomous`'s --max-cost-usd
    validation so the two surfaces give identical errors on identical
    bad input.
    """
    raw_value = scope.raw.get("cost_cap_usd")
    if raw_value is None:
        return None
    try:
        v = float(raw_value)
    except (TypeError, ValueError):
        raise ValueError(
            f"scope.yaml cost_cap_usd must be numeric, got {raw_value!r} "
            f"({type(raw_value).__name__}). Use a positive USD value "
            f"(e.g., cost_cap_usd: 5)."
        )
    if v <= 0:
        raise ValueError(
            f"scope.yaml cost_cap_usd must be > 0 (got {v}). Use a positive "
            f"USD value (e.g., cost_cap_usd: 5). Negative caps are "
            f"always-satisfied; zero would abort every scan after the first phase."
        )
    return v


def _load_canonical_vulns(suite_name: str) -> list[dict]:
    """Load `bench/<suite_name>/canonical-vulns.yaml` and return its
    `vulns` list. Returns [] if the file doesn't exist (the harness
    keeps running with empty canonical lists — all phases score 0/0).
    """
    cv_path = Path("bench") / suite_name / "canonical-vulns.yaml"
    if not cv_path.exists():
        log.warning("canonical-vulns.yaml not found for suite %r at %s — "
                     "scoring will return 0/0 for every phase",
                     suite_name, cv_path)
        return []
    try:
        data = yaml.safe_load(cv_path.read_text()) or {}
    except yaml.YAMLError as e:
        log.warning("could not parse %s: %s — scoring will return 0/0",
                     cv_path, e)
        return []
    return data.get("vulns") or []


def _score_run_phases(run: dict, canonical_vulns: list[dict]) -> None:
    """Mutate each phase dict in `run["phases"]` to add
    precision/recall/f1/tp/fp/fn/matched_canonical_ids/
    unmatched_canonical_ids/verdict.

    Source of emitted findings per phase: `phase["emitted_findings"]` if
    present (preferred — full dict form Plan 02-02 introduces), else
    fall back to building stub dicts from `emitted_finding_fingerprints`
    so v1.0-shape phase dicts still get scored (FP-heavy, since the
    fingerprint alone doesn't carry CWE / location). Plan 02-03 may
    refine the back-compat path; Plan 02-02 ships forward-compat.
    """
    phases = run.get("phases", [])
    per_phase_verdicts: dict[str, str] = {}

    for phase in phases:
        phase_name = phase.get("name", "")
        # Filter canonical to this phase.
        expected = [
            c for c in canonical_vulns
            if c.get("expected_phase") == phase_name
        ]
        # Get emitted findings — prefer the rich v1.1 shape; degrade to
        # fingerprint-only stubs if a stale v1.0 invoke_fn was used.
        emitted = phase.get("emitted_findings")
        if emitted is None:
            emitted = [
                {"title": fp, "location": "", "cwe": ""}
                for fp in phase.get("emitted_finding_fingerprints", [])
            ]
        result = score_phase(emitted, expected)
        # Merge scoring fields into the phase dict in-place.
        phase.update(result)
        phase["verdict"] = verdict_for_phase(phase_name, result["f1"])
        per_phase_verdicts[phase_name] = phase["verdict"]

    run["per_phase_verdicts"] = per_phase_verdicts


def run_parity_eval(*,
                    suite: "str | list[str]",
                    baseline_profile: str,
                    candidate_profile: str,
                    scope_path: "str | None" = None,
                    output_dir: "Path | str" = Path("runs"),
                    invoke_fn: Optional[Callable[..., dict]] = None,
                    extra_scan_args: Optional[list[str]] = None) -> dict:
    """Run the parity benchmark across one or more suites and write the eval JSON.

    Plan 02-02 extension: `suite` accepts a comma-separated string OR a list
    so the harness fans out across multiple targets (juice-shop, dvwa, ctf-box).
    Each (suite, profile) pair is one scan-autonomous invocation; the eval JSON
    aggregates all runs in a flat `runs[]` array (length = len(suites) * 2).

    Flow:
      1. Normalize suite → list of suite names.
      2. Validate both profile names against MODEL_PROFILES (fail fast).
      3. For each suite name:
            a. Resolve scope_path → bench/<suite>/scope.yaml if not provided.
            b. Verify the file exists; raise FileNotFoundError if not.
            c. Scope.load() → writes scope_loaded audit entry.
            d. Resolve target URL from scope.targets.
            e. authorize_url + write bench_parity_eval_started (per-suite event).
            f. For each profile in [baseline, candidate]:
                  - apply_model_profile(profile)
                  - invoke_fn(...) → per-run dict.
                  - load canonical-vulns.yaml + score phases + tag verdicts.
                  - tag run with suite_name + target_url + scope_engagement_id.
                  - append to runs[].
            g. write bench_parity_eval_completed (per-suite).
      4. Assemble + write eval JSON (top-level suite = comma-joined names,
         top-level target = first suite's URL for v1.0 back-compat).

    Args:
        suite: Bench suite name (str), comma-separated names (str), or list.
        baseline_profile: ModelRouter profile for the baseline run.
        candidate_profile: ModelRouter profile for the candidate run.
        scope_path: Optional path to ONE scope YAML. When provided and a
            single suite is specified, used as-is. When None or multiple
            suites are specified, harness derives bench/<suite>/scope.yaml
            per suite (raises FileNotFoundError if missing).
        output_dir: Directory the eval JSON lands in (default ./runs).
        invoke_fn: Injectable replacement for `_invoke_scan_autonomous`.
            Tests pass a canned stub; production leaves it None.
        extra_scan_args: Extra argv forwarded into both scan-autonomous
            invocations (e.g. --corpus-dir, --no-verify-before-exploit).

    Returns:
        The eval JSON dict (same content as what's written to disk).

    Plan 03-02 (COST-02): when `bench/<suite>/scope.yaml` carries a top-level
    `cost_cap_usd: <N>` field, the harness extracts the value via
    `scope.raw.get('cost_cap_usd')` once at scope-load time per suite,
    validates it (must be a positive number; non-numeric or <= 0 raises
    ValueError BEFORE any subprocess spawn), and passes the SAME numeric
    cap to BOTH the baseline and candidate `invoke_fn` calls as
    `cost_cap_usd=<N>`. The default `_invoke_scan_autonomous` then appends
    `--max-cost-usd <N>` to the spawned scan-autonomous argv. A/B fairness:
    identical cap on both sides of the comparison.

    Raises:
        ValueError: if either profile name is unknown. No JSON is written.
        ValueError: if any suite's scope.yaml carries a non-numeric or
            non-positive `cost_cap_usd` (Plan 03-02 COST-02). No JSON
            is written; no scan-autonomous subprocess is spawned.
        FileNotFoundError: if a derived bench/<suite>/scope.yaml doesn't exist.
            No JSON is written.
        ScopeError / OutOfScopeError: if scope load or authorize fails.
    """
    # ---- 1. Normalize suite argument -----------------------------------
    suite_names = _normalize_suite_arg(suite)
    if not suite_names:
        raise ValueError(f"suite argument resolved to empty list: {suite!r}")

    # ---- 2. Fail-fast profile validation -------------------------------
    for label, name in [("baseline", baseline_profile),
                         ("candidate", candidate_profile)]:
        if name not in MODEL_PROFILES:
            valid = sorted(MODEL_PROFILES.keys())
            raise ValueError(
                f"unknown {label} profile: {name!r}. valid profiles: {valid}"
            )

    output_dir = Path(output_dir)
    invoke_fn = invoke_fn or _invoke_scan_autonomous

    # ---- 3. Resolve & validate scope paths PER SUITE (fail fast) -------
    # Build the (suite_name, scope_path) pairs up-front so an unknown suite
    # raises BEFORE the harness writes any audit entries OR mkdir's runs/.
    suite_scope_pairs: list[tuple[str, Path]] = []
    for suite_name in suite_names:
        if scope_path is not None and len(suite_names) == 1:
            sp = Path(scope_path)
        else:
            sp = Path("bench") / suite_name / "scope.yaml"
        if not sp.exists():
            raise FileNotFoundError(
                f"bench scope file not found for suite {suite_name!r}: {sp} — "
                f"expected scope at bench/{suite_name}/scope.yaml"
            )
        suite_scope_pairs.append((suite_name, sp))

    # All suites validated — now safe to mkdir output_dir.
    output_dir.mkdir(parents=True, exist_ok=True)
    overall_started_at = datetime.now(timezone.utc).isoformat()

    # ---- 4. Per-suite, per-profile invocations + per-phase scoring -----
    runs: list[dict] = []
    first_target_url: Optional[str] = None
    first_engagement_id: Optional[str] = None
    # Track each suite's scope so we can write the matching completed
    # event AFTER the eval JSON is written (it needs eval_json_path).
    per_suite_scopes: list[tuple[str, "Scope"]] = []

    for suite_name, sp in suite_scope_pairs:
        scope = Scope.load(str(sp))
        target_url = _resolve_target_url(scope)
        if first_target_url is None:
            first_target_url = target_url
            first_engagement_id = scope.engagement_id

        scope.authorize_url(target_url)
        per_suite_scopes.append((suite_name, scope))

        # Plan 03-02 (COST-02): read + validate cost_cap_usd from
        # scope.raw BEFORE writing the per-suite audit-eval-started event
        # or spawning any subprocess. Bad values raise ValueError here,
        # which means the harness fails fast with a clean message instead
        # of corrupting the audit log with a started-but-never-completed
        # event. Same cap is applied identically to baseline + candidate
        # invocations below (A/B fairness).
        cost_cap_usd = _extract_cost_cap_usd(scope)

        if scope.audit_log:
            scope.audit_log.write(
                "bench_parity_eval_started",
                {
                    "suite_name": suite_name,
                    "suite": ",".join(suite_names),
                    "baseline_profile": baseline_profile,
                    "candidate_profile": candidate_profile,
                    "target": target_url,
                    "schema_version": EVAL_JSON_SCHEMA_VERSION,
                    # Record the cap in the audit log so the deliverable's
                    # cost numbers can be defended ("baseline ran with $N cap;
                    # candidate ran with same $N cap").
                    "cost_cap_usd": cost_cap_usd,
                },
                mode=scope.engagement_mode.value,
            )

        canonical_vulns = _load_canonical_vulns(suite_name)

        for profile in [baseline_profile, candidate_profile]:
            apply_model_profile(profile)
            # Plan 03-02 (COST-02): invoke_fn receives cost_cap_usd as a
            # keyword arg. The default _invoke_scan_autonomous accepts it
            # natively. Older test stubs that don't accept the kwarg fall
            # back to the no-cost-cap path (cost_cap_usd is dropped silently
            # via the explicit try/except). Stubs MAY accept it via **kwargs
            # or via an explicit cost_cap_usd parameter — both work.
            try:
                run = invoke_fn(
                    target=target_url,
                    scope_path=str(sp),
                    profile=profile,
                    suite=suite_name,
                    cost_cap_usd=cost_cap_usd,
                )
            except TypeError as e:
                # Test-stub back-compat path: stub signature didn't accept
                # cost_cap_usd. Log + retry without the kwarg. Production
                # _invoke_scan_autonomous accepts the kwarg so this branch
                # only fires under unit tests with legacy stubs.
                if "cost_cap_usd" not in str(e):
                    raise
                log.debug(
                    "invoke_fn stub doesn't accept cost_cap_usd; "
                    "retrying without (legacy stub back-compat)"
                )
                run = invoke_fn(
                    target=target_url,
                    scope_path=str(sp),
                    profile=profile,
                    suite=suite_name,
                )
            # Tag with suite metadata so the eval JSON consumer can tell
            # which target produced this run without re-deriving from
            # workspace_path.
            run["suite_name"] = suite_name
            run["target_url"] = target_url
            run["scope_engagement_id"] = scope.engagement_id
            # Score every phase against the canonical-vulns list, attach
            # precision/recall/f1/verdict.
            _score_run_phases(run, canonical_vulns)
            # Plan 02-03 (BENCH-07): embed per-run cost summary from
            # pricing.PROFILE_PRICING. Uses LIVE token counts from each
            # llm_call's input_tokens/output_tokens (captured upstream
            # via the existing llm_call_completed event handler).
            run["cost_summary"] = _cost_summary_for_run(run)
            runs.append(run)

    # ---- 5. Assemble + write eval JSON ---------------------------------
    overall_completed_at = datetime.now(timezone.utc).isoformat()
    # Plan 02-03: per-suite aggregation — cost_delta + verdict.
    suites_block = _build_suites_block(runs, baseline_profile, candidate_profile)
    verdict_overall = _aggregate_overall_verdict(suites_block)

    eval_json = {
        "schema_version": EVAL_JSON_SCHEMA_VERSION,
        # v1.0 back-compat: top-level suite/target reflect the first suite
        # so v1.0 readers see something sensible. v1.1+ readers should index
        # runs[].suite_name / runs[].target_url instead.
        "suite": (
            suite_names[0] if len(suite_names) == 1
            else ",".join(suite_names)
        ),
        "target": first_target_url,
        "scope_engagement_id": first_engagement_id,
        "baseline_profile": baseline_profile,
        "candidate_profile": candidate_profile,
        "started_at": overall_started_at,
        "completed_at": overall_completed_at,
        "runs": runs,
        # v1.2 additions:
        "suites": suites_block,
        "verdict_overall": verdict_overall,
    }
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")
    out_path = output_dir / f"bench-parity-{date_str}.json"

    # Plan 02-03 (BENCH-08): render the Markdown report alongside the JSON
    # so the JSON's markdown_report_path field references its own companion.
    # The renderer is imported lazily; if it's not yet installed (e.g. an
    # older Plan 02-03 intermediate tree without the renderer module), the
    # eval JSON still writes — verdict_overall + cost_delta are usable
    # without the Markdown surface.
    md_path: "Path | None" = None
    try:
        from sentinel.benchmark.report_renderer import write_parity_report
    except ImportError:
        log.warning(
            "parity_eval: sentinel.benchmark.report_renderer not available — "
            "skipping Markdown report rendering. Eval JSON still written."
        )
    else:
        md_path = write_parity_report(eval_json, output_dir=output_dir)
        eval_json["markdown_report_path"] = str(md_path)

    out_path.write_text(json.dumps(eval_json, indent=2))
    log.info("parity_eval: wrote %s", out_path)
    if md_path is not None:
        log.info("parity_eval: wrote %s", md_path)

    # ---- 6. Per-suite bench_parity_eval_completed audit events ---------
    # Write AFTER the JSON exists so the audit event can reference its path.
    # Each suite's completed event includes only the runs scoped to that suite.
    for suite_name, scope in per_suite_scopes:
        if not scope.audit_log:
            continue
        suite_runs = [r for r in runs if r.get("suite_name") == suite_name]
        completed_payload = {
            "suite_name": suite_name,
            "suite": ",".join(suite_names),
            "eval_json_path": str(out_path),
            "runs": [
                {"profile": r["profile"],
                 "workspace_path": r.get("workspace_path", "")}
                for r in suite_runs
            ],
        }
        if md_path is not None:
            completed_payload["markdown_report_path"] = str(md_path)
        scope.audit_log.write(
            "bench_parity_eval_completed",
            completed_payload,
            mode=scope.engagement_mode.value,
        )

    return eval_json


# ---- Plan 02-03 helpers: per-suite aggregation + overall verdict --------


def _build_suites_block(runs: list[dict],
                        baseline_profile: str,
                        candidate_profile: str) -> dict:
    """Group runs by suite_name; for each suite, compute cost_delta
    (baseline_run vs candidate_run) and a per-suite verdict.

    Per-suite verdict logic (BENCH-07 + BENCH-06 combined):
      - 'pass' iff EVERY candidate-phase verdict is 'pass' AND
        cost_delta.verdict is 'pass'.
      - 'fail' iff cost_delta.verdict is 'fail' OR ≥50% of candidate-phase
        verdicts are 'fail'.
      - 'partial' otherwise.

    Returns a dict keyed by suite_name, with subkeys:
      - cost_delta: dict (from cost_accounting.cost_delta).
      - verdict: 'pass' | 'partial' | 'fail' (for the candidate).
      - baseline_run_index / candidate_run_index: int — index into runs[]
        for downstream consumers (Plan 02-04 dashboard).
    """
    suites_block: dict[str, dict] = {}
    # Bucket runs by (suite, profile) so we can pair them.
    by_suite: dict[str, dict[str, tuple[int, dict]]] = {}
    for i, run in enumerate(runs):
        sname = run.get("suite_name", "")
        prof = run.get("profile", "")
        by_suite.setdefault(sname, {})[prof] = (i, run)

    for sname, profile_map in by_suite.items():
        baseline_entry = profile_map.get(baseline_profile)
        candidate_entry = profile_map.get(candidate_profile)
        if baseline_entry is None or candidate_entry is None:
            log.warning(
                "_build_suites_block: suite %r missing one of "
                "(baseline=%r, candidate=%r); skipping cost_delta",
                sname, baseline_profile, candidate_profile,
            )
            continue
        baseline_idx, baseline_run = baseline_entry
        candidate_idx, candidate_run = candidate_entry

        cd = _cost_delta(baseline_run, candidate_run)

        # Per-suite verdict aggregation across candidate-phase verdicts.
        candidate_phase_verdicts = [
            ph.get("verdict") for ph in candidate_run.get("phases", [])
            if ph.get("verdict") is not None
        ]
        n_phases = len(candidate_phase_verdicts)
        n_fail = sum(1 for v in candidate_phase_verdicts if v == "fail")
        n_pass = sum(1 for v in candidate_phase_verdicts if v == "pass")
        # ≥50% phases failed → suite fail (regardless of cost).
        majority_failed = (n_phases > 0 and (n_fail / n_phases) >= 0.5)

        if cd["verdict"] == "fail" or majority_failed:
            suite_verdict = "fail"
        elif n_phases > 0 and n_pass == n_phases and cd["verdict"] == "pass":
            suite_verdict = "pass"
        else:
            suite_verdict = "partial"

        suites_block[sname] = {
            "cost_delta": cd,
            "verdict": suite_verdict,
            "baseline_run_index": baseline_idx,
            "candidate_run_index": candidate_idx,
        }

    return suites_block


def _aggregate_overall_verdict(suites_block: dict) -> str:
    """Roll up per-suite verdicts to a single eval-wide verdict.

    Logic:
      - 'pass' iff every suite's verdict is 'pass'.
      - 'fail' iff every suite's verdict is 'fail'.
      - 'partial' otherwise (or if suites_block is empty — defensive default).
    """
    if not suites_block:
        return "partial"
    verdicts = [s.get("verdict", "partial") for s in suites_block.values()]
    if all(v == "pass" for v in verdicts):
        return "pass"
    if all(v == "fail" for v in verdicts):
        return "fail"
    return "partial"


__all__ = [
    "EVAL_JSON_SCHEMA_VERSION",
    "ParityEvalConfig",
    "run_parity_eval",
]
