"""BENCH-09: ModelRouter default-profile switch.

After a `sentinel bench parity-eval` run completes, the CLI checks
`should_flip_default(eval_json)`. If True, it calls `flip_default(eval_json)`
which persists a small state file at::

    ~/.sentinel/model_profile_default.txt

`ModelRouter` reads this file at module import time to populate the
`DEFAULT_MODEL_PROFILE` constant — so subsequent `sentinel scan-autonomous`
invocations (without an explicit `--model-profile` flag) auto-apply the
proven-parity profile.

State file shape (newline-separated lines, UTF-8)::

    line 1: profile name        ('siliconflow-qwen-235b')
    line 2: eval JSON path      (absolute path to the bench-parity-*.json
                                 that triggered the flip — the audit trail)
    line 3: ISO 8601 timestamp  (when the flip happened)

Operator overrides:

- `sentinel scan-autonomous --model-profile anthropic-baseline` always wins
  (the explicit flag short-circuits the default-switch read).
- `sentinel bench reset-default` removes the state file, reverting to
  the baseline.

Hard contract:

- `flip_default` REFUSES to write the state file unless
  `eval_json['verdict_overall'] == 'pass'`. A 'partial' or 'fail' verdict
  raises `ValueError` — the gap is documented in the eval report's
  per-suite verdicts, NOT silently papered over with a default flip.

This module is pure I/O on a single state file. No network, no audit-log
mutation — the CLI layer writes the corresponding
`bench_default_profile_flipped` audit event on top of this state write.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


log = logging.getLogger(__name__)


# ---- Module-level constants ----------------------------------------------

DEFAULT_PROFILE_STATE_PATH: Path = Path(
    "~/.sentinel/model_profile_default.txt"
).expanduser()

# Profile names recognized by ModelRouter (Plan 02-01 MODEL_PROFILES keys).
# Kept inline (NOT imported from model_router) to avoid an import cycle:
# model_router imports read_current_default at module load, so we cannot
# import MODEL_PROFILES back from there. Future profile additions need to
# be reflected in both places — a 4-test smoke fixture in
# test_model_profile_routing.py guards against drift.
_KNOWN_PROFILES = frozenset({"anthropic-baseline", "siliconflow-qwen-235b"})

_BASELINE_PROFILE = "anthropic-baseline"
_CANDIDATE_PROFILE = "siliconflow-qwen-235b"


# ---- Public API ----------------------------------------------------------


def should_flip_default(eval_json: dict) -> bool:
    """Return True iff `eval_json['verdict_overall'] == 'pass'`.

    Missing field → False (with a warning, since downstream consumers
    depend on schema v1.2's verdict_overall existence).
    """
    verdict = eval_json.get("verdict_overall")
    if verdict is None:
        log.warning(
            "should_flip_default: eval JSON missing 'verdict_overall' field "
            "(eval-schema < v1.2?). Refusing to flip default."
        )
        return False
    return verdict == "pass"


def flip_default(eval_json: dict,
                  state_path: Optional[Path] = None) -> Path:
    """Persist `siliconflow-qwen-235b` as the new ModelRouter default.

    Writes a 3-line UTF-8 state file at `state_path` (creates parent
    directories as needed). Refuses to write if the eval verdict is not
    `'pass'` — a partial/fail eval should leave the default untouched and
    the gap surfaced in the report.

    Args:
        eval_json: The eval JSON dict from `run_parity_eval(...)`. Must
            contain `verdict_overall: 'pass'`. The function ALSO reads
            `eval_json_path` (Plan 02-04 contract — passed by the CLI
            wrapper as the absolute path to the just-written
            `bench-parity-<ts>.json`) and falls back to deriving from
            `markdown_report_path` if `eval_json_path` is absent.

    Returns:
        The `Path` to the written state file (== `state_path`).

    Raises:
        ValueError: If `eval_json['verdict_overall']` is not `'pass'`.
    """
    verdict = eval_json.get("verdict_overall")
    if verdict != "pass":
        raise ValueError(
            f"refusing to flip default — verdict_overall is {verdict!r} "
            f"(only 'pass' triggers a flip; partial/fail must be "
            f"documented in the eval report instead)"
        )

    # Resolve the state path at call time so monkeypatching the
    # module-level constant works correctly in tests.
    if state_path is None:
        state_path = DEFAULT_PROFILE_STATE_PATH

    # Derive the audit-trail path to embed in line 2 of the state file.
    eval_path_str = eval_json.get("eval_json_path") or ""
    if not eval_path_str:
        # Fall back to deriving from markdown_report_path if present
        # (replace .md → .json), or empty string if neither is present.
        md_path = eval_json.get("markdown_report_path", "")
        if md_path and md_path.endswith(".md"):
            # The markdown file's companion JSON is bench-parity-<ts>.json
            # in the same directory. The renderer keeps these as a pair.
            # We cannot derive the exact name without scanning the dir,
            # so just record the markdown path for the audit trail.
            eval_path_str = md_path
        else:
            eval_path_str = "<unknown>"

    ts = datetime.now(timezone.utc).isoformat()

    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        f"{_CANDIDATE_PROFILE}\n{eval_path_str}\n{ts}\n",
        encoding="utf-8",
    )
    log.info(
        "default_switch: flipped ModelRouter default to %r (state file %s; "
        "eval JSON %s)",
        _CANDIDATE_PROFILE, state_path, eval_path_str,
    )
    return state_path


def read_current_default(
    state_path: Optional[Path] = None,
) -> str:
    """Read line 1 of `state_path` and return it if it's a known profile.

    Fallback to `'anthropic-baseline'`:
      - File doesn't exist.
      - File is empty / unreadable (OSError, UnicodeDecodeError).
      - Line 1 is not in `_KNOWN_PROFILES` (corruption or stale file from
        a removed profile). Emits a warning.

    No I/O beyond reading the single file. Never raises.
    """
    # Resolve the state path at call time so monkeypatching the
    # module-level constant works correctly in tests.
    if state_path is None:
        state_path = DEFAULT_PROFILE_STATE_PATH
    try:
        text = state_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return _BASELINE_PROFILE

    if not text.strip():
        # Empty file → fall back silently. An empty file is normal during
        # tests / fresh installs and doesn't warrant a warning.
        return _BASELINE_PROFILE

    profile = text.splitlines()[0].strip()
    if profile not in _KNOWN_PROFILES:
        log.warning(
            "read_current_default: state file %s contains unknown profile "
            "%r — falling back to %r. valid profiles: %s",
            state_path, profile, _BASELINE_PROFILE,
            sorted(_KNOWN_PROFILES),
        )
        return _BASELINE_PROFILE
    return profile


def reset_default(
    state_path: Optional[Path] = None,
) -> None:
    """Remove the state file, reverting the ModelRouter default to
    `'anthropic-baseline'`. Idempotent — does not raise if absent."""
    # Resolve the state path at call time so monkeypatching the
    # module-level constant works correctly in tests.
    if state_path is None:
        state_path = DEFAULT_PROFILE_STATE_PATH
    try:
        state_path.unlink(missing_ok=True)
        log.info("default_switch: removed state file %s", state_path)
    except OSError as e:  # pragma: no cover — defensive on weird FS errors
        log.warning(
            "default_switch: reset_default failed to remove %s: %s",
            state_path, e,
        )


__all__ = [
    "DEFAULT_PROFILE_STATE_PATH",
    "should_flip_default",
    "flip_default",
    "read_current_default",
    "reset_default",
]
