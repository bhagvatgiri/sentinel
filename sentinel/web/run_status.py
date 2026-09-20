"""Single source of truth for the "Running / Stalled / Completed / Failed / Aborted"
badge that the agent-runs dashboard shows.

Before this module existed, the list-view (`/agent-runs`) computed the badge from
`sentinel.agent.event_log._sniff_status` (which DOES apply a staleness check —
a non-empty file whose last event is older than `stall_after_seconds` is
"stalled"), while the detail-view (`/agent-runs/<job_id>`) computed it from
`EventLog._derive_meta` (which DOES NOT apply staleness — it just returns
"running" whenever a `pipeline_started` event exists without a matching
`pipeline_completed`). The result: the same run rendered as "Stalled" in the
list and "Running" in the detail page, which is the bug we're fixing.

Both views now call `compute_run_status()` so the badge agrees.

Contract:
- Pure function of the event log file on disk; never raises.
- Returns one of: 'running' | 'stalled' | 'completed' | 'failed' | 'aborted'
  | 'initializing' | 'unknown'.
- Threshold default = 60 seconds, which is the value the pre-existing
  `_sniff_status` was already using (we are unifying behavior, not changing
  it). Override via the `stall_after_seconds` kwarg.

This module deliberately lives under `sentinel/web/` because the long-running
pentest pipeline imports `sentinel/agent/event_log.py` and we don't want a
trivial UI tweak to ride into the agent runtime.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Literal


RunStatus = Literal[
    "running", "stalled", "completed", "failed", "aborted",
    "initializing", "unknown",
]


# Event kinds that mean the run reached a terminal state. If the LAST event
# in the log is one of these, staleness is irrelevant — the run is done.
# Kept narrow on purpose: per-phase failures (`phase_failed`) do NOT end the
# run; the pipeline can recover and keep going. A run is only terminal when
# something at the run level fires.
_TERMINAL_KIND_TO_STATUS: dict[str, RunStatus] = {
    "pipeline_completed": "completed",
    "pipeline_aborted":   "aborted",
}


def _read_tail_lines(path: Path, tail_bytes: int = 8192) -> list[str]:
    """Read the last `tail_bytes` of `path` and return its lines.

    Bounded read so this stays cheap even on a 200k-event log. Returns []
    on any IO error so callers can fall through to 'unknown'.
    """
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - tail_bytes))
            tail = fh.read().decode("utf-8", errors="ignore")
    except OSError:
        return []
    return [ln for ln in tail.splitlines() if ln.strip()]


def compute_run_status(
    events_path: Path | str,
    *,
    stall_after_seconds: int = 600,
    now: float | None = None,
) -> RunStatus:
    """Return the badge status for an event-log file.

    Resolution order:

    1. Path missing / unreadable → ``'unknown'``.
    2. File exists but is empty → ``'initializing'`` if the file is younger
       than ``stall_after_seconds``, else ``'stalled'``.
    3. Walk the tail of the file (newest line first). The first event that
       matches a key in ``_TERMINAL_KIND_TO_STATUS`` wins — that's the
       authoritative state. ``pipeline_completed`` → 'completed';
       ``pipeline_aborted`` → 'aborted'.
    4. No terminal marker found → compare ``last_event_ts`` to ``now``.
       If the file was last touched within ``stall_after_seconds`` →
       ``'running'``; otherwise ``'stalled'``.

    Notes:
    - Step 4 uses the file mtime as a fallback (not the in-file ts) because
      the pipeline appends in real time, so mtime ~ last event ts. mtime is
      O(1) and survives even on a truncated/corrupt tail.
    - This function does NOT distinguish 'failed' from 'running' / 'stalled'
      on its own — per-phase `phase_failed` events are not run-terminal.
      A future caller can layer that on if needed.
    """
    p = Path(events_path)
    if not p.is_file():
        return "unknown"

    now_ts = time.time() if now is None else now
    try:
        stat = p.stat()
    except OSError:
        return "unknown"
    age = now_ts - stat.st_mtime

    if stat.st_size == 0:
        return "initializing" if age < stall_after_seconds else "stalled"

    # Scan the tail newest-first looking for a terminal marker.
    for line in reversed(_read_tail_lines(p)):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = ev.get("kind", "")
        terminal = _TERMINAL_KIND_TO_STATUS.get(kind)
        if terminal is not None:
            return terminal

    # No terminal marker in the tail window — fall through to liveness check.
    return "running" if age < stall_after_seconds else "stalled"
