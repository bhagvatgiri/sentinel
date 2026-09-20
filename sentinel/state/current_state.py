"""Synthesize a human-readable session-continuity snapshot from on-disk artifacts.

`CURRENT_STATE.md` lives at the project root and rolls up:

- Engagement progress matrices (`workspaces/*/.completed_phases.json`)
- H1 submission queue (`workspaces/*/deliverables/h1-submissions/*.md`)
- Recent runs (`runs/<client>-<engagement>.json`)
- Recent phase activity (last `phase_*` events from `runs/events-*.jsonl`)
- Memory index (`<memory_dir>/MEMORY.md`)

Every input source already exists for other reasons; this module only
synthesizes — it does NOT introduce a new persistence layer.

Two entry points:

- `build_snapshot(project_dir)` → dict (testable; deterministic given inputs)
- `update_current_state(project_dir)` → Path (writes the rendered markdown)

The pipeline calls `update_current_state` from a phase-end hook so the
file stays fresh as work progresses. The `sentinel state --show` CLI
just reads the existing file (or builds a fresh one with `--update`).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


log = logging.getLogger(__name__)


CURRENT_STATE_FILENAME = "CURRENT_STATE.md"
DEFAULT_MAX_ENGAGEMENTS = 10
DEFAULT_MAX_RUNS = 5
DEFAULT_MAX_PHASE_EVENTS = 10
DEFAULT_MAX_MEMORY_ENTRIES = 12
DEFAULT_MEMORY_DIR = (
    "/Users/bhagvatgiri/.claude/projects/"
    "-Users-bhagvatgiri-Documents-Claude-Projects-Cyber-agent/memory"
)

# ---- STATE-03 blocked-H1 pacing -----------------------------------------
#
# H1 submission pacing rule (memory `feedback_h1_submission_pacing.md`):
# space submissions to the same H1 program across HOURS, not minutes, so
# triage doesn't auto-flag the batch as automation. Default 4h; overridable
# via `~/.sentinel/notify.yaml` (`h1_pacing_hours: N`) or the
# `sentinel state --update --pacing-hours N` CLI flag.

DEFAULT_H1_PACING_HOURS = 4
H1_PACING_HOURS_MIN = 1
H1_PACING_HOURS_MAX = 168  # one week — clamp prevents pathological config

# Status tokens that mean "the H1 program already has this report; pacing
# is gated against the most-recent one with one of these tokens". Compare
# case-insensitively via substring match (handles `submitted (H1-1234)`,
# `triaged 2026-XX-XX`, etc.).
SUBMITTED_STATUS_TOKENS = frozenset(
    {"submitted", "closed", "accepted", "triaged", "duplicate", "n/a", "informative"}
)


# ---- snapshot synthesis ---------------------------------------------------


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(p: Path) -> Optional[dict]:
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _scan_h1_reports(h1_dir: Path) -> list[dict]:
    """Read each .md file under `h1-submissions/` and extract title + status.

    Recognized status field formats (any one matches):
      - `**Status:** Ready to submit — ...`
      - `Status: drafted`
      - `> **Status:** submitted (H1-NNNN)`

    Falls back to "drafted" if nothing matches.
    """
    if not h1_dir.is_dir():
        return []
    out: list[dict] = []
    for md in sorted(h1_dir.glob("*.md")):
        # Skip the AUTHORIZATION grant artifact and any non-report markdown.
        if md.name.startswith("AUTHORIZATION") or md.name.startswith("00-"):
            continue
        try:
            text = md.read_text(errors="replace")
        except OSError:
            continue
        title = _extract_title(text) or md.stem
        status = _extract_status(text)
        try:
            mtime_epoch = int(md.stat().st_mtime)
        except OSError:
            mtime_epoch = 0
        out.append(
            {
                "file": md.name,
                "title": title,
                "status": status,
                "mtime_epoch": mtime_epoch,
            }
        )
    return out


_TITLE_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
_STATUS_RE = re.compile(
    r"\*{0,2}Status:\*{0,2}\s+([A-Za-z][^\n*]+?)(?:\s*[-—]|\s*$|\n)",
    re.IGNORECASE,
)


def _extract_title(text: str) -> Optional[str]:
    m = _TITLE_RE.search(text)
    if not m:
        return None
    raw = m.group(1).strip()
    # Drop leading "H1 Report —" / "H1 Submission —" prefixes for brevity.
    return re.sub(r"^H1\s+(Report|Submission)\s*[—\-:]\s*", "", raw)


def _extract_status(text: str) -> str:
    m = _STATUS_RE.search(text)
    if not m:
        return "drafted"
    s = m.group(1).strip().rstrip(".,;")
    return s


def _is_submitted(status: Optional[str]) -> bool:
    """True iff `status` indicates the H1 report has reached the platform.

    Substring (case-insensitive) match against `SUBMITTED_STATUS_TOKENS`.
    `submitted (H1-1234)` matches via the "submitted" token; `triaged at...`
    matches via "triaged"; etc. Drafted-ish statuses (`drafted`, `Ready to
    submit`, empty, None) return False.
    """
    s = (status or "").lower()
    if not s:
        return False
    return any(tok in s for tok in SUBMITTED_STATUS_TOKENS)


def _load_pacing_hours_from_yaml() -> int:
    """Read `~/.sentinel/notify.yaml` → `h1_pacing_hours` (default 4).

    Best-effort. Returns `DEFAULT_H1_PACING_HOURS` on any failure (missing
    file, missing key, unparseable YAML, PyYAML not installed). Clamped to
    `[H1_PACING_HOURS_MIN, H1_PACING_HOURS_MAX]` to prevent pathological
    config (e.g. negative, zero, or week+ values).
    """
    path = Path.home() / ".sentinel" / "notify.yaml"
    if not path.is_file():
        return DEFAULT_H1_PACING_HOURS
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return DEFAULT_H1_PACING_HOURS
    try:
        data = yaml.safe_load(path.read_text(errors="replace")) or {}
    except (OSError, Exception):  # yaml.YAMLError + any IO failure
        return DEFAULT_H1_PACING_HOURS
    if not isinstance(data, dict):
        return DEFAULT_H1_PACING_HOURS
    try:
        raw = int(data.get("h1_pacing_hours", DEFAULT_H1_PACING_HOURS))
    except (TypeError, ValueError):
        return DEFAULT_H1_PACING_HOURS
    return max(H1_PACING_HOURS_MIN, min(H1_PACING_HOURS_MAX, raw))


def _scan_blocked_h1_submissions(
    engagements: list[dict],
    *,
    pacing_hours: int,
    now_epoch: Optional[float] = None,
) -> list[dict]:
    """Return drafted H1 reports whose pacing window has elapsed.

    For each engagement:
      - Find the most-recent submitted report (`_is_submitted(status)` true).
      - For each drafted report (`_is_submitted` false):
        * If a submitted report exists and `now - last_submitted_mtime >=
          pacing_hours * 3600` → blocked, reason `pacing-elapsed`.
        * If NO submitted report exists and `now - drafted_mtime >=
          pacing_hours * 3600` → blocked, reason `no-prior-submission`.
        * Otherwise → not blocked (pacing window still ticking, or operator
          just drafted the file — give them a moment).

    `pacing_hours` is REQUIRED kwarg — callers must pass it explicitly.
    This is the hermeticity contract: tests cannot accidentally pick up the
    operator's real `~/.sentinel/notify.yaml` via this code path.

    `now_epoch` defaults to `time.time()` but tests inject a fixed value for
    deterministic age calculation.

    Returns rows shaped:
        {
            "engagement_id": str,
            "file": str,
            "title": str,
            "status": str,
            "reason": "pacing-elapsed" | "no-prior-submission",
            "drafted_age_hours": int,
        }
    """
    now = float(now_epoch if now_epoch is not None else time.time())
    threshold_sec = pacing_hours * 3600.0
    blocked: list[dict] = []
    for eng in engagements or []:
        reports = list(eng.get("h1_reports") or [])
        if not reports:
            continue
        # Most-recent submitted report's mtime (None if no submission yet).
        submitted_mtimes = [
            float(r.get("mtime_epoch") or 0.0)
            for r in reports
            if _is_submitted(r.get("status"))
        ]
        last_submitted = max(submitted_mtimes) if submitted_mtimes else None

        for r in reports:
            if _is_submitted(r.get("status")):
                continue
            drafted_mtime = float(r.get("mtime_epoch") or 0.0)
            if last_submitted is not None:
                age_sec = now - last_submitted
                reason = "pacing-elapsed"
            else:
                age_sec = now - drafted_mtime
                reason = "no-prior-submission"
            if age_sec < threshold_sec:
                continue
            drafted_age_hours = int(max(0.0, (now - drafted_mtime) / 3600.0))
            blocked.append(
                {
                    "engagement_id": eng.get("id", "?"),
                    "file": r.get("file", "?"),
                    "title": r.get("title", "") or "",
                    "status": r.get("status", "") or "",
                    "reason": reason,
                    "drafted_age_hours": drafted_age_hours,
                }
            )
    return blocked


def _scan_engagement(ws_dir: Path) -> dict:
    completed_path = ws_dir / ".completed_phases.json"
    completed: list[str] = []
    last_phase = ""
    metadata: dict = {}
    if completed_path.is_file():
        data = _read_json(completed_path) or {}
        completed = list(data.get("completed", []) or data.get("phases", []))
        last_phase = data.get("last_phase") or (completed[-1] if completed else "")
        metadata = data.get("metadata") or {}
    deliv_dir = ws_dir / "deliverables"
    n_deliverables = 0
    if deliv_dir.is_dir():
        n_deliverables = len(list(deliv_dir.glob("*.md")))
    h1_dir = deliv_dir / "h1-submissions"
    h1_reports = _scan_h1_reports(h1_dir)
    mtime = datetime.fromtimestamp(ws_dir.stat().st_mtime, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M"
    )
    return {
        "id": ws_dir.name,
        "ws_path": str(ws_dir),
        "completed_phases": completed,
        "last_phase": last_phase,
        "n_completed_phases": len(completed),
        "metadata": metadata,
        "n_deliverables_md": n_deliverables,
        "h1_reports": h1_reports,
        "mtime": mtime,
    }


def _scan_workspaces(workspaces_root: Path, max_count: int) -> list[dict]:
    if not workspaces_root.is_dir():
        return []
    out: list[dict] = []
    for ws in workspaces_root.iterdir():
        if not ws.is_dir():
            continue
        try:
            out.append(_scan_engagement(ws))
        except OSError as exc:
            log.warning("skip workspace %s: %s", ws.name, exc)
    out.sort(key=lambda e: e["mtime"], reverse=True)
    return out[:max_count]


def _scan_runs(runs_dir: Path, max_count: int) -> list[dict]:
    if not runs_dir.is_dir():
        return []
    out: list[dict] = []
    for jf in runs_dir.glob("*.json"):
        data = _read_json(jf)
        if not isinstance(data, dict):
            continue
        scope = data.get("scope") or {}
        out.append(
            {
                "filename": jf.name,
                "client": scope.get("client", "?"),
                "engagement": scope.get("engagement_id", "?"),
                "n_findings": len(data.get("findings") or []),
                "n_errors": len(data.get("errors") or []),
                "mtime_epoch": jf.stat().st_mtime,
                "mtime": datetime.fromtimestamp(
                    jf.stat().st_mtime, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M"),
            }
        )
    out.sort(key=lambda r: r["mtime_epoch"], reverse=True)
    return out[:max_count]


_PHASE_KINDS = {"phase_started", "phase_completed", "phase_failed", "phase_skipped_resume"}


def _scan_recent_phase_events(runs_dir: Path, max_count: int) -> list[dict]:
    if not runs_dir.is_dir():
        return []
    files = sorted(
        runs_dir.glob("events-*.jsonl"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:5]  # only walk the 5 most-recent event logs
    rows: list[dict] = []
    for log_path in files:
        engagement = _engagement_from_event_log_name(log_path.name)
        try:
            tail = log_path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        # Walk last 200 lines per file to find phase events.
        for line in tail[-200:]:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = ev.get("kind")
            if kind not in _PHASE_KINDS:
                continue
            ts_epoch = float(ev.get("ts") or 0.0)
            rows.append(
                {
                    "ts_epoch": ts_epoch,
                    "ts": datetime.fromtimestamp(
                        ts_epoch, tz=timezone.utc
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                    "kind": kind,
                    "phase": ev.get("phase", "?"),
                    "engagement": engagement,
                }
            )
    rows.sort(key=lambda r: r["ts_epoch"], reverse=True)
    return rows[:max_count]


_EVENT_LOG_RE = re.compile(r"^events-(?:cli-)?(?P<eng>.+?)-\d+\.jsonl$")


def _engagement_from_event_log_name(name: str) -> str:
    m = _EVENT_LOG_RE.match(name)
    return m.group("eng") if m else "?"


def _scan_memory_index(memory_dir: Path, max_count: int) -> list[dict]:
    """Read MEMORY.md (a flat index) and return up to `max_count` entries."""
    if not memory_dir.is_dir():
        return []
    idx_path = memory_dir / "MEMORY.md"
    if not idx_path.is_file():
        return []
    try:
        lines = idx_path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    out: list[dict] = []
    line_re = re.compile(r"^- \[(?P<title>.+?)\]\((?P<file>[^)]+)\)\s*[—\-]\s*(?P<hook>.+)$")
    for line in lines:
        m = line_re.match(line.strip())
        if not m:
            continue
        out.append(
            {
                "title": m.group("title"),
                "file": m.group("file"),
                "hook": m.group("hook"),
            }
        )
        if len(out) >= max_count:
            break
    return out


# ---- public API -----------------------------------------------------------


def build_snapshot(
    project_dir: str | Path,
    *,
    workspaces_root: Optional[str | Path] = None,
    runs_dir: Optional[str | Path] = None,
    memory_dir: Optional[str | Path] = None,
    pacing_hours: Optional[int] = None,
    max_engagements: int = DEFAULT_MAX_ENGAGEMENTS,
    max_runs: int = DEFAULT_MAX_RUNS,
    max_phase_events: int = DEFAULT_MAX_PHASE_EVENTS,
    max_memory_entries: int = DEFAULT_MAX_MEMORY_ENTRIES,
) -> dict:
    """Build a snapshot dict from project-relative artifacts.

    Pure function (deterministic given inputs). All paths default off
    `project_dir`. Returns a JSON-serializable dict.

    STATE-03 hermeticity contract: when `pacing_hours` is passed
    explicitly, `_load_pacing_hours_from_yaml()` is NEVER invoked. Tests
    rely on this — every test exercising the blocked-H1 LOGIC passes
    `pacing_hours=N` explicitly so the operator's real `~/.sentinel/
    notify.yaml` cannot leak in. Only when `pacing_hours is None` does
    the loader fall back to the YAML file (or `DEFAULT_H1_PACING_HOURS`).
    """
    root = Path(project_dir).expanduser().resolve()
    ws_root = Path(workspaces_root) if workspaces_root else (root / "workspaces")
    runs_root = Path(runs_dir) if runs_dir else (root / "runs")
    mem_root = Path(memory_dir) if memory_dir else Path(DEFAULT_MEMORY_DIR)

    effective_pacing = (
        int(pacing_hours)
        if pacing_hours is not None
        else _load_pacing_hours_from_yaml()
    )

    engagements = _scan_workspaces(ws_root, max_engagements)
    blocked_h1 = _scan_blocked_h1_submissions(
        engagements, pacing_hours=effective_pacing
    )

    return {
        "generated_at": _now_iso_utc(),
        "project_root": str(root),
        "engagements": engagements,
        "recent_runs": _scan_runs(runs_root, max_runs),
        "recent_phase_events": _scan_recent_phase_events(runs_root, max_phase_events),
        "memory_index": _scan_memory_index(mem_root, max_memory_entries),
        "blocked_h1_submissions": blocked_h1,
        "h1_pacing_hours": effective_pacing,
    }


def render_markdown(snapshot: dict) -> str:
    """Render a snapshot dict as the human-readable CURRENT_STATE.md body."""
    lines: list[str] = []
    lines.append("# Sentinel — Current State")
    lines.append("")
    lines.append(
        f"_Generated {snapshot['generated_at']} from `{snapshot['project_root']}`._  "
    )
    lines.append(
        "_This file is auto-rolled by `sentinel state --update` and the pipeline phase-end hook. "
        "Edit-by-hand changes will be overwritten on next refresh._"
    )
    lines.append("")

    engagements = snapshot.get("engagements") or []
    h1_rows: list[tuple[str, str, str, str]] = []
    lines.append("## Active engagements")
    lines.append("")
    if not engagements:
        lines.append("_No workspaces found under `workspaces/`._")
    else:
        lines.append(
            "| Engagement | Last phase | Phases | Deliverables | H1 reports | Updated |"
        )
        lines.append("|---|---|---:|---:|---:|---|")
        for e in engagements:
            n_h1 = len(e.get("h1_reports") or [])
            lines.append(
                f"| `{e['id']}` | "
                f"{e['last_phase'] or '_—_'} | "
                f"{e['n_completed_phases']} | "
                f"{e['n_deliverables_md']} | "
                f"{n_h1} | "
                f"{e['mtime']} |"
            )
            for r in e.get("h1_reports") or []:
                h1_rows.append((e["id"], r["file"], r["title"], r["status"]))
    lines.append("")

    lines.append("## H1 submission queue")
    lines.append("")
    if not h1_rows:
        lines.append("_No `h1-submissions/*.md` reports drafted yet._")
    else:
        lines.append("| Engagement | File | Title | Status |")
        lines.append("|---|---|---|---|")
        for eng_id, fname, title, status in h1_rows:
            title_short = title if len(title) <= 80 else (title[:77] + "…")
            lines.append(f"| `{eng_id}` | `{fname}` | {title_short} | {status} |")
    lines.append("")

    # STATE-03: drafted reports whose pacing window has elapsed.
    pacing_h = snapshot.get("h1_pacing_hours", DEFAULT_H1_PACING_HOURS)
    blocked = snapshot.get("blocked_h1_submissions") or []
    lines.append(f"## Blocked H1 submissions (pacing: {pacing_h}h)")
    lines.append("")
    if not blocked:
        lines.append("_No H1 submissions blocked on pacing._")
    else:
        lines.append("| Engagement | File | Title | Status | Reason | Drafted |")
        lines.append("|---|---|---|---|---|---:|")
        for b in blocked:
            title_short = (b["title"] if len(b["title"]) <= 60
                           else (b["title"][:57] + "…"))
            lines.append(
                f"| `{b['engagement_id']}` | `{b['file']}` | "
                f"{title_short} | {b['status']} | "
                f"{b['reason']} | {b['drafted_age_hours']}h |"
            )
    lines.append("")

    runs = snapshot.get("recent_runs") or []
    lines.append("## Recent runs")
    lines.append("")
    if not runs:
        lines.append("_No `runs/*.json` files found._")
    else:
        lines.append("| Run | Client | Engagement | Findings | Errors | Modified |")
        lines.append("|---|---|---|---:|---:|---|")
        for r in runs:
            lines.append(
                f"| `{r['filename']}` | "
                f"{r['client']} | "
                f"{r['engagement']} | "
                f"{r['n_findings']} | "
                f"{r['n_errors']} | "
                f"{r['mtime']} |"
            )
    lines.append("")

    events = snapshot.get("recent_phase_events") or []
    lines.append("## Recent phase activity")
    lines.append("")
    if not events:
        lines.append("_No `runs/events-*.jsonl` phase events found._")
    else:
        lines.append("| Time (UTC) | Engagement | Phase | Event |")
        lines.append("|---|---|---|---|")
        for ev in events:
            lines.append(
                f"| {ev['ts']} | `{ev['engagement']}` | {ev['phase']} | "
                f"{ev['kind']} |"
            )
    lines.append("")

    mem = snapshot.get("memory_index") or []
    lines.append("## Memory index (top entries)")
    lines.append("")
    if not mem:
        lines.append("_No memory directory or empty `MEMORY.md`._")
    else:
        for item in mem:
            lines.append(f"- **{item['title']}** — {item['hook']}")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "Refresh manually: `sentinel state --update`. "
        "Auto-refresh on phase completion is wired into "
        "`sentinel/agent/pentest/pipeline.py` (best-effort, never blocks pipeline)."
    )
    lines.append("")
    return "\n".join(lines)


def update_current_state(
    project_dir: str | Path,
    *,
    output_path: Optional[str | Path] = None,
    **kwargs,
) -> Path:
    """Build a fresh snapshot, render it, write `CURRENT_STATE.md`. Return the path."""
    snap = build_snapshot(project_dir, **kwargs)
    md = render_markdown(snap)
    target = (
        Path(output_path).expanduser()
        if output_path
        else Path(project_dir).expanduser().resolve() / CURRENT_STATE_FILENAME
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(md)
    return target


def update_current_state_with_status(
    project_dir: str | Path, **kwargs
) -> tuple[Optional[Path], Optional[str]]:
    """Best-effort update — never raises. Returns `(path, err)`.

    - On success: `(Path, None)` — `Path` is the file just written.
    - On failure: `(None, str)` — `str` is a non-empty error description
      (the exception's `str()` form) so the caller can surface it via a
      structured event (`state_update_failed` reason=...).

    Used by the pipeline phase-end hook (`_refresh_current_state_with_events`)
    and by `sentinel state --update` to surface why a refresh failed without
    blocking the operator.
    """
    try:
        path = update_current_state(project_dir, **kwargs)
        return path, None
    except Exception as exc:  # noqa: BLE001
        # log.debug here, NOT log.warning — this is best-effort and the caller
        # is responsible for surfacing the failure (via event_log emission).
        log.debug("CURRENT_STATE.md refresh failed: %s", exc)
        return None, str(exc)


def update_current_state_safe(project_dir: str | Path, **kwargs) -> Optional[Path]:
    """Backward-compatible thin wrapper around `update_current_state_with_status`.

    Callers that don't care about the error reason (e.g. the FastAPI route
    in `sentinel/web/routes/state.py`) keep their existing return-shape
    contract: `Path | None`.
    """
    path, _err = update_current_state_with_status(project_dir, **kwargs)
    return path
