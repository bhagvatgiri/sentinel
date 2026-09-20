"""In-memory tracking for long-running scan subprocesses.

One operator, no auth, single process — a dict keyed by job_id is plenty.
Lost on restart; that's intentional (the underlying scan may still finish
on disk and the run JSON appears in runs/).
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Job:
    job_id: str
    argv: list[str]
    started_at: float
    proc: subprocess.Popen
    # 10k lines covers a multi-hour Shannon run (it streams planning + tool
    # calls + LLM responses). Deque drops oldest first when full so the
    # live tail keeps moving.
    log_lines: deque = field(default_factory=lambda: deque(maxlen=10000))
    finished_at: Optional[float] = None
    exit_code: Optional[int] = None
    expected_run_json: Optional[str] = None  # path the CLI is expected to write

    @property
    def is_running(self) -> bool:
        return self.exit_code is None and self.proc.poll() is None

    @property
    def elapsed_sec(self) -> int:
        end = self.finished_at if self.finished_at else time.time()
        return int(end - self.started_at)

    def status(self) -> str:
        if self.is_running:
            return "running"
        return "ok" if self.exit_code == 0 else f"failed (exit {self.exit_code})"

    def tail(self, n: int = 30) -> str:
        return "\n".join(list(self.log_lines)[-n:])


_jobs: dict[str, Job] = {}


def all_jobs() -> list[Job]:
    return sorted(_jobs.values(), key=lambda j: j.started_at, reverse=True)


def get(job_id: str) -> Optional[Job]:
    return _jobs.get(job_id)


def launch(argv: list[str], cwd: str, expected_run_json: Optional[str] = None) -> Job:
    """Spawn the subprocess; spawn a reader thread that drains stdout into the
    job's bounded log buffer. Updates exit_code / finished_at when done.

    Sets SENTINEL_JOB_ID in the child env so the autonomous pentest pipeline
    writes its EventLog to runs/events-<job_id>.jsonl — the dashboard route
    (/agent-runs/<job_id>) reads from that path."""
    job_id = str(uuid.uuid4())[:8]
    env = {**os.environ, "SENTINEL_JOB_ID": job_id}
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )
    job = Job(
        job_id=job_id,
        argv=argv,
        started_at=time.time(),
        proc=proc,
        expected_run_json=expected_run_json,
    )
    _jobs[job.job_id] = job

    def reader() -> None:
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                job.log_lines.append(line.rstrip("\n"))
        finally:
            job.exit_code = proc.wait()
            job.finished_at = time.time()

    threading.Thread(target=reader, daemon=True).start()
    return job


def stop(job_id: str) -> str:
    """SIGTERM, escalate to SIGKILL after 5s. Returns status message."""
    job = _jobs.get(job_id)
    if not job:
        return f"no job {job_id}"
    if not job.is_running:
        return f"job {job_id} already finished"
    pid = job.proc.pid
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return f"PID {pid} already gone"
    for _ in range(20):
        time.sleep(0.25)
        if job.proc.poll() is not None:
            return f"PID {pid} stopped (SIGTERM)"
    try:
        os.kill(pid, signal.SIGKILL)
        return f"PID {pid} killed (SIGKILL escalation)"
    except ProcessLookupError:
        return f"PID {pid} stopped during escalation"


def prune_finished(older_than_sec: int = 3600) -> int:
    """Drop finished jobs older than N seconds. Returns count removed."""
    now = time.time()
    to_drop = [
        jid for jid, j in _jobs.items()
        if j.finished_at and (now - j.finished_at) > older_than_sec
    ]
    for jid in to_drop:
        del _jobs[jid]
    return len(to_drop)


def list_active_runs() -> list[dict]:
    """All runs that are currently active, from BOTH sources.

    Returns dicts (not Job objects) shaped uniformly so the Scan page can
    render them in one section without per-source branching:

        {
          "job_id": str,
          "source": "in-memory" | "external",
          "started_at": float,
          "elapsed_sec": int,
          "status_label": str,         # "Running" / "Failed (...)" / etc.
          "argv_summary": str,         # for in-memory: shlex argv; for external: from event log
          "can_stop": bool,            # only in-memory has Popen we can SIGTERM
          "dashboard_url": str | None, # /agent-runs/<id> for agent-mode runs
          "log_lines_tail": list[str], # for in-memory only
        }

    "External" runs are autonomous-pentest-pipeline subprocesses that
    survived a FastAPI restart — their subprocess is orphaned to PID 1 but
    the EventLog file (runs/events-<job_id>.jsonl) is still being written.
    We discover them by scanning the runs/ dir for event logs whose status
    sniff says "running" AND whose job_id isn't already in `_jobs`.
    """
    import shlex

    from sentinel.agent import event_log as elog

    out: list[dict] = []
    in_mem_ids: set[str] = set(_jobs)

    # 1. In-memory jobs (what we already track).
    for j in _jobs.values():
        if not j.is_running:
            continue
        argv_str = " ".join(shlex.quote(a) for a in j.argv)
        is_agent_mode = (
            len(j.argv) > 1
            and j.argv[1] in ("agent", "scan-autonomous", "brain-grow")
        )
        out.append({
            "job_id": j.job_id,
            "source": "in-memory",
            "started_at": j.started_at,
            "elapsed_sec": j.elapsed_sec,
            "status_label": j.status(),
            "argv_summary": argv_str,
            "can_stop": True,
            "dashboard_url": f"/agent-runs/{j.job_id}" if is_agent_mode else None,
            "log_lines_tail": list(j.log_lines)[-10:],
        })

    # 2. External / orphaned runs — event logs whose subprocess isn't in
    # _jobs but is still actively writing.
    for entry in elog.list_event_logs():
        if entry["job_id"] in in_mem_ids:
            continue
        if entry["status"] != "running":
            continue
        # Pull the started_at + target from the pipeline_started event.
        started_at = entry["mtime"]
        argv_summary = "(orphaned — subprocess survived FastAPI restart)"
        try:
            log_obj = elog.EventLog.load(entry["path"], max_events=200)
            meta = log_obj.grouped()["meta"]
            sp = meta.get("started_payload") or {}
            if meta.get("started_at"):
                started_at = meta["started_at"]
            target = sp.get("target") or sp.get("topic") or "?"
            engagement = sp.get("engagement_id") or ""
            argv_summary = f"agent run · {target}"
            if engagement:
                argv_summary += f" · {engagement}"
        except Exception:
            pass
        out.append({
            "job_id": entry["job_id"],
            "source": "external",
            "started_at": started_at,
            "elapsed_sec": int(time.time() - started_at),
            "status_label": "running (orphaned)",
            "argv_summary": argv_summary,
            "can_stop": False,
            "dashboard_url": f"/agent-runs/{entry['job_id']}",
            "log_lines_tail": [],
        })

    return sorted(out, key=lambda r: r["started_at"], reverse=True)
