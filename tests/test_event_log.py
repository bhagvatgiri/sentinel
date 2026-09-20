"""Unit tests for the structured EventLog used by the agent dashboard."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.agent import event_log as elog


@pytest.fixture
def tmp_log(tmp_path):
    return elog.EventLog(tmp_path / "events.jsonl")


def test_emit_appends_to_disk(tmp_log):
    tmp_log.emit("test_event", foo="bar")
    raw = tmp_log.path.read_text().strip().splitlines()
    assert len(raw) == 1
    parsed = json.loads(raw[0])
    assert parsed["kind"] == "test_event"
    assert parsed["foo"] == "bar"
    assert "ts" in parsed


def test_emit_buffers_in_memory(tmp_log):
    tmp_log.emit("a")
    tmp_log.emit("b")
    tmp_log.emit("c")
    kinds = [e["kind"] for e in tmp_log.all_events()]
    assert kinds == ["a", "b", "c"]


def test_events_since_filter(tmp_log):
    tmp_log.emit("first")
    import time
    cutoff = time.time()
    time.sleep(0.01)
    tmp_log.emit("second")
    fresh = tmp_log.events_since(cutoff)
    assert len(fresh) == 1
    assert fresh[0]["kind"] == "second"


def test_load_reads_existing_file(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text(
        '{"ts": 1.0, "kind": "first"}\n'
        '{"ts": 2.0, "kind": "second"}\n'
    )
    log = elog.EventLog.load(p)
    kinds = [e["kind"] for e in log.all_events()]
    assert kinds == ["first", "second"]


def test_load_skips_malformed_lines(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text(
        '{"ts": 1.0, "kind": "ok"}\n'
        'not json\n'
        '{"ts": 2.0, "kind": "ok2"}\n'
    )
    log = elog.EventLog.load(p)
    kinds = [e["kind"] for e in log.all_events()]
    assert kinds == ["ok", "ok2"]


def test_load_returns_empty_when_file_missing(tmp_path):
    log = elog.EventLog.load(tmp_path / "nope.jsonl")
    assert log.all_events() == []


# ---- grouped() ----------------------------------------------------------

def test_grouped_meta_status_running(tmp_log):
    tmp_log.emit(elog.KIND_PIPELINE_STARTED, target="https://t", engagement_id="eng1")
    g = tmp_log.grouped()
    assert g["meta"]["status"] == "running"
    assert g["meta"]["started_payload"]["target"] == "https://t"


def test_grouped_meta_status_completed(tmp_log):
    tmp_log.emit(elog.KIND_PIPELINE_STARTED, target="https://t")
    tmp_log.emit(elog.KIND_PIPELINE_COMPLETED, total_cost_usd=1.5, total_phases=5,
                  successes=5, total_turns=42)
    g = tmp_log.grouped()
    assert g["meta"]["status"] == "completed"
    assert g["meta"]["completed_payload"]["total_cost_usd"] == 1.5


def test_grouped_phases_running_then_done(tmp_log):
    tmp_log.emit(elog.KIND_PHASE_STARTED, phase="recon", max_turns=20)
    tmp_log.emit(elog.KIND_TOOL_CALLED, phase="recon",
                  tool_name="http_get", args_summary="url='https://x'")
    g = tmp_log.grouped()
    assert len(g["phases"]) == 1
    assert g["phases"][0]["status"] == "running"
    assert g["phases"][0]["current_tool"] == "http_get"

    tmp_log.emit(elog.KIND_PHASE_COMPLETED, phase="recon",
                  duration_sec=10, cost_usd=0.42, turns=8)
    g2 = tmp_log.grouped()
    assert g2["phases"][0]["status"] == "ok"
    assert g2["phases"][0]["cost_usd"] == 0.42
    assert g2["phases"][0]["current_tool"] is None  # cleared on completion


def test_grouped_phases_failed(tmp_log):
    tmp_log.emit(elog.KIND_PHASE_STARTED, phase="exploit:auth")
    tmp_log.emit(elog.KIND_PHASE_FAILED, phase="exploit:auth",
                  error="api 429 throttle", duration_sec=5)
    g = tmp_log.grouped()
    assert g["phases"][0]["status"] == "failed"
    assert "429" in g["phases"][0]["error"]


def test_grouped_phases_ordered_by_start(tmp_log):
    import time
    tmp_log.emit(elog.KIND_PHASE_STARTED, phase="recon")
    time.sleep(0.01)
    tmp_log.emit(elog.KIND_PHASE_STARTED, phase="vuln:auth")
    g = tmp_log.grouped()
    names = [p["name"] for p in g["phases"]]
    assert names == ["recon", "vuln:auth"]


# ---- brain panel --------------------------------------------------------

def test_grouped_brain_in_flight(tmp_log):
    tmp_log.emit(elog.KIND_BRAIN_ENQUEUED, topic="SSRF Next.js", requested_by="vuln:ssrf")
    tmp_log.emit(elog.KIND_BRAIN_STARTED, topic="SSRF Next.js")
    g = tmp_log.grouped()
    assert g["brain"]["in_flight"] == "SSRF Next.js"
    assert g["brain"]["queued"] == []  # moved to in_flight


def test_grouped_brain_completed_clears_in_flight(tmp_log):
    tmp_log.emit(elog.KIND_BRAIN_ENQUEUED, topic="SSRF Next.js")
    tmp_log.emit(elog.KIND_BRAIN_STARTED, topic="SSRF Next.js")
    tmp_log.emit(elog.KIND_BRAIN_COMPLETED, topic="SSRF Next.js",
                  chunks_added=3, cost_usd=0.18)
    g = tmp_log.grouped()
    assert g["brain"]["in_flight"] is None
    assert g["brain"]["chunks_added"] == 3
    assert g["brain"]["total_cost_usd"] == 0.18
    assert len(g["brain"]["processed"]) == 1


def test_grouped_brain_skipped(tmp_log):
    tmp_log.emit(elog.KIND_BRAIN_SKIPPED, topic="dup-topic", reason="already in this session")
    g = tmp_log.grouped()
    assert len(g["brain"]["skipped"]) == 1


def test_grouped_recent_newest_first(tmp_log):
    import time
    tmp_log.emit("a")
    time.sleep(0.001)
    tmp_log.emit("b")
    g = tmp_log.grouped()
    assert g["recent"][0]["kind"] == "b"
    assert g["recent"][1]["kind"] == "a"


# ---- helpers ------------------------------------------------------------

def test_derive_job_id_from_env_set(monkeypatch):
    monkeypatch.setenv("SENTINEL_JOB_ID", "abc12345")
    assert elog.derive_job_id_from_env() == "abc12345"


def test_derive_job_id_sanitizes(monkeypatch):
    monkeypatch.setenv("SENTINEL_JOB_ID", "weird/path; rm -rf $HOME")
    out = elog.derive_job_id_from_env()
    assert "/" not in out
    assert " " not in out
    assert ";" not in out


def test_derive_job_id_default(monkeypatch):
    monkeypatch.delenv("SENTINEL_JOB_ID", raising=False)
    out = elog.derive_job_id_from_env(default="my-default")
    assert out == "my-default"


def test_derive_job_id_falls_back_to_timestamp(monkeypatch):
    monkeypatch.delenv("SENTINEL_JOB_ID", raising=False)
    out = elog.derive_job_id_from_env()
    assert out.startswith("cli-")


def test_list_event_logs_lists_files(tmp_path):
    (tmp_path / "events-job1.jsonl").write_text('{"ts":1,"kind":"pipeline_started"}\n')
    (tmp_path / "events-job2.jsonl").write_text(
        '{"ts":1,"kind":"pipeline_started"}\n'
        '{"ts":2,"kind":"pipeline_completed"}\n'
    )
    (tmp_path / "ignore-me.txt").write_text("not an event log")
    runs = elog.list_event_logs(tmp_path)
    job_ids = sorted(r["job_id"] for r in runs)
    assert job_ids == ["job1", "job2"]
    by_id = {r["job_id"]: r for r in runs}
    assert by_id["job2"]["status"] == "completed"


def test_events_path_creates_runs_dir(tmp_path):
    target = tmp_path / "subdir" / "runs"
    p = elog.events_path("job7", runs_dir=target)
    assert p.parent.is_dir()
    assert p.name == "events-job7.jsonl"


# ---- delete_event_log -----------------------------------------------------


def test_delete_event_log_removes_file_and_tail_buffer(tmp_path):
    main = tmp_path / "events-jobX.jsonl"
    tail0 = tmp_path / "events-jobX.tail.0"
    main.write_text('{"kind":"x"}\n')
    tail0.write_text("buffer")
    other = tmp_path / "events-untouchable.jsonl"
    other.write_text("DO NOT DELETE")

    ok = elog.delete_event_log("jobX", runs_dir=tmp_path)
    assert ok is True
    assert not main.exists()
    assert not tail0.exists()
    assert other.exists(), "delete should not touch siblings"
    assert other.read_text() == "DO NOT DELETE"


def test_delete_event_log_missing_file_returns_false(tmp_path):
    """Idempotent: deleting a non-existent run is not an error."""
    assert elog.delete_event_log("never-existed", runs_dir=tmp_path) is False


def test_delete_event_log_refuses_traversal(tmp_path):
    """A job_id like '../sibling' must not escape runs_dir."""
    parent = tmp_path.parent
    victim = parent / "events-secret.jsonl"
    victim.write_text("must survive")
    try:
        with pytest.raises(ValueError):
            elog.delete_event_log("../events-secret", runs_dir=tmp_path)
        assert victim.exists(), "traversal target must be untouched"
    finally:
        victim.unlink(missing_ok=True)


def test_delete_event_log_refuses_nested_path(tmp_path):
    """A job_id containing a slash should be rejected even if the
    resolved path is technically inside runs_dir — the helper requires
    target.parent == runs_dir exactly."""
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "events-x.jsonl").write_text("nested")
    with pytest.raises(ValueError):
        elog.delete_event_log("nested/x", runs_dir=tmp_path)
