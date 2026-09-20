"""Wave 2 / A7 — Ctrl+C reconcile tests.

Asserted properties:
  - SIGINT mid-tool-call leaves a synthetic tool_result for every
    in-flight tool_call_id.
  - Persisted checkpoint round-trips: write → load → consume.
  - Resume from the saved buffer does not 400 (no unmatched
    tool_use_ids — verified via `buffer_has_unmatched_tool_uses`).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.agent.pentest.ctrlc_reconcile import (
    InFlightTool,
    SYNTHETIC_INTERRUPT_TEXT,
    buffer_has_unmatched_tool_uses,
    consume_checkpoint,
    load_checkpoint,
    reconcile_in_flight,
    synthesize_tool_result,
    write_checkpoint,
)


def _mk_in_flight(*ids: str) -> dict[str, InFlightTool]:
    return {
        i: InFlightTool(tool_use_id=i, tool_name=f"tool_{i}", started_at=0.0)
        for i in ids
    }


def test_synthesize_single_tool_result():
    t = InFlightTool(tool_use_id="abc123", tool_name="run_bash", started_at=0.0)
    out = synthesize_tool_result(t)
    assert out["tool_use_id"] == "abc123"
    assert out["tool_call_id"] == "abc123"  # both aliases
    assert out["role"] == "tool"
    assert out["is_error"] is True
    assert out["_synthetic"] is True
    assert SYNTHETIC_INTERRUPT_TEXT in out["content"][0]["text"]


def test_reconcile_produces_one_entry_per_in_flight():
    in_flight = _mk_in_flight("a", "b", "c")
    rr = reconcile_in_flight(in_flight=in_flight, phase="vuln:auth")
    assert rr.in_flight_count == 3
    assert len(rr.synthetic_results) == 3
    ids = [r["tool_use_id"] for r in rr.synthetic_results]
    assert sorted(ids) == ["a", "b", "c"]


def test_reconcile_empty_in_flight():
    rr = reconcile_in_flight(in_flight={}, phase="recon")
    assert rr.synthetic_results == []
    assert rr.in_flight_count == 0


def test_write_then_load_checkpoint(tmp_path: Path):
    in_flight = _mk_in_flight("u-1", "u-2")
    rr = reconcile_in_flight(in_flight=in_flight, phase="vuln:auth")
    cp_path = write_checkpoint(tmp_path, "vuln:auth", rr)
    assert cp_path.exists()
    loaded = load_checkpoint(tmp_path, "vuln:auth")
    assert loaded is not None
    assert loaded["in_flight_count"] == 2
    assert loaded["phase"] == "vuln:auth"
    ids = [r["tool_use_id"] for r in loaded["synthetic_results"]]
    assert sorted(ids) == ["u-1", "u-2"]


def test_phase_name_with_colon_is_safe_filename(tmp_path: Path):
    """`vuln:auth` should land at `vuln_auth.json` so the filesystem
    accepts it. Resume must read using the same sanitization."""
    in_flight = _mk_in_flight("u-1")
    rr = reconcile_in_flight(in_flight=in_flight, phase="vuln:auth")
    cp_path = write_checkpoint(tmp_path, "vuln:auth", rr)
    assert ":" not in cp_path.name
    # Resume sanitizes the same way.
    assert load_checkpoint(tmp_path, "vuln:auth") is not None


def test_consume_checkpoint_deletes_after_read(tmp_path: Path):
    in_flight = _mk_in_flight("u-1")
    rr = reconcile_in_flight(in_flight=in_flight, phase="recon")
    write_checkpoint(tmp_path, "recon", rr)
    payload = consume_checkpoint(tmp_path, "recon")
    assert payload is not None
    # Second read returns None — file deleted.
    assert load_checkpoint(tmp_path, "recon") is None
    assert consume_checkpoint(tmp_path, "recon") is None


def test_load_missing_returns_none(tmp_path: Path):
    assert load_checkpoint(tmp_path, "no_such_phase") is None


def test_buffer_unmatched_detection():
    """Pre-reconcile: buffer has unmatched tool_uses → list is non-empty.
    Post-reconcile: synthetic results applied → list is empty."""
    buffer = [
        {"role": "user", "content": "scan target"},
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "tu-1", "name": "run_bash", "input": {}},
            {"type": "tool_use", "id": "tu-2", "name": "http_get", "input": {}},
        ]},
        # Operator Ctrl+C'd here: no tool_result for tu-1 or tu-2.
    ]
    unmatched = buffer_has_unmatched_tool_uses(buffer)
    assert sorted(unmatched) == ["tu-1", "tu-2"]

    # Apply synthetic results.
    in_flight = _mk_in_flight("tu-1", "tu-2")
    rr = reconcile_in_flight(in_flight=in_flight, phase="vuln:auth")
    buffer.extend(rr.synthetic_results)
    # Now no unmatched ids remain.
    assert buffer_has_unmatched_tool_uses(buffer) == []


def test_buffer_with_native_tool_result_blocks():
    """Buffer using Anthropic's native tool_result block shape (the
    common case after a normal turn) should also resolve correctly."""
    buffer = [
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "tu-1", "name": "x", "input": {}},
        ]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "tu-1", "content": "ok"},
        ]},
    ]
    assert buffer_has_unmatched_tool_uses(buffer) == []


def test_reconciled_buffer_is_json_serializable(tmp_path: Path):
    """The persisted JSON must round-trip cleanly so `--resume` can
    parse it."""
    in_flight = _mk_in_flight("u-1", "u-2")
    rr = reconcile_in_flight(in_flight=in_flight, phase="recon")
    write_checkpoint(tmp_path, "recon", rr)
    raw = (tmp_path / ".resume" / "recon.json").read_text()
    parsed = json.loads(raw)
    assert parsed["schema"] == "sentinel.ctrlc_reconcile.v1"
    assert parsed["synthetic_results"][0]["role"] == "tool"
