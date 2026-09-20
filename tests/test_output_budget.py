"""Tests for the bounded tool-output budgeting (2026-XX-XX streaming-hang fix).

The contract that matters: large tool output is CAPPED in the agent's context
but the FULL output is persisted to the workspace with an actionable pointer, so
the agent never loses data (the operator's "won't truncation give half-cooked info?"
concern). See sentinel/agent/pentest/output_budget.py.
"""
from __future__ import annotations

from pathlib import Path

from sentinel.agent.pentest.output_budget import (
    persist_and_cap, HTTP_BODY_CAP, BASH_STDOUT_CAP, OUTFILE_CAP,
)


def test_small_output_passes_through_untouched(tmp_path):
    """Under the cap → returned verbatim, no file written, no note."""
    preview, note = persist_and_cap(tmp_path, "small body", 24_000, "x")
    assert preview == "small body"
    assert note == ""
    assert not (tmp_path / ".tool-output").exists()


def test_large_output_capped_persisted_and_pointed(tmp_path):
    """Over the cap → preview is exactly `cap` chars, full text on disk, note
    tells the agent the path + how to read the rest."""
    big = "X" * 60_000
    preview, note = persist_and_cap(tmp_path, big, 24_000, "http_example.com")
    assert len(preview) == 24_000
    assert preview == big[:24_000]
    # note is actionable
    assert "read_file" in note
    assert "60,000" in note and "24,000" in note
    assert ".tool-output" in note
    # full fidelity preserved on disk
    saved = list((tmp_path / ".tool-output").glob("*.txt"))
    assert len(saved) == 1
    assert saved[0].read_text() == big, "persisted output must be byte-identical"


def test_no_data_lost_preview_is_prefix_of_full(tmp_path):
    """The preview must be a true prefix of the persisted full output."""
    full = "".join(f"line{i}\n" for i in range(5000))
    preview, _ = persist_and_cap(tmp_path, full, 1000, "bash_stdout_nuclei")
    saved = (tmp_path / ".tool-output").glob("*.txt").__next__().read_text()
    assert saved.startswith(preview)
    assert saved == full


def test_empty_output_is_safe(tmp_path):
    for val in ("", None):
        preview, note = persist_and_cap(tmp_path, val, 100, "x")
        assert preview == ""
        assert note == ""


def test_filename_is_sanitized(tmp_path):
    """A hostile name can't escape .tool-output via path chars."""
    big = "Y" * 30_000
    persist_and_cap(tmp_path, big, 100, "../../etc/passwd http://evil/")
    saved = list((tmp_path / ".tool-output").glob("*.txt"))
    assert len(saved) == 1
    assert saved[0].parent == tmp_path / ".tool-output"


def test_persist_failure_never_raises_and_still_caps(tmp_path):
    """If the workspace path is unwritable, still return a capped preview +
    a note (degrade, never crash the tool call)."""
    bad = tmp_path / "is_a_file"
    bad.write_text("not a dir")
    preview, note = persist_and_cap(bad, "Z" * 50_000, 1000, "x")
    assert len(preview) == 1000
    assert "CAPPED" in note  # told the agent it was truncated


def test_caps_are_context_sane():
    """Guard against a future edit re-bloating the caps back to streaming-stall
    territory (the bug was 200KB/80KB/40KB)."""
    assert HTTP_BODY_CAP <= 32_000
    assert BASH_STDOUT_CAP <= 32_000
    assert OUTFILE_CAP <= 24_000
