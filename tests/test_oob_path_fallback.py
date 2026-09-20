"""Hermetic test for interactsh-client PATH fallback in _OobSession.start().

When `shutil.which("interactsh-client")` returns None (e.g. $(go env GOPATH)/bin
isn't on the scan subprocess's PATH), the session should fall back to
`$GOPATH/bin/interactsh-client` (or `$GOBIN/interactsh-client`) before raising.
This was a silent failure mode on the live ExampleChat scan — the binary was installed
at /Users/bhagvatgiri/go/bin/interactsh-client but the scan PATH didn't include
GOPATH/bin, so SSRF blind verifier crashed with "interactsh-client not on PATH".
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _reset_oob_singletons():
    from sentinel.agent.pentest import oob_tool
    oob_tool._SESSIONS_BY_JOB.clear()
    yield
    oob_tool._SESSIONS_BY_JOB.clear()


@pytest.mark.asyncio
async def test_start_falls_back_to_gopath_bin_when_not_on_path(tmp_path, monkeypatch):
    """shutil.which returns None → fallback to $GOPATH/bin/interactsh-client."""
    from sentinel.agent.pentest import oob_tool

    # Simulate GOPATH/bin/interactsh-client existing on disk.
    fake_gopath = tmp_path / "go"
    bin_dir = fake_gopath / "bin"
    bin_dir.mkdir(parents=True)
    fake_binary = bin_dir / "interactsh-client"
    fake_binary.write_text("#!/bin/sh\necho stub\n")
    fake_binary.chmod(0o755)

    # shutil.which → None (PATH miss)
    monkeypatch.setattr(oob_tool.shutil, "which", lambda name: None)
    # GOPATH points at our tmpdir
    monkeypatch.setenv("GOPATH", str(fake_gopath))
    monkeypatch.delenv("GOBIN", raising=False)

    # Stub asyncio subprocess creation so we don't actually exec.
    captured_binary = {}

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured_binary["path"] = args[0]
        proc = MagicMock()
        proc.returncode = None
        proc.stdout = MagicMock()

        async def fake_readline():
            await asyncio.sleep(10)  # never produces a line during the test
            return b""

        proc.stdout.readline = fake_readline
        return proc

    monkeypatch.setattr(
        oob_tool.asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    session = oob_tool._OobSession(job_id="test")
    await session.start()

    assert captured_binary["path"] == str(fake_binary), (
        f"Expected fallback to GOPATH/bin/interactsh-client, got {captured_binary}"
    )
    assert session._started is True

    # Tidy: cancel the reader task we just spawned so pytest doesn't warn.
    if session._reader_task:
        session._reader_task.cancel()


@pytest.mark.asyncio
async def test_start_falls_back_to_gobin_when_set(tmp_path, monkeypatch):
    """If GOBIN is set, prefer that over $GOPATH/bin."""
    from sentinel.agent.pentest import oob_tool

    fake_gobin = tmp_path / "custom-gobin"
    fake_gobin.mkdir(parents=True)
    fake_binary = fake_gobin / "interactsh-client"
    fake_binary.write_text("#!/bin/sh\necho stub\n")
    fake_binary.chmod(0o755)

    monkeypatch.setattr(oob_tool.shutil, "which", lambda name: None)
    monkeypatch.setenv("GOBIN", str(fake_gobin))
    monkeypatch.setenv("GOPATH", str(tmp_path / "wrong-gopath"))

    captured_binary = {}

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured_binary["path"] = args[0]
        proc = MagicMock()
        proc.returncode = None
        proc.stdout = MagicMock()

        async def fake_readline():
            await asyncio.sleep(10)
            return b""

        proc.stdout.readline = fake_readline
        return proc

    monkeypatch.setattr(
        oob_tool.asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    session = oob_tool._OobSession(job_id="test")
    await session.start()

    assert captured_binary["path"] == str(fake_binary), (
        f"Expected fallback to GOBIN/interactsh-client, got {captured_binary}"
    )

    if session._reader_task:
        session._reader_task.cancel()


@pytest.mark.asyncio
async def test_start_raises_when_neither_path_nor_gopath_have_binary(
    tmp_path, monkeypatch
):
    """No PATH hit AND no GOPATH/bin binary → RuntimeError with helpful message."""
    from sentinel.agent.pentest import oob_tool

    monkeypatch.setattr(oob_tool.shutil, "which", lambda name: None)
    # Point GOPATH at an empty dir so the binary doesn't exist.
    empty_gopath = tmp_path / "empty"
    (empty_gopath / "bin").mkdir(parents=True)
    monkeypatch.setenv("GOPATH", str(empty_gopath))
    monkeypatch.delenv("GOBIN", raising=False)

    session = oob_tool._OobSession(job_id="test")

    with pytest.raises(RuntimeError, match="interactsh-client"):
        await session.start()


@pytest.mark.asyncio
async def test_start_defaults_gopath_to_home_go_when_unset(tmp_path, monkeypatch):
    """If neither GOPATH nor GOBIN is set, default GOPATH to ~/go."""
    from sentinel.agent.pentest import oob_tool

    # Build ~/go/bin/interactsh-client inside tmp_path-as-home.
    fake_home = tmp_path / "home"
    bin_dir = fake_home / "go" / "bin"
    bin_dir.mkdir(parents=True)
    fake_binary = bin_dir / "interactsh-client"
    fake_binary.write_text("#!/bin/sh\necho stub\n")
    fake_binary.chmod(0o755)

    monkeypatch.setattr(oob_tool.shutil, "which", lambda name: None)
    monkeypatch.delenv("GOPATH", raising=False)
    monkeypatch.delenv("GOBIN", raising=False)
    monkeypatch.setenv("HOME", str(fake_home))

    captured_binary = {}

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured_binary["path"] = args[0]
        proc = MagicMock()
        proc.returncode = None
        proc.stdout = MagicMock()

        async def fake_readline():
            await asyncio.sleep(10)
            return b""

        proc.stdout.readline = fake_readline
        return proc

    monkeypatch.setattr(
        oob_tool.asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    session = oob_tool._OobSession(job_id="test")
    await session.start()

    assert captured_binary["path"] == str(fake_binary), (
        f"Expected default ~/go/bin/interactsh-client fallback, got {captured_binary}"
    )

    if session._reader_task:
        session._reader_task.cancel()
