"""B16 — Memory analysis agent tests.

Real volatility3 dumps are 4-32GB and impractical for CI. We assert on:
  - schema/shape of every entrypoint
  - graceful degradation when vol3 isn't installed
  - workspace path traversal block
  - the built-in `dump_strings` fallback works on any file
  - vol3 plugin invocation is correctly mocked when available
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

import sentinel.agent.pentest.memory_analysis as mem


# ---- shape / registration ------------------------------------------------

def test_module_has_expected_tools():
    assert callable(mem.list_processes)
    assert callable(mem.extract_credentials)
    assert callable(mem.find_injected_code)
    assert callable(mem.dump_strings)
    assert "list_processes" in mem.__all__
    assert "extract_credentials" in mem.__all__
    assert "find_injected_code" in mem.__all__
    assert "dump_strings" in mem.__all__


# ---- _have_vol3 ----------------------------------------------------------

def test_have_vol3_returns_string_or_none(monkeypatch):
    monkeypatch.setattr(mem.shutil, "which", lambda _: None)
    assert mem._have_vol3() is None
    monkeypatch.setattr(mem.shutil, "which",
                          lambda n: "/usr/local/bin/vol" if n == "vol" else None)
    assert mem._have_vol3() == "/usr/local/bin/vol"


# ---- list_processes ------------------------------------------------------

def test_list_processes_missing_dump_returns_error(tmp_path):
    out = mem.list_processes(str(tmp_path / "absent.raw"),
                                workspace=str(tmp_path))
    assert out["backend"] == "error"
    assert "not found" in (out.get("error") or "")


def test_list_processes_workspace_traversal_blocked(tmp_path):
    outside = tmp_path / "outside.raw"
    outside.write_bytes(b"X" * 16)
    ws = tmp_path / "ws"
    ws.mkdir()
    out = mem.list_processes(str(outside), workspace=str(ws))
    assert "outside" in (out.get("error") or "")


def test_list_processes_no_vol3_returns_install_hint(tmp_path, monkeypatch):
    dump = tmp_path / "memdump.raw"
    dump.write_bytes(b"X" * 16)
    monkeypatch.setattr(mem.shutil, "which", lambda _: None)
    out = mem.list_processes(str(dump), workspace=str(tmp_path))
    assert out["backend"] == "error"
    assert "volatility3" in (out.get("error") or "")


def test_list_processes_with_mocked_vol3(tmp_path, monkeypatch):
    """Mock subprocess.run to return a CSV-shape pslist response."""
    dump = tmp_path / "memdump.raw"
    dump.write_bytes(b"X" * 16)
    monkeypatch.setattr(mem.shutil, "which",
                          lambda n: "/usr/local/bin/vol" if n == "vol" else None)

    fake_csv = (
        b"PID,PPID,ImageFileName,Offset(V),Threads\n"
        b"4,0,System,0xfffff80012345678,200\n"
        b"888,4,csrss.exe,0xfffff8001abcd000,12\n"
    )

    class _FakeProc:
        returncode = 0
        stdout = fake_csv
        stderr = b""

    monkeypatch.setattr(mem.subprocess, "run", lambda *a, **kw: _FakeProc())
    out = mem.list_processes(str(dump), os_family="windows",
                                workspace=str(tmp_path))
    assert out["backend"] == "vol3"
    assert out["process_count"] == 2
    pids = [r["PID"] for r in out["processes"]]
    assert "4" in pids
    assert "888" in pids


# ---- extract_credentials -------------------------------------------------

def test_extract_credentials_linux_returns_clear_error(tmp_path):
    dump = tmp_path / "linux.raw"
    dump.write_bytes(b"X" * 16)
    out = mem.extract_credentials(str(dump), os_family="linux",
                                       workspace=str(tmp_path))
    assert "Windows-only" in (out.get("error") or "")


def test_extract_credentials_no_vol3(tmp_path, monkeypatch):
    dump = tmp_path / "win.raw"
    dump.write_bytes(b"X" * 16)
    monkeypatch.setattr(mem.shutil, "which", lambda _: None)
    out = mem.extract_credentials(str(dump), os_family="windows",
                                       workspace=str(tmp_path))
    # Each plugin will fail with "not installed"; aggregate state shows
    # no creds + plugin_results carries the error per plugin.
    assert out["credential_count"] == 0
    assert all("volatility3" in v["error"] or "vol3 plugin" in v["error"]
                for v in out["plugin_results"].values())


# ---- find_injected_code -------------------------------------------------

def test_find_injected_code_unsupported_os(tmp_path, monkeypatch):
    dump = tmp_path / "mac.raw"
    dump.write_bytes(b"X" * 16)
    monkeypatch.setattr(mem.shutil, "which",
                          lambda n: "/usr/local/bin/vol" if n == "vol" else None)
    out = mem.find_injected_code(str(dump), os_family="mac",
                                       workspace=str(tmp_path))
    assert "not available" in (out.get("error") or "")


def test_find_injected_code_with_mocked_vol3(tmp_path, monkeypatch):
    dump = tmp_path / "win.raw"
    dump.write_bytes(b"X" * 16)
    monkeypatch.setattr(mem.shutil, "which",
                          lambda n: "/usr/local/bin/vol" if n == "vol" else None)
    fake_csv = (
        b"PID,Process,Address,Protection,Hexdump\n"
        b"1234,evil.exe,0x401000,PAGE_EXECUTE_READWRITE,4d 5a 90\n"
    )

    class _FakeProc:
        returncode = 0
        stdout = fake_csv
        stderr = b""

    monkeypatch.setattr(mem.subprocess, "run", lambda *a, **kw: _FakeProc())
    out = mem.find_injected_code(str(dump), os_family="windows",
                                       workspace=str(tmp_path))
    assert out["backend"] == "vol3"
    assert out["injection_count"] == 1
    assert out["injections"][0]["Process"] == "evil.exe"


# ---- dump_strings (built-in fallback) -----------------------------------

def test_dump_strings_builtin_fallback(tmp_path, monkeypatch):
    """Without vol3 installed, the built-in path extracts strings."""
    monkeypatch.setattr(mem.shutil, "which", lambda _: None)
    dump = tmp_path / "tiny.raw"
    dump.write_bytes(
        b"\x00\x00hello_world_string\x00\x00"
        + b"another_long_string_here\x00\x00"
        + b"shrt\x00"   # too short with default min_length=8
    )
    out = mem.dump_strings(str(dump), workspace=str(tmp_path))
    assert out["backend"] == "builtin"
    strings = out["strings"]
    assert any("hello_world_string" in s for s in strings)
    assert any("another_long_string_here" in s for s in strings)
    assert "shrt" not in strings


def test_dump_strings_min_length_filter(tmp_path, monkeypatch):
    monkeypatch.setattr(mem.shutil, "which", lambda _: None)
    dump = tmp_path / "tiny.raw"
    dump.write_bytes(b"\x00short\x00longer_string_at_least_18_chars\x00")
    out = mem.dump_strings(str(dump), min_length=18, workspace=str(tmp_path))
    assert any("longer_string_at_least_18_chars" in s for s in out["strings"])
    assert "short" not in out["strings"]


def test_dump_strings_max_bytes_bound(tmp_path, monkeypatch):
    """A huge dump must respect max_bytes."""
    monkeypatch.setattr(mem.shutil, "which", lambda _: None)
    dump = tmp_path / "huge.raw"
    # 200 KB of repeating pattern
    dump.write_bytes(b"\x00ABCDEFGHIJ" * 20_000)
    out = mem.dump_strings(str(dump), workspace=str(tmp_path),
                              max_bytes=64 * 1024)
    assert out["bytes_scanned"] <= 64 * 1024 + 65 * 1024  # one extra chunk worst-case
    assert out["backend"] == "builtin"


def test_dump_strings_workspace_block(tmp_path):
    outside = tmp_path / "outside.raw"
    outside.write_bytes(b"x")
    ws = tmp_path / "ws"
    ws.mkdir()
    out = mem.dump_strings(str(outside), workspace=str(ws))
    assert "outside" in (out.get("error") or "")


def test_dump_strings_missing_file(tmp_path):
    out = mem.dump_strings(str(tmp_path / "missing.raw"),
                              workspace=str(tmp_path))
    assert "not found" in (out.get("error") or "")


# ---- env scrubbing on subprocess invocations ---------------------------

def test_run_vol3_uses_scrubbed_env(tmp_path, monkeypatch):
    """The env passed to subprocess.run must NOT contain AWS_/GOOGLE_/etc."""
    dump = tmp_path / "x.raw"
    dump.write_bytes(b"X")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "s3cret")
    monkeypatch.setenv("GOOGLE_API_KEY", "g00g")
    monkeypatch.setenv("HOME", "/Users/test")  # innocuous, must persist
    monkeypatch.setattr(mem.shutil, "which",
                          lambda n: "/usr/local/bin/vol" if n == "vol" else None)

    captured: dict = {}

    class _FakeProc:
        returncode = 0
        stdout = b"PID\n"
        stderr = b""

    def _fake_run(*args, **kwargs):
        captured["env"] = kwargs.get("env", {})
        return _FakeProc()

    monkeypatch.setattr(mem.subprocess, "run", _fake_run)
    mem.list_processes(str(dump), workspace=str(tmp_path))
    env = captured["env"]
    assert "HOME" in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GOOGLE_API_KEY" not in env
