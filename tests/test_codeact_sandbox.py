"""Wave 5 / C5 — CodeAct sandbox tests.

Asserted properties:
  - AST validator rejects every documented sandbox-escape pattern:
      * os.system("id"), subprocess.run(["id"])
      * __import__("os").system(...)
      * ().__class__.__bases__[0].__subclasses__() (Python sandbox escape)
      * eval / exec / compile direct calls
      * getattr(obj, "__class__") dunder bypass
      * forbidden imports (os, subprocess, sys, socket, ctypes, ...)
  - Allowed code runs through the sandbox and returns the stdout/exit:
      * base64.b64decode("SGVsbG8=") → "Hello"
      * hashlib.sha256("hello".encode()).hexdigest() prints
  - Resource limits work:
      * Infinite loop killed at the CPU timeout
  - Mode gating: execute_python_code refuses under production / bbp.
  - File-write outside workspace is blocked at runtime via the sandbox
    open() wrapper.
  - Empty / whitespace-only code is rejected.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from sentinel.agent.pentest import codeact_agent as p_codeact
from sentinel.agent.pentest import codeact_sandbox as p_sandbox
from sentinel.agent.pentest import tools as p_tools
from sentinel.core.scope import Scope


# ---- helpers --------------------------------------------------------------


def _scope_yaml(tmp_path: Path, **overrides) -> Path:
    today = date.today()
    data = {
        "client": "ctf-client",
        "engagement_id": "ctf-codeact-001",
        "authorized_by": "test@example.com",
        "valid_from": (today - timedelta(days=1)).isoformat(),
        "valid_until": (today + timedelta(days=30)).isoformat(),
        "targets": {"domains": ["target.com"], "ips": []},
        "rate_limits": {"requests_per_second": 5},
    }
    data.update(overrides)
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def _make_ctx(tmp_path: Path, *, mode: str = "ctf",
                **scope_overrides) -> p_tools.PentestContext:
    log_path = tmp_path / "audit.jsonl"
    s = Scope.load(
        _scope_yaml(tmp_path, engagement_mode=mode, **scope_overrides),
        audit_log_path=log_path,
    )
    workspace = tmp_path / "ws"
    workspace.mkdir(exist_ok=True)

    class _StubHttp:
        async def get(self, url, *a, **k):
            class _R:
                status_code = 200
                text = "stub-body"
                url_attr = url
                headers: dict = {}
            return _R()

        async def post(self, *a, **k):
            class _R:
                status_code = 200
                text = "stub-body"
                headers: dict = {}
            return _R()

    ctx = p_tools.PentestContext(
        scope=s, audit=s.audit_log, workspace_dir=workspace,
        http=_StubHttp(),  # type: ignore[arg-type]
        rate_limit_per_host_sec=0.0,
    )
    p_tools.set_context(ctx)
    return ctx


# ---- AST validator: rejects ----------------------------------------------


def test_validator_rejects_os_system():
    res = p_sandbox.validate_code_ast("import os\nos.system('id')")
    assert not res.ok
    assert any(v["kind"] in ("forbidden_import", "forbidden_module_attr")
                for v in res.violations)


def test_validator_rejects_subprocess_run():
    res = p_sandbox.validate_code_ast(
        "import subprocess\nsubprocess.run(['id'])"
    )
    assert not res.ok
    assert any(v["kind"] == "forbidden_import" for v in res.violations)


def test_validator_rejects_dunder_import_chain():
    res = p_sandbox.validate_code_ast('__import__("os").system("id")')
    assert not res.ok
    # __import__ is a forbidden_builtin_call; getattr is an alternate path.
    assert any(v["kind"] == "forbidden_builtin_call" for v in res.violations)


def test_validator_rejects_python_sandbox_escape_classes():
    res = p_sandbox.validate_code_ast(
        '().__class__.__bases__[0].__subclasses__()'
    )
    assert not res.ok
    # Either __class__ or __bases__ or __subclasses__ — all forbidden dunders.
    assert any(v["kind"] == "forbidden_dunder" for v in res.violations)


def test_validator_rejects_eval():
    res = p_sandbox.validate_code_ast('eval("1+1")')
    assert not res.ok
    assert any(v["kind"] == "forbidden_builtin_call" for v in res.violations)


def test_validator_rejects_exec():
    res = p_sandbox.validate_code_ast('exec("import os")')
    assert not res.ok


def test_validator_rejects_compile():
    res = p_sandbox.validate_code_ast('compile("x", "<s>", "exec")')
    assert not res.ok


def test_validator_rejects_getattr_dunder_bypass():
    res = p_sandbox.validate_code_ast(
        'x = getattr(("",), "__class__")'
    )
    assert not res.ok
    assert any(v["kind"] == "getattr_dunder_bypass" for v in res.violations)


def test_validator_rejects_socket_import():
    res = p_sandbox.validate_code_ast("import socket")
    assert not res.ok
    assert any(v["kind"] == "forbidden_import" for v in res.violations)


def test_validator_rejects_ctypes_import():
    res = p_sandbox.validate_code_ast('import ctypes')
    assert not res.ok


def test_validator_rejects_wildcard_import():
    res = p_sandbox.validate_code_ast("from base64 import *")
    assert not res.ok
    assert any(v["kind"] == "wildcard_import" for v in res.violations)


def test_validator_rejects_pickle_import():
    res = p_sandbox.validate_code_ast("import pickle")
    assert not res.ok


def test_validator_rejects_threading_import():
    res = p_sandbox.validate_code_ast("import threading")
    assert not res.ok


def test_validator_rejects_empty_code():
    res = p_sandbox.validate_code_ast("")
    assert not res.ok
    assert "empty" in res.reason


def test_validator_rejects_whitespace_only():
    res = p_sandbox.validate_code_ast("   \n\n  \t")
    assert not res.ok


def test_validator_rejects_syntax_error():
    res = p_sandbox.validate_code_ast("def foo(:")
    assert not res.ok
    assert any(v["kind"] == "syntax" for v in res.violations)


# ---- AST validator: accepts ----------------------------------------------


def test_validator_accepts_base64_decode():
    res = p_sandbox.validate_code_ast(
        'import base64\nprint(base64.b64decode("SGVsbG8=").decode())'
    )
    assert res.ok, f"unexpected violations: {res.violations}"


def test_validator_accepts_hashlib():
    res = p_sandbox.validate_code_ast(
        'import hashlib\n'
        'h = hashlib.sha256(b"hello").hexdigest()\n'
        'print(h)'
    )
    assert res.ok


def test_validator_accepts_urllib_parse():
    # urllib.parse is allowed; urllib.request is forbidden.
    res = p_sandbox.validate_code_ast(
        'import urllib.parse\n'
        'print(urllib.parse.quote("a b"))'
    )
    assert res.ok


def test_validator_accepts_re_json_struct():
    code = (
        'import re, json, struct\n'
        'm = re.match(r"(\\d+)", "42")\n'
        'print(json.dumps({"v": int(m.group(1))}))\n'
        'print(struct.pack(">I", 42).hex())'
    )
    res = p_sandbox.validate_code_ast(code)
    assert res.ok


def test_validator_accepts_base64_with_secrets():
    """Mix of allowed modules typical of CTF crypto challenges."""
    res = p_sandbox.validate_code_ast(
        'import base64, hashlib, secrets\n'
        'tok = secrets.token_bytes(16)\n'
        'enc = base64.b64encode(tok).decode()\n'
        'h = hashlib.sha256(tok).hexdigest()\n'
        'print(enc, h)'
    )
    assert res.ok


# ---- Run-in-sandbox subprocess execution ---------------------------------


def test_sandbox_runs_simple_base64(tmp_path):
    ctx = _make_ctx(tmp_path)
    code = (
        'import base64\n'
        'print(base64.b64decode("SGVsbG8=").decode())'
    )
    result = p_sandbox.run_in_sandbox(
        code, scope=ctx.scope, workspace_dir=ctx.workspace_dir,
        cpu_timeout_sec=10, memory_limit_mb=200,
    )
    assert result.ok, f"failed: stderr={result.stderr!r}"
    assert "Hello" in result.stdout


def test_sandbox_runs_hashlib(tmp_path):
    ctx = _make_ctx(tmp_path)
    code = (
        'import hashlib\n'
        'print(hashlib.sha256(b"hello").hexdigest()[:16])'
    )
    result = p_sandbox.run_in_sandbox(
        code, scope=ctx.scope, workspace_dir=ctx.workspace_dir,
    )
    assert result.ok, result.stderr
    # SHA-256 of "hello" starts with 2cf24dba.
    assert "2cf24dba" in result.stdout


def test_sandbox_rejects_validator_failure(tmp_path):
    ctx = _make_ctx(tmp_path)
    result = p_sandbox.run_in_sandbox(
        'import os\nos.system("id")',
        scope=ctx.scope, workspace_dir=ctx.workspace_dir,
    )
    assert not result.ok
    assert result.violation
    assert "os" in result.violation or "forbidden" in result.violation.lower()


def test_sandbox_cpu_timeout_kills_infinite_loop(tmp_path):
    ctx = _make_ctx(tmp_path)
    # The validator allows `while True: pass`, but the sandbox SIGALRM
    # kills the process after the CPU budget. Use a low budget for a
    # fast test (1s), wall-timeout cap is 2x+5 = 7s.
    result = p_sandbox.run_in_sandbox(
        'while True:\n  pass',
        scope=ctx.scope, workspace_dir=ctx.workspace_dir,
        cpu_timeout_sec=2,
    )
    # Infinite loop never returned ok; either timed_out OR exit_code != 0.
    assert not result.ok
    assert result.duration_sec > 0


@pytest.mark.skipif(sys.platform == "darwin",
                     reason="RLIMIT_AS on macOS is unreliable for malloc cap")
def test_sandbox_memory_limit_blocks_large_allocation(tmp_path):
    ctx = _make_ctx(tmp_path)
    # Try to allocate ~1GB. Sandbox limit is 50MB → MemoryError.
    code = 'x = "a" * (1_000_000_000)\nprint("should not print")'
    result = p_sandbox.run_in_sandbox(
        code, scope=ctx.scope, workspace_dir=ctx.workspace_dir,
        memory_limit_mb=50,
    )
    assert not result.ok
    assert result.memory_exceeded or "MemoryError" in result.stderr or result.exit_code != 0


def test_sandbox_blocks_file_write_outside_workspace(tmp_path):
    ctx = _make_ctx(tmp_path)
    # Try to write to /tmp/sentinel-pwn.txt — outside the workspace.
    bad_path = "/tmp/sentinel-pwn-test.txt"
    code = (
        f'with open({bad_path!r}, "w") as f:\n'
        f'  f.write("escape")\n'
        f'print("wrote outside")'
    )
    result = p_sandbox.run_in_sandbox(
        code, scope=ctx.scope, workspace_dir=ctx.workspace_dir,
    )
    # Either the wrapper raised PermissionError (→ non-zero exit) or
    # the open() call failed; either way, no escape file written.
    assert not result.ok
    assert not Path(bad_path).is_file() or "escape" not in Path(bad_path).read_text()


def test_sandbox_allows_file_write_inside_workspace(tmp_path):
    ctx = _make_ctx(tmp_path)
    out_relpath = "scratch.txt"
    code = (
        f'with open({out_relpath!r}, "w") as f:\n'
        f'  f.write("in-workspace")\n'
        f'print("ok")'
    )
    result = p_sandbox.run_in_sandbox(
        code, scope=ctx.scope, workspace_dir=ctx.workspace_dir,
    )
    assert result.ok, result.stderr
    out_path = ctx.workspace_dir / out_relpath
    assert out_path.is_file()
    assert "in-workspace" in out_path.read_text()


def test_sandbox_blocks_file_read_outside_workspace(tmp_path):
    """Reads, not just writes, must be confined to the workspace — otherwise
    jail code can exfiltrate host secrets (~/.sentinel/.env, ~/.h1_token,
    .audit-* NDA logs, ~/.ssh/*). Regression for the 2026-XX-XX sandbox-escape
    arena finding #1 (open() boundary check previously gated writes only)."""
    ctx = _make_ctx(tmp_path)
    secret = tmp_path / "host-secret.txt"   # sibling of ws/ → outside workspace
    secret.write_text("TOPSECRET-DO-NOT-LEAK")
    code = f'print(open({str(secret)!r}).read())'
    result = p_sandbox.run_in_sandbox(
        code, scope=ctx.scope, workspace_dir=ctx.workspace_dir,
    )
    assert "TOPSECRET-DO-NOT-LEAK" not in (result.stdout or ""), (
        "sandbox leaked a file READ from outside the workspace"
    )


def test_sandbox_allows_file_read_inside_workspace(tmp_path):
    """Workspace-internal reads must still work — don't over-confine."""
    ctx = _make_ctx(tmp_path)
    (ctx.workspace_dir / "data.txt").write_text("workspace-data")
    code = 'print(open("data.txt").read())'
    result = p_sandbox.run_in_sandbox(
        code, scope=ctx.scope, workspace_dir=ctx.workspace_dir,
    )
    assert result.ok, result.stderr
    assert "workspace-data" in (result.stdout or "")


def test_sandbox_http_proxy_scope_gates(tmp_path):
    """sentinel_http_get from the sandbox round-trips via the parent;
    parent must call scope.authorize_url, refusing out-of-scope URLs."""
    ctx = _make_ctx(tmp_path)

    def _http_get(url, headers, timeout):
        return f"PROXIED:{url}"

    # In-scope target: target.com is in scope_yaml.
    code_in_scope = (
        'body = sentinel_http_get("https://target.com/healthz")\n'
        'print(body)'
    )
    result = p_sandbox.run_in_sandbox(
        code_in_scope, scope=ctx.scope, workspace_dir=ctx.workspace_dir,
        http_get=_http_get,
    )
    assert result.ok, result.stderr
    assert "PROXIED:https://target.com/healthz" in result.stdout

    # Out-of-scope: evil.com should raise PermissionError in the sandbox.
    code_oos = (
        'try:\n'
        '  sentinel_http_get("https://evil.com/x")\n'
        '  print("LEAKED")\n'
        'except PermissionError as e:\n'
        '  print("REFUSED:", str(e))'
    )
    result = p_sandbox.run_in_sandbox(
        code_oos, scope=ctx.scope, workspace_dir=ctx.workspace_dir,
        http_get=_http_get,
    )
    assert result.ok, result.stderr
    assert "REFUSED" in result.stdout
    assert "LEAKED" not in result.stdout


# ---- MCP tool: mode gating + audit ---------------------------------------


def test_execute_python_code_refuses_under_production(tmp_path):
    ctx = _make_ctx(tmp_path, mode="production")
    result = asyncio.run(p_codeact.execute_python_code.handler({
        "code": "print(1)",
    }))
    assert result.get("is_error"), f"expected refusal, got {result}"
    assert "execute_python_code" in result["content"][0]["text"]


def test_execute_python_code_refuses_under_bbp(tmp_path):
    ctx = _make_ctx(tmp_path, mode="bbp")
    result = asyncio.run(p_codeact.execute_python_code.handler({
        "code": "print(1)",
    }))
    assert result.get("is_error")


def test_execute_python_code_runs_under_ctf(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    result = asyncio.run(p_codeact.execute_python_code.handler({
        "code": (
            'import base64\n'
            'print(base64.b64decode("SGVsbG8=").decode())'
        ),
        "cpu_timeout_sec": 5,
    }))
    text = result["content"][0]["text"]
    assert not result.get("is_error"), f"expected ok, got {text}"
    assert "Hello" in text


def test_execute_python_code_under_lab(tmp_path):
    ctx = _make_ctx(
        tmp_path, mode="lab",
        targets={"domains": [], "ips": ["127.0.0.1"]},
    )
    result = asyncio.run(p_codeact.execute_python_code.handler({
        "code": "print(1+1)",
        "cpu_timeout_sec": 5,
    }))
    assert not result.get("is_error")


def test_execute_python_code_rejects_dangerous_under_ctf(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    result = asyncio.run(p_codeact.execute_python_code.handler({
        "code": "import os\nos.system('id')",
    }))
    # Validator catches it — reported as is_error with the violation reason.
    assert result.get("is_error")
    assert "sandbox" in result["content"][0]["text"].lower()


def test_execute_python_code_audit_logs_invocation(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    asyncio.run(p_codeact.execute_python_code.handler({
        "code": "print('audit-check')",
        "cpu_timeout_sec": 5,
    }))
    # The audit log on disk must have an "execute_python_code" entry
    # with mode=ctf.
    log_text = (tmp_path / "audit.jsonl").read_text()
    import json
    entries = [json.loads(l) for l in log_text.strip().splitlines()]
    matching = [e for e in entries if e.get("event") == "execute_python_code"]
    assert matching, f"no execute_python_code in audit; got {[e['event'] for e in entries]}"
    assert matching[0].get("mode") == "ctf"


def test_execute_python_code_empty_code_rejected(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    result = asyncio.run(p_codeact.execute_python_code.handler({
        "code": "   ",
    }))
    assert result.get("is_error")
    assert "empty" in result["content"][0]["text"].lower()


# ---- Filter integration --------------------------------------------------


def test_filter_drops_codeact_in_production():
    from sentinel.core.engagement_mode import (
        EngagementMode, filter_tools_for_mode,
    )
    filtered = filter_tools_for_mode(p_codeact.ALL_TOOLS, EngagementMode.PRODUCTION)
    assert filtered == [], (
        f"production must drop execute_python_code; got: "
        f"{[t.name for t in filtered]}"
    )


def test_filter_keeps_codeact_in_ctf_and_lab():
    from sentinel.core.engagement_mode import (
        EngagementMode, filter_tools_for_mode,
    )
    for mode in (EngagementMode.CTF, EngagementMode.LAB):
        filtered = filter_tools_for_mode(p_codeact.ALL_TOOLS, mode)
        names = {t.name for t in filtered}
        assert "execute_python_code" in names
