"""SHUTDOWN-01 + SHUTDOWN-02 regression test — chrome route latency cap +
shutdown_chrome log visibility.

Gates two issues from .planning/phases/03-exploit-verification-loop/03-01-PLAN.md:

  SHUTDOWN-01: POST /chrome/{filename}/clean must return within 3 seconds
               wall-clock even when shutdown_chrome's underlying CDP/lsof/
               SIGTERM chain takes 10+ seconds. Fix is FastAPI BackgroundTasks
               dispatch — return 200 with `flash_ok` "shutdown initiated"
               in ~50ms; operator polls GET /chrome/{filename} for actual
               status. Previously: 8-second timeout_sec + WebSocket/urlopen
               latency + template render = ~15s hang -> HTTP 000 curl
               timeouts on the operator side.

  SHUTDOWN-02: shutdown_chrome's per-strategy failure log lines must surface
               at WARNING level so the operator sees them in the default INFO
               log stream. Previously log.debug — invisible unless
               SHIM_LOG_LEVEL=DEBUG.

Test coverage:

  Test 1 — `test_chrome_clean_returns_within_3_seconds_even_when_shutdown_blocks`
           Monkeypatches shutdown_chrome to sleep(10); measures wall-clock
           duration of POST /chrome/<scope>/clean; asserts < 3.0s. This is
           the SHUTDOWN-01 acceptance gate.
  Test 2 — `test_chrome_clean_background_task_actually_invokes_shutdown`
           Monkeypatches shutdown_chrome with a counter; POSTs to /clean;
           waits for the BackgroundTasks queue to drain; asserts counter == 1.
           Proves the refactor didn't break the actual shutdown call.
  Test 3 — `test_chrome_clean_route_returns_404_when_scope_filename_missing`
           Validates the new BackgroundTasks dispatch didn't bypass
           _scope_path's filename existence check.
  Test 4 — `test_chrome_clean_route_rejects_filename_traversal`
           Validates _scope_path's path-traversal rejection still works
           after the refactor (T-03-01-05 mitigation).
  Test 5 — `test_shutdown_chrome_per_strategy_failures_log_at_warning`
           caplog test — does NOT use TestClient. Imports
           sentinel.agent.chrome_profile, forces a path where strategy 1
           (WebSocket) fails, asserts caplog records contain WARNING-level
           entries from shutdown_chrome. SHUTDOWN-02 acceptance gate.
"""

from __future__ import annotations

import inspect
import logging
import socket
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from sentinel.web.app import create_app
from sentinel.web.deps import get_config
from sentinel.ui.state import UIConfig


# ---- Fixture --------------------------------------------------------------


_MIN_SCOPE_YAML = """\
client: bench-test
engagement_id: bench-test
authorized_by: test@example.com
valid_from: 2026-01-01
valid_until: 2030-12-31
targets:
  domains:
    - 127.0.0.1
"""


@pytest.fixture
def client_with_tmp_scope(tmp_path: Path):
    """TestClient with a tmp scope.yaml fixture and dependency-overridden
    UIConfig pointing scopes_dir to the tmp dir."""
    scopes_dir = tmp_path / "scopes"
    scopes_dir.mkdir()
    scope_path = scopes_dir / "bench-test.yaml"
    scope_path.write_text(_MIN_SCOPE_YAML)

    cfg = UIConfig(
        vault_path=str(tmp_path / "vault"),
        corpus_dir=str(tmp_path / "corpus"),
        scopes_dir=str(scopes_dir),
        runs_dir=str(tmp_path / "runs"),
        ollama_host="http://localhost:11434",
        ollama_model="llama3.1:8b",
        embed_model="nomic-embed-text",
        project_dir=str(tmp_path),
    )

    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.clear()


# ---- Tests ---------------------------------------------------------------


def _find_free_port() -> int:
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_chrome_clean_returns_within_3_seconds_even_when_shutdown_blocks(
    tmp_path: Path, monkeypatch
):
    """SHUTDOWN-01 acceptance gate. The route MUST return within 3s wall-clock
    even when shutdown_chrome blocks for 10s — proves BackgroundTasks dispatch
    is in place and the HTTP response is not waiting on the actual chrome
    shutdown.

    Uses a real uvicorn server (NOT TestClient) because Starlette's TestClient
    synchronously drains BackgroundTasks before returning the response — a
    test artifact that does NOT match real ASGI server behavior. Real uvicorn
    sends the response, THEN runs the BackgroundTasks. The 3s wall-clock cap
    only matters against the real-server behavior so we spin up uvicorn here.
    """
    def slow_shutdown(*args, **kwargs):
        time.sleep(10.0)
        return True

    # Patch globally so the BackgroundTasks worker (running on the uvicorn
    # thread) picks up the slow stub.
    monkeypatch.setattr(
        "sentinel.agent.chrome_profile.shutdown_chrome", slow_shutdown
    )

    # Build a tmp scope file + cfg + app instance with overridden config.
    scopes_dir = tmp_path / "scopes"
    scopes_dir.mkdir()
    (scopes_dir / "bench-test.yaml").write_text(_MIN_SCOPE_YAML)
    cfg = UIConfig(
        vault_path=str(tmp_path / "vault"),
        corpus_dir=str(tmp_path / "corpus"),
        scopes_dir=str(scopes_dir),
        runs_dir=str(tmp_path / "runs"),
        ollama_host="http://localhost:11434",
        ollama_model="llama3.1:8b",
        embed_model="nomic-embed-text",
        project_dir=str(tmp_path),
    )
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg

    # Spin up a real uvicorn server in a daemon thread.
    port = _find_free_port()
    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="error",
        lifespan="on",
    )
    server = uvicorn.Server(config)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    try:
        # Poll for server readiness.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                httpx.get(
                    f"http://127.0.0.1:{port}/openapi.json", timeout=0.5,
                )
                break
            except (httpx.ConnectError, httpx.ReadTimeout):
                time.sleep(0.05)
        else:
            pytest.fail("uvicorn did not start within 5s")

        start = time.monotonic()
        r = httpx.post(
            f"http://127.0.0.1:{port}/chrome/bench-test.yaml/clean",
            timeout=5.0,
        )
        elapsed = time.monotonic() - start

        assert r.status_code == 200, (
            f"expected HTTP 200, got {r.status_code}. Body: {r.text[:400]}"
        )
        # 3.0s acceptance gate per <success_criteria> of 03-01-PLAN.md.
        assert elapsed < 3.0, (
            f"POST /chrome/.../clean took {elapsed:.2f}s — must be < 3s. "
            f"BackgroundTasks dispatch is not in place."
        )
        # The response HTML should contain a flash_ok indicating initiation.
        assert "shutdown" in r.text.lower(), (
            f"response HTML missing 'shutdown' flash — got: {r.text[:400]}"
        )
    finally:
        server.should_exit = True
        server_thread.join(timeout=2.0)
        app.dependency_overrides.clear()


def test_chrome_clean_route_signature_includes_background_tasks():
    """Structural gate (cheap to run, no server needed): the chrome_clean
    function MUST declare a BackgroundTasks parameter. If a future refactor
    drops it, the route silently regresses to blocking on shutdown_chrome
    (which is what SHUTDOWN-01 fixed).
    """
    from sentinel.web.routes.chrome import chrome_clean
    sig = inspect.signature(chrome_clean)
    assert "background" in sig.parameters, (
        f"chrome_clean missing `background: BackgroundTasks` parameter — "
        f"signature is {sig}. Regression of SHUTDOWN-01 fix."
    )
    # Verify the annotation is BackgroundTasks (not some other dependency).
    # The chrome.py module uses `from __future__ import annotations`, so
    # the annotation is a string at runtime — compare by name OR resolve.
    from fastapi import BackgroundTasks
    bg_param = sig.parameters["background"]
    ann = bg_param.annotation
    if isinstance(ann, str):
        ann_name = ann
    else:
        ann_name = getattr(ann, "__name__", repr(ann))
    assert ann_name == "BackgroundTasks", (
        f"chrome_clean.background annotation is {bg_param.annotation!r}, "
        f"expected BackgroundTasks (qualified or string form)"
    )
    # Also resolve to the real class via typing.get_type_hints to catch
    # a future bug where someone shadows BackgroundTasks with a fake.
    import typing
    try:
        hints = typing.get_type_hints(
            __import__("sentinel.web.routes.chrome", fromlist=["chrome_clean"]).chrome_clean
        )
        assert hints.get("background") is BackgroundTasks, (
            f"resolved type hint for `background` is {hints.get('background')!r}, "
            f"expected fastapi.BackgroundTasks"
        )
    except (NameError, AttributeError):
        # Type-hint resolution can fail if forward-refs reference symbols
        # not in module globals; the string-name check above is sufficient.
        pass


def test_chrome_clean_background_task_actually_invokes_shutdown(
    client_with_tmp_scope: TestClient, monkeypatch
):
    """Prove BackgroundTasks actually fires the shutdown call after the HTTP
    response — not just discards it. The route returns fast (test 1) AND the
    underlying shutdown function does eventually run (this test)."""
    invocations: list[dict[str, Any]] = []

    def counting_shutdown(*args, **kwargs):
        invocations.append({"args": args, "kwargs": dict(kwargs)})
        return True

    monkeypatch.setattr(
        "sentinel.agent.chrome_profile.shutdown_chrome", counting_shutdown
    )

    r = client_with_tmp_scope.post("/chrome/bench-test.yaml/clean")
    assert r.status_code == 200

    # FastAPI's TestClient runs BackgroundTasks synchronously after the
    # response is sent (within the same request scope). By the time
    # .post() returns, the BackgroundTasks queue has drained.
    assert len(invocations) == 1, (
        f"BackgroundTasks did not invoke shutdown_chrome — "
        f"invocations: {invocations}"
    )
    # The route is expected to pass cdp_port and timeout_sec as kwargs.
    call = invocations[0]
    assert "cdp_port" in call["kwargs"], (
        f"shutdown_chrome called without cdp_port kwarg: {call}"
    )


def test_chrome_clean_route_returns_404_when_scope_filename_missing(
    client_with_tmp_scope: TestClient
):
    """The BackgroundTasks refactor MUST NOT bypass _scope_path's existence
    check. Posting to a non-existent scope file returns 404."""
    r = client_with_tmp_scope.post("/chrome/does-not-exist.yaml/clean")
    assert r.status_code == 404, (
        f"expected 404 for missing scope, got {r.status_code}: {r.text[:400]}"
    )


def test_chrome_clean_route_rejects_filename_traversal(
    client_with_tmp_scope: TestClient
):
    """T-03-01-05 mitigation: _scope_path rejects path-traversal filenames.
    The BackgroundTasks refactor must inherit that check."""
    # URL-encoded `../../etc/passwd`. FastAPI's path converter decodes %2F
    # but the encoded sequence in the test exercises the underlying rejection.
    # We use a literal `..something` filename which _scope_path rejects via
    # the startswith('..') guard.
    r = client_with_tmp_scope.post("/chrome/..hidden/clean")
    assert r.status_code == 400, (
        f"expected 400 for filename traversal, got {r.status_code}: "
        f"{r.text[:400]}"
    )


def test_shutdown_chrome_per_strategy_failures_log_at_warning(
    monkeypatch, caplog
):
    """SHUTDOWN-02 acceptance gate. When shutdown_chrome's WebSocket strategy
    fails, the failure MUST log at WARNING level (not DEBUG) so the operator
    sees it without setting SHIM_LOG_LEVEL=DEBUG.

    Forces the path:
      - attach_status returns a fake dict with a bogus webSocketDebuggerUrl
      - WebSocket connect fails (bogus URL)
      - urlopen fails (no chrome listening)
      - lsof returns no PID
      - final fallthrough hits the warning-level message
    """
    from sentinel.agent import chrome_profile as cp

    # First attach_status() (line 527 gatekeeper) returns truthy so the
    # function actually enters the cleanup logic. Subsequent calls
    # (line 531 to fetch ws_url, lines 557 + 572 polling) also return
    # truthy so the function exhausts all strategies and hits the
    # fallthrough warning.
    fake_status = {"webSocketDebuggerUrl": "ws://127.0.0.1:1/devtools/browser/fake"}
    monkeypatch.setattr(cp, "attach_status", lambda *a, **kw: fake_status)
    # No PID found via lsof -> SIGTERM strategy is a noop.
    monkeypatch.setattr(cp, "_pid_listening_on", lambda port: None)

    caplog.set_level(logging.WARNING, logger="sentinel.agent.chrome_profile")
    result = cp.shutdown_chrome(cdp_port=65530, timeout_sec=1.0)
    # Port "stays up" (fake attach_status keeps returning truthy) -> False.
    assert result is False

    warning_records = [
        rec for rec in caplog.records
        if rec.levelname == "WARNING"
        and "shutdown_chrome" in rec.getMessage()
    ]
    assert warning_records, (
        f"no WARNING-level shutdown_chrome log records captured — "
        f"SHUTDOWN-02 fix not applied. All records: "
        f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
    )
    # At minimum the WebSocket-failure path should fire a warning since
    # the bogus ws://127.0.0.1:1 will raise ConnectionRefused.
    ws_warnings = [
        r for r in warning_records
        if "WebSocket" in r.getMessage() or "Browser.close" in r.getMessage()
    ]
    assert ws_warnings, (
        f"WebSocket-failure path did not log at WARNING — got: "
        f"{[r.getMessage() for r in warning_records]}"
    )
