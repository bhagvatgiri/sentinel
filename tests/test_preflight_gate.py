"""Cut #3 (2026-XX-XX cost-cut audit) — pre-flight gate refuses scans that
would burn Claude tokens against unreachable / unauth-able targets.

Two technical refusals that must fire before any phase runs:
  (a) browser_strategy=cdp + Chrome cold on cdp_port → refuse
  (b) target returns 403 + scope.auth_cookies empty + no CDP → refuse
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from sentinel.agent.pentest.pipeline import PentestPipeline, PipelineConfig, PreflightRefused


def _mk_pipeline(tmp_path: Path, *, target: str, browser_strategy: str = "playwright_spawn",
                  auth_cookies: list = None, max_budget: float = 15.0) -> tuple[PentestPipeline, object]:
    """Construct a pipeline + mock scope for preflight tests.

    Returns (pipeline, scope) so the test can call await pipeline._preflight_gate(scope).
    """
    cfg = PipelineConfig(
        target=target,
        scope_path=str(tmp_path / "fake-scope.yaml"),
        workspaces_root=str(tmp_path / "workspaces"),
        max_budget_per_scan_usd=max_budget,
    )
    pipeline = PentestPipeline(cfg)
    # Mock scope (don't actually load YAML)
    scope = SimpleNamespace(
        engagement_id="test-eng",
        engagement_mode=SimpleNamespace(value="bbp"),
        browser_strategy=browser_strategy,
        chrome_cdp_port=9222,
        auth_cookies=auth_cookies or [],
        audit_log=MagicMock(),
    )
    scope.audit_log.write = MagicMock()
    return pipeline, scope


def test_preflight_refuses_cdp_strategy_with_cold_chrome(tmp_path: Path, monkeypatch):
    """browser_strategy=cdp + no Chrome on port → REFUSE."""
    pipeline, scope = _mk_pipeline(tmp_path, target="https://example.com",
                                     browser_strategy="cdp")
    # Mock Chrome attach_status to return None (cold port)
    from sentinel.agent import chrome_profile as _cp
    monkeypatch.setattr(_cp, "attach_status", lambda port: None)
    with pytest.raises(PreflightRefused) as exc_info:
        asyncio.run(pipeline._preflight_gate(scope))
    msg = str(exc_info.value)
    assert "browser_strategy" in msg
    assert "9222" in msg
    assert "bootstrap" in msg.lower()
    # Audit-logged
    scope.audit_log.write.assert_called_once()
    call_args = scope.audit_log.write.call_args
    assert call_args[0][0] == "preflight_refused"


def test_preflight_passes_when_cdp_warm(tmp_path: Path, monkeypatch):
    """browser_strategy=cdp + warm Chrome → PASSES gate."""
    pipeline, scope = _mk_pipeline(tmp_path, target="https://example.com",
                                     browser_strategy="cdp")
    from sentinel.agent import chrome_profile as _cp
    monkeypatch.setattr(_cp, "attach_status", lambda port: {"Browser": "Chrome/148"})
    # Mock httpx probe to avoid real network call
    monkeypatch.setattr("urllib.request.urlopen",
                         lambda *a, **kw: _FakeHttpResp(200))
    # Should not raise
    asyncio.run(pipeline._preflight_gate(scope))


def test_preflight_refuses_403_with_no_cookies_no_cdp(tmp_path: Path, monkeypatch):
    """Target 403 + empty auth_cookies + no CDP → REFUSE."""
    pipeline, scope = _mk_pipeline(tmp_path, target="https://example.com",
                                     browser_strategy="playwright_spawn",
                                     auth_cookies=[])
    # Mock httpx probe to return 403
    import urllib.error
    def _raise_403(*a, **kw):
        raise urllib.error.HTTPError(
            url="https://example.com", code=403, msg="Forbidden",
            hdrs=None, fp=None,
        )
    monkeypatch.setattr("urllib.request.urlopen", _raise_403)
    with pytest.raises(PreflightRefused) as exc_info:
        asyncio.run(pipeline._preflight_gate(scope))
    msg = str(exc_info.value)
    assert "403" in msg
    assert "auth_cookies" in msg or "cookies" in msg


def test_preflight_passes_403_when_auth_cookies_present(tmp_path: Path, monkeypatch):
    """Target 403 BUT scope.auth_cookies has entries → PASSES (might still
    work via cookies on subsequent probes)."""
    pipeline, scope = _mk_pipeline(tmp_path, target="https://example.com",
                                     browser_strategy="playwright_spawn",
                                     auth_cookies=[{"name": "session", "value": "x"}])
    import urllib.error
    monkeypatch.setattr("urllib.request.urlopen",
                         lambda *a, **kw: (_ for _ in ()).throw(
                             urllib.error.HTTPError(
                                 url="https://example.com", code=403, msg="Forbidden",
                                 hdrs=None, fp=None,
                             )
                         ))
    # Should not raise — auth_cookies provide a fallback
    asyncio.run(pipeline._preflight_gate(scope))


def test_preflight_passes_200_response(tmp_path: Path, monkeypatch):
    """Target 200 → PASSES regardless of cookies."""
    pipeline, scope = _mk_pipeline(tmp_path, target="https://example.com")
    monkeypatch.setattr("urllib.request.urlopen",
                         lambda *a, **kw: _FakeHttpResp(200))
    asyncio.run(pipeline._preflight_gate(scope))


# ---- helpers --------------------------------------------------------------


class _FakeHttpResp:
    def __init__(self, status: int):
        self.status = status
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self): return b""
