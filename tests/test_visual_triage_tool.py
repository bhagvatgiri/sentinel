"""Hermetic tests for sentinel/agent/pentest/visual_triage_tool.py.

Mocks gowitness subprocess + Ollama llava API. No real network or browser.

Test contract notes:
- `_ok` and `_err` from sentinel/agent/pentest/tools.py return dicts of shape
  {"content": [{"type":"text","text":"..."}], "is_error"?: True}
- We assert on result["content"][0]["text"] for body matches and
  result.get("is_error") for failure paths.
- B1 audit-log discipline: every ctx.audit.write(kind, payload, ...) MUST
  include `mode=` kwarg matching ctx.scope.engagement_mode.value.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _text(result: dict) -> str:
    """Pull the text body out of an _ok / _err dict."""
    return result["content"][0]["text"]


@pytest.fixture
def fake_ctx(tmp_path):
    ctx = MagicMock()
    ctx.scope = MagicMock()
    ctx.scope.engagement_mode.value = "bbp"
    ctx.scope.authorize_url = MagicMock()
    ctx.audit = MagicMock()
    ctx.audit.write = MagicMock()
    ctx.event_log = MagicMock()
    ctx.event_log.emit = MagicMock()
    ctx.job_id = "job-test"
    ctx.runs_dir = tmp_path
    return ctx


@pytest.mark.asyncio
async def test_visual_recon_scope_gates_every_url(fake_ctx, monkeypatch):
    """Each URL is scope-authorized before gowitness runs."""
    from sentinel.agent.pentest import visual_triage_tool as vt

    monkeypatch.setattr(vt, "_require_ctx", lambda: fake_ctx)

    async def fake_gowitness(urls, screenshot_dir):
        Path(screenshot_dir).mkdir(parents=True, exist_ok=True)
        out = []
        for u in urls:
            p = Path(screenshot_dir) / (u.replace("://", "_").replace("/", "_") + ".png")
            p.write_bytes(b"fake-png")
            out.append(str(p))
        return out

    monkeypatch.setattr(vt, "_run_gowitness", fake_gowitness)

    await vt.visual_recon.handler(
        {"urls": "https://target.com, https://admin.target.com"}
    )

    # Both URLs scope-checked
    assert fake_ctx.scope.authorize_url.call_count == 2


@pytest.mark.asyncio
async def test_visual_recon_emits_audit_with_mode(fake_ctx, monkeypatch):
    """visual_recon_captured event with mode= kwarg (B1)."""
    from sentinel.agent.pentest import visual_triage_tool as vt

    monkeypatch.setattr(vt, "_require_ctx", lambda: fake_ctx)

    async def fake_gowitness(urls, screenshot_dir):
        Path(screenshot_dir).mkdir(parents=True, exist_ok=True)
        p = Path(screenshot_dir) / "t.png"
        p.write_bytes(b"fake")
        return [str(p)]

    monkeypatch.setattr(vt, "_run_gowitness", fake_gowitness)
    await vt.visual_recon.handler({"urls": "https://t.com"})

    audit_kinds = [c.args[0] for c in fake_ctx.audit.write.call_args_list]
    assert "visual_recon_captured" in audit_kinds
    for c in fake_ctx.audit.write.call_args_list:
        assert c.kwargs.get("mode") == "bbp", (
            f"audit.write({c.args[0]!r}) missing mode= kwarg"
        )


@pytest.mark.asyncio
async def test_triage_screenshot_calls_llava_and_emits_audit(
    fake_ctx, monkeypatch, tmp_path
):
    """triage_screenshot POSTs to Ollama llava model and emits audit event."""
    from sentinel.agent.pentest import visual_triage_tool as vt

    monkeypatch.setattr(vt, "_require_ctx", lambda: fake_ctx)

    shot = tmp_path / "screenshot.png"
    shot.write_bytes(b"fake-png-bytes")

    async def fake_llava(screenshot_b64, prompt):
        return "Jenkins login page with default credentials hint visible"

    monkeypatch.setattr(vt, "_call_llava", fake_llava)
    result = await vt.triage_screenshot.handler({"screenshot_path": str(shot)})

    text = _text(result)
    assert "Jenkins" in text or "jenkins" in text.lower()
    audit_kinds = [c.args[0] for c in fake_ctx.audit.write.call_args_list]
    assert "visual_triage_completed" in audit_kinds
    for c in fake_ctx.audit.write.call_args_list:
        assert c.kwargs.get("mode") == "bbp"


@pytest.mark.asyncio
async def test_triage_screenshot_missing_file_errors(fake_ctx, monkeypatch):
    """Missing screenshot file returns _err without calling llava."""
    from sentinel.agent.pentest import visual_triage_tool as vt

    monkeypatch.setattr(vt, "_require_ctx", lambda: fake_ctx)
    called = MagicMock()
    monkeypatch.setattr(vt, "_call_llava", called)

    result = await vt.triage_screenshot.handler(
        {"screenshot_path": "/nonexistent.png"}
    )
    assert result.get("is_error") is True
    body = _text(result).lower()
    assert "not found" in body or "missing" in body or "error" in body
    called.assert_not_called()


@pytest.mark.asyncio
async def test_visual_recon_out_of_scope_filtered(fake_ctx, monkeypatch):
    """Out-of-scope URLs are filtered out; in-scope continue."""
    from sentinel.agent.pentest import visual_triage_tool as vt
    from sentinel.core.scope import OutOfScopeError

    monkeypatch.setattr(vt, "_require_ctx", lambda: fake_ctx)

    def authorize_side(url):
        if "out-of-scope" in url:
            raise OutOfScopeError("oos")
        return None

    fake_ctx.scope.authorize_url.side_effect = authorize_side

    async def fake_gowitness(urls, screenshot_dir):
        Path(screenshot_dir).mkdir(parents=True, exist_ok=True)
        out = []
        for u in urls:
            p = Path(screenshot_dir) / (u.replace("://", "_").replace("/", "_") + ".png")
            p.write_bytes(b"x")
            out.append(str(p))
        return out

    monkeypatch.setattr(vt, "_run_gowitness", fake_gowitness)

    result = await vt.visual_recon.handler(
        {"urls": "https://out-of-scope.com, https://target.com"}
    )
    text = _text(result)
    # gowitness only saw the in-scope URL
    assert "target.com" in text
    # filtering note mentioned
    assert "out-of-scope" in text.lower() or "filtered" in text.lower() or "1" in text
