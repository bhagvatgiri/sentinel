"""Hermetic tests for sentinel/agent/pentest/oob_tool.py.

Mocks the interactsh-client subprocess + the AuditLog. No real network.
"""
from __future__ import annotations
import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

# ---- the module under test imports lazily because it expects ctx setup ----


@pytest.fixture
def fake_ctx(tmp_path):
    """Build a fake ctx with scope (oob_callbacks=None) + audit + event_log."""
    ctx = MagicMock()
    ctx.scope = MagicMock()
    ctx.scope.oob_callbacks = None
    ctx.scope.engagement_mode.value = "bbp"
    ctx.scope.client = "testclient"
    ctx.scope.engagement_id = "e1"
    ctx.scope.authorize_url = MagicMock()  # raises if out of scope
    ctx.audit = MagicMock()
    ctx.audit.write = MagicMock()
    ctx.event_log = MagicMock()
    ctx.event_log.emit = MagicMock()
    ctx.job_id = "job-test"
    ctx.runs_dir = tmp_path
    return ctx


@pytest.fixture(autouse=True)
def _reset_oob_singletons():
    """Clear the module-level session singleton between tests."""
    from sentinel.agent.pentest import oob_tool
    oob_tool._SESSIONS_BY_JOB.clear()
    yield
    oob_tool._SESSIONS_BY_JOB.clear()


@pytest.mark.asyncio
async def test_register_oob_token_emits_audit_event(fake_ctx, monkeypatch):
    """Calling register_oob_token writes a hash-chained audit event with mode=."""
    from sentinel.agent.pentest import oob_tool

    monkeypatch.setattr(oob_tool, "_require_ctx", lambda: fake_ctx)

    # Stub the subprocess interactsh client — _OobSession.start() is mocked
    fake_session = AsyncMock()
    fake_session.register_token = AsyncMock(return_value="abcd1234")
    fake_session.full_url_for = MagicMock(return_value="abcd1234.oast.fun")

    async def fake_get_session(job_id):
        return fake_session

    monkeypatch.setattr(oob_tool, "_get_session_for_job", fake_get_session)

    result = await oob_tool.register_oob_token.handler({"purpose": "blind ssrf payload"})

    assert result.get("is_error") is not True
    text = result["content"][0]["text"]
    assert "abcd1234" in text
    fake_ctx.audit.write.assert_called()
    args, kwargs = fake_ctx.audit.write.call_args
    assert kwargs.get("mode") == "bbp", "audit.write must include mode=ctx.scope.engagement_mode.value"
    assert args[0] == "oob_token_registered"


@pytest.mark.asyncio
async def test_register_oob_token_refuses_when_scope_disabled(fake_ctx, monkeypatch):
    """When scope.oob_callbacks == 'disabled', the tool returns _err without spawning."""
    from sentinel.agent.pentest import oob_tool

    fake_ctx.scope.oob_callbacks = "disabled"
    monkeypatch.setattr(oob_tool, "_require_ctx", lambda: fake_ctx)

    # Even if session-spawn would succeed, the tool must refuse first
    spawned = MagicMock()
    monkeypatch.setattr(oob_tool, "_get_session_for_job", spawned)

    result = await oob_tool.register_oob_token.handler({"purpose": "blind ssrf"})
    assert result.get("is_error") is True
    assert "disabled" in result["content"][0]["text"].lower()
    spawned.assert_not_called()


@pytest.mark.asyncio
async def test_check_oob_callback_parses_session_output(fake_ctx, monkeypatch):
    """check_oob_callback returns callbacks the session collected for that token."""
    from sentinel.agent.pentest import oob_tool

    monkeypatch.setattr(oob_tool, "_require_ctx", lambda: fake_ctx)

    fake_session = AsyncMock()
    fake_session.collect_callbacks = AsyncMock(
        return_value=[
            {"ts": "2026-XX-XXT13:00:00Z", "protocol": "dns", "src_ip": "1.2.3.4", "data": "abcd1234.oast.fun"}
        ]
    )

    async def fake_get_session(job_id):
        return fake_session

    monkeypatch.setattr(oob_tool, "_get_session_for_job", fake_get_session)

    result = await oob_tool.check_oob_callback.handler({"token": "abcd1234", "wait_seconds": 1})

    assert result.get("is_error") is not True
    text = result["content"][0]["text"]
    assert "dns" in text
    assert "1" in text  # count
    fake_session.collect_callbacks.assert_called_once_with("abcd1234", 1)

    # Audit event emitted when callbacks were received
    audit_calls = fake_ctx.audit.write.call_args_list
    kinds = [c.args[0] for c in audit_calls]
    assert "oob_callback_received" in kinds
    # Every emit MUST include mode=
    for c in audit_calls:
        assert c.kwargs.get("mode") == "bbp"


@pytest.mark.asyncio
async def test_check_oob_callback_empty_no_audit_event(fake_ctx, monkeypatch):
    """When no callbacks arrived, no oob_callback_received audit event is emitted."""
    from sentinel.agent.pentest import oob_tool

    monkeypatch.setattr(oob_tool, "_require_ctx", lambda: fake_ctx)

    fake_session = AsyncMock()
    fake_session.collect_callbacks = AsyncMock(return_value=[])

    async def fake_get_session(job_id):
        return fake_session

    monkeypatch.setattr(oob_tool, "_get_session_for_job", fake_get_session)

    result = await oob_tool.check_oob_callback.handler({"token": "abcd1234", "wait_seconds": 1})

    assert result.get("is_error") is not True
    kinds = [c.args[0] for c in fake_ctx.audit.write.call_args_list]
    assert "oob_callback_received" not in kinds


@pytest.mark.asyncio
async def test_oob_audit_mode_kwarg_discipline(fake_ctx, monkeypatch):
    """Every ctx.audit.write call in oob_tool MUST include mode=ctx.scope.engagement_mode.value.

    Lessons learned from quick task 260517-f7a (plan-checker B1) — the mode
    stamp is what the anti-laundering check in scope.py uses to prove the
    event originated under the declared engagement mode. Drop it and audit-trail
    integrity silently breaks.
    """
    from sentinel.agent.pentest import oob_tool

    monkeypatch.setattr(oob_tool, "_require_ctx", lambda: fake_ctx)

    fake_session = AsyncMock()
    fake_session.register_token = AsyncMock(return_value="t1")
    fake_session.full_url_for = MagicMock(return_value="t1.oast.fun")
    fake_session.collect_callbacks = AsyncMock(
        return_value=[{"ts": "2026-XX-XXT13:00:00Z", "protocol": "dns", "src_ip": "1.2.3.4", "data": "t1.oast.fun"}]
    )

    async def fake_get_session(job_id):
        return fake_session

    monkeypatch.setattr(oob_tool, "_get_session_for_job", fake_get_session)

    await oob_tool.register_oob_token.handler({"purpose": "blind ssrf"})
    await oob_tool.check_oob_callback.handler({"token": "t1", "wait_seconds": 1})

    assert fake_ctx.audit.write.call_count >= 2
    for c in fake_ctx.audit.write.call_args_list:
        assert c.kwargs.get("mode") == "bbp", (
            f"audit.write({c.args[0]!r}, ...) missing mode= kwarg — "
            f"see plan B1 regression guard"
        )


@pytest.mark.asyncio
async def test_event_log_emit_uses_kwargs_shape(fake_ctx, monkeypatch):
    """event_log.emit must be called as emit(kind, **payload) — matches
    the signature in sentinel/agent/event_log.py (`def emit(self, kind: str,
    **payload: Any)`). If we ever switch to a positional dict, the call
    silently fails inside the bare-except wrapper and the /oob route shows
    empty data even after callbacks arrive — regression guard.
    """
    from sentinel.agent.pentest import oob_tool

    monkeypatch.setattr(oob_tool, "_require_ctx", lambda: fake_ctx)

    fake_session = AsyncMock()
    fake_session.register_token = AsyncMock(return_value="tk00face")
    fake_session.full_url_for = MagicMock(return_value="tk00face.oast.fun")
    fake_session.collect_callbacks = AsyncMock(
        return_value=[{"ts": "2026-XX-XXT13:00:00Z", "protocol": "dns",
                       "src_ip": "1.2.3.4", "data": "tk00face.oast.fun"}]
    )

    async def fake_get_session(job_id):
        return fake_session

    monkeypatch.setattr(oob_tool, "_get_session_for_job", fake_get_session)

    await oob_tool.register_oob_token.handler({"purpose": "blind ssrf"})
    await oob_tool.check_oob_callback.handler({"token": "tk00face", "wait_seconds": 1})

    # Two emit calls — one per event kind
    emit_calls = fake_ctx.event_log.emit.call_args_list
    kinds = [c.args[0] for c in emit_calls]
    assert "oob_token_registered" in kinds
    assert "oob_callback_received" in kinds

    # Both calls must use kwargs, NOT a positional dict (matches event_log.emit
    # signature `def emit(self, kind: str, **payload: Any)`)
    for c in emit_calls:
        # Positional args should be exactly (kind,) — no second positional dict
        assert len(c.args) == 1, (
            f"event_log.emit({c.args!r}, ...) — payload must be kwargs not "
            f"a positional dict; would break against the real signature."
        )
        assert isinstance(c.args[0], str)
        # kwargs must contain the payload
        assert "token" in c.kwargs, f"emit kwargs missing 'token': {c.kwargs!r}"

    # Specifically: the token-registered emit carries token/full_url/purpose
    reg_call = next(c for c in emit_calls if c.args[0] == "oob_token_registered")
    assert reg_call.kwargs["token"] == "tk00face"
    assert reg_call.kwargs["full_url"] == "tk00face.oast.fun"
    assert reg_call.kwargs["purpose"] == "blind ssrf"

    # And the callback-received emit carries token/count/protocols
    cb_call = next(c for c in emit_calls if c.args[0] == "oob_callback_received")
    assert cb_call.kwargs["token"] == "tk00face"
    assert cb_call.kwargs["count"] == 1
    assert cb_call.kwargs["protocols"] == ["dns"]


@pytest.mark.asyncio
async def test_register_oob_token_returns_err_when_subprocess_dead(fake_ctx, monkeypatch):
    """If interactsh-client crashed (returncode != None), register_oob_token
    must return _err with an informative message rather than raise or hand out
    a token that can never receive callbacks.
    """
    from sentinel.agent.pentest import oob_tool

    monkeypatch.setattr(oob_tool, "_require_ctx", lambda: fake_ctx)

    fake_session = AsyncMock()
    fake_session.register_token = AsyncMock(side_effect=RuntimeError(
        "interactsh-client subprocess exited (rc=-9); the OOB session is dead."
    ))

    async def fake_get_session(job_id):
        return fake_session

    monkeypatch.setattr(oob_tool, "_get_session_for_job", fake_get_session)

    result = await oob_tool.register_oob_token.handler({"purpose": "blind ssrf"})
    assert result.get("is_error") is True
    text = result["content"][0]["text"]
    assert "subprocess" in text.lower()
    assert "interactsh-client" in text.lower() or "oob" in text.lower()


@pytest.mark.asyncio
async def test_check_oob_callback_returns_err_when_subprocess_dead(fake_ctx, monkeypatch):
    """If interactsh-client crashed, check_oob_callback must return _err
    rather than hang the full wait_seconds and return empty silently.
    """
    from sentinel.agent.pentest import oob_tool

    monkeypatch.setattr(oob_tool, "_require_ctx", lambda: fake_ctx)

    fake_session = AsyncMock()
    fake_session.collect_callbacks = AsyncMock(side_effect=RuntimeError(
        "interactsh-client subprocess exited (rc=1); the OOB session is dead."
    ))

    async def fake_get_session(job_id):
        return fake_session

    monkeypatch.setattr(oob_tool, "_get_session_for_job", fake_get_session)

    result = await oob_tool.check_oob_callback.handler({"token": "abcd1234", "wait_seconds": 1})
    assert result.get("is_error") is True
    text = result["content"][0]["text"]
    assert "subprocess" in text.lower()


def test_assert_subprocess_alive_raises_when_returncode_set():
    """Direct test on _OobSession._assert_subprocess_alive — when the
    subprocess has exited (returncode is not None), the helper must raise
    with a message that mentions the return code AND tells the operator
    what to check (`which interactsh-client`).
    """
    from sentinel.agent.pentest import oob_tool

    sess = oob_tool._OobSession(job_id="job-dead")
    fake_proc = MagicMock()
    fake_proc.returncode = -9
    sess._proc = fake_proc

    with pytest.raises(RuntimeError) as exc_info:
        sess._assert_subprocess_alive()

    msg = str(exc_info.value)
    assert "rc=-9" in msg or "-9" in msg
    assert "interactsh-client" in msg
    # Operator-actionable hint
    assert "which" in msg.lower() or "re-launch" in msg.lower()


def test_assert_subprocess_alive_passes_when_alive():
    """When subprocess is running (returncode is None), helper is a no-op."""
    from sentinel.agent.pentest import oob_tool

    sess = oob_tool._OobSession(job_id="job-alive")
    fake_proc = MagicMock()
    fake_proc.returncode = None  # still running
    sess._proc = fake_proc

    # Should not raise
    sess._assert_subprocess_alive()

    # Also a no-op when proc hasn't been created yet
    sess2 = oob_tool._OobSession(job_id="job-new")
    sess2._assert_subprocess_alive()
