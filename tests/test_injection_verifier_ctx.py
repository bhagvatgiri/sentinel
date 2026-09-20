"""Regression guard: injection verifier's _timed_get must NOT reference an
undefined ctx — caller must pass ctx so cookies/auth state can be used.

The original bug: _timed_get(url, headers) did
    cookies=httpx_cookie_jar(ctx.auth_cookies)
inside its body, but ctx was only in the outer verify(ctx) function's
scope. All 6 injection-class hypotheses crashed with NameError on the
live ExampleChat scan and got stuck in verification_error state.
"""
from __future__ import annotations

import inspect

import pytest


def test_timed_get_does_not_reference_undefined_ctx():
    """Compile-time check: _timed_get's source body must not reference ctx
    unless ctx is a parameter of the function."""
    from sentinel.agent.pentest.verifiers import injection

    src = inspect.getsource(injection._timed_get)
    sig = inspect.signature(injection._timed_get)
    param_names = set(sig.parameters.keys())

    if "ctx." in src:
        assert "ctx" in param_names, (
            "_timed_get accesses ctx but has no ctx parameter. "
            "Caller-side ctx is not in the helper's scope at runtime."
        )


@pytest.mark.asyncio
async def test_timed_get_runs_without_nameerror(monkeypatch):
    """Smoke: call _timed_get with a mocked httpx and confirm no NameError."""
    from unittest.mock import MagicMock

    from sentinel.agent.pentest.verifiers import injection

    class FakeResp:
        status_code = 200
        text = ""

    class FakeClient:
        def __init__(self, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def get(self, url, headers=None):
            return FakeResp()

    monkeypatch.setattr("httpx.AsyncClient", FakeClient)

    fake_ctx = MagicMock()
    fake_ctx.auth_cookies = []

    sig = inspect.signature(injection._timed_get)
    kwargs = {"url": "https://example.com", "headers": {}}
    if "ctx" in sig.parameters:
        kwargs["ctx"] = fake_ctx

    result = await injection._timed_get(**kwargs)
    assert "url" in result
    assert "elapsed_sec" in result
