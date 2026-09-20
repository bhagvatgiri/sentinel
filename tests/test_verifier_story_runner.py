"""Tests for the YAML verifier story runner (sentinel/agent/pentest/
verifier_story_runner.py) plus the two sample auth stories shipped at
sentinel/agent/pentest/verifier_stories/auth/*.yaml.

Strategy: monkeypatch `httpx.AsyncClient.get` (matches the pattern in
test_phase25_verifier.py) so we can drive each step deterministically
without making real network calls.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest import mock

import pytest

from sentinel.core.findings import EvidenceState
from sentinel.agent.pentest import verifier_story_runner as runner


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


class _FakeResp:
    def __init__(self, status: int = 200, location: str = "", body: str = ""):
        self.status_code = status
        self.headers = {"location": location} if location else {}
        self.text = body


def _scope_allow_all():
    s = mock.MagicMock()
    s.authorize_url.return_value = None
    return s


def _make_story(steps, **overrides) -> runner.Story:
    """Build a Story object directly so tests don't need YAML files on disk."""
    return runner.Story(
        path=Path("<inline>"),
        name=overrides.get("name", "inline-test"),
        vuln_class=overrides.get("vuln_class", "auth"),
        hypothesis=overrides.get("hypothesis", ""),
        description=overrides.get("description", ""),
        expected_state=overrides.get(
            "expected_state", EvidenceState.LIVE_DISPROVEN
        ),
        variables=overrides.get("variables", {}),
        steps=[runner.StoryStep(action=s["action"],
                                 args={k: v for k, v in s.items()
                                       if k != "action"})
               for s in steps],
    )


# --------------------------------------------------------------------------
# Variable interpolation
# --------------------------------------------------------------------------


def test_interpolate_replaces_known_variables():
    out = runner._interpolate("{target}/path?a={x}",
                                {"target": "https://t.example", "x": "1"})
    assert out == "https://t.example/path?a=1"


def test_interpolate_leaves_unknown_variables_literal():
    out = runner._interpolate("hello {missing}", {})
    assert out == "hello {missing}"


# --------------------------------------------------------------------------
# Story discovery
# --------------------------------------------------------------------------


def test_load_stories_for_class_finds_shipped_auth_stories():
    """The two sample stories under verifier_stories/auth/ must load."""
    stories = runner.load_stories_for_class("auth")
    names = {s.name for s in stories}
    assert "returnurl-redirect-chain" in names
    assert "maxauthage-injection" in names


def test_load_stories_for_class_returns_empty_for_unknown():
    assert runner.load_stories_for_class("__nonexistent__") == []


def test_shipped_returnurl_story_has_disproven_expectation():
    """Catches regressions where someone flips the expected_state."""
    stories = runner.load_stories_for_class("auth")
    story = next(s for s in stories if s.name == "returnurl-redirect-chain")
    assert story.expected_state is EvidenceState.LIVE_DISPROVEN


# --------------------------------------------------------------------------
# Story execution — terminal verdicts
# --------------------------------------------------------------------------


def test_run_story_returnurl_chain_disproven_on_op_404(monkeypatch):
    """The ExampleStore.com over-claim scenario: chain dead-ends at OP 404."""

    hop = {"n": 0}

    async def fake_get(self, url, headers=None):
        hop["n"] += 1
        if hop["n"] == 1:
            # signinRedirect → 302 to amazon /ap/signin
            return _FakeResp(
                302,
                location=("https://www.amazon.com/ap/signin?openid.return_to="
                          "https%3A%2F%2Fexample-attacker.invalid%2F"),
            )
        # amazon /ap/signin → OP 404 body
        return _FakeResp(
            200, body="Looking for Something? Sorry, that page is not on our site",
        )

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    stories = runner.load_stories_for_class("auth")
    story = next(s for s in stories if s.name == "returnurl-redirect-chain")
    result = asyncio.run(runner.run_story(
        story, target="https://www.ExampleStore.com", scope=_scope_allow_all(),
        rate_limit_per_host_sec=0.0,
    ))
    assert result.state is EvidenceState.LIVE_DISPROVEN
    assert result.matched_expected, \
        f"story expected {story.expected_state}, got {result.state}"


def test_run_story_returnurl_chain_confirmed_when_lands_on_attacker(monkeypatch):
    """If the chain actually reaches the attacker host the story confirms."""

    import urllib.parse as _urlparse

    async def fake_get(self, url, headers=None):
        # Check the actual destination host, NOT just substring presence —
        # the navigate step's URL embeds the attacker URL inside the
        # returnUrl query param so a naive `in url` check misfires.
        host = (_urlparse.urlparse(url).hostname or "").lower()
        if host == "example-attacker-localdemo.invalid":
            return _FakeResp(200, body="captured assertion=ABC123")
        # Anything else: redirect to attacker host directly.
        return _FakeResp(
            302,
            location="https://example-attacker-localdemo.invalid/captured?openid.assertion=X",
        )

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    stories = runner.load_stories_for_class("auth")
    story = next(s for s in stories if s.name == "returnurl-redirect-chain")
    result = asyncio.run(runner.run_story(
        story, target="https://www.ExampleStore.com", scope=_scope_allow_all(),
        rate_limit_per_host_sec=0.0,
    ))
    assert result.state is EvidenceState.LIVE_CONFIRMED, \
        f"expected confirmed (chain reached attacker host), got {result.state}"


def test_run_story_maxauthage_disproven_on_no_reflection(monkeypatch):
    """maxAuthAge=99999999 not reflected in Location → disproven."""

    async def fake_get(self, url, headers=None):
        # Server normalised — Location has max_auth_age=0
        return _FakeResp(
            302,
            location=("https://www.amazon.com/ap/signin?openid.return_to=..."
                      "&openid.pape.max_auth_age=0"),
        )

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    stories = runner.load_stories_for_class("auth")
    story = next(s for s in stories if s.name == "maxauthage-injection")
    result = asyncio.run(runner.run_story(
        story, target="https://www.ExampleStore.com", scope=_scope_allow_all(),
        rate_limit_per_host_sec=0.0,
    ))
    assert result.state is EvidenceState.LIVE_DISPROVEN


def test_run_story_maxauthage_confirmed_when_value_reflects(monkeypatch):
    """If 99999999 IS reflected, story confirms (regression scenario)."""

    async def fake_get(self, url, headers=None):
        return _FakeResp(
            302,
            location=("https://www.amazon.com/ap/signin?openid.return_to=..."
                      "&openid.pape.max_auth_age=99999999"),
        )

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    stories = runner.load_stories_for_class("auth")
    story = next(s for s in stories if s.name == "maxauthage-injection")
    result = asyncio.run(runner.run_story(
        story, target="https://www.ExampleStore.com", scope=_scope_allow_all(),
        rate_limit_per_host_sec=0.0,
    ))
    assert result.state is EvidenceState.LIVE_CONFIRMED


# --------------------------------------------------------------------------
# Step DSL — direct unit coverage
# --------------------------------------------------------------------------


def test_unknown_action_returns_verification_error(monkeypatch):
    story = _make_story([{"action": "definitely_not_a_real_step"}])
    result = asyncio.run(runner.run_story(
        story, target="https://t.example", scope=_scope_allow_all(),
        rate_limit_per_host_sec=0.0,
    ))
    assert result.state is EvidenceState.VERIFICATION_ERROR
    assert "unknown action" in (result.error or "")


def test_step_assert_status_terminal_verdict(monkeypatch):
    async def fake_get(self, url, headers=None):
        return _FakeResp(403, body="forbidden")

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    story = _make_story([
        {"action": "navigate", "url": "{target}/secret"},
        {"action": "assert_status",
         "expect": 403,
         "verdict_match": "live_confirmed"},
    ])
    result = asyncio.run(runner.run_story(
        story, target="https://t.example", scope=_scope_allow_all(),
        rate_limit_per_host_sec=0.0,
    ))
    assert result.state is EvidenceState.LIVE_CONFIRMED


def test_assert_param_reflected_with_expected_value(monkeypatch):
    async def fake_get(self, url, headers=None):
        return _FakeResp(
            302, location="https://x.example/?token=ABC&max_age=99",
        )

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    story = _make_story([
        {"action": "navigate", "url": "{target}/probe"},
        {"action": "assert_param_reflected",
         "param": "token",
         "in_header": "location",
         "expected_value": "ABC",
         "verdict_match": "live_confirmed",
         "verdict_mismatch": "live_disproven"},
    ])
    result = asyncio.run(runner.run_story(
        story, target="https://t.example", scope=_scope_allow_all(),
        rate_limit_per_host_sec=0.0,
    ))
    assert result.state is EvidenceState.LIVE_CONFIRMED


def test_out_of_scope_url_yields_verification_error(monkeypatch):
    from sentinel.core.scope import OutOfScopeError
    bad_scope = mock.MagicMock()
    bad_scope.authorize_url.side_effect = OutOfScopeError("blocked")

    story = _make_story([
        {"action": "navigate", "url": "https://forbidden.example/"},
    ])
    result = asyncio.run(runner.run_story(
        story, target="https://t.example", scope=bad_scope,
        rate_limit_per_host_sec=0.0,
    ))
    assert result.state is EvidenceState.VERIFICATION_ERROR
    assert "out-of-scope" in (result.error or "").lower() or "blocked" in (result.error or "")


def test_story_completing_without_verdict_yields_manual(monkeypatch):
    """Story with no verdict-setting steps → manual_verification_required."""

    async def fake_get(self, url, headers=None):
        return _FakeResp(200, body="hi")

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    story = _make_story([
        {"action": "navigate", "url": "{target}/"},
    ])
    result = asyncio.run(runner.run_story(
        story, target="https://t.example", scope=_scope_allow_all(),
        rate_limit_per_host_sec=0.0,
    ))
    assert result.state is EvidenceState.MANUAL_VERIFICATION_REQUIRED


# --------------------------------------------------------------------------
# Verdict merge across multiple stories
# --------------------------------------------------------------------------


def test_merge_confirmed_wins_over_everything():
    fake_results = [
        runner.StoryResult(
            story=_make_story([], name="a"),
            state=EvidenceState.LIVE_DISPROVEN, summary="a",
        ),
        runner.StoryResult(
            story=_make_story([], name="b"),
            state=EvidenceState.LIVE_CONFIRMED, summary="b",
        ),
        runner.StoryResult(
            story=_make_story([], name="c"),
            state=EvidenceState.MANUAL_VERIFICATION_REQUIRED, summary="c",
        ),
    ]
    state, summary = runner.merge_story_verdicts(fake_results)
    assert state is EvidenceState.LIVE_CONFIRMED
    assert "b" in summary


def test_merge_empty_list_returns_none():
    state, summary = runner.merge_story_verdicts([])
    assert state is None


def test_merge_all_disproven_returns_disproven():
    fake_results = [
        runner.StoryResult(story=_make_story([], name="a"),
                            state=EvidenceState.LIVE_DISPROVEN, summary=""),
        runner.StoryResult(story=_make_story([], name="b"),
                            state=EvidenceState.LIVE_DISPROVEN, summary=""),
    ]
    state, _ = runner.merge_story_verdicts(fake_results)
    assert state is EvidenceState.LIVE_DISPROVEN
