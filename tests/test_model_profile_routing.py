"""BENCH-01 regression tests — ModelRouter profile switching.

Phase 2 introduces a `MODEL_PROFILES` registry on `sentinel.agent.model_router`
that lets the operator flip the entire Claude-tier agent loop between two
named profiles:

  - 'anthropic-baseline'      — real Anthropic API (Sonnet/Opus/Haiku); the
                                 existing default. Clears any SiliconFlow
                                 routing env vars so the SDK hits
                                 api.anthropic.com directly.
  - 'siliconflow-qwen-235b'   — route Sonnet → Qwen3-235B-A22B-Instruct-2507,
                                 Opus → DeepSeek-R1, Haiku → Qwen3-Coder-30B-A3B
                                 via the local anthropic-shim on port 4002.
                                 Sets ANTHROPIC_BASE_URL + CLAUDE_CODE_BASE_URL,
                                 unsets ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN
                                 so the SDK sends an empty bearer (shim ignores).

These tests are hermetic — no network, no shim required. Env state is
snapshotted + restored per-test via the autouse fixture, so test ordering
cannot leak state into the operator's real shell.

Test contract:
  - `apply_model_profile(name)` switches env state cleanly.
  - `current_model_profile()` returns the active profile name.
  - Unknown profile name raises ValueError naming the bad name + valid options.
  - `MODEL_PROFILES` registry shape is stable (dict of name → callable).
"""

from __future__ import annotations

import os

import pytest

from sentinel.agent.model_router import (
    MODEL_PROFILES,
    SILICONFLOW_PROXY_URL,
    apply_model_profile,
    current_model_profile,
)


# ---- Fixtures -----------------------------------------------------------


_TRACKED_ENV_VARS = (
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_BASE_URL",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
)


@pytest.fixture(autouse=True)
def _reset_env(monkeypatch):
    """Snapshot + restore env vars that profiles mutate.

    Using monkeypatch.delenv/setenv ensures every assertion runs against
    a known starting state, and the operator's real shell env (e.g. a
    pre-existing ANTHROPIC_API_KEY) cannot leak into the test path.
    """
    for var in _TRACKED_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    # Reset internal profile state to a known starting point via the public API.
    # If apply_model_profile hasn't been implemented yet (RED phase), the
    # import above will already have failed — so this fixture body only runs
    # when the registry exists.
    apply_model_profile("anthropic-baseline")
    yield
    # monkeypatch automatically restores env on teardown; nothing else needed.


# ---- Tests --------------------------------------------------------------


def test_model_profiles_registry_shape():
    """`MODEL_PROFILES` is a dict mapping the two required profile names to
    callables. Plans 02-02..02-04 read this registry to populate CLI choice
    lists and dashboard dropdowns — its shape is part of the public contract.
    """
    assert isinstance(MODEL_PROFILES, dict)
    assert "anthropic-baseline" in MODEL_PROFILES, list(MODEL_PROFILES.keys())
    assert "siliconflow-qwen-235b" in MODEL_PROFILES, list(MODEL_PROFILES.keys())
    for name, fn in MODEL_PROFILES.items():
        assert callable(fn), f"MODEL_PROFILES[{name!r}] is not callable"


def test_apply_siliconflow_qwen_235b_sets_shim_url(monkeypatch):
    """Switching to the SiliconFlow profile must:
      - set ANTHROPIC_BASE_URL to the shim URL (this is the env var the
        Anthropic SDK inside claude CLI actually reads — without it the
        routing silently falls through to api.anthropic.com)
      - set CLAUDE_CODE_BASE_URL to the same shim URL
      - unset ANTHROPIC_API_KEY so the SDK sends an empty bearer (the shim
        doesn't require master_key auth and an invalid key triggers
        claude CLI's pre-network auth check, breaking routing)
      - mark current_model_profile() as 'siliconflow-qwen-235b'
    """
    # Pre-mutate env with a stale API key to prove the profile unsets it.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-stale-leftover-from-prior-run")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "tok-stale")

    apply_model_profile("siliconflow-qwen-235b")

    assert os.environ.get("ANTHROPIC_BASE_URL") == SILICONFLOW_PROXY_URL
    assert os.environ.get("CLAUDE_CODE_BASE_URL") == SILICONFLOW_PROXY_URL
    # API key + auth token must be gone — shim sends empty bearer.
    assert "ANTHROPIC_API_KEY" not in os.environ
    assert "ANTHROPIC_AUTH_TOKEN" not in os.environ
    assert current_model_profile() == "siliconflow-qwen-235b"


def test_apply_anthropic_baseline_restores_real_anthropic(monkeypatch):
    """Switching to the Anthropic baseline must:
      - clear the SiliconFlow shim env vars (ANTHROPIC_BASE_URL,
        CLAUDE_CODE_BASE_URL) so the SDK routes to api.anthropic.com
      - NOT re-mint ANTHROPIC_API_KEY (operator's real key, if present,
        flows in from their shell; if absent, the scan fails loudly which
        is correct — silent fallthrough is worse than a loud failure)
      - mark current_model_profile() as 'anthropic-baseline'
    """
    # Pre-mutate env to look like a stale SiliconFlow routing leftover.
    monkeypatch.setenv("ANTHROPIC_BASE_URL", SILICONFLOW_PROXY_URL)
    monkeypatch.setenv("CLAUDE_CODE_BASE_URL", SILICONFLOW_PROXY_URL)

    apply_model_profile("anthropic-baseline")

    assert "ANTHROPIC_BASE_URL" not in os.environ
    assert "CLAUDE_CODE_BASE_URL" not in os.environ
    assert current_model_profile() == "anthropic-baseline"


def test_unknown_model_profile_raises_valueerror():
    """Unknown profile name → ValueError that names BOTH the bad input
    and the list of valid profile names, so the operator can fix their
    --model-profile flag without spelunking through the source.
    """
    with pytest.raises(ValueError) as excinfo:
        apply_model_profile("not-a-real-profile")

    msg = str(excinfo.value)
    assert "not-a-real-profile" in msg
    # The list of valid profiles must appear in the error so the operator
    # sees both 'anthropic-baseline' and 'siliconflow-qwen-235b' in the help.
    assert "anthropic-baseline" in msg
    assert "siliconflow-qwen-235b" in msg


def test_profile_round_trip_returns_env_to_clean_state(monkeypatch):
    """Switching SiliconFlow → Anthropic round-trip ends in a clean env;
    proves the baseline profile's unset is symmetric with SiliconFlow's set.
    Important because the harness in Task 3 flips back-and-forth twice per
    parity-eval run.
    """
    # Start clean (fixture already did this).
    apply_model_profile("siliconflow-qwen-235b")
    assert os.environ.get("ANTHROPIC_BASE_URL") == SILICONFLOW_PROXY_URL

    apply_model_profile("anthropic-baseline")
    assert "ANTHROPIC_BASE_URL" not in os.environ
    assert "CLAUDE_CODE_BASE_URL" not in os.environ
    assert current_model_profile() == "anthropic-baseline"

    # Round-trip back — must be idempotent (no leftover from first apply).
    apply_model_profile("siliconflow-qwen-235b")
    assert os.environ.get("ANTHROPIC_BASE_URL") == SILICONFLOW_PROXY_URL
    assert current_model_profile() == "siliconflow-qwen-235b"
