"""Fix 1 (C3) — Cloudflare middlebox detection + faster fail.

Live ExampleChat scan showed the Claude SDK streaming connection hangs (no SDK
output for 120s) on Cloudflare-fronted targets. The previous retry pattern
([5s, 30s, 120s] × 4 attempts) wasted 20-40 min per stuck phase because the
underlying problem is the network path, not a transient blip.

This test pins the two PipelineConfig defaults that govern that wait:

- `sdk_hang_max_retries` — caps additional attempts after the first crash.
- `sdk_hang_timeout_sec` — per-iteration timeout that converts a silent
  stream freeze into a retryable TimeoutError.

Hermetic — no SDK, no network, no Ollama. Just instantiates the dataclass
and asserts on its field defaults.
"""

import pytest


def test_sdk_hang_config_defaults_reasonable():
    from sentinel.agent.pentest.pipeline import PipelineConfig

    cfg = PipelineConfig(target="https://example.com", scope_path="/tmp/x.yaml")
    assert cfg.sdk_hang_max_retries <= 2, "retries should cap at 2 to limit waste"
    assert cfg.sdk_hang_timeout_sec <= 60, "hang detect should fire within 60s"
    assert cfg.sdk_hang_max_retries >= 1, "must allow at least 1 retry"


def test_sdk_hang_config_overridable():
    """Operator must still be able to bump the cap when running on a
    well-known-good path (e.g. direct-to-anthropic without Cloudflare).
    """
    from sentinel.agent.pentest.pipeline import PipelineConfig

    cfg = PipelineConfig(
        target="https://example.com",
        scope_path="/tmp/x.yaml",
        sdk_hang_max_retries=3,
        sdk_hang_timeout_sec=180,
    )
    assert cfg.sdk_hang_max_retries == 3
    assert cfg.sdk_hang_timeout_sec == 180
