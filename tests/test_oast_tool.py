"""Smoke tests for B3 — OAST callback receiver.

Tests pure helpers + scope yaml loading. Live interactsh integration is
not tested (would require a running interactsh server).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from sentinel.agent.pentest.oast_tool import (
    _generate_secret_key,
    _generate_token_id,
    _resolve_oast_endpoint,
    _token_registry,
    ALL_TOOLS,
)


def test_all_tools_export():
    assert isinstance(ALL_TOOLS, list)
    assert len(ALL_TOOLS) == 2
    names = {t.name for t in ALL_TOOLS}
    assert "oast_register_token" in names
    assert "oast_poll" in names


def test_generate_token_id_format():
    """Tokens must be 20-char alphanumeric (interactsh-compatible)."""
    for _ in range(20):
        tok = _generate_token_id()
        assert len(tok) == 20
        assert tok.islower()
        assert all(c.isalnum() for c in tok)


def test_generate_token_id_unique():
    """Defensive: tokens must be unique per generation (no collisions)."""
    tokens = {_generate_token_id() for _ in range(100)}
    assert len(tokens) == 100, "token-ID collision — entropy too low"


def test_generate_secret_key_format():
    """Secret keys are url-safe (interactsh requirement)."""
    for _ in range(10):
        s = _generate_secret_key()
        assert len(s) >= 16
        # url-safe base64 charset
        assert all(c.isalnum() or c in "-_" for c in s)


def test_resolve_oast_endpoint_env_var(monkeypatch):
    """SENTINEL_OAST_ENDPOINT env var takes priority."""
    monkeypatch.setenv("SENTINEL_OAST_ENDPOINT", "https://oast.test/")
    ep, src = _resolve_oast_endpoint()
    assert ep == "https://oast.test"  # trailing slash stripped
    assert src == "env"


def test_resolve_oast_endpoint_no_config(monkeypatch):
    """Without env var AND without scope.oast_endpoint → (None, None)."""
    monkeypatch.delenv("SENTINEL_OAST_ENDPOINT", raising=False)
    # Note: this test assumes no PentestContext is set. _require_ctx will
    # raise, _resolve_oast_endpoint catches → returns (None, None).
    ep, src = _resolve_oast_endpoint()
    assert ep is None
    assert src is None


def test_token_registry_starts_empty_or_persists():
    """Registry is process-global. New runs DO see prior tokens unless
    process restarts. Test it's a dict with expected schema when populated."""
    assert isinstance(_token_registry, dict)
    # Add and remove a fake entry to verify schema
    _token_registry["test_token_xyz"] = {
        "secret_key": "x", "endpoint": "https://oast.test",
        "class_hint": "test", "callback_url": "https://x.oast.test",
        "callback_dns": "x.oast.test",
    }
    assert "test_token_xyz" in _token_registry
    entry = _token_registry["test_token_xyz"]
    assert entry["secret_key"] == "x"
    del _token_registry["test_token_xyz"]


def test_scope_loads_oast_endpoint(tmp_path):
    """Scope.oast_endpoint field loads correctly from yaml."""
    from sentinel.core.scope import Scope
    scope_yaml = textwrap.dedent("""\
        client: x
        engagement_id: test-oast
        authorized_by: tester@example.com
        valid_from: 2026-XX-XX
        valid_until: 2026-06-08
        targets:
          domains:
            - example.com
        oast_endpoint: https://oast.fun
        """)
    p = tmp_path / "scope.yaml"
    p.write_text(scope_yaml)
    s = Scope.load(p)
    assert s.oast_endpoint == "https://oast.fun"


def test_scope_oast_endpoint_optional(tmp_path):
    """Scope without oast_endpoint loads with field=None (no breakage)."""
    from sentinel.core.scope import Scope
    scope_yaml = textwrap.dedent("""\
        client: x
        engagement_id: test-oast2
        authorized_by: tester@example.com
        valid_from: 2026-XX-XX
        valid_until: 2026-06-08
        targets:
          domains:
            - example.com
        """)
    p = tmp_path / "scope.yaml"
    p.write_text(scope_yaml)
    s = Scope.load(p)
    assert s.oast_endpoint is None


def test_event_styles_register_oast_events():
    from sentinel.web.event_styles import EVENT_STYLES
    for kind in ("oast_token_issued", "oast_poll", "oast_callback_observed"):
        assert kind in EVENT_STYLES
    assert EVENT_STYLES["oast_callback_observed"]["chip"] == "critical"
