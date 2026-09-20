"""Tests for the `captcha_solver` scope field (added 2026-XX-XX).

Mirrors test_scope_browser_strategy.py's yaml-builder pattern. Drives
NopeCHA browser-extension activation in _BrowserSession; default None
preserves the existing back-compat launch path.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from sentinel.core.scope import Scope, ScopeError


def _scope_yaml(tmp_path: Path, **overrides) -> Path:
    today = date.today()
    data = {
        "client": "test-client",
        "engagement_id": "test-captcha-001",
        "authorized_by": "test@example.com",
        "valid_from": (today - timedelta(days=1)).isoformat(),
        "valid_until": (today + timedelta(days=30)).isoformat(),
        "targets": {
            "domains": ["example.com"],
        },
    }
    data.update(overrides)
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_captcha_solver_defaults_to_none(tmp_path: Path):
    """Unset captcha_solver → None (back-compat — no NopeCHA activation)."""
    scope = Scope.load(_scope_yaml(tmp_path))
    assert scope.captcha_solver is None


def test_captcha_solver_nopecha_loads(tmp_path: Path):
    """captcha_solver=nopecha is the only supported value today."""
    scope = Scope.load(_scope_yaml(tmp_path, captcha_solver="nopecha"))
    assert scope.captcha_solver == "nopecha"


def test_captcha_solver_normalizes_case(tmp_path: Path):
    """Case-insensitive — operator can write NopeCHA, NOPECHA, nopecha."""
    scope = Scope.load(_scope_yaml(tmp_path, captcha_solver="NopeCHA"))
    assert scope.captcha_solver == "nopecha"


def test_captcha_solver_unknown_value_raises(tmp_path: Path):
    """Unknown solver values are rejected with a clear ScopeError."""
    with pytest.raises(ScopeError) as exc_info:
        Scope.load(_scope_yaml(tmp_path, captcha_solver="anticaptcha"))
    msg = str(exc_info.value)
    assert "unknown captcha_solver" in msg
    assert "nopecha" in msg


def test_captcha_solver_non_string_raises(tmp_path: Path):
    """Non-string values like 123 fail loud at load time."""
    with pytest.raises(ScopeError) as exc_info:
        Scope.load(_scope_yaml(tmp_path, captcha_solver=123))
    assert "must be a string" in str(exc_info.value)


def test_captcha_solver_empty_string_treated_as_none(tmp_path: Path):
    """Empty string is permissive: same as unset → None."""
    scope = Scope.load(_scope_yaml(tmp_path, captcha_solver=""))
    assert scope.captcha_solver is None
