"""Tests for the `allow_human_signup` scope field (added 2026-XX-XX).

Mirrors test_scope_browser_strategy.py's yaml-builder pattern. Gates the
human_signup tool — operator must opt in per-engagement. Default False
preserves backward compat.
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
        "engagement_id": "test-signup-001",
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


def test_allow_human_signup_defaults_to_false(tmp_path: Path):
    """Unset → False (back-compat — human_signup tool refuses by default)."""
    scope = Scope.load(_scope_yaml(tmp_path))
    assert scope.allow_human_signup is False


def test_allow_human_signup_true_loads(tmp_path: Path):
    scope = Scope.load(_scope_yaml(tmp_path, allow_human_signup=True))
    assert scope.allow_human_signup is True


def test_allow_human_signup_false_explicit_loads(tmp_path: Path):
    scope = Scope.load(_scope_yaml(tmp_path, allow_human_signup=False))
    assert scope.allow_human_signup is False


def test_allow_human_signup_string_yes_rejected(tmp_path: Path):
    """Explicit bool only — no string coercion. 'yes' raises."""
    with pytest.raises(ScopeError) as exc_info:
        Scope.load(_scope_yaml(tmp_path, allow_human_signup="yes"))
    assert "allow_human_signup" in str(exc_info.value)
    assert "true or false" in str(exc_info.value)


def test_allow_human_signup_integer_rejected(tmp_path: Path):
    """Integers (1/0) are not coerced — must be explicit YAML bool."""
    with pytest.raises(ScopeError):
        Scope.load(_scope_yaml(tmp_path, allow_human_signup=1))


def test_allow_human_signup_empty_string_treated_as_default(tmp_path: Path):
    """Empty string is permissive: same as unset → False."""
    scope = Scope.load(_scope_yaml(tmp_path, allow_human_signup=""))
    assert scope.allow_human_signup is False
