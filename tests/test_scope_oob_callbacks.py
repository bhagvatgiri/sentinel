"""Verify Scope accepts and validates the oob_callbacks opt-out field."""
from __future__ import annotations
import textwrap
import tempfile
import os
import pytest
from sentinel.core.scope import Scope


def _write_scope(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w") as f:
        f.write(textwrap.dedent(content))
    return path


def test_oob_callbacks_default_is_none() -> None:
    """Without oob_callbacks in yaml, the field defaults to None (OOB enabled)."""
    path = _write_scope(
        """
        client: test
        engagement_id: e
        authorized_by: a
        valid_from: 2026-01-01
        valid_until: 2027-01-01
        targets:
          domains: [example.com]
        """
    )
    s = Scope.load(path)
    assert s.oob_callbacks is None


def test_oob_callbacks_explicit_disabled_accepted() -> None:
    """Setting oob_callbacks: disabled disables the OOB tool."""
    path = _write_scope(
        """
        client: test
        engagement_id: e
        authorized_by: a
        valid_from: 2026-01-01
        valid_until: 2027-01-01
        targets:
          domains: [example.com]
        oob_callbacks: disabled
        """
    )
    s = Scope.load(path)
    assert s.oob_callbacks == "disabled"


def test_oob_callbacks_unknown_value_rejected() -> None:
    """Any value other than None or 'disabled' is rejected at load time."""
    path = _write_scope(
        """
        client: test
        engagement_id: e
        authorized_by: a
        valid_from: 2026-01-01
        valid_until: 2027-01-01
        targets:
          domains: [example.com]
        oob_callbacks: enabled
        """
    )
    with pytest.raises(Exception, match=r"oob_callbacks.*disabled"):
        Scope.load(path)
