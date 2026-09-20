"""Verify Scope accepts + validates the oauth_test_apps block and the
matches_oauth_test_app() helper finds the right app entry by token_url host.

oauth_test_apps registers operator-owned OAuth apps the agent can install
programmatically (via oauth_install_tool) to obtain fresh refresh tokens
for RFC 6749 §10.4 token-lifecycle verification.
"""
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


def test_oauth_test_apps_default_empty():
    """Without oauth_test_apps in yaml, the field defaults to []."""
    path = _write_scope(
        """
        client: t
        engagement_id: e
        authorized_by: a
        valid_from: 2026-01-01
        valid_until: 2027-01-01
        targets:
          domains: [example.com]
        """
    )
    s = Scope.load(path)
    assert s.oauth_test_apps == []


def test_oauth_test_apps_loaded():
    path = _write_scope(
        """
        client: t
        engagement_id: e
        authorized_by: a
        valid_from: 2026-01-01
        valid_until: 2027-01-01
        targets:
          domains: [example.com, ExampleChat.com]
        oauth_test_apps:
          - name: ExampleChat-ws1
            client_id_env: SLACK_WS1_CLIENT_ID
            client_secret_env: SLACK_WS1_CLIENT_SECRET
            authorize_url: https://ExampleChat.com/oauth/v2/authorize?client_id=X&scope=channels:read
            redirect_uri: https://example.com/ExampleChat-oauth-callback
            token_url: https://ExampleChat.com/api/oauth.v2.access
        """
    )
    s = Scope.load(path)
    assert len(s.oauth_test_apps) == 1
    app = s.oauth_test_apps[0]
    assert app["name"] == "ExampleChat-ws1"
    assert app["client_id_env"] == "SLACK_WS1_CLIENT_ID"
    assert app["token_url"] == "https://ExampleChat.com/api/oauth.v2.access"


def test_oauth_test_apps_not_a_list_rejected():
    path = _write_scope(
        """
        client: t
        engagement_id: e
        authorized_by: a
        valid_from: 2026-01-01
        valid_until: 2027-01-01
        targets:
          domains: [example.com]
        oauth_test_apps: "not-a-list"
        """
    )
    with pytest.raises(Exception, match=r"oauth_test_apps.*list"):
        Scope.load(path)


def test_oauth_test_apps_missing_required_field_rejected():
    """Each app entry must have name, client_id_env, client_secret_env,
    authorize_url, redirect_uri, token_url."""
    path = _write_scope(
        """
        client: t
        engagement_id: e
        authorized_by: a
        valid_from: 2026-01-01
        valid_until: 2027-01-01
        targets:
          domains: [example.com]
        oauth_test_apps:
          - name: incomplete
            client_id_env: X
        """
    )
    with pytest.raises(Exception, match=r"oauth_test_apps.*required"):
        Scope.load(path)


def test_oauth_test_apps_duplicate_names_rejected():
    path = _write_scope(
        """
        client: t
        engagement_id: e
        authorized_by: a
        valid_from: 2026-01-01
        valid_until: 2027-01-01
        targets:
          domains: [example.com]
        oauth_test_apps:
          - name: dup
            client_id_env: A
            client_secret_env: B
            authorize_url: https://example.com/auth
            redirect_uri: https://example.com/cb
            token_url: https://example.com/token
          - name: dup
            client_id_env: C
            client_secret_env: D
            authorize_url: https://example.com/auth2
            redirect_uri: https://example.com/cb
            token_url: https://example.com/token
        """
    )
    with pytest.raises(Exception, match=r"oauth_test_apps.*duplicate.*dup"):
        Scope.load(path)


def test_matches_oauth_test_app_by_token_host():
    path = _write_scope(
        """
        client: t
        engagement_id: e
        authorized_by: a
        valid_from: 2026-01-01
        valid_until: 2027-01-01
        targets:
          domains: [example.com]
        oauth_test_apps:
          - name: app1
            client_id_env: A
            client_secret_env: B
            authorize_url: https://example.com/auth
            redirect_uri: https://example.com/cb
            token_url: https://api.example.com/oauth/token
        """
    )
    s = Scope.load(path)
    match = s.matches_oauth_test_app("https://api.example.com/oauth/token?foo=bar")
    assert match is not None
    assert match["name"] == "app1"
    no_match = s.matches_oauth_test_app("https://other.example.org/oauth/token")
    assert no_match is None
    assert s.matches_oauth_test_app("") is None
