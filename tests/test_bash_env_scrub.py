"""Wave 1 / A8 — env-scrub regression tests.

Threat model: attacker successfully smuggles a prompt-injection past
layers 1–3 (somehow), and the agent executes a `$(env)`-style command.
The child process MUST NOT see the operator's auth secrets in its environment;
otherwise the leaked stdout becomes data the agent (or the attacker)
can exfil.
"""

from __future__ import annotations

import os

import pytest

from sentinel.agent.pentest.bash_tool import _scrubbed_env


def test_anthropic_api_key_scrubbed(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    env = _scrubbed_env()
    assert "ANTHROPIC_API_KEY" not in env


def test_openai_api_key_scrubbed(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-secret")
    env = _scrubbed_env()
    assert "OPENAI_API_KEY" not in env


def test_claude_oauth_token_scrubbed(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-secret")
    env = _scrubbed_env()
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in env


def test_arbitrary_token_scrubbed(monkeypatch):
    monkeypatch.setenv("MY_PRIVATE_TOKEN", "deadbeef")
    env = _scrubbed_env()
    assert "MY_PRIVATE_TOKEN" not in env


def test_arbitrary_secret_scrubbed(monkeypatch):
    monkeypatch.setenv("APPLICATION_SECRET", "deadbeef")
    env = _scrubbed_env()
    assert "APPLICATION_SECRET" not in env


def test_arbitrary_key_scrubbed(monkeypatch):
    monkeypatch.setenv("DATABASE_KEY", "deadbeef")
    env = _scrubbed_env()
    assert "DATABASE_KEY" not in env


def test_aws_creds_scrubbed(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAxxxxxxxxxxxxxxxxx")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "token")
    env = _scrubbed_env()
    assert "AWS_ACCESS_KEY_ID" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "AWS_SESSION_TOKEN" not in env


def test_gcp_creds_scrubbed(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "myproj")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/path/cred.json")
    env = _scrubbed_env()
    assert "GCP_PROJECT" not in env
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in env


def test_path_kept(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
    env = _scrubbed_env()
    assert env.get("PATH") == "/usr/local/bin:/usr/bin:/bin"


def test_home_kept(monkeypatch):
    monkeypatch.setenv("HOME", "/Users/test")
    env = _scrubbed_env()
    assert env.get("HOME") == "/Users/test"


def test_lang_kept(monkeypatch):
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    env = _scrubbed_env()
    assert env.get("LANG") == "en_US.UTF-8"


def test_password_var_scrubbed(monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "p4ss")
    env = _scrubbed_env()
    assert "DB_PASSWORD" not in env


def test_github_token_scrubbed(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("GH_TOKEN", "ghp_x")
    env = _scrubbed_env()
    assert "GITHUB_TOKEN" not in env
    assert "GH_TOKEN" not in env


def test_npm_pypi_scrubbed(monkeypatch):
    monkeypatch.setenv("NPM_TOKEN", "x")
    monkeypatch.setenv("PYPI_PASSWORD", "x")
    env = _scrubbed_env()
    assert "NPM_TOKEN" not in env
    assert "PYPI_PASSWORD" not in env


def test_normal_var_kept(monkeypatch):
    monkeypatch.setenv("MY_HARMLESS_VAR", "value")
    env = _scrubbed_env()
    assert env.get("MY_HARMLESS_VAR") == "value"


def test_returns_dict_not_view(monkeypatch):
    """Caller is going to mutate the returned dict (rare, but defensive).
    Ensure we returned a fresh dict, not a view of os.environ."""
    env = _scrubbed_env()
    env["SCRATCH"] = "x"
    assert os.environ.get("SCRATCH") != "x"
