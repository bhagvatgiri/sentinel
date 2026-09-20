"""Tests for the scope module — the safety-critical part.

If any of these fail, do NOT run the live scanner. The whole point of the
agent's safety story is that scope.authorize_url() rejects out-of-scope
targets, so these tests are the contract.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from sentinel.core.scope import (
    AuditLog,
    OutOfScopeError,
    Scope,
    ScopeError,
    _domain_matches,
    _ip_in_cidr,
    _normalize_repo,
)


def _scope_yaml(tmp_path: Path, **overrides) -> Path:
    today = date.today()
    data = {
        "client": "test-client",
        "engagement_id": "test-001",
        "authorized_by": "test@example.com",
        "valid_from": (today - timedelta(days=1)).isoformat(),
        "valid_until": (today + timedelta(days=30)).isoformat(),
        "targets": {
            "repos": ["github.com/acme-corp/api"],
            "domains": ["*.staging.acme.com", "api.dev.acme.com"],
            "ips": ["10.0.50.0/24"],
        },
        "out_of_scope": ["prod.acme.com", "*.customer-data.acme.com"],
        "rate_limits": {"requests_per_second": 5},
    }
    data.update(overrides)
    p = tmp_path / "scope.yaml"
    import yaml
    p.write_text(yaml.safe_dump(data))
    return p


# ---- helpers --------------------------------------------------------------


def test_domain_matches_exact():
    assert _domain_matches("api.dev.acme.com", "api.dev.acme.com")
    assert not _domain_matches("api.dev.acme.com", "api.dev.other.com")


def test_domain_matches_wildcard():
    assert _domain_matches("foo.staging.acme.com", "*.staging.acme.com")
    assert _domain_matches("staging.acme.com", "*.staging.acme.com")  # bare also matches
    assert not _domain_matches("foo.bar.staging.acme.com", "*.staging.acme.com")  # only one level
    assert not _domain_matches("staging.acme.com.evil.com", "*.staging.acme.com")


def test_ip_in_cidr():
    assert _ip_in_cidr("10.0.50.5", "10.0.50.0/24")
    assert not _ip_in_cidr("10.0.51.5", "10.0.50.0/24")
    assert not _ip_in_cidr("not-an-ip", "10.0.50.0/24")


def test_normalize_repo():
    assert _normalize_repo("https://github.com/acme/api.git") == "github.com/acme/api"
    assert _normalize_repo("git@github.com:acme/api.git") == "github.com/acme/api"
    assert _normalize_repo("github.com/acme/api") == "github.com/acme/api"
    # Case insensitive.
    assert _normalize_repo("GitHub.com/Acme/API") == "github.com/acme/api"


# ---- scope loading --------------------------------------------------------


def test_load_minimal(tmp_path):
    s = Scope.load(_scope_yaml(tmp_path))
    assert s.client == "test-client"
    assert s.is_currently_valid()
    assert s.source_hash and len(s.source_hash) == 64


def test_load_missing_required(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("client: only-this\n")
    with pytest.raises(ScopeError):
        Scope.load(p)


def test_load_inverted_dates(tmp_path):
    today = date.today()
    p = _scope_yaml(
        tmp_path,
        valid_from=(today + timedelta(days=10)).isoformat(),
        valid_until=today.isoformat(),
    )
    with pytest.raises(ScopeError):
        Scope.load(p)


def test_expired_scope_refuses(tmp_path):
    today = date.today()
    p = _scope_yaml(
        tmp_path,
        valid_from=(today - timedelta(days=30)).isoformat(),
        valid_until=(today - timedelta(days=1)).isoformat(),
    )
    s = Scope.load(p)
    assert not s.is_currently_valid()
    with pytest.raises(OutOfScopeError):
        s.authorize_url("https://api.dev.acme.com")


# ---- repo authorization ---------------------------------------------------


def test_authorize_repo_exact(tmp_path):
    s = Scope.load(_scope_yaml(tmp_path))
    s.authorize_repo("github.com/acme-corp/api")  # in scope
    s.authorize_repo("https://github.com/acme-corp/api.git")  # same, normalized


def test_authorize_repo_rejects_out_of_scope(tmp_path):
    s = Scope.load(_scope_yaml(tmp_path))
    with pytest.raises(OutOfScopeError):
        s.authorize_repo("github.com/acme-corp/totally-different")


# ---- URL authorization ----------------------------------------------------


def test_authorize_url_in_scope_domain(tmp_path):
    s = Scope.load(_scope_yaml(tmp_path))
    s.authorize_url("https://api.dev.acme.com/path")
    s.authorize_url("https://foo.staging.acme.com")


def test_authorize_url_rejects_unrelated_host(tmp_path):
    s = Scope.load(_scope_yaml(tmp_path))
    with pytest.raises(OutOfScopeError):
        s.authorize_url("https://evil.example.com")


def test_out_of_scope_overrides_in_scope(tmp_path):
    """Even if a host could match a target pattern, out_of_scope wins."""
    s = Scope.load(
        _scope_yaml(
            tmp_path,
            targets={
                "repos": [],
                "domains": ["*.acme.com"],  # would match prod.acme.com too
                "ips": [],
            },
        )
    )
    with pytest.raises(OutOfScopeError):
        s.authorize_url("https://prod.acme.com")


def test_authorize_url_no_host(tmp_path):
    s = Scope.load(_scope_yaml(tmp_path))
    with pytest.raises(OutOfScopeError):
        s.authorize_url("not-a-url")


# ---- audit log ------------------------------------------------------------


def test_audit_log_chain_intact(tmp_path):
    s = Scope.load(_scope_yaml(tmp_path), audit_log_path=tmp_path / "audit.jsonl")
    s.authorize_repo("github.com/acme-corp/api")
    try:
        s.authorize_repo("github.com/not/in-scope")
    except OutOfScopeError:
        pass
    ok, err = AuditLog.verify(tmp_path / "audit.jsonl")
    assert ok, err


def test_audit_log_detects_tampering(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    s = Scope.load(_scope_yaml(tmp_path), audit_log_path=log_path)
    s.authorize_repo("github.com/acme-corp/api")
    s.authorize_url("https://api.dev.acme.com")

    # Tamper: rewrite a middle line.
    lines = log_path.read_text().splitlines()
    assert len(lines) >= 2
    tampered = json.loads(lines[1])
    tampered["payload"] = {"hacked": True}
    lines[1] = json.dumps(tampered, sort_keys=True)
    log_path.write_text("\n".join(lines) + "\n")

    ok, err = AuditLog.verify(log_path)
    assert not ok
    assert err is not None


def test_audit_log_records_denial(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    s = Scope.load(_scope_yaml(tmp_path), audit_log_path=log_path)
    with pytest.raises(OutOfScopeError):
        s.authorize_url("https://evil.example.com")
    text = log_path.read_text()
    # Should contain a 'denied' event for the rejected URL.
    assert "denied" in text
    assert "evil.example.com" in text
