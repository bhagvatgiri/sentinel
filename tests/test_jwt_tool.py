"""Smoke tests for B7 — JWT analyzer.

Tests the pure functions (_b64url_decode, _crack_hmac, _audit_claims,
_format_analysis). The async tool wrapper analyze_jwt is exercised at
the smoke level — full e2e (with PentestContext) is covered by the
integration suite.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from sentinel.agent.pentest.jwt_tool import (
    _audit_claims,
    _b64url_decode,
    _crack_hmac,
    _format_analysis,
    _WEAK_HMAC_SECRETS,
)


# ---- helper to build a real-shaped JWT for the cracker test --------------

def _make_hs256_jwt(payload: dict, secret: str) -> str:
    """Build a real HS256 JWT signed with the given secret."""
    header = {"alg": "HS256", "typ": "JWT"}
    h = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    p = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    s = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{h}.{p}.{s}"


# ---- _b64url_decode ------------------------------------------------------

def test_b64url_decode_with_unpadded_input():
    """JWTs strip padding; decoder must add it back."""
    encoded = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
    decoded = _b64url_decode(encoded)
    assert decoded == b'{"alg":"HS256"}'


def test_b64url_decode_handles_garbage():
    """Defensive — never raises; returns empty bytes on bad input."""
    assert _b64url_decode("!@#$%") == b""


# ---- _crack_hmac ---------------------------------------------------------

def test_crack_hmac_finds_weak_secret():
    """Token signed with `secret` (in our wordlist) should be cracked."""
    token = _make_hs256_jwt({"sub": "alice", "exp": 9999999999}, "secret")
    assert _crack_hmac(token, "HS256") == "secret"


def test_crack_hmac_finds_password123():
    token = _make_hs256_jwt({"sub": "bob"}, "password123")
    assert _crack_hmac(token, "HS256") == "password123"


def test_crack_hmac_returns_none_on_strong_secret():
    """A 64-byte random secret should NOT crack against the wordlist."""
    strong = "X" * 64 + "Z"  # not in wordlist, not a common pattern
    token = _make_hs256_jwt({"sub": "carol"}, strong)
    assert _crack_hmac(token, "HS256") is None


def test_crack_hmac_returns_none_for_non_hs_alg():
    """RS256 cannot be cracked with HMAC; cracker must early-out."""
    token = _make_hs256_jwt({"sub": "dave"}, "secret")
    # Lie about the alg — cracker only handles HS-class.
    assert _crack_hmac(token, "RS256") is None


def test_crack_hmac_handles_malformed_token():
    """Two-segment token is not a JWT; cracker returns None."""
    assert _crack_hmac("not.a.token.at.all", "HS256") is None
    assert _crack_hmac("only.two", "HS256") is None


def test_weak_secrets_wordlist_is_nonempty():
    """Defensive — the wordlist matters; ensure it's populated."""
    assert len(_WEAK_HMAC_SECRETS) >= 50
    # Famous defaults from real disclosed bugs must be present.
    assert "secret" in _WEAK_HMAC_SECRETS
    assert "your-256-bit-secret" in _WEAK_HMAC_SECRETS


# ---- _audit_claims -------------------------------------------------------

def test_audit_claims_flags_missing_exp():
    notes = _audit_claims({"sub": "alice"})
    assert any("NO `exp`" in n for n in notes)


def test_audit_claims_flags_missing_iss_and_aud():
    notes = _audit_claims({"sub": "alice", "exp": 9999999999})
    assert any("NO `iss`" in n for n in notes)
    assert any("NO `aud`" in n for n in notes)


def test_audit_claims_flags_admin_role():
    """Token claiming admin role is high-value compromise target — must be flagged."""
    notes = _audit_claims({"sub": "1", "role": "admin", "exp": 9999999999, "iss": "x", "aud": "y"})
    assert any("admin" in n.lower() and "high-value" in n for n in notes)


def test_audit_claims_flags_empty_subject():
    """Empty sub is a known auth-bypass surface (some servers default to anonymous)."""
    notes = _audit_claims({"sub": "", "exp": 9999999999, "iss": "x", "aud": "y"})
    assert any("Empty/zero `sub`" in n for n in notes)


def test_audit_claims_flags_long_lived_token():
    """exp >30d in the future = wider blast radius if leaked."""
    far_future = int(time.time()) + 365 * 86400  # 1 year
    notes = _audit_claims({"sub": "1", "exp": far_future, "iss": "x", "aud": "y"})
    assert any("Long-lived" in n for n in notes)


def test_audit_claims_quiet_on_well_formed_token():
    """A well-formed token (exp/iat/iss/aud/sub all set, short TTL) should
    produce NO warning notes — only informational `·` ones."""
    short = int(time.time()) + 3600
    notes = _audit_claims({
        "sub": "user-42", "exp": short, "iat": int(time.time()) - 60,
        "iss": "https://issuer.example", "aud": "api.example.com",
        "role": "user",
    })
    assert all("" not in n and "" not in n for n in notes)


# ---- _format_analysis ----------------------------------------------------

def test_format_analysis_flags_alg_none():
    """alg=none is the highest-severity JWT bug — must be unmissable."""
    out = _format_analysis(
        header={"alg": "none", "typ": "JWT"}, payload={"sub": "alice"},
        sig_present=False, weak_secret=None, audit_notes=[],
    )
    assert "alg=none" in out
    assert "" in out  # critical-finding marker


def test_format_analysis_flags_weak_secret():
    out = _format_analysis(
        header={"alg": "HS256", "typ": "JWT"}, payload={"sub": "alice"},
        sig_present=True, weak_secret="secret", audit_notes=[],
    )
    assert "WEAK HMAC SECRET" in out
    assert "'secret'" in out  # secret is short enough to print
    assert "" in out


def test_format_analysis_redacts_long_weak_secret():
    """If a long secret somehow matched, redact it from the report — operator
    safety in case of screenshot sharing during triage."""
    long_secret = "a" * 64
    out = _format_analysis(
        header={"alg": "HS256"}, payload={"sub": "x"},
        sig_present=True, weak_secret=long_secret, audit_notes=[],
    )
    assert long_secret not in out
    assert "redacted" in out.lower()
    assert "length 64" in out or "len=64" in out or "(length 64" in out


def test_format_analysis_flags_suspicious_kid():
    """kid = path traversal indicator → pentest follow-up signal."""
    out = _format_analysis(
        header={"alg": "RS256", "kid": "../../../etc/passwd"},
        payload={"sub": "alice"}, sig_present=True, weak_secret=None,
        audit_notes=[],
    )
    assert "suspicious" in out.lower()
    assert "../" in out


def test_format_analysis_recommends_alg_confusion_for_rs256():
    """When alg is RS256/ES256, the report should suggest the alg-confusion attack."""
    out = _format_analysis(
        header={"alg": "RS256"}, payload={"sub": "alice"},
        sig_present=True, weak_secret=None, audit_notes=[],
    )
    assert "alg-confusion" in out or "alg confusion" in out


def test_all_tools_export():
    from sentinel.agent.pentest.jwt_tool import ALL_TOOLS
    assert isinstance(ALL_TOOLS, list)
    assert len(ALL_TOOLS) >= 1
    for t in ALL_TOOLS:
        assert hasattr(t, "name")
