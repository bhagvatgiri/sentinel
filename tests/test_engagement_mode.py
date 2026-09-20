"""Wave 3 — engagement_mode core tests.

Asserted properties:
  - EngagementMode.from_string round-trips, case-insensitive, raises
    on unknown values, defaults None / "" to PRODUCTION.
  - is_tool_allowed correctly gates webshell / reverse-shell / etc. by
    mode. Production / BBP block; CTF / LAB allow.
  - Scope.assert_mode_matches raises on mismatched CLI mode.
  - assert_lab_mode_scope raises if scope contains a non-RFC1918 /
    non-loopback target.
  - AuditLog.write stamps mode on every entry, hash chain still
    verifies clean, and verify(scope_mode=...) catches a mismatch.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from sentinel.core.engagement_mode import (
    CTF_ONLY_TOOL_SET,
    EngagementMode,
    ModeError,
    ModeMismatchError,
    PRODUCTION_TOOL_SET,
    assert_lab_mode_scope,
    assert_tool_allowed_at_runtime,
    filter_tools_for_mode,
    is_tool_allowed,
)
from sentinel.core.scope import AuditLog, OutOfScopeError, Scope, ScopeError


# ---- helpers --------------------------------------------------------------


def _scope_yaml(tmp_path: Path, **overrides) -> Path:
    today = date.today()
    data = {
        "client": "test-client",
        "engagement_id": "test-001",
        "authorized_by": "test@example.com",
        "valid_from": (today - timedelta(days=1)).isoformat(),
        "valid_until": (today + timedelta(days=30)).isoformat(),
        "targets": {
            "domains": ["target.com"],
            "ips": [],
        },
        "rate_limits": {"requests_per_second": 5},
    }
    data.update(overrides)
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


# ---- EngagementMode.from_string ------------------------------------------


def test_from_string_default_is_production():
    assert EngagementMode.from_string(None) is EngagementMode.PRODUCTION
    assert EngagementMode.from_string("") is EngagementMode.PRODUCTION


def test_from_string_each_mode():
    assert EngagementMode.from_string("production") is EngagementMode.PRODUCTION
    assert EngagementMode.from_string("bbp") is EngagementMode.BBP
    assert EngagementMode.from_string("ctf") is EngagementMode.CTF
    assert EngagementMode.from_string("lab") is EngagementMode.LAB


def test_from_string_case_insensitive():
    assert EngagementMode.from_string("CTF") is EngagementMode.CTF
    assert EngagementMode.from_string("CtF") is EngagementMode.CTF
    assert EngagementMode.from_string("  Lab  ") is EngagementMode.LAB


def test_from_string_unknown_raises():
    with pytest.raises(ModeError):
        EngagementMode.from_string("hacker")
    with pytest.raises(ModeError):
        EngagementMode.from_string("prod")
    with pytest.raises(ModeError):
        EngagementMode.from_string(123)  # type: ignore[arg-type]


def test_allows_ctf_tools_property():
    assert not EngagementMode.PRODUCTION.allows_ctf_tools
    assert not EngagementMode.BBP.allows_ctf_tools
    assert EngagementMode.CTF.allows_ctf_tools
    assert EngagementMode.LAB.allows_ctf_tools


# ---- is_tool_allowed -----------------------------------------------------


@pytest.mark.parametrize("tool_name", sorted(CTF_ONLY_TOOL_SET))
def test_ctf_tools_blocked_in_production(tool_name):
    assert not is_tool_allowed(tool_name, EngagementMode.PRODUCTION)


@pytest.mark.parametrize("tool_name", sorted(CTF_ONLY_TOOL_SET))
def test_ctf_tools_blocked_in_bbp(tool_name):
    assert not is_tool_allowed(tool_name, EngagementMode.BBP)


@pytest.mark.parametrize("tool_name", sorted(CTF_ONLY_TOOL_SET))
def test_ctf_tools_allowed_in_ctf(tool_name):
    assert is_tool_allowed(tool_name, EngagementMode.CTF)


@pytest.mark.parametrize("tool_name", sorted(CTF_ONLY_TOOL_SET))
def test_ctf_tools_allowed_in_lab(tool_name):
    assert is_tool_allowed(tool_name, EngagementMode.LAB)


def test_production_tools_allowed_everywhere():
    # Every production tool stays available in CTF / LAB too — CTF is a
    # SUPERSET, not a replacement.
    for name in PRODUCTION_TOOL_SET:
        for mode in EngagementMode:
            assert is_tool_allowed(name, mode), (
                f"{name} blocked under {mode}"
            )


def test_unknown_tool_defaults_to_allowed():
    # Future tools added by Wave 4+ should keep working until they're
    # explicitly added to one of the gating sets.
    assert is_tool_allowed("brand_new_tool_in_wave_99", EngagementMode.PRODUCTION)


def test_assert_tool_allowed_at_runtime():
    # Production refuses CTF tools.
    with pytest.raises(ModeError):
        assert_tool_allowed_at_runtime(
            "drop_webshell", EngagementMode.PRODUCTION,
        )
    # CTF allows them.
    assert_tool_allowed_at_runtime("drop_webshell", EngagementMode.CTF) is None


# ---- filter_tools_for_mode -----------------------------------------------


class _StubTool:
    def __init__(self, name):
        self.name = name


def test_filter_drops_ctf_tools_in_production():
    tools = [
        _StubTool("http_get"),
        _StubTool("drop_webshell"),
        _StubTool("flag_discriminator"),
        _StubTool("oast_register_token"),
    ]
    filtered = filter_tools_for_mode(tools, EngagementMode.PRODUCTION)
    names = {t.name for t in filtered}
    assert "drop_webshell" not in names
    assert "flag_discriminator" not in names
    assert "http_get" in names
    assert "oast_register_token" in names


def test_filter_keeps_ctf_tools_in_ctf():
    tools = [
        _StubTool("http_get"),
        _StubTool("drop_webshell"),
        _StubTool("flag_discriminator"),
    ]
    filtered = filter_tools_for_mode(tools, EngagementMode.CTF)
    names = {t.name for t in filtered}
    assert names == {"http_get", "drop_webshell", "flag_discriminator"}


# ---- Scope mode parsing --------------------------------------------------


def test_scope_default_mode_is_production(tmp_path):
    s = Scope.load(_scope_yaml(tmp_path))
    assert s.engagement_mode is EngagementMode.PRODUCTION


def test_scope_loads_ctf_mode(tmp_path):
    s = Scope.load(_scope_yaml(tmp_path, engagement_mode="ctf",
                                ctf_platform="hackthebox",
                                ctf_flag_format="HTB{...}",
                                ctf_box_writeup_dir=str(tmp_path / "writeups")))
    assert s.engagement_mode is EngagementMode.CTF
    assert s.ctf_platform == "hackthebox"


def test_scope_unknown_mode_raises_scope_error(tmp_path):
    with pytest.raises(ScopeError):
        Scope.load(_scope_yaml(tmp_path, engagement_mode="hacker"))


# ---- Scope.assert_mode_matches -------------------------------------------


def test_assert_mode_matches_agreement(tmp_path):
    s = Scope.load(_scope_yaml(tmp_path, engagement_mode="ctf",
                                targets={"domains": ["target.com"]}))
    # Same mode → no raise.
    s.assert_mode_matches("ctf")
    s.assert_mode_matches(EngagementMode.CTF)
    # None / "" → trust scope, no raise.
    s.assert_mode_matches(None)
    s.assert_mode_matches("")


def test_assert_mode_matches_disagreement_raises(tmp_path):
    s = Scope.load(_scope_yaml(tmp_path, engagement_mode="production"))
    with pytest.raises(ModeMismatchError):
        s.assert_mode_matches("ctf")


def test_assert_mode_matches_unknown_raises(tmp_path):
    s = Scope.load(_scope_yaml(tmp_path))
    with pytest.raises(ModeMismatchError):
        s.assert_mode_matches("not-a-real-mode")


# ---- LAB-mode scope guard ------------------------------------------------


def test_lab_mode_accepts_loopback(tmp_path):
    s = Scope.load(_scope_yaml(
        tmp_path, engagement_mode="lab",
        targets={"domains": ["localhost"], "ips": ["127.0.0.1"]},
    ))
    assert s.engagement_mode is EngagementMode.LAB


def test_lab_mode_accepts_rfc1918(tmp_path):
    s = Scope.load(_scope_yaml(
        tmp_path, engagement_mode="lab",
        targets={"domains": [], "ips": ["10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12"]},
    ))
    assert s.engagement_mode is EngagementMode.LAB


def test_lab_mode_rejects_public_domain(tmp_path):
    with pytest.raises(OutOfScopeError):
        Scope.load(_scope_yaml(
            tmp_path, engagement_mode="lab",
            targets={"domains": ["target.com"], "ips": []},
        ))


def test_lab_mode_rejects_public_ip(tmp_path):
    with pytest.raises(OutOfScopeError):
        Scope.load(_scope_yaml(
            tmp_path, engagement_mode="lab",
            targets={"domains": [], "ips": ["8.8.8.8"]},
        ))


# ---- AuditLog mode stamping + verify -------------------------------------


def test_audit_log_stamps_mode(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    s = Scope.load(_scope_yaml(tmp_path, engagement_mode="ctf"),
                    audit_log_path=log_path)
    # Trigger another entry so we have >1 line stamped.
    try:
        s.authorize_url("https://target.com/")
    except OutOfScopeError:
        pass
    text = log_path.read_text()
    for line in text.strip().splitlines():
        entry = json.loads(line)
        assert entry.get("mode") == "ctf"


def test_audit_log_chain_verifies_with_mode(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    s = Scope.load(_scope_yaml(tmp_path, engagement_mode="ctf"),
                    audit_log_path=log_path)
    try:
        s.authorize_url("https://target.com/")
    except OutOfScopeError:
        pass
    ok, err = AuditLog.verify(log_path)
    assert ok, err


def test_audit_log_verify_rejects_mode_mismatch(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    s = Scope.load(_scope_yaml(tmp_path, engagement_mode="ctf"),
                    audit_log_path=log_path)
    # Verify against a scope that claims production — must fail.
    ok, err = AuditLog.verify(log_path, scope_mode="production")
    assert not ok
    assert err is not None
    assert "mode" in err.lower()


def test_audit_log_verify_accepts_matching_mode(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    s = Scope.load(_scope_yaml(tmp_path, engagement_mode="bbp"),
                    audit_log_path=log_path)
    ok, err = AuditLog.verify(log_path, scope_mode="bbp")
    assert ok, err


def test_audit_log_pre_wave3_entries_still_verify(tmp_path):
    """A pre-Wave-3 audit log (no mode field) must still verify clean.
    Backwards-compat for existing engagements on disk."""
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    log.write("scope_loaded", {"x": 1})  # no mode arg
    log.write("authorized", {"target": "https://x.com"})
    ok, err = AuditLog.verify(log_path)
    assert ok, err
