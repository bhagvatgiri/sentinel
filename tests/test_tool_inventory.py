"""Canonical tool inventory — both UIs + the CLI consume this single source."""

from __future__ import annotations

from sentinel.core.tool_inventory import (
    TOOL_INVENTORY, all_tools, by_tier, check_all, check_all_grouped,
    check_tool, get,
)


def test_inventory_has_all_phase1_offensive_tools():
    """Phase 1 added hydra/sqlmap/nikto/gobuster/kr/testssl.sh — all must be here."""
    names = {t.name for t in TOOL_INVENTORY}
    for required in ("hydra", "sqlmap", "nikto", "gobuster", "kiterunner", "testssl"):
        assert required in names, f"missing {required!r} from canonical inventory"


def test_every_tool_has_install_hint():
    for t in TOOL_INVENTORY:
        assert t.install_hint, f"{t.name} missing install_hint"
        assert t.label, f"{t.name} missing label"
        assert t.tier in ("passive", "active", "network", "ai"), \
            f"{t.name} has invalid tier {t.tier!r}"


def test_active_tier_includes_brute_and_inject_tools():
    active_names = {t.name for t in by_tier().get("active", [])}
    for offensive in ("hydra", "sqlmap", "nikto", "gobuster", "ffuf", "nuclei"):
        assert offensive in active_names, \
            f"{offensive!r} should be tier=active (it sends payloads/brute traffic)"


def test_passive_tier_excludes_offensive_tools():
    passive_names = {t.name for t in by_tier().get("passive", [])}
    # Brute-force / injection tools must never be tagged passive — operators
    # shouldn't think they're safe to flip on.
    for not_passive in ("hydra", "sqlmap", "nikto", "nuclei"):
        assert not_passive not in passive_names, \
            f"{not_passive!r} must NOT be tier=passive"


def test_get_returns_none_for_unknown():
    assert get("nonexistent-tool-12345") is None


def test_get_returns_canonical_tool():
    t = get("semgrep")
    assert t is not None
    assert t.label == "SAST"
    assert t.tier == "passive"


def test_check_all_returns_one_row_per_tool():
    rows = check_all()
    assert len(rows) == len(TOOL_INVENTORY)
    for r in rows:
        assert {"name", "label", "install_hint", "tier", "ok", "path"} <= set(r.keys())


def test_check_all_grouped_buckets_match_by_tier():
    grouped = check_all_grouped()
    flat_count = sum(len(v) for v in grouped.values())
    assert flat_count == len(TOOL_INVENTORY)


def test_check_tool_handles_missing_binary():
    """A tool that's definitely not on PATH should report (False, '')."""
    from sentinel.core.tool_inventory import Tool
    fake = Tool("fake-xyz-99999", "fake", "n/a", "active",
                binaries=("definitely-not-real-binary-xyz-99999",))
    ok, path = check_tool(fake)
    assert ok is False
    assert path == ""


def test_zap_special_case_present():
    """ZAP cask path should be checked even when zap.sh isn't on PATH.
    We can't assert it's installed (depends on the operator's machine), but
    the check_tool() codepath shouldn't raise."""
    z = get("zap")
    assert z is not None
    ok, path = check_tool(z)
    assert isinstance(ok, bool)
    assert isinstance(path, str)


# --------------------------------------------------------------------------
# Tier-1 install pass (2026-XX-XX) — verify every newly-registered tool is
# in the inventory and well-formed. These tests don't require the binaries
# to be installed; they only check the registration metadata.
# --------------------------------------------------------------------------


_TIER1_NEW_TOOLS = {
    # iOS / mobile
    "frida", "objection", "jadx", "apktool", "ipsw",
    # Container / Kubernetes
    "kube-bench", "kube-hunter", "dive",
    # Active Directory / internal pentest
    "impacket", "bloodhound-python", "netexec", "smbmap",
    "enum4linux-ng", "ldapsearch",
    # OSINT depth
    "shodan", "theHarvester", "holehe", "sherlock",
    # Web3 / smart contracts
    "slither", "mythril",
    # Source-code review
    "bandit", "brakeman", "gosec",
    # Web / API specific
    "dalfox", "schemathesis", "hakrawler", "dirsearch",
    # Recon depth
    "findomain", "chaos", "aquatone",
    # Cloud depth
    "scoutsuite", "pacu",
}


def test_tier1_install_pass_all_registered():
    names = {t.name for t in TOOL_INVENTORY}
    missing = _TIER1_NEW_TOOLS - names
    assert not missing, f"tier-1 install pass missing inventory entries: {missing}"


def test_tier1_install_hints_are_actionable():
    for tool in TOOL_INVENTORY:
        if tool.name not in _TIER1_NEW_TOOLS:
            continue
        # Hint must look like a real install command (brew/pipx/go/gem/npm).
        hint = tool.install_hint.lower()
        assert any(p in hint for p in ("brew install", "pipx install",
                                         "go install", "gem install",
                                         "npm install")), \
            f"{tool.name}: install_hint not actionable: {tool.install_hint!r}"


def test_tier1_no_duplicate_names():
    names = [t.name for t in TOOL_INVENTORY]
    assert len(names) == len(set(names)), \
        f"duplicate tool names in TOOL_INVENTORY: {[n for n in names if names.count(n) > 1]}"


def test_tier1_tiers_are_sensible():
    """Spot-check tier assignments on the new tools so we catch obvious miscategorizations."""
    # Static analyzers should be passive.
    for static in ("slither", "bandit", "brakeman", "gosec",
                   "jadx", "apktool", "ipsw", "kube-bench", "dive"):
        t = get(static)
        assert t is not None, static
        assert t.tier == "passive", \
            f"{static} should be tier=passive, got {t.tier!r}"
    # Brute / fuzz / dynamic instrumentation tools should be active.
    for active in ("frida", "objection", "kube-hunter", "dalfox",
                   "schemathesis", "dirsearch", "pacu"):
        t = get(active)
        assert t is not None, active
        assert t.tier == "active", \
            f"{active} should be tier=active, got {t.tier!r}"
    # AD / SMB / LDAP enum sits at the network tier.
    for net in ("impacket", "bloodhound-python", "netexec",
                "smbmap", "enum4linux-ng", "ldapsearch"):
        t = get(net)
        assert t is not None, net
        assert t.tier == "network", \
            f"{net} should be tier=network, got {t.tier!r}"


def test_tier1_binaries_set_when_name_differs():
    # When the binary names differ from the tool key, `binaries=` must be set.
    expectations = {
        "mythril": ("myth",),
        "netexec": ("nxc",),
        "scoutsuite": ("scout",),
    }
    for tool_name, expected_binaries in expectations.items():
        t = get(tool_name)
        assert t is not None
        assert t.binaries == expected_binaries, \
            f"{tool_name}: expected binaries={expected_binaries}, got {t.binaries}"
