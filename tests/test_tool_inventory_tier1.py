"""Verify the 13 Tier-1 pentest tools are registered in TOOL_INVENTORY."""
from __future__ import annotations
import pytest
from sentinel.core.tool_inventory import TOOL_INVENTORY, Tool

TIER1_EXPECTED = {
    "httpx-pd":     ("passive",  "HTTP probe / tech detect (PD)"),
    "dnsx":         ("passive",  "DNS toolkit (PD)"),
    "naabu":        ("active",   "Port scanner (PD)"),
    "wpscan":       ("active",   "WordPress vuln scan"),
    "netexec":      ("network",  "SMB/WinRM/LDAP/MSSQL (formerly CrackMapExec)"),
    "arjun":        ("active",   "HTTP parameter discovery"),
    "paramspider":  ("passive",  "Wayback URL parameter mining"),
    "subzy":        ("active",   "Subdomain takeover scanner"),
    "subjack":      ("active",   "Subdomain takeover scanner"),
    "secretfinder": ("passive",  "JS secret regex extractor"),
    "linkfinder":   ("passive",  "JS endpoint extractor"),
    "mantra":       ("passive",  "JS endpoint+secret discovery (Go)"),
    "jwt_tool":     ("active",   "JWT auditing"),
}


@pytest.mark.parametrize("name,expected", TIER1_EXPECTED.items())
def test_tier1_tool_registered(name: str, expected: tuple[str, str]) -> None:
    expected_tier, expected_label_substr = expected
    matches = [t for t in TOOL_INVENTORY if t.name == name]
    assert len(matches) == 1, f"expected exactly one Tool({name=}), found {len(matches)}"
    tool = matches[0]
    assert tool.tier == expected_tier
    assert expected_label_substr.lower() in tool.label.lower(), (
        f"{name}: label {tool.label!r} doesn't mention {expected_label_substr!r}"
    )


def test_tier1_tools_have_install_hints() -> None:
    for name in TIER1_EXPECTED:
        tool = next(t for t in TOOL_INVENTORY if t.name == name)
        assert tool.install_hint, f"{name} missing install_hint"
        assert any(
            keyword in tool.install_hint.lower()
            for keyword in ("go install", "pipx", "gem install", "brew", "git+https")
        ), f"{name} install_hint looks suspicious: {tool.install_hint!r}"


def test_secretfinder_binary_search() -> None:
    """secretfinder is installed via git-clone, so the binary name is SecretFinder.py."""
    tool = next(t for t in TOOL_INVENTORY if t.name == "secretfinder")
    assert "SecretFinder.py" in tool.search_names()


def test_netexec_binary_search() -> None:
    """netexec installs as `nxc` binary."""
    tool = next(t for t in TOOL_INVENTORY if t.name == "netexec")
    assert "nxc" in tool.search_names()


def test_httpx_pd_distinct_from_python_httpx_library() -> None:
    """The PD httpx binary must be installed as httpx-pd (renamed at install) to avoid
    colliding with the Python httpx library that Sentinel depends on."""
    tool = next(t for t in TOOL_INVENTORY if t.name == "httpx-pd")
    assert "httpx-pd" in tool.search_names()
    assert "httpx" not in tool.search_names(), (
        "httpx-pd must NOT search for plain 'httpx' — collides with Python httpx library"
    )
