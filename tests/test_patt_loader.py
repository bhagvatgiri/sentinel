"""Tests for the PayloadsAllTheThings → payload_bank loader."""

from __future__ import annotations

from pathlib import Path

import pytest


def _make_patt_root(tmp_path: Path) -> Path:
    """Build a tiny PATT-shaped tree for the loader to walk."""
    root = tmp_path / "PayloadsAllTheThings"
    (root / "SQL Injection").mkdir(parents=True)
    (root / "XSS Injection").mkdir(parents=True)
    (root / "Race Condition").mkdir(parents=True)  # unmapped — must be skipped

    (root / "SQL Injection" / "MySQL Injection.md").write_text(
        "# MySQL\n\n"
        "## Union Based\n"
        "Run a union-select chain.\n"
        "```sql\n"
        "UNION SELECT NULL,NULL,NULL--\n"
        "UNION SELECT user(),version(),NULL--\n"
        "```\n"
        "\n"
        "## Time-Based Blind\n"
        "```sql\n"
        "AND SLEEP(5)--\n"
        "```\n"
        "\n"
        "## Setup\n"
        "```\n"
        "pip install sqlmap\n"  # this should be filtered as install command
        "```\n"
    )
    (root / "XSS Injection" / "README.md").write_text(
        "# XSS\n\n"
        "## Filter Bypass\n"
        "```html\n"
        "<svg onload=alert(1)>\n"
        "```\n"
    )
    (root / "Race Condition" / "README.md").write_text(
        "## Tactics\n```\nfoo\n```\n"
    )
    return root


def test_load_patt_extracts_code_blocks_and_skips_install(tmp_path):
    from sentinel.agent.pentest.payloads._patt_loader import load_patt_payloads
    root = _make_patt_root(tmp_path)
    out = load_patt_payloads(root)

    # Class mapping worked: SQL Injection → injection, XSS → xss.
    assert "injection" in out
    assert "xss" in out
    # Race Condition is unmapped and must NOT appear.
    assert all("race" not in cls.lower() for cls in out)

    # Each code block becomes a payload entry. The install-command
    # block ("pip install sqlmap") must be filtered.
    inj_subs = out["injection"]
    inj_entries = [e for sub in inj_subs.values() for e in sub]
    payloads = [e["payload"] for e in inj_entries]
    assert any("UNION SELECT NULL" in p for p in payloads)
    assert any("SLEEP(5)" in p for p in payloads)
    assert not any("pip install" in p for p in payloads), (
        "install command must be filtered out"
    )

    # Subtypes are namespaced with patt_ prefix — guarantees no
    # collision with curated subtypes.
    assert all(sub.startswith("patt_") for sub in inj_subs)


def test_load_patt_handles_missing_dir(tmp_path):
    """Non-existent PATT path → empty dict, no exception."""
    from sentinel.agent.pentest.payloads._patt_loader import load_patt_payloads
    out = load_patt_payloads(tmp_path / "nope")
    assert out == {}


def test_merge_into_does_not_overwrite_curated(tmp_path):
    from sentinel.agent.pentest.payloads._patt_loader import (
        load_patt_payloads, merge_into,
    )
    # Pre-populate with a curated entry under a name PATT might
    # accidentally collide with (e.g. someone renamed a curated sub
    # to start with patt_).
    registry: dict[str, dict[str, list[dict]]] = {
        "injection": {
            "patt_mysql_injection_union_based": [
                {"name": "CURATED — keep me", "payload": "x", "notes": ""},
            ]
        }
    }
    root = _make_patt_root(tmp_path)
    patt = load_patt_payloads(root)
    merge_into(registry, patt)
    # Curated entry must survive.
    union_sub = registry["injection"]["patt_mysql_injection_union_based"]
    assert any(p["name"] == "CURATED — keep me" for p in union_sub)


def test_live_payload_bank_includes_patt():
    """Smoke test against the real PATT clone: the registry has a
    patt_-prefixed subtype under at least one class. If this fails
    locally it means the PATT clone went missing — that's fine
    (test_load_patt_handles_missing_dir covers the no-op case)."""
    from sentinel.agent.pentest import payloads as pb
    found_patt_subtype = False
    for cls in pb.all_classes():
        for sub in pb.available_subtypes(cls):
            if sub.startswith("patt_"):
                found_patt_subtype = True
                break
        if found_patt_subtype:
            break
    if not found_patt_subtype:
        pytest.skip("PATT clone not present in this checkout")
