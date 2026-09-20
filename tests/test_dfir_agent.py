"""B12 — DFIR agent tests.

Synthetic apache log + raw text → assert IOC extraction (IPs, hashes,
URLs, emails) AND timeline reconstruction (sorted-by-ts events, per-source
bucketing, first/last seen).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agent.pentest.dfir_agent import (
    build_timeline,
    extract_iocs,
    match_yara,
    parse_log,
    render_incident_report,
)


# ---- IOC extraction ------------------------------------------------------

def test_extract_iocs_ipv4_and_ipv6():
    text = "src=10.0.0.5 dst=192.168.1.1 v6=2001:db8::1 evil=2001:abcd:1234::f"
    out = extract_iocs(text)
    assert "10.0.0.5" in out["ipv4"]
    assert "192.168.1.1" in out["ipv4"]
    assert "2001:db8::1" in out["ipv6"]
    assert "2001:abcd:1234::f" in out["ipv6"]


def test_extract_iocs_hashes_separated_by_length():
    sha256 = "a" * 64
    sha1 = "b" * 40
    md5 = "c" * 32
    text = f"sha256={sha256} sha1={sha1} md5={md5}"
    out = extract_iocs(text)
    assert sha256 in out["sha256"]
    assert sha1 in out["sha1"]
    assert md5 in out["md5"]
    # 32-char string also matches md5 — the deconfliction must remove
    # md5 entries that are *also* in sha256 prefix; the 32-char must
    # still be classified as md5 if it's a standalone 32-hex token.
    assert sha1 not in out["sha256"]
    assert md5 not in out["sha1"]


def test_extract_iocs_urls_and_emails():
    text = (
        "Visit http://attacker.example.com/payload.exe to download\n"
        "Contact attacker@evil.example for ransom"
    )
    out = extract_iocs(text)
    assert "http://attacker.example.com/payload.exe" in out["urls"]
    assert "attacker@evil.example" in out["emails"]


def test_extract_iocs_url_host_not_double_counted_as_domain():
    """attacker.example.com appears in URL → not duplicated in domains."""
    text = "http://attacker.example.com/x.exe and someother.host.example"
    out = extract_iocs(text)
    assert "attacker.example.com" not in out["domains"]
    # someother.host.example wasn't in a URL → stays in domains
    assert "someother.host.example" in out["domains"]


def test_extract_iocs_empty_input():
    out = extract_iocs("")
    assert all(out[k] == [] for k in out)


# ---- log parsing ---------------------------------------------------------

APACHE_ATTACK_LINES = [
    '203.0.113.5 - - [01/May/2026:12:00:01 +0000] "GET /admin HTTP/1.1" 401 162 "-" "Mozilla"',
    '203.0.113.5 - - [01/May/2026:12:00:02 +0000] "POST /login HTTP/1.1" 401 89 "-" "Mozilla"',
    '203.0.113.5 - - [01/May/2026:12:00:03 +0000] "POST /login HTTP/1.1" 200 412 "-" "Mozilla"',
    '203.0.113.5 - - [01/May/2026:12:00:10 +0000] "GET /admin/dashboard HTTP/1.1" 200 1024 "-" "Mozilla"',
    '203.0.113.5 - - [01/May/2026:12:00:15 +0000] "GET /etc/passwd HTTP/1.1" 404 200 "-" "Mozilla"',
    '198.51.100.99 - - [01/May/2026:12:01:00 +0000] "GET / HTTP/1.1" 200 5000 "-" "Browser"',
]


def test_parse_apache_log(tmp_path: Path):
    log_path = tmp_path / "access.log"
    log_path.write_text("\n".join(APACHE_ATTACK_LINES) + "\n")
    out = parse_log(str(log_path), format="apache", workspace=str(tmp_path))
    assert out["format"] == "apache"
    assert out["event_count"] == len(APACHE_ATTACK_LINES)
    first = out["events"][0]
    assert first["ip"] == "203.0.113.5"
    assert first["method"] == "GET"
    assert first["path"] == "/admin"
    assert first["status"] == 401
    # Timestamps parsed
    assert "2026" in (first["ts"] or "")


def test_parse_log_auto_detects_apache(tmp_path: Path):
    log_path = tmp_path / "access.log"
    log_path.write_text("\n".join(APACHE_ATTACK_LINES) + "\n")
    out = parse_log(str(log_path), format="auto", workspace=str(tmp_path))
    assert out["format"] == "apache"
    assert out["event_count"] == len(APACHE_ATTACK_LINES)


def test_parse_log_json_format(tmp_path: Path):
    log_path = tmp_path / "events.json"
    log_path.write_text(
        '{"ts":"2026-XX-XXT12:00:01Z","ip":"203.0.113.5","action":"login_failed"}\n'
        '{"ts":"2026-XX-XXT12:00:05Z","ip":"203.0.113.5","action":"login_success"}\n'
    )
    out = parse_log(str(log_path), format="auto")
    assert out["format"] == "json"
    assert out["event_count"] == 2
    assert out["events"][0]["ip"] == "203.0.113.5"


def test_parse_log_workspace_traversal_blocked(tmp_path: Path):
    outside = tmp_path / "outside.log"
    outside.write_text("foo\n")
    ws = tmp_path / "ws"
    ws.mkdir()
    out = parse_log(str(outside), workspace=str(ws))
    assert "outside workspace" in (out.get("error") or "")


def test_parse_log_missing_file():
    out = parse_log("/nonexistent/log/file.log")
    assert "not found" in (out.get("error") or "")


# ---- timeline reconstruction --------------------------------------------

def test_build_timeline_orders_chronologically_and_buckets_by_source(tmp_path):
    log_path = tmp_path / "access.log"
    log_path.write_text("\n".join(APACHE_ATTACK_LINES) + "\n")
    parsed = parse_log(str(log_path), format="apache")
    tl = build_timeline(parsed["events"])
    # Ordered events sorted ascending by ts
    times = [e["ts"] for e in tl["ordered_events"] if e.get("ts")]
    assert times == sorted(times)
    # Two distinct sources (203.0.113.5 + 198.51.100.99)
    assert "203.0.113.5" in tl["by_source"]
    assert "198.51.100.99" in tl["by_source"]
    # Source 203.0.113.5 contributed 5 events
    assert len(tl["by_source"]["203.0.113.5"]) == 5
    # First/last seen populated
    assert tl["first_seen"] is not None
    assert tl["last_seen"] is not None
    assert tl["summary"]["unique_sources"] == 2
    assert tl["summary"]["event_count"] == 6


def test_build_timeline_unknown_ts_sorts_last():
    evs = [
        {"ts": "2026-XX-XXT12:00:00Z", "ip": "1.1.1.1"},
        {"ts": None, "ip": "no-ts.host"},
        {"ts": "2026-XX-XXT11:00:00Z", "ip": "earlier.host"},
    ]
    tl = build_timeline(evs)
    # First two ordered should both have ts; the one with None goes last
    assert tl["ordered_events"][-1]["ip"] == "no-ts.host"
    assert tl["ordered_events"][0]["ip"] == "earlier.host"


# ---- yara graceful degradation ------------------------------------------

def test_match_yara_missing_yara_returns_install_hint(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world")
    out = match_yara(str(target), 'rule x { strings: $a = "hello" condition: $a }',
                       workspace=str(tmp_path))
    # Either yara is installed (matches=1) or it's not (error guidance).
    if "error" in out and out["error"]:
        assert "yara-python" in out["error"] or "yara" in out["error"].lower()
    else:
        assert out.get("match_count", 0) >= 1


def test_match_yara_workspace_block(tmp_path):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x")
    ws = tmp_path / "ws"
    ws.mkdir()
    out = match_yara(str(outside), 'rule x { condition: true }',
                       workspace=str(ws))
    assert "outside" in (out.get("error") or "")


# ---- end-to-end render --------------------------------------------------

def test_render_incident_report_executive_section(tmp_path):
    log_path = tmp_path / "access.log"
    log_path.write_text("\n".join(APACHE_ATTACK_LINES) + "\n")
    parsed = parse_log(str(log_path), format="apache")
    iocs = extract_iocs(
        "203.0.113.5 dropped malware sha256: " + ("a" * 64) +
        " talking to http://evil.example.com/c2"
    )
    tl = build_timeline(parsed["events"])
    md = render_incident_report(
        incident_id="INC-2026-XX-XX-001",
        target="api.acme.example",
        parsed_logs=parsed, iocs=iocs, timeline=tl,
        suspected_attack="Credential stuffing → admin path traversal",
    )
    assert "INC-2026-XX-XX-001" in md
    assert "203.0.113.5" in md
    assert "a" * 64 in md
    # Recommended containment block present
    assert "containment" in md.lower()
    assert "perimeter firewall" in md.lower() or "block" in md.lower()
