"""B11 — Network traffic analyzer tests.

We synthesize a tiny pcap with a port-scan signature and assert that
:func:`detect_anomalies` flags it. Other heuristics (exfil, beaconing,
DNS tunneling) are exercised against direct in-memory parsed dicts so
the test doesn't depend on either scapy OR tshark being installed —
the parser is the only piece that needs a backend, and we test that
shape via a synthetic dict too.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from sentinel.agent.pentest import network_analyzer
from sentinel.agent.pentest.network_analyzer import (
    detect_anomalies,
    parse_pcap,
    render_network_report,
    summarize_traffic,
)


HAVE_SCAPY = importlib.util.find_spec("scapy") is not None


# ---- detect_anomalies on synthetic parsed dicts -------------------------

def _flow(proto, src, sport, dst, dport, *, n_pkts=1, nbytes=64,
           syn=True, ack=False, fin=False, ts=0.0):
    return {
        "5tuple": [proto, src, sport, dst, dport],
        "packet_count": n_pkts,
        "bytes": nbytes,
        "first_ts": ts, "last_ts": ts + 1,
        "syn": syn, "ack": ack, "fin": fin,
    }


def test_detect_port_scan_fires_on_syn_to_many_ports():
    """20 SYN-only TCP flows from the same src to distinct dst ports
    on the same target → port_scan must fire."""
    flows = [
        _flow("TCP", "10.0.0.5", 50000 + i, "10.0.0.10", 1000 + i,
                syn=True, ack=False, fin=False)
        for i in range(20)
    ]
    parsed = {"flows": flows, "protocols": {"TCP": 20}, "dns_queries": [],
               "packet_count": 20}
    out = detect_anomalies(parsed)
    assert out["port_scans"], (
        "expected port_scan signature on 20 SYN-only flows to distinct ports"
    )
    ps = out["port_scans"][0]
    assert ps["src"] == "10.0.0.5"
    assert ps["distinct_dst_ports"] == 20
    assert ps["syn_only_flows"] == 20


def test_detect_port_scan_does_not_fire_on_completed_handshakes():
    """Same flow set but with full SYN+ACK+FIN — these are real
    connections, not scan probes."""
    flows = [
        _flow("TCP", "10.0.0.5", 50000 + i, "10.0.0.10", 1000 + i,
                syn=True, ack=True, fin=True)
        for i in range(20)
    ]
    parsed = {"flows": flows, "protocols": {"TCP": 20}, "dns_queries": [],
               "packet_count": 20}
    out = detect_anomalies(parsed)
    assert out["port_scans"] == []


def test_detect_exfil_candidate_5mb_threshold():
    flows = [
        _flow("TCP", "10.0.0.5", 1234, "evil.example", 443,
                nbytes=10 * 1024 * 1024, syn=True, ack=True, fin=True),
    ]
    parsed = {"flows": flows, "protocols": {"TCP": 1}, "dns_queries": [],
               "packet_count": 100}
    out = detect_anomalies(parsed)
    assert out["exfil_candidates"]
    ec = out["exfil_candidates"][0]
    assert ec["src"] == "10.0.0.5"
    assert ec["dst"] == "evil.example"
    assert ec["bytes_out"] == 10 * 1024 * 1024


def test_detect_beaconing_low_jitter():
    """Five flows from same src->dst at 60s intervals (jitter < 0.30)."""
    flows = []
    for i in range(6):
        f = _flow("TCP", "10.0.0.5", 1234, "c2.example", 443,
                    syn=True, ack=True, fin=True)
        f["first_ts"] = 1000.0 + i * 60.0  # exactly 60s apart
        f["last_ts"] = f["first_ts"] + 1
        flows.append(f)
    parsed = {"flows": flows, "protocols": {"TCP": 6}, "dns_queries": [],
               "packet_count": 30}
    out = detect_anomalies(parsed)
    assert out["beaconing"]
    bc = out["beaconing"][0]
    assert abs(bc["interval_sec_mean"] - 60.0) < 0.5
    assert bc["interval_jitter"] < 0.30
    assert bc["count"] == 6


def test_detect_dns_tunneling_long_label():
    parsed = {
        "flows": [],
        "protocols": {"DNS": 1},
        "dns_queries": [
            "a" * 60 + ".tunnel.evil.example",   # 60-char label
            "normal.example.com",                # baseline; should not flag
        ],
        "packet_count": 2,
    }
    out = detect_anomalies(parsed)
    assert out["dns_tunneling"]
    assert out["dns_tunneling"][0]["label_max_len"] >= 50


def test_detect_anomalies_handles_empty_parse():
    out = detect_anomalies({"flows": [], "dns_queries": []})
    # No anomalies but doesn't crash; summary explicit
    assert out["summary"] == "no anomalies detected"


def test_detect_anomalies_short_circuits_on_error_dict():
    out = detect_anomalies({"error": "no backend"})
    assert "error" in out


# ---- summarize_traffic --------------------------------------------------

def test_summarize_top_talkers_sort_by_bytes():
    flows = [
        _flow("TCP", "1.1.1.1", 1, "2.2.2.2", 80, nbytes=100),
        _flow("TCP", "3.3.3.3", 1, "4.4.4.4", 80, nbytes=50_000),
        _flow("TCP", "1.1.1.1", 2, "2.2.2.2", 443, nbytes=200),
    ]
    parsed = {
        "flows": flows, "packet_count": 3,
        "protocols": {"TCP": 3}, "dns_queries": [],
    }
    out = summarize_traffic(parsed)
    # Heaviest pair (3.3.3.3 + 4.4.4.4) — both should sit at top of list
    top_hosts = {t["host"] for t in out["top_talkers"][:2]}
    assert "3.3.3.3" in top_hosts
    assert "4.4.4.4" in top_hosts


def test_summarize_handles_error_dict():
    out = summarize_traffic({"error": "bad pcap"})
    assert "error" in out


# ---- render_network_report ----------------------------------------------

def test_render_network_report_includes_anomalies_section():
    parsed = {
        "flows": [_flow("TCP", "10.0.0.5", 50000 + i, "10.0.0.10", 1000 + i,
                          syn=True, ack=False, fin=False)
                  for i in range(20)],
        "protocols": {"TCP": 20}, "dns_queries": [], "packet_count": 20,
    }
    anomalies = detect_anomalies(parsed)
    md = render_network_report(parsed, anomalies, target="10.0.0.10")
    assert "# Network Traffic Analysis" in md
    assert "PORT SCAN" in md
    assert "10.0.0.5" in md


# ---- parse_pcap (only when scapy is available) --------------------------

@pytest.mark.skipif(not HAVE_SCAPY, reason="scapy not installed")
def test_parse_pcap_with_scapy_synthetic_pcap(tmp_path: Path):
    """Build a tiny pcap with 5 SYN packets and verify parse + detect."""
    from scapy.all import IP, TCP, wrpcap   # type: ignore

    pkts = []
    for i in range(20):
        pkts.append(
            IP(src="10.0.0.5", dst="10.0.0.10")
            / TCP(sport=50000 + i, dport=1000 + i, flags="S")
        )
    pcap_path = tmp_path / "scan.pcap"
    wrpcap(str(pcap_path), pkts)

    parsed = parse_pcap(str(pcap_path), workspace=str(tmp_path))
    assert parsed["backend"] == "scapy"
    assert parsed["packet_count"] == 20
    assert len(parsed["flows"]) == 20

    anomalies = detect_anomalies(parsed)
    assert anomalies["port_scans"]


def test_parse_pcap_workspace_traversal_refused(tmp_path: Path):
    """A pcap outside the workspace must be refused."""
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"\xd4\xc3\xb2\xa1")  # libpcap magic only
    sub_ws = tmp_path / "ws"
    sub_ws.mkdir()
    out = parse_pcap(str(outside), workspace=str(sub_ws))
    assert out.get("backend") == "error"
    assert "outside" in (out.get("error") or "")


def test_parse_pcap_missing_file_returns_error(tmp_path: Path):
    out = parse_pcap(str(tmp_path / "nonexistent.pcap"))
    assert out.get("backend") == "error"
    assert "not found" in (out.get("error") or "")
