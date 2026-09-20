"""Tests for auto-synthesized recon_deliverable.md (2026-XX-XX).

The recon agent sometimes finishes discovery without writing the structured
handoff — the synthesizer assembles one from the raw workspace artifacts so
downstream phases don't stall. See sentinel/agent/pentest/recon_synthesis.py.
"""
from __future__ import annotations

import json
from pathlib import Path

from sentinel.agent.pentest.recon_synthesis import synthesize_recon_deliverable


def _seed(ws: Path, crawl=None, nuclei=None, nmap=None) -> None:
    if crawl is not None:
        (ws / "crawl.txt").write_text(crawl)
    if nuclei is not None:
        (ws / "nuclei.json").write_text(nuclei)
    if nmap is not None:
        (ws / "nmap.txt").write_text(nmap)


def test_no_artifacts_returns_false(tmp_path):
    """No raw scanner output → nothing to synthesize → return False."""
    assert synthesize_recon_deliverable(tmp_path, "http://localhost:3000") is False
    assert not (tmp_path / "deliverables" / "recon_deliverable.md").exists()


def test_crawl_only(tmp_path):
    _seed(tmp_path, crawl="http://localhost:3000\nhttp://localhost:3000/api\nnot-a-url\n")
    assert synthesize_recon_deliverable(tmp_path, "http://localhost:3000") is True
    md = (tmp_path / "deliverables" / "recon_deliverable.md").read_text()
    assert "Crawled Surface (2 URLs)" in md
    assert "http://localhost:3000/api" in md
    assert "not-a-url" not in md  # non-URL lines filtered


def test_nuclei_findings_sorted_by_severity(tmp_path):
    """Nuclei JSONL → markdown table, criticals first."""
    findings = [
        {"info": {"name": "Info A", "severity": "info"}, "matched-at": "http://x/a",
         "template-id": "tpl-a"},
        {"info": {"name": "Critical X", "severity": "critical"}, "matched-at": "http://x/c",
         "template-id": "tpl-c"},
        {"info": {"name": "Medium B", "severity": "medium"}, "matched-at": "http://x/b",
         "template-id": "tpl-b"},
    ]
    _seed(tmp_path, nuclei="\n".join(json.dumps(d) for d in findings))
    assert synthesize_recon_deliverable(tmp_path, "http://x") is True
    md = (tmp_path / "deliverables" / "recon_deliverable.md").read_text()
    assert "Nuclei Findings (3)" in md
    # critical should appear before medium which should appear before info
    assert md.index("Critical X") < md.index("Medium B") < md.index("Info A")


def test_nmap_open_ports(tmp_path):
    _seed(tmp_path, nmap=(
        "Nmap scan report for localhost\n"
        "Host is up.\n"
        "PORT     STATE SERVICE VERSION\n"
        "22/tcp   open  ssh     OpenSSH 8.0\n"
        "80/tcp   open  http    nginx 1.24\n"
        "443/tcp  filtered https\n"
    ))
    assert synthesize_recon_deliverable(tmp_path, "http://x") is True
    md = (tmp_path / "deliverables" / "recon_deliverable.md").read_text()
    assert "Open Ports / Services (nmap)" in md
    assert "22/tcp" in md and "80/tcp" in md and "443/tcp" in md
    # Non-port lines shouldn't appear in the ports section
    assert "Nmap scan report" not in md


def test_combined_full_recon(tmp_path):
    """All three artifacts → one deliverable with all sections."""
    _seed(tmp_path,
          crawl="http://t/a\nhttp://t/b",
          nuclei=json.dumps({"info": {"name": "CORS Wide Open", "severity": "high"},
                             "matched-at": "http://t", "template-id": "cors"}),
          nmap="3000/tcp open  http")
    assert synthesize_recon_deliverable(
        tmp_path, "http://t", agent_notes="Manual note: source maps exposed."
    )
    md = (tmp_path / "deliverables" / "recon_deliverable.md").read_text()
    assert "Crawled Surface (2 URLs)" in md
    assert "CORS Wide Open" in md
    assert "3000/tcp" in md
    assert "source maps exposed" in md
    assert "Auto-synthesized from workspace artifacts" in md


def test_agent_notes_only_no_artifacts(tmp_path):
    """Notes alone (no scanner artifacts) still produce a deliverable."""
    assert synthesize_recon_deliverable(tmp_path, "http://t",
                                        agent_notes="found /admin endpoint")
    md = (tmp_path / "deliverables" / "recon_deliverable.md").read_text()
    assert "found /admin endpoint" in md
    assert "Agent Narrative Findings" in md


def test_corrupt_nuclei_json_is_skipped_not_raised(tmp_path):
    """A malformed nuclei file shouldn't break synthesis of other sections."""
    _seed(tmp_path,
          crawl="http://t/a",
          nuclei="this is not json\n{also not json\n")
    # Should not raise; the crawl section still saves the file.
    assert synthesize_recon_deliverable(tmp_path, "http://t") is True
    md = (tmp_path / "deliverables" / "recon_deliverable.md").read_text()
    assert "Crawled Surface" in md
    # No nuclei section because nothing parsed
    assert "Nuclei Findings" not in md
