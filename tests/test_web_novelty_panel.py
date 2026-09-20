"""NOVEL-07 — `/findings/<run>/<fp>` Novelty panel dashboard surface.

Pins the contract that the Plan 03-06 finding-detail route gains a Novelty
panel (Plan 05-05 extension) rendering:

1. The finding's `novelty_score` as a colored chip via the new
   `_chip_class_for_novelty(score)` helper, with documented vocabulary:
      score >= 0.75            -> chip-novelty-high
      0.5 <= score < 0.75      -> chip-novelty-medium
      score <  0.5             -> chip-info  (below escalation territory)

2. The `nearest_corpus_match` block (title + source + cosine_distance +
   text_preview) ONLY when the matching `novel_findings` entry from
   Plan 05-04's RunReport.novel_findings is present in the run JSON.

3. The structured `exploit_chain` triplet (input / behavior / impact)
   ONLY when the novel_evidence entry carries one (escalation succeeded).

Defensive contract:
  - Legacy run JSONs without `novel_findings` key + findings without
    `novelty_score` render the panel with the empty-state placeholder
    (data-testid="novelty-no-evidence"). NO 500.
  - Findings WITH novelty_score but no matching novel_findings entry
    render the score chip but the empty-state placeholder for
    nearest_match / exploit_chain (score above threshold but escalation
    never ran is a valid pipeline state).
  - XSS escape via Jinja autoescape: exploit_chain string fields containing
    `<script>` payloads render as `&lt;script&gt;` text — pinned by Test 8.

Hermetic — uses `app.dependency_overrides[get_config]` per Plan 03-06's
canonical pattern. No live network, no Ollama, no Chroma, no Claude SDK.

Run with:
    PYTHONPATH=. .venv/bin/python -m pytest tests/test_web_novelty_panel.py -v -m 'not integration'
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.web.app import create_app
from sentinel.web.deps import get_config
from sentinel.ui.state import UIConfig


# ---- Fixture helpers ----------------------------------------------------


FP = "aaaaaaaaaaaaaaaa"  # 16 hex, the canonical test fingerprint
ENGAGEMENT_ID = "bench-test"


def _fixture_finding_dict(
    *,
    fingerprint: str = FP,
    novelty_score: float | None = None,
    evidence_state: str = "verified",
    severity: str = "high",
    extras: dict | None = None,
) -> dict:
    base = {
        "title": "Reflected XSS in /search",
        "description": "Search reflects q unescaped.",
        "severity": severity,
        "scanner": "exploit",
        "target": "https://target.example/",
        "location": "/search",
        "cwe": "CWE-79",
        "fingerprint": fingerprint,
        "evidence_state": evidence_state,
    }
    if novelty_score is not None:
        base["novelty_score"] = novelty_score
    if extras:
        base.update(extras)
    return base


def _fixture_novel_evidence(
    *,
    finding_fingerprint: str = FP,
    novelty_score: float = 0.95,
    nearest_corpus_match: dict | None = None,
    exploit_chain: dict | None = None,
    verifier_evidence_path: str | None = None,
) -> dict:
    """Mirror of NovelFindingEvidence.to_dict() shape (Plan 05-04)."""
    return {
        "finding_fingerprint": finding_fingerprint,
        "novelty_score": float(novelty_score),
        "nearest_corpus_match": nearest_corpus_match or {},
        "exploit_chain": exploit_chain or {},
        "verifier_evidence_path": verifier_evidence_path,
        "captured_at": "2026-XX-XXT15:00:00Z",
    }


def _build_fixture_tree(
    tmp_path: Path,
    *,
    findings: list[dict] | None = None,
    novel_findings: list[dict] | None = None,
    omit_novel_findings_key: bool = False,
) -> Path:
    """Hermetic tree: runs/test-run.json + workspaces dir scaffold."""
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    workspaces_dir = tmp_path / "workspaces"
    workspaces_dir.mkdir(parents=True, exist_ok=True)

    findings_list = findings if findings is not None else [_fixture_finding_dict()]

    run_data: dict = {
        "engagement_id": ENGAGEMENT_ID,
        "scope": {
            "client": "bench-client",
            "engagement_id": ENGAGEMENT_ID,
        },
        "scanners_run": ["exploit", "verify-phase-03"],
        "findings": findings_list,
        "errors": [],
    }
    if not omit_novel_findings_key:
        run_data["novel_findings"] = novel_findings if novel_findings is not None else []

    (runs_dir / "test-run.json").write_text(json.dumps(run_data, indent=2))
    return tmp_path


def _make_cfg(tmp_path: Path) -> UIConfig:
    return UIConfig(
        vault_path=str(tmp_path / "vault"),
        corpus_dir=str(tmp_path / "corpus"),
        scopes_dir=str(tmp_path / "scopes"),
        runs_dir=str(tmp_path / "runs"),
        workspaces_dir=str(tmp_path / "workspaces"),
        ollama_host="http://localhost:11434",
        ollama_model="llama3.1:8b",
        embed_model="nomic-embed-text",
        project_dir=str(tmp_path),
    )


def _client(tmp_path: Path):
    cfg = _make_cfg(tmp_path)
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    return app, cfg


# ---- Tests --------------------------------------------------------------


def test_novelty_panel_renders_score_chip_high(tmp_path):
    """Finding(novelty_score=0.95) -> chip-novelty-high + score chip data-testid + '0.950' label."""
    _build_fixture_tree(
        tmp_path,
        findings=[_fixture_finding_dict(novelty_score=0.95)],
    )
    app, _ = _client(tmp_path)
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}")
            assert r.status_code == 200, r.text
            body = r.text
            assert 'data-testid="novelty-panel"' in body, "missing novelty panel section"
            assert 'data-testid="novelty-score-chip"' in body, "missing score chip data-testid"
            assert "chip-novelty-high" in body, "chip should use novelty-high vocabulary class"
            assert "0.950" in body, "score chip should display '0.950'"
    finally:
        app.dependency_overrides.clear()


def test_novelty_panel_renders_score_chip_medium(tmp_path):
    """Finding(novelty_score=0.6) -> chip-novelty-medium."""
    _build_fixture_tree(
        tmp_path,
        findings=[_fixture_finding_dict(novelty_score=0.6)],
    )
    app, _ = _client(tmp_path)
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}")
            assert r.status_code == 200, r.text
            body = r.text
            assert "chip-novelty-medium" in body, "chip should use novelty-medium vocabulary class"
            # Must NOT use the high tier
            assert "chip-novelty-high" not in body, (
                "score 0.6 must NOT trigger novelty-high (threshold is 0.75)"
            )
    finally:
        app.dependency_overrides.clear()


def test_novelty_panel_renders_score_chip_info_below_threshold(tmp_path):
    """Finding(novelty_score=0.30) -> chip-info (below medium tier)."""
    _build_fixture_tree(
        tmp_path,
        findings=[_fixture_finding_dict(novelty_score=0.30)],
    )
    app, _ = _client(tmp_path)
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}")
            assert r.status_code == 200, r.text
            body = r.text
            # The score chip itself must render with chip-info
            assert 'data-testid="novelty-score-chip"' in body
            # Locate the chip and assert chip-info is one of its classes
            chip_marker = 'data-testid="novelty-score-chip"'
            chip_idx = body.find(chip_marker)
            # Look backwards for the chip's class attribute (within ~200 chars)
            preceding = body[max(0, chip_idx - 200): chip_idx]
            assert "chip-info" in preceding, (
                "score 0.30 chip should use chip-info class (below medium tier)"
            )
            # Negative: the chip itself must NOT carry novelty-high/medium
            assert "chip-novelty-high" not in preceding, (
                "below-threshold score must not use chip-novelty-high"
            )
            assert "chip-novelty-medium" not in preceding, (
                "below-threshold score must not use chip-novelty-medium"
            )
    finally:
        app.dependency_overrides.clear()


def test_novelty_panel_backward_compat_legacy_run_json(tmp_path):
    """Legacy run JSON (no `novel_findings` key, finding has no `novelty_score`)
    renders the panel with score 0.000 + the no-evidence empty state. NO 500."""
    _build_fixture_tree(
        tmp_path,
        findings=[_fixture_finding_dict(novelty_score=None)],  # no novelty_score key
        omit_novel_findings_key=True,
    )
    app, _ = _client(tmp_path)
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}")
            assert r.status_code == 200, (
                f"legacy run JSON should NOT 500: status={r.status_code}, body={r.text[:500]}"
            )
            body = r.text
            assert 'data-testid="novelty-panel"' in body, (
                "panel must render even on legacy run JSON"
            )
            assert 'data-testid="novelty-no-evidence"' in body, (
                "no-evidence empty state must render when novel_findings absent"
            )
            assert "0.000" in body, "score chip should display '0.000' for missing score"
    finally:
        app.dependency_overrides.clear()


def test_novelty_panel_no_evidence_when_only_score_set(tmp_path):
    """Finding(novelty_score=0.85) but NO matching novel_findings entry —
    chip renders + no-evidence empty state visible (score above threshold
    but escalation never ran is a valid pipeline state)."""
    _build_fixture_tree(
        tmp_path,
        findings=[_fixture_finding_dict(novelty_score=0.85)],
        novel_findings=[],  # explicitly empty
    )
    app, _ = _client(tmp_path)
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}")
            assert r.status_code == 200, r.text
            body = r.text
            # Score chip renders with the high-tier class
            assert "chip-novelty-high" in body, "high score chip must still render"
            assert "0.850" in body
            # No-evidence empty state visible
            assert 'data-testid="novelty-no-evidence"' in body, (
                "empty state must render when no matching novel_findings entry"
            )
            # And neither the nearest-match nor exploit-chain blocks rendered
            assert 'data-testid="novelty-nearest-match"' not in body
            assert 'data-testid="novelty-exploit-chain"' not in body
    finally:
        app.dependency_overrides.clear()


def test_novelty_panel_renders_full_exploit_chain(tmp_path):
    """novel_findings entry with nearest_corpus_match + exploit_chain — all
    three labeled blocks render with their data-testid markers."""
    _build_fixture_tree(
        tmp_path,
        findings=[_fixture_finding_dict(novelty_score=0.92)],
        novel_findings=[
            _fixture_novel_evidence(
                novelty_score=0.92,
                nearest_corpus_match={
                    "title": "OWASP XSS Cheat Sheet",
                    "source": "owasp",
                    "cosine_distance": 0.42,
                    "text_preview": "Reflected XSS occurs when user input is rendered back...",
                    "url": "https://owasp.org/xss",
                },
                exploit_chain={
                    "input": "GET /search?q=<svg/onload=alert(1)>",
                    "behavior": "Server echoes the payload into the result page without HTML-escaping the <script> tags or sanitizing event handlers.",
                    "impact": "Attacker can steal session cookies, perform actions on behalf of the victim, or pivot to admin-session takeover via stored CSRF token leak.",
                },
                verifier_evidence_path=f"workspaces/{ENGAGEMENT_ID}/verification/{FP}/",
            ),
        ],
    )
    app, _ = _client(tmp_path)
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}")
            assert r.status_code == 200, r.text
            body = r.text
            # nearest-match block
            assert 'data-testid="novelty-nearest-match"' in body, (
                "missing nearest_corpus_match block"
            )
            assert "OWASP XSS Cheat Sheet" in body, "title not rendered"
            # exploit-chain block + three triplet sections
            assert 'data-testid="novelty-exploit-chain"' in body, (
                "missing exploit_chain block"
            )
            assert 'data-testid="novelty-exploit-chain-input"' in body
            assert 'data-testid="novelty-exploit-chain-behavior"' in body
            assert 'data-testid="novelty-exploit-chain-impact"' in body
            # Verify the actual content flows through
            assert "GET /search?q=" in body, "input field content missing"
            assert "Server echoes the payload" in body, "behavior field content missing"
            assert "Attacker can steal session cookies" in body, "impact field content missing"
            # No-evidence empty state should NOT be present when evidence IS present
            assert 'data-testid="novelty-no-evidence"' not in body
    finally:
        app.dependency_overrides.clear()


def test_novelty_panel_renders_nearest_match_without_exploit_chain(tmp_path):
    """novel_evidence with nearest_corpus_match but NO exploit_chain key —
    renders the match block + no exploit chain block + no crash."""
    _build_fixture_tree(
        tmp_path,
        findings=[_fixture_finding_dict(novelty_score=0.80)],
        novel_findings=[
            _fixture_novel_evidence(
                novelty_score=0.80,
                nearest_corpus_match={
                    "title": "CWE-79: Improper Neutralization of Input",
                    "source": "mitre-cwe",
                    "cosine_distance": 0.55,
                    "text_preview": "The software does not neutralize special chars...",
                },
                exploit_chain={},  # empty — escalation incomplete
            ),
        ],
    )
    app, _ = _client(tmp_path)
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}")
            assert r.status_code == 200, r.text
            body = r.text
            assert 'data-testid="novelty-nearest-match"' in body, "match block missing"
            assert "CWE-79" in body
            # Exploit-chain block must NOT render when chain dict is empty
            assert 'data-testid="novelty-exploit-chain"' not in body, (
                "exploit_chain block rendered despite empty chain dict"
            )
    finally:
        app.dependency_overrides.clear()


def test_novelty_panel_escapes_xss_in_exploit_chain_input(tmp_path):
    """exploit_chain.input == '<script>alert(1)</script>' -> rendered HTML
    contains '&lt;script&gt;alert(1)&lt;/script&gt;' (Jinja autoescape)
    and DOES NOT contain the raw '<script>' tag.

    Critical: the exploit_chain string fields come from an LLM response;
    autoescape is the load-bearing XSS guard for the dashboard surface.
    """
    xss = "<script>alert(1)</script>"
    _build_fixture_tree(
        tmp_path,
        findings=[_fixture_finding_dict(novelty_score=0.95)],
        novel_findings=[
            _fixture_novel_evidence(
                novelty_score=0.95,
                nearest_corpus_match={"title": "x", "source": "x", "cosine_distance": 0.1},
                exploit_chain={
                    "input": xss,
                    "behavior": "behavior text",
                    "impact": "impact text",
                },
            ),
        ],
    )
    app, _ = _client(tmp_path)
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}")
            assert r.status_code == 200, r.text
            body = r.text
            # Escaped version present
            assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body, (
                "XSS payload not HTML-escaped — Jinja autoescape regression"
            )
            # Raw script tag MUST NOT appear in the rendered HTML body. We allow
            # `<script>` to legitimately appear in the page's own vanilla-JS
            # IIFE (the existing Copy-Reproduction-Markdown handler), so we
            # specifically assert the XSS payload's literal sequence is absent.
            assert "<script>alert(1)</script>" not in body, (
                "raw XSS payload present in HTML — autoescape BYPASSED"
            )
    finally:
        app.dependency_overrides.clear()


def test_novelty_panel_safe_url_rendering(tmp_path):
    """nearest_corpus_match.url renders as an anchor with target='_blank' +
    rel='noopener' attributes (reverse-tabnabbing mitigation)."""
    _build_fixture_tree(
        tmp_path,
        findings=[_fixture_finding_dict(novelty_score=0.90)],
        novel_findings=[
            _fixture_novel_evidence(
                novelty_score=0.90,
                nearest_corpus_match={
                    "title": "OWASP XSS Cheat Sheet",
                    "source": "owasp",
                    "cosine_distance": 0.42,
                    "url": "https://owasp.org/xss",
                },
                exploit_chain={},
            ),
        ],
    )
    app, _ = _client(tmp_path)
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}")
            assert r.status_code == 200, r.text
            body = r.text
            assert 'data-testid="novelty-nearest-match"' in body
            # Locate the nearest-match section and check its anchor attributes
            match_marker = 'data-testid="novelty-nearest-match"'
            match_idx = body.find(match_marker)
            assert match_idx >= 0
            # Look at ~1500 chars after the marker for the rendered <a> tag
            section = body[match_idx: match_idx + 1500]
            assert "https://owasp.org/xss" in section, "URL not rendered in match section"
            assert 'target="_blank"' in section, "anchor missing target='_blank'"
            assert 'rel="noopener"' in section, "anchor missing rel='noopener'"
    finally:
        app.dependency_overrides.clear()
