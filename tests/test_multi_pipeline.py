"""Multi-target orchestration — scope expansion + summary rendering."""

from __future__ import annotations

import types
from pathlib import Path

from sentinel.agent.pentest.multi_pipeline import (
    MultiTargetResult, expand_scope_to_targets, render_combined_summary,
)


def _scope_with(domains, repos=()):
    """Return a fake scope object matching Scope.load()'s shape — domains
    and repos are direct attributes (NOT a .targets dict). Earlier versions
    of expand_scope_to_targets read scope.targets.get("domains") which
    silently returned [] in production; fixed 2026-XX-XX."""
    return types.SimpleNamespace(domains=list(domains), repos=list(repos))


def test_expand_skips_wildcards():
    scope = _scope_with(["app.acme.com", "*.acme.com", "api.acme.com"])
    targets = expand_scope_to_targets(scope)
    assert "https://app.acme.com/" in targets
    assert "https://api.acme.com/" in targets
    assert not any("*" in t for t in targets)


def test_expand_returns_https_urls():
    scope = _scope_with(["one.com", "two.com"])
    targets = expand_scope_to_targets(scope)
    assert all(t.startswith("https://") for t in targets)
    assert all(t.endswith("/") for t in targets)


def test_expand_with_no_domains_returns_empty():
    assert expand_scope_to_targets(_scope_with([])) == []


def test_combined_summary_renders_per_target_table(tmp_path):
    results = [
        MultiTargetResult(target="https://a.test/", success=True,
                          workspace=tmp_path / "ws-a", cost_usd=1.23, duration_sec=300),
        MultiTargetResult(target="https://b.test/", success=False,
                          workspace=None, cost_usd=0.0, duration_sec=10,
                          error="auth refused"),
    ]
    out = tmp_path / "summary.md"
    render_combined_summary(results, out)
    text = out.read_text()
    assert "Targets attempted: 2" in text
    assert "succeeded: 1" in text
    assert "failed: 1" in text
    assert "https://a.test/" in text
    assert "auth refused" in text


def test_combined_summary_surfaces_cross_target_overlap(tmp_path):
    # Two workspaces with the same deliverable kind should be flagged.
    for name in ("ws-a", "ws-b"):
        ws = tmp_path / name
        (ws / "deliverables").mkdir(parents=True)
        (ws / "deliverables" / "auth_analysis_deliverable.md").write_text("x")
    results = [
        MultiTargetResult(target="https://a/", success=True,
                          workspace=tmp_path / "ws-a", cost_usd=0, duration_sec=0),
        MultiTargetResult(target="https://b/", success=True,
                          workspace=tmp_path / "ws-b", cost_usd=0, duration_sec=0),
    ]
    out = tmp_path / "summary.md"
    render_combined_summary(results, out)
    text = out.read_text()
    assert "auth_analysis_deliverable" in text
    assert "2 targets" in text
