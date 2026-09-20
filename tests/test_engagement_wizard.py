"""Tests for `sentinel.engagements.wizard` — covers all four templates,
filesystem scaffolding, validation errors, and round-tripping the
generated YAML through PyYAML.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sentinel.engagements import wizard


def _spec(**overrides) -> wizard.EngagementSpec:
    base = dict(
        template="hackerone",
        client="acme-corp",
        engagement_id="2026-q2-pentest-001",
        authorized_by="jane.doe@acme-corp.com",
        domains=("*.staging.acme-corp.com",),
        research_handle="myh1handle",
    )
    base.update(overrides)
    return wizard.EngagementSpec(**base)


def test_templates_listed():
    names = {t.name for t in wizard.list_templates()}
    assert names == {"hackerone", "bugcrowd", "synack", "private"}


def test_unknown_template_raises():
    with pytest.raises(ValueError):
        wizard.template_for("not-a-real-program")


def test_render_hackerone_includes_research_header():
    yml = wizard.render_scope_yaml(_spec(template="hackerone"))
    parsed = yaml.safe_load(yml)
    assert parsed["client"] == "acme-corp"
    assert parsed["targets"]["domains"] == ["*.staging.acme-corp.com"]
    assert parsed["rate_limits"]["requests_per_second"] == 5
    assert parsed["research_headers"]["X-HackerOne-Research"] == "myh1handle"


def test_render_bugcrowd_uses_bugcrowd_header():
    yml = wizard.render_scope_yaml(_spec(template="bugcrowd"))
    parsed = yaml.safe_load(yml)
    assert "X-Bugcrowd-Researcher" in parsed["research_headers"]


def test_render_synack_default_rate_limit_is_10():
    yml = wizard.render_scope_yaml(_spec(template="synack"))
    parsed = yaml.safe_load(yml)
    assert parsed["rate_limits"]["requests_per_second"] == 10
    assert "X-Synack-Researcher" in parsed["research_headers"]


def test_render_private_omits_research_headers_block():
    yml = wizard.render_scope_yaml(
        _spec(template="private", research_handle="")
    )
    parsed = yaml.safe_load(yml)
    assert "research_headers" not in parsed


def test_rate_limit_override_wins_over_template():
    yml = wizard.render_scope_yaml(
        _spec(template="hackerone", rate_limit_rps_override=2)
    )
    parsed = yaml.safe_load(yml)
    assert parsed["rate_limits"]["requests_per_second"] == 2


def test_validation_requires_client():
    with pytest.raises(ValueError):
        wizard.render_scope_yaml(_spec(client=""))


def test_validation_requires_at_least_one_target():
    with pytest.raises(ValueError):
        wizard.render_scope_yaml(_spec(domains=(), repos=(), ips=()))


def test_validation_rejects_bad_iso_date():
    with pytest.raises(ValueError):
        wizard.render_scope_yaml(_spec(valid_from="not-a-date"))


def test_default_dates_filled_in():
    yml = wizard.render_scope_yaml(_spec())
    parsed = yaml.safe_load(yml)
    # Both dates filled in even without explicit valid_from / valid_until.
    assert parsed["valid_from"]
    assert parsed["valid_until"]


def test_extra_research_headers_merge():
    spec = _spec(extra_research_headers={"X-Custom": "custom-value"})
    yml = wizard.render_scope_yaml(spec)
    parsed = yaml.safe_load(yml)
    assert parsed["research_headers"]["X-Custom"] == "custom-value"
    # Template-provided header still present.
    assert parsed["research_headers"]["X-HackerOne-Research"] == "myh1handle"


def test_create_engagement_writes_files(tmp_path: Path):
    scopes = tmp_path / "engagements"
    workspaces = tmp_path / "workspaces"
    spec = _spec()
    res = wizard.create_engagement(spec, scopes_dir=scopes, workspaces_root=workspaces)
    assert res.scope_path.is_file()
    assert res.workspace_dir.is_dir()
    assert (res.workspace_dir / "deliverables").is_dir()
    # SHA matches content.
    import hashlib as _h
    assert res.sha256 == _h.sha256(res.yaml_text.encode()).hexdigest()


def test_create_engagement_refuses_overwrite(tmp_path: Path):
    scopes = tmp_path / "engagements"
    workspaces = tmp_path / "workspaces"
    spec = _spec()
    wizard.create_engagement(spec, scopes_dir=scopes, workspaces_root=workspaces)
    with pytest.raises(FileExistsError):
        wizard.create_engagement(spec, scopes_dir=scopes, workspaces_root=workspaces)


def test_create_engagement_overwrite_ok(tmp_path: Path):
    scopes = tmp_path / "engagements"
    workspaces = tmp_path / "workspaces"
    spec = _spec()
    wizard.create_engagement(spec, scopes_dir=scopes, workspaces_root=workspaces)
    # Second call with overwrite=True should succeed.
    res = wizard.create_engagement(
        spec, scopes_dir=scopes, workspaces_root=workspaces, overwrite=True,
    )
    assert res.scope_path.is_file()


def test_scope_filename_slugifies():
    assert wizard.scope_filename_for("Acme Corp!", "2026 Q2 Pentest 001") == \
        "acme-corp-2026-q2-pentest-001.yaml"
