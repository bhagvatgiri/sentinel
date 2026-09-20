from pathlib import Path
from sentinel.agent.pentest.briefs import load_brief, BRIEFS_DIR


def test_load_brief_returns_none_when_file_missing():
    assert load_brief("nonexistent-class-slug-xyz") is None


def test_load_brief_returns_file_contents_when_present(tmp_path, monkeypatch):
    import sentinel.agent.pentest.briefs as briefs_mod
    fake_briefs = tmp_path / "briefs"
    fake_briefs.mkdir()
    (fake_briefs / "ssrf.md").write_text("# SSRF expert brief\n\nKey patterns: cloud metadata, file://, gopher://")
    monkeypatch.setattr(briefs_mod, "BRIEFS_DIR", fake_briefs)
    result = load_brief("ssrf")
    assert result is not None
    assert "cloud metadata" in result
    assert "Key patterns" in result


def test_briefs_dir_is_package_relative():
    assert BRIEFS_DIR.name == "briefs"
    assert BRIEFS_DIR.parent.name == "pentest"


def test_build_brief_prompt_includes_class_metadata():
    from tools.build_expert_briefs import build_brief_prompt
    prompt = build_brief_prompt(
        display="Cross-Site Scripting",
        slug="xss",
        default_cwe="CWE-79",
        summary="XSS sinks — reflected, stored, DOM-based.",
        context_block="<context>\n[1] owasp: XSS cheatsheet <...>\nBody...\n</context>",
    )
    assert "Cross-Site Scripting" in prompt
    assert "CWE-79" in prompt
    assert "<context>" in prompt
    assert "5 patterns" in prompt.lower() or "five patterns" in prompt.lower()


def test_select_source_filter_for_class():
    from tools.build_expert_briefs import source_filter_for
    # injection-flavored classes pull from broad sources
    assert "owasp" in source_filter_for("ssrf")
    assert "mitre-cwe" in source_filter_for("ssrf")
    # H1 writeups should be queried for every class
    assert "hackerone" in source_filter_for("auth")
    # Unknown slug falls back to defaults
    assert "owasp" in source_filter_for("unknown-class-xyz")


def test_render_vuln_prompt_includes_expert_brief_when_present(tmp_path, monkeypatch):
    import sentinel.agent.pentest.briefs as briefs_mod
    fake_briefs = tmp_path / "briefs"
    fake_briefs.mkdir()
    (fake_briefs / "ssrf.md").write_text(
        "## The 5 patterns that catch 80% of real cases\n\n1. Cloud metadata endpoint probes...\n"
    )
    monkeypatch.setattr(briefs_mod, "BRIEFS_DIR", fake_briefs)

    from sentinel.agent.pentest.vuln_classes import vuln_class
    from sentinel.agent.pentest.vuln_prompts import render_vuln_prompt

    out = render_vuln_prompt(
        cls=vuln_class("ssrf"),
        client="testco",
        engagement_id="e1",
        target="https://example.com",
        workspace="/tmp/ws",
        audit_log="/tmp/a.jsonl",
        max_pages=10, max_turns=20, max_budget_usd=1.0,
    )
    assert "Cloud metadata endpoint probes" in out
    # Header should be present in some form
    assert "Expert brief" in out or "expert brief" in out.lower()


def test_render_vuln_prompt_renders_cleanly_when_brief_missing(tmp_path, monkeypatch):
    import sentinel.agent.pentest.briefs as briefs_mod
    fake_briefs = tmp_path / "briefs"
    fake_briefs.mkdir()  # empty — no briefs available
    monkeypatch.setattr(briefs_mod, "BRIEFS_DIR", fake_briefs)

    from sentinel.agent.pentest.vuln_classes import vuln_class
    from sentinel.agent.pentest.vuln_prompts import render_vuln_prompt

    out = render_vuln_prompt(
        cls=vuln_class("auth"),
        client="testco", engagement_id="e1", target="https://example.com",
        workspace="/tmp/ws", audit_log="/tmp/a.jsonl",
        max_pages=10, max_turns=20, max_budget_usd=1.0,
    )
    # No KeyError, no literal placeholder text leaking, no stray header
    assert "{expert_brief_block}" not in out
    assert "Expert brief" not in out
    assert "expert brief" not in out.lower()


def test_render_exploit_prompt_includes_expert_brief_when_present(tmp_path, monkeypatch):
    import sentinel.agent.pentest.briefs as briefs_mod
    fake_briefs = tmp_path / "briefs"
    fake_briefs.mkdir()
    (fake_briefs / "ssrf.md").write_text(
        "## Typical exploitation chains\n\nSSRF → metadata → IAM creds → S3 takeover.\n"
    )
    monkeypatch.setattr(briefs_mod, "BRIEFS_DIR", fake_briefs)

    from sentinel.agent.pentest.vuln_classes import vuln_class
    from sentinel.agent.pentest.exploit_prompts import render_exploit_prompt

    out = render_exploit_prompt(
        cls=vuln_class("ssrf"),
        client="testco", engagement_id="e1", target="https://example.com",
        workspace="/tmp/ws", audit_log="/tmp/a.jsonl",
        max_pages=10, max_turns=20, max_budget_usd=1.0,
    )
    assert "metadata → IAM creds" in out
    assert "Expert brief" in out or "expert brief" in out.lower()
    assert "{expert_brief_block}" not in out


def test_render_exploit_prompt_renders_cleanly_when_brief_missing(tmp_path, monkeypatch):
    import sentinel.agent.pentest.briefs as briefs_mod
    fake_briefs = tmp_path / "briefs"
    fake_briefs.mkdir()  # empty — no briefs available
    monkeypatch.setattr(briefs_mod, "BRIEFS_DIR", fake_briefs)

    from sentinel.agent.pentest.vuln_classes import vuln_class
    from sentinel.agent.pentest.exploit_prompts import render_exploit_prompt

    out = render_exploit_prompt(
        cls=vuln_class("auth"),
        client="testco", engagement_id="e1", target="https://example.com",
        workspace="/tmp/ws", audit_log="/tmp/a.jsonl",
        max_pages=10, max_turns=20, max_budget_usd=1.0,
    )
    assert "{expert_brief_block}" not in out
    assert "Expert brief" not in out
    assert "expert brief" not in out.lower()


def test_make_expert_brief_block_returns_empty_when_missing(tmp_path, monkeypatch):
    import sentinel.agent.pentest.briefs as briefs_mod
    fake_briefs = tmp_path / "briefs"
    fake_briefs.mkdir()
    monkeypatch.setattr(briefs_mod, "BRIEFS_DIR", fake_briefs)
    from sentinel.agent.pentest.briefs import make_expert_brief_block
    assert make_expert_brief_block("anything") == ""


def test_make_expert_brief_block_wraps_with_header_when_present(tmp_path, monkeypatch):
    import sentinel.agent.pentest.briefs as briefs_mod
    fake_briefs = tmp_path / "briefs"
    fake_briefs.mkdir()
    (fake_briefs / "xss.md").write_text("## The 5 patterns...\n\n1. Reflected from query string\n")
    monkeypatch.setattr(briefs_mod, "BRIEFS_DIR", fake_briefs)
    from sentinel.agent.pentest.briefs import make_expert_brief_block
    out = make_expert_brief_block("xss")
    assert out.startswith("## Expert brief — distilled corpus knowledge for this class")
    assert "Reflected from query string" in out
    assert out.endswith("\n")
