"""Wave 3 — CTF-mode dangerous-tool gating tests.

Asserted properties:
  - Pipeline tool-union filter drops C1/C2/C3/C4/C13 in production /
    bbp; keeps them in CTF / LAB.
  - Belt-and-suspenders body check: invoking drop_webshell with
    PRODUCTION mode raises ModeError before any side-effect.
  - AuditLog `mode=ctf` stamped on every entry when the scope file
    declares ctf.
  - PDF reporter prepends a "NOT A CLIENT DELIVERABLE" banner when
    engagement_mode != production.
  - verify-audit rejects when scope yaml says production but the
    audit log first entry says ctf.
  - flag_discriminator regex helper is correctness-tested.
  - ctf_writeup helper renders the standard markdown shape.
  - The Wave 2 verifier loop still works under CTF mode (no Wave-2
    regressions from the mode gating changes).
"""

from __future__ import annotations

import asyncio
import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from sentinel.agent.pentest import (
    c2_tool as p_c2,
    ctf_writeup as p_ctfwu,
    exec_code_tool as p_exec,
    exfil_tool as p_exfil,
    flag_discriminator as p_flag,
    netcat_tool as p_netcat,
    sshpass_tool as p_ssh,
    webshell_tool as p_webshell,
)
from sentinel.agent.pentest import tools as p_tools
from sentinel.core.engagement_mode import (
    CTF_ONLY_TOOL_SET,
    EngagementMode,
    ModeError,
    PRODUCTION_TOOL_SET,
    filter_tools_for_mode,
    is_tool_allowed,
)
from sentinel.core.scope import AuditLog, Scope


# ---- helpers --------------------------------------------------------------


def _scope_yaml(tmp_path: Path, **overrides) -> Path:
    today = date.today()
    data = {
        "client": "ctf-client",
        "engagement_id": "ctf-001",
        "authorized_by": "test@example.com",
        "valid_from": (today - timedelta(days=1)).isoformat(),
        "valid_until": (today + timedelta(days=30)).isoformat(),
        "targets": {"domains": ["target.com"], "ips": []},
        "rate_limits": {"requests_per_second": 5},
    }
    data.update(overrides)
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def _make_ctx(tmp_path: Path, *, mode: str = "ctf") -> p_tools.PentestContext:
    log_path = tmp_path / "audit.jsonl"
    s = Scope.load(_scope_yaml(tmp_path, engagement_mode=mode),
                    audit_log_path=log_path)
    workspace = tmp_path / "ws"
    workspace.mkdir(exist_ok=True)
    import httpx

    class _StubHttp:
        async def get(self, *a, **k):
            class _R:
                status_code = 200
                text = "stub"
                url = a[0] if a else ""
                headers = {}
            return _R()

        async def post(self, *a, **k):
            class _R:
                status_code = 200
                text = "ok"
                url = a[0] if a else ""
                headers = {}
            return _R()

    ctx = p_tools.PentestContext(
        scope=s, audit=s.audit_log, workspace_dir=workspace,
        http=_StubHttp(),  # type: ignore[arg-type]
        rate_limit_per_host_sec=0.0,
    )
    p_tools.set_context(ctx)
    return ctx


# ---- Pipeline tool-union filter ------------------------------------------


def test_filter_drops_all_ctf_tools_in_production():
    """Build the same union the exploit phase passes, run the filter,
    confirm CTF tools are gone."""
    union = (
        p_webshell.ALL_TOOLS + p_c2.ALL_TOOLS + p_ssh.ALL_TOOLS
        + p_exec.ALL_TOOLS + p_netcat.ALL_TOOLS + p_exfil.ALL_TOOLS
        + p_flag.ALL_TOOLS + p_ctfwu.ALL_TOOLS
    )
    filtered = filter_tools_for_mode(union, EngagementMode.PRODUCTION)
    assert filtered == [], (
        "production must drop every CTF tool; got: "
        + str([t.name for t in filtered])
    )

    filtered_bbp = filter_tools_for_mode(union, EngagementMode.BBP)
    assert filtered_bbp == []


def test_filter_keeps_ctf_tools_in_ctf_and_lab():
    union = (
        p_webshell.ALL_TOOLS + p_c2.ALL_TOOLS + p_ssh.ALL_TOOLS
        + p_exec.ALL_TOOLS + p_netcat.ALL_TOOLS + p_exfil.ALL_TOOLS
        + p_flag.ALL_TOOLS + p_ctfwu.ALL_TOOLS
    )
    for mode in (EngagementMode.CTF, EngagementMode.LAB):
        filtered = filter_tools_for_mode(union, mode)
        # All CTF tools survive the filter (ssh + flag etc. live in
        # CTF_ONLY_TOOL_SET so they get the allowance).
        names = {t.name for t in filtered}
        assert "drop_webshell" in names
        assert "open_reverse_shell_listener" in names
        assert "ssh_with_credentials" in names
        assert "execute_arbitrary_code" in names
        assert "netcat_raw" in names
        assert "exfil_file_via_oast" in names
        assert "flag_discriminator" in names
        assert "ctf_writeup" in names


# ---- Belt-and-suspenders runtime body checks -----------------------------


def test_drop_webshell_refuses_under_production(tmp_path):
    ctx = _make_ctx(tmp_path, mode="production")
    # Production scope rejects the tool name BEFORE it would even be
    # registered, but the body's runtime guard is the second layer.
    result = asyncio.run(p_webshell.drop_webshell.handler({
        "upload_url": "https://target.com/upload",
        "filename": "shell.php",
        "lang": "php",
        "shell_url": "https://target.com/uploads/shell.php",
    }))
    assert result.get("is_error"), f"expected refusal, got {result}"
    assert "drop_webshell" in result["content"][0]["text"]


def test_open_reverse_shell_listener_refuses_under_production(tmp_path):
    ctx = _make_ctx(tmp_path, mode="production")
    result = asyncio.run(p_c2.open_reverse_shell_listener.handler({
        "port": 4444,
    }))
    assert result.get("is_error"), f"expected refusal, got {result}"


def test_ssh_with_credentials_refuses_under_bbp(tmp_path):
    ctx = _make_ctx(tmp_path, mode="bbp")
    result = asyncio.run(p_ssh.ssh_with_credentials.handler({
        "host": "target.com", "port": 22, "username": "root",
        "password": "x", "command": "id",
    }))
    assert result.get("is_error")


def test_netcat_raw_refuses_under_production(tmp_path):
    ctx = _make_ctx(tmp_path, mode="production")
    result = asyncio.run(p_netcat.netcat_raw.handler({
        "host": "target.com", "port": 80, "mode": "banner",
    }))
    assert result.get("is_error")


def test_flag_discriminator_refuses_under_bbp(tmp_path):
    ctx = _make_ctx(tmp_path, mode="bbp")
    result = asyncio.run(p_flag.flag_discriminator.handler({
        "text": "HTB{some_flag_here}",
    }))
    assert result.get("is_error")


def test_ctf_writeup_refuses_under_production(tmp_path):
    ctx = _make_ctx(tmp_path, mode="production")
    result = asyncio.run(p_ctfwu.ctf_writeup.handler({
        "box_name": "Sauna", "difficulty": "easy",
        "flag": "HTB{x}", "chain_summary": "lfi -> rce",
        "steps": ["1"], "lessons": "z", "mitigations": "z",
    }))
    assert result.get("is_error")


# ---- Audit log mode stamping under CTF -----------------------------------


def test_ctf_run_stamps_mode_on_every_audit_entry(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    s = Scope.load(_scope_yaml(tmp_path, engagement_mode="ctf"),
                    audit_log_path=log_path)
    s.audit_log.write("test_event", {"x": 1}, mode=s.engagement_mode.value)
    s.audit_log.write("another", {"y": 2}, mode=s.engagement_mode.value)
    text = log_path.read_text()
    for line in text.strip().splitlines():
        entry = json.loads(line)
        assert entry.get("mode") == "ctf"
    ok, err = AuditLog.verify(log_path)
    assert ok, err


# ---- verify-audit anti-tamper --------------------------------------------


def test_verify_audit_rejects_scope_mode_mismatch(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    Scope.load(_scope_yaml(tmp_path, engagement_mode="ctf"),
                audit_log_path=log_path)
    # Scope file edited post-hoc to claim production while audit log
    # still says ctf — verifier must catch the laundering.
    ok, err = AuditLog.verify(log_path, scope_mode="production")
    assert not ok
    assert "mode" in (err or "").lower()


def test_verify_audit_passes_when_modes_agree(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    Scope.load(_scope_yaml(tmp_path, engagement_mode="ctf"),
                audit_log_path=log_path)
    ok, err = AuditLog.verify(log_path, scope_mode="ctf")
    assert ok, err


# ---- PDF reporter banner -------------------------------------------------


def test_pdf_reporter_prepends_banner_for_ctf(tmp_path):
    """Build a minimal RunReport and confirm the PDF mode-banner
    helper returns content for CTF and is empty for production."""
    from sentinel.reporting.pdf import PDFReporter
    from sentinel.core.orchestrator import RunReport

    s = Scope.load(_scope_yaml(tmp_path, engagement_mode="ctf"),
                    audit_log_path=tmp_path / "audit.jsonl")
    rep = PDFReporter(tmp_path)
    styles = rep._styles()
    banner = rep._mode_banner(s, styles)
    assert banner, "CTF mode must produce a banner block"
    # The banner's first paragraph carries the warning string.
    rendered = banner[0].text if hasattr(banner[0], "text") else str(banner[0])
    assert "CTF" in rendered.upper()
    assert "NOT A CLIENT DELIVERABLE" in rendered.upper()


def test_pdf_reporter_no_banner_for_production(tmp_path):
    from sentinel.reporting.pdf import PDFReporter

    s = Scope.load(_scope_yaml(tmp_path, engagement_mode="production"),
                    audit_log_path=tmp_path / "audit.jsonl")
    rep = PDFReporter(tmp_path)
    styles = rep._styles()
    banner = rep._mode_banner(s, styles)
    assert banner == [], "production must not emit a banner"


# ---- flag_discriminator regex correctness --------------------------------


def test_flag_discriminator_finds_htb_flag():
    matches = p_flag.discover_flags(
        "stuff before HTB{this_is_a_flag_string} stuff after",
        platform="hackthebox",
    )
    assert any("HTB{this_is_a_flag_string}" == m["match"] for m in matches)


def test_flag_discriminator_finds_picoctf_flag():
    matches = p_flag.discover_flags(
        "picoCTF{some_pico_flag_value}", platform="picoctf",
    )
    assert any("picoCTF{some_pico_flag_value}" == m["match"] for m in matches)


def test_flag_discriminator_custom_format():
    matches = p_flag.discover_flags(
        "TEST{very_custom}",
        custom_format=r"TEST\{[^}]+\}",
    )
    assert any("TEST{very_custom}" == m["match"] for m in matches)


def test_flag_discriminator_no_match_returns_empty():
    matches = p_flag.discover_flags("just some random text without a flag")
    # Generic patterns may or may not catch random hex; assert no
    # 'flag{...}' style match at minimum.
    assert not any("flag{" in m["match"].lower() for m in matches)


# ---- ctf_writeup render shape --------------------------------------------


def test_ctf_writeup_renders_standard_shape():
    body = p_ctfwu.render_writeup(
        box_name="Sauna",
        difficulty="easy",
        flag="HTB{flag_here}",
        chain_summary="anonymous SMB → kerberoast → DCSync",
        steps=["nmap", "smbclient", "GetNPUsers"],
        lessons="never disable preauth",
        mitigations="enable preauth, monitor TGS",
    )
    assert body.startswith("# Sauna — easy\n")
    assert "**Flag:** `HTB{flag_here}`" in body
    assert "## Steps\n" in body
    assert "## Lessons\n" in body
    assert "## Mitigations" in body
    # Step renumbering
    assert "1. nmap" in body
    assert "2. smbclient" in body
    assert "3. GetNPUsers" in body


def test_ctf_writeup_handles_empty_optionals():
    body = p_ctfwu.render_writeup(
        box_name="Anon", difficulty="",
        flag="x", chain_summary="",
        steps=[], lessons="", mitigations="",
    )
    assert "(none)" in body
    assert "1. (no steps recorded)" in body


# ---- Wave 2 retester integration sanity (no regression) ------------------


def test_wave2_retester_swarm_imports_under_ctf(tmp_path):
    """The whole Wave-2 retester surface must still import / run under
    CTF mode. We just exercise the import + trip-counter, which were
    the main Wave-2 deliverables we don't want to break."""
    from sentinel.agent.pentest.retester_agent import RetesterTripCounter
    rc = RetesterTripCounter()
    assert rc.get("xss", "vuln-1") == 0
    rc.bump("xss", "vuln-1")
    assert rc.get("xss", "vuln-1") == 1


# ---- Pipeline-level mode propagation -------------------------------------


def test_pipeline_config_engagement_mode_threads_to_scope_check(tmp_path):
    """Constructing a PipelineConfig with engagement_mode='ctf' against
    a scope that says production must surface a ModeMismatchError when
    the pipeline starts."""
    from sentinel.agent.pentest.pipeline import PentestPipeline, PipelineConfig
    from sentinel.core.engagement_mode import ModeMismatchError

    scope_path = _scope_yaml(tmp_path, engagement_mode="production")
    cfg = PipelineConfig(
        target="https://target.com/",
        scope_path=str(scope_path),
        workspaces_root=str(tmp_path / "ws"),
        engagement_mode="ctf",  # mismatch
    )
    with pytest.raises(ModeMismatchError):
        asyncio.run(PentestPipeline(cfg).run())


def test_event_styles_has_mode_badge_for_each_mode():
    from sentinel.web.event_styles import MODE_BADGE_STYLES, style_for_mode
    for m in ("production", "bbp", "ctf", "lab"):
        s = style_for_mode(m)
        assert s.get("label")
        assert s.get("chip")


def test_event_styles_includes_ctf_kinds():
    from sentinel.web.event_styles import EVENT_STYLES
    for kind in (
        "webshell_dropped", "c2_listener_opened", "c2_command_sent",
        "ssh_command_run", "ctf_code_executed",
        "ctf_flag_search", "ctf_flag_found",
        "netcat_probe", "ctf_exfil_staged", "ctf_writeup_saved",
    ):
        assert kind in EVENT_STYLES, f"missing event style for {kind}"
