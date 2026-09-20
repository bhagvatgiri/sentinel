"""Wave 5 / C10 — Red-teamer agent tests.

Asserted properties:
  - build_red_teamer_tools returns the empty list under production / bbp
    (structural CTF gate — even before runtime mode check).
  - build_red_teamer_tools returns the full kill-chain tool union under
    ctf / lab.
  - assert_red_teamer_allowed raises ModeError under production / bbp.
  - The kill-chain tool union includes every documented CTF tool +
    CodeAct so the agent can fall back to Python sub-tasks.
"""

from __future__ import annotations

import pytest

from sentinel.agent.pentest import red_teamer as p_redteam
from sentinel.core.engagement_mode import EngagementMode, ModeError


# ---- Tool union construction --------------------------------------------


def test_build_red_teamer_tools_empty_under_production():
    tools = p_redteam.build_red_teamer_tools(EngagementMode.PRODUCTION)
    assert tools == [], (
        f"production must return empty tool union; got: "
        f"{[t.name for t in tools]}"
    )


def test_build_red_teamer_tools_empty_under_bbp():
    tools = p_redteam.build_red_teamer_tools(EngagementMode.BBP)
    assert tools == []


def test_build_red_teamer_tools_full_under_ctf():
    tools = p_redteam.build_red_teamer_tools(EngagementMode.CTF)
    names = {t.name for t in tools}
    expected = {
        "drop_webshell",
        "open_reverse_shell_listener", "reverse_shell_send",
        "reverse_shell_history",
        "ssh_with_credentials", "execute_arbitrary_code",
        "execute_python_code",
        "netcat_raw",
        "exfil_file_via_oast",
        "drop_persistent_backdoor",
        "flag_discriminator",
        "ctf_writeup",
    }
    missing = expected - names
    assert not missing, f"red-teamer is missing kill-chain tools: {missing}"


def test_build_red_teamer_tools_full_under_lab():
    tools = p_redteam.build_red_teamer_tools(EngagementMode.LAB)
    names = {t.name for t in tools}
    assert "drop_persistent_backdoor" in names
    assert "execute_python_code" in names


# ---- Spawn-time gate -----------------------------------------------------


def test_assert_red_teamer_allowed_under_ctf():
    # Should not raise.
    p_redteam.assert_red_teamer_allowed(EngagementMode.CTF)
    p_redteam.assert_red_teamer_allowed(EngagementMode.LAB)


def test_assert_red_teamer_allowed_refuses_under_production():
    with pytest.raises(ModeError):
        p_redteam.assert_red_teamer_allowed(EngagementMode.PRODUCTION)
    with pytest.raises(ModeError):
        p_redteam.assert_red_teamer_allowed(EngagementMode.BBP)


# ---- Kill-chain ATT&CK tactics --------------------------------------------


def test_kill_chain_tactics_in_canonical_order():
    """Wave 4 / A6 — every tactic in KILL_CHAIN_TACTICS must be a
    canonical ATT&CK Enterprise tactic name. The dashboard's heatmap
    renders these to the matching attack_tactic_<slug> event style."""
    from sentinel.web.event_styles import attack_tactic_slug, EVENT_STYLES
    for tactic in p_redteam.KILL_CHAIN_TACTICS:
        slug = attack_tactic_slug(tactic)
        # Every canonical tactic should have a dedicated style row;
        # if a future tactic is added to the kill chain, the test
        # surfaces the missing row immediately.
        assert slug in EVENT_STYLES, (
            f"missing event style for kill-chain tactic {tactic!r} "
            f"(slug={slug})"
        )


# ---- System prompt sanity ------------------------------------------------


def test_system_prompt_documents_kill_chain():
    """Sanity: the prompt mentions ATT&CK tactics for each step."""
    prompt = p_redteam.RED_TEAMER_SYSTEM_PROMPT
    for label in (
        "Initial Access", "Execution", "Privilege Escalation",
        "Persistence", "Lateral Movement", "Exfiltration",
    ):
        assert label in prompt, f"prompt missing kill-chain step {label!r}"


def test_system_prompt_mentions_writeup_and_cleanup():
    """The agent MUST write up the run + attest to cleanup of any
    backdoor it dropped. If this regression is introduced the test
    flags it."""
    prompt = p_redteam.RED_TEAMER_SYSTEM_PROMPT
    assert "ctf_writeup" in prompt
    assert "cleanup" in prompt.lower()


# ---- Niche agents (sub-GHz + WiFi) — mode gating + registration ----------


def test_subghz_filter_drops_in_production():
    from sentinel.agent.pentest import subghz_agent as p_subghz
    from sentinel.core.engagement_mode import filter_tools_for_mode
    filtered = filter_tools_for_mode(p_subghz.ALL_TOOLS, EngagementMode.PRODUCTION)
    assert filtered == []


def test_subghz_filter_keeps_in_ctf_and_lab():
    from sentinel.agent.pentest import subghz_agent as p_subghz
    from sentinel.core.engagement_mode import filter_tools_for_mode
    for mode in (EngagementMode.CTF, EngagementMode.LAB):
        filtered = filter_tools_for_mode(p_subghz.ALL_TOOLS, mode)
        assert {t.name for t in filtered} == {"analyze_radio_capture"}


def test_wifi_filter_drops_in_production():
    from sentinel.agent.pentest import wifi_agent as p_wifi
    from sentinel.core.engagement_mode import filter_tools_for_mode
    filtered = filter_tools_for_mode(p_wifi.ALL_TOOLS, EngagementMode.PRODUCTION)
    assert filtered == []


def test_wifi_filter_keeps_in_ctf_and_lab():
    from sentinel.agent.pentest import wifi_agent as p_wifi
    from sentinel.core.engagement_mode import filter_tools_for_mode
    for mode in (EngagementMode.CTF, EngagementMode.LAB):
        filtered = filter_tools_for_mode(p_wifi.ALL_TOOLS, mode)
        assert {t.name for t in filtered} == {"wifi_handshake_crack"}


def test_subghz_runtime_refuses_under_production(tmp_path):
    """Belt-and-suspenders runtime check on the niche sub-GHz tool body."""
    import asyncio
    from datetime import date, timedelta
    import yaml
    from sentinel.agent.pentest import subghz_agent as p_subghz
    from sentinel.agent.pentest import tools as p_tools
    from sentinel.core.scope import Scope

    today = date.today()
    data = {
        "client": "x", "engagement_id": "y", "authorized_by": "z@x.com",
        "valid_from": (today - timedelta(days=1)).isoformat(),
        "valid_until": (today + timedelta(days=30)).isoformat(),
        "targets": {"domains": ["target.com"], "ips": []},
        "rate_limits": {"requests_per_second": 5},
        "engagement_mode": "production",
    }
    p = tmp_path / "scope.yaml"; p.write_text(yaml.safe_dump(data))
    s = Scope.load(p, audit_log_path=tmp_path / "audit.jsonl")
    workspace = tmp_path / "ws"; workspace.mkdir()
    cap = workspace / "x.cu8"; cap.write_bytes(b"\x00" * 1024)

    class _StubHttp:
        async def get(self, *a, **k):
            class _R:
                status_code = 200; text = ""; headers = {}; url = ""
            return _R()

    p_tools.set_context(p_tools.PentestContext(
        scope=s, audit=s.audit_log, workspace_dir=workspace,
        http=_StubHttp(),  # type: ignore[arg-type]
        rate_limit_per_host_sec=0.0,
    ))

    result = asyncio.run(p_subghz.analyze_radio_capture.handler({
        "file": "x.cu8", "freq": "433.92", "modulation": "ook",
    }))
    assert result.get("is_error")


def test_wifi_runtime_refuses_under_bbp(tmp_path):
    """Belt-and-suspenders runtime check on the WiFi tool body."""
    import asyncio
    from datetime import date, timedelta
    import yaml
    from sentinel.agent.pentest import wifi_agent as p_wifi
    from sentinel.agent.pentest import tools as p_tools
    from sentinel.core.scope import Scope

    today = date.today()
    data = {
        "client": "x", "engagement_id": "y", "authorized_by": "z@x.com",
        "valid_from": (today - timedelta(days=1)).isoformat(),
        "valid_until": (today + timedelta(days=30)).isoformat(),
        "targets": {"domains": ["target.com"], "ips": []},
        "rate_limits": {"requests_per_second": 5},
        "engagement_mode": "bbp",
    }
    p = tmp_path / "scope.yaml"; p.write_text(yaml.safe_dump(data))
    s = Scope.load(p, audit_log_path=tmp_path / "audit.jsonl")
    workspace = tmp_path / "ws"; workspace.mkdir()
    (workspace / "x.cap").write_bytes(b"\x00" * 1024)
    (workspace / "wl.txt").write_text("password\nadmin\n")

    class _StubHttp:
        async def get(self, *a, **k):
            class _R:
                status_code = 200; text = ""; headers = {}; url = ""
            return _R()

    p_tools.set_context(p_tools.PentestContext(
        scope=s, audit=s.audit_log, workspace_dir=workspace,
        http=_StubHttp(),  # type: ignore[arg-type]
        rate_limit_per_host_sec=0.0,
    ))

    result = asyncio.run(p_wifi.wifi_handshake_crack.handler({
        "file": "x.cap", "wordlist": "wl.txt",
    }))
    assert result.get("is_error")
