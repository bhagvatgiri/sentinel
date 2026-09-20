"""Wave 5 / C7 — Replay-attack agent tests.

Asserted properties:
  - Mode gating: pcap_parse + replay_request refuse under production
    and bbp; allow under ctf and lab.
  - Tool registration: filter_tools_for_mode drops them in production.
  - parse_capture_file works on a synthetic JSON-shaped capture
    (HAR-like) — extracts request shape + auth tokens.
  - replay_request:
      * applies header / body / url mutations correctly
      * scope-gates the resulting URL (out-of-scope refused)
      * audit-logs the replay
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from sentinel.agent.pentest import replay_attack as p_replay
from sentinel.agent.pentest import tools as p_tools
from sentinel.core.scope import Scope


def _scope_yaml(tmp_path: Path, **overrides) -> Path:
    today = date.today()
    data = {
        "client": "ctf-client",
        "engagement_id": "ctf-replay-001",
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

    class _StubResp:
        def __init__(self, *, status_code=200, text="stub-body", headers=None, url=""):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}
            self.url = url

    class _StubHttp:
        def __init__(self):
            self.calls = []

        async def get(self, url, *a, **k):
            self.calls.append({"method": "GET", "url": url, **k})
            return _StubResp(url=url)

        async def request(self, method, url, *a, **k):
            self.calls.append({"method": method, "url": url, **k})
            return _StubResp(url=url)

    ctx = p_tools.PentestContext(
        scope=s, audit=s.audit_log, workspace_dir=workspace,
        http=_StubHttp(),  # type: ignore[arg-type]
        rate_limit_per_host_sec=0.0,
    )
    p_tools.set_context(ctx)
    return ctx


# ---- parse_capture_file --------------------------------------------------


def test_parse_capture_file_har_shape(tmp_path):
    """JSON capture in HAR-like shape extracts requests + tokens."""
    har = {
        "entries": [
            {
                "request": {
                    "method": "POST",
                    "url": "https://target.com/api/login",
                    "headers": [
                        {"name": "Authorization", "value": "Bearer eyJabc.def.ghi"},
                        {"name": "Cookie", "value": "session=abc123"},
                    ],
                    "body": '{"nonce": "xyz789nonceval", "csrf_token": "kZ8aPqLM12345"}',
                },
            },
            {
                "request": {
                    "method": "GET",
                    "url": "https://target.com/api/me",
                    "headers": {"Authorization": "Bearer eyJabc.def.ghi"},
                },
            },
        ],
    }
    cap = tmp_path / "cap.json"
    cap.write_text(json.dumps(har))
    result = p_replay.parse_capture_file(cap)

    assert result.get("requests"), f"no requests parsed: {result}"
    assert len(result["requests"]) == 2
    methods = {r["method"] for r in result["requests"]}
    assert methods == {"POST", "GET"}

    tokens = result.get("tokens", {})
    # The `body` is a JSON string in the captured payload, so the
    # bytes-level regex finds the auth header.
    assert any("eyJabc" in t for t_list in tokens.values() for t in t_list)
    # Authorization header is captured as a Bearer token.
    assert "authorization_bearer" in tokens or "jwt" in tokens


def test_parse_capture_file_missing_file(tmp_path):
    res = p_replay.parse_capture_file(tmp_path / "nope.pcap")
    assert "error" in res


def test_parse_capture_file_jwt_extraction(tmp_path):
    """JWT bytes are picked out by the dedicated regex."""
    cap = tmp_path / "raw.json"
    cap.write_text(json.dumps({
        "entries": [{
            "request": {
                "method": "GET", "url": "https://target.com/x",
                "headers": {"X-Token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.abcd-XYZ_signature"},
            },
        }],
    }))
    result = p_replay.parse_capture_file(cap)
    tokens = result.get("tokens", {})
    assert "jwt" in tokens, f"jwt not surfaced; got: {list(tokens.keys())}"
    assert any("eyJhbGc" in t for t in tokens["jwt"])


# ---- pcap_parse MCP tool: mode gating ------------------------------------


def test_pcap_parse_refuses_under_production(tmp_path):
    ctx = _make_ctx(tmp_path, mode="production")
    cap = ctx.workspace_dir / "cap.json"
    cap.write_text(json.dumps({"entries": []}))
    result = asyncio.run(p_replay.pcap_parse.handler({"file": "cap.json"}))
    assert result.get("is_error")


def test_pcap_parse_refuses_under_bbp(tmp_path):
    ctx = _make_ctx(tmp_path, mode="bbp")
    cap = ctx.workspace_dir / "cap.json"
    cap.write_text(json.dumps({"entries": []}))
    result = asyncio.run(p_replay.pcap_parse.handler({"file": "cap.json"}))
    assert result.get("is_error")


def test_pcap_parse_runs_under_ctf(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    cap = ctx.workspace_dir / "cap.json"
    cap.write_text(json.dumps({
        "entries": [{
            "request": {
                "method": "GET", "url": "https://target.com/healthz",
                "headers": {"Cookie": "session=abc"},
            },
        }],
    }))
    result = asyncio.run(p_replay.pcap_parse.handler({"file": "cap.json"}))
    assert not result.get("is_error"), result
    assert "parsed 1 HTTP request" in result["content"][0]["text"]


def test_pcap_parse_workspace_traversal_blocked(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    result = asyncio.run(p_replay.pcap_parse.handler({"file": "../escape.pcap"}))
    assert result.get("is_error")


# ---- replay_request MCP tool ---------------------------------------------


def test_replay_request_refuses_under_production(tmp_path):
    ctx = _make_ctx(tmp_path, mode="production")
    result = asyncio.run(p_replay.replay_request.handler({
        "captured": json.dumps({
            "method": "GET", "url": "https://target.com/x",
            "headers": {}, "body": "",
        }),
        "mutations": json.dumps({}),
    }))
    assert result.get("is_error")


def test_replay_request_applies_header_mutation(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    result = asyncio.run(p_replay.replay_request.handler({
        "captured": json.dumps({
            "method": "GET", "url": "https://target.com/api/me",
            "headers": {"Authorization": "Bearer old"},
            "body": "",
        }),
        "mutations": json.dumps({"header.Authorization": "Bearer new"}),
    }))
    assert not result.get("is_error"), result
    text = result["content"][0]["text"]
    assert "header.Authorization" in text
    # Stub captured the call — confirm mutated header is what http saw.
    last_call = ctx.http.calls[-1]
    assert last_call["headers"]["Authorization"] == "Bearer new"


def test_replay_request_applies_body_mutation_json(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    asyncio.run(p_replay.replay_request.handler({
        "captured": json.dumps({
            "method": "POST", "url": "https://target.com/api/x",
            "headers": {"Content-Type": "application/json"},
            "body": '{"nonce": "old"}',
        }),
        "mutations": json.dumps({"body.nonce": "0"}),
    }))
    last_call = ctx.http.calls[-1]
    body = last_call.get("content")
    assert body, f"no body in call: {last_call}"
    parsed = json.loads(body)
    assert parsed["nonce"] == "0"


def test_replay_request_url_mutation_then_oos_refused(tmp_path):
    """If the mutation sets URL to out-of-scope, scope refuses + audits."""
    ctx = _make_ctx(tmp_path, mode="ctf")
    result = asyncio.run(p_replay.replay_request.handler({
        "captured": json.dumps({
            "method": "GET", "url": "https://target.com/x",
            "headers": {}, "body": "",
        }),
        "mutations": json.dumps({"url": "https://evil.com/x"}),
    }))
    assert result.get("is_error")
    text = result["content"][0]["text"]
    assert "out-of-scope" in text or "scope" in text.lower()


def test_replay_request_unknown_mutation_key_rejected(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    result = asyncio.run(p_replay.replay_request.handler({
        "captured": json.dumps({
            "method": "GET", "url": "https://target.com/x",
            "headers": {}, "body": "",
        }),
        "mutations": json.dumps({"weird.key": "value"}),
    }))
    assert result.get("is_error")
    assert "weird.key" in result["content"][0]["text"]


def test_replay_request_audit_logs_the_call(tmp_path):
    ctx = _make_ctx(tmp_path, mode="ctf")
    asyncio.run(p_replay.replay_request.handler({
        "captured": json.dumps({
            "method": "GET", "url": "https://target.com/x",
            "headers": {}, "body": "",
        }),
        "mutations": json.dumps({}),
    }))
    log = (tmp_path / "audit.jsonl").read_text()
    assert "replay_request" in log


# ---- Filter integration --------------------------------------------------


def test_filter_drops_replay_tools_in_production():
    from sentinel.core.engagement_mode import (
        EngagementMode, filter_tools_for_mode,
    )
    filtered = filter_tools_for_mode(p_replay.ALL_TOOLS, EngagementMode.PRODUCTION)
    assert filtered == []


def test_filter_keeps_replay_tools_in_ctf_and_lab():
    from sentinel.core.engagement_mode import (
        EngagementMode, filter_tools_for_mode,
    )
    for mode in (EngagementMode.CTF, EngagementMode.LAB):
        filtered = filter_tools_for_mode(p_replay.ALL_TOOLS, mode)
        names = {t.name for t in filtered}
        assert "pcap_parse" in names
        assert "replay_request" in names
