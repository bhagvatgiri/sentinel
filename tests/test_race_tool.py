"""Smoke tests for B4 — race-condition tester.

Tests pure helpers (_parse_headers, distribution analysis logic).
Live HTTP firing tested via integration tests against an httpbin/local
mock server — not in unit tests.
"""

from __future__ import annotations

import asyncio
import hashlib

from sentinel.agent.pentest.race_tool import (
    _parse_headers,
    ALL_TOOLS,
)


def test_all_tools_export():
    assert isinstance(ALL_TOOLS, list)
    assert len(ALL_TOOLS) == 1
    assert ALL_TOOLS[0].name == "race_request"


def test_parse_headers_empty():
    assert _parse_headers("") == {}
    assert _parse_headers(None or "") == {}
    assert _parse_headers("   ") == {}


def test_parse_headers_valid_json():
    h = _parse_headers('{"Authorization": "Bearer abc"}')
    assert h == {"Authorization": "Bearer abc"}


def test_parse_headers_invalid_returns_empty():
    assert _parse_headers("not json") == {}
    assert _parse_headers("{") == {}
    assert _parse_headers('["array"]') == {}


def test_parse_headers_coerces_to_strings():
    h = _parse_headers('{"X-Count": 5, "X-Bool": true}')
    assert h["X-Count"] == "5"
    assert h["X-Bool"] == "True"


# ─────────── distribution / race-signal heuristic ───────────────────────

def _fake_results(statuses: list[int], hashes: list[str]) -> list[dict]:
    """Build a list of fake _fire_one outputs for testing the
    distribution-analysis path."""
    return [
        {"idx": i, "status": s, "body_hash": h, "body_len": len(h or ""),
         "elapsed_ms": 100 + i, "headers_subset": {}, "error": None}
        for i, (s, h) in enumerate(zip(statuses, hashes))
    ]


def _classify(results: list[dict]) -> str:
    """Mirror the race-signal heuristic from _fire_parallel internals.
    Replicates the production logic so unit tests can exercise it without
    actual network calls."""
    from collections import Counter
    success_hashes = Counter(
        r["body_hash"] for r in results
        if 200 <= r["status"] < 400 and r["body_hash"]
    )
    distinct_statuses = len({r["status"] for r in results})
    error_count = sum(1 for r in results if r["error"])
    parallel = len(results)

    if len(success_hashes) >= 2:
        return "STRONG"
    if distinct_statuses >= 2:
        return "MEDIUM"
    if error_count > 0 and error_count < parallel:
        return "WEAK"
    return "none"


def test_classify_strong_signal_distinct_success_hashes():
    """Multiple distinct body hashes among 2xx responses = STRONG signal.
    The classic TOCTOU pattern: parallel coupon-redeem requests, half
    return 'success: claimed' and half return 'success: already-claimed'
    — distinct success bodies prove the race window."""
    r = _fake_results([200, 200, 200, 200], ["aaa", "bbb", "aaa", "bbb"])
    assert _classify(r) == "STRONG"


def test_classify_medium_signal_distinct_statuses():
    """Mix of 200 and 429 statuses = MEDIUM (could be rate-limit, but
    might also be partial success)."""
    r = _fake_results([200, 429, 200, 429], ["a", "b", "a", "b"])
    assert _classify(r) == "MEDIUM"


def test_classify_no_signal_uniform():
    """All identical responses = no race signal."""
    r = _fake_results([200] * 5, ["aaa"] * 5)
    assert _classify(r) == "none"


def test_classify_weak_signal_partial_errors():
    """If some requests error and others succeed, that's a WEAK signal
    of lock contention."""
    r = _fake_results([200, 200, 200], ["a", "a", "a"])
    r[1]["error"] = "timeout"  # one error
    assert _classify(r) == "WEAK"


def test_classify_no_signal_all_errors():
    """All requests errored = network problem, not race signal."""
    r = _fake_results([0, 0, 0], ["", "", ""])
    for x in r:
        x["error"] = "connection refused"
    # All errored → signal is 'none' (not actionable as race)
    assert _classify(r) == "none"


def test_classify_strong_outweighs_medium():
    """If both conditions fire, STRONG wins (distinct success hashes is
    the higher-fidelity signal)."""
    r = _fake_results([200, 200, 429, 200], ["a", "b", "", "a"])
    # 2 distinct hashes among 2xx → STRONG
    assert _classify(r) == "STRONG"


def test_event_styles_register_race_events():
    from sentinel.web.event_styles import EVENT_STYLES
    assert "race_request_run" in EVENT_STYLES
    assert "race_state_diverged" in EVENT_STYLES
    assert EVENT_STYLES["race_state_diverged"]["chip"] == "high"


def test_h2_graceful_degradation():
    """If h2 module is missing, code path falls back to HTTP/1.1
    instead of crashing. We can't easily test the absence-path here
    (h2 IS installed), but assert the import-shielded code is
    reachable in the function source."""
    from sentinel.agent.pentest import race_tool
    src = open(race_tool.__file__).read()
    assert "import h2" in src
    assert "ImportError" in src
    assert "use_h2 = False" in src


# ─────────── Tier-2 (2026-XX-XX) integration tests — burst semantics ────


class _FakeAuditLog:
    def __init__(self):
        self.events: list[tuple] = []

    def write(self, event, payload):
        self.events.append((event, dict(payload)))


class _FakeScope:
    def __init__(
        self, *,
        domains=("example.com",),
        race_test_concurrent_max=None,
        out_of_scope_for: tuple = (),
        research_headers: dict | None = None,
    ):
        self.research_headers = research_headers or {}
        self.domains = list(domains)
        self.repos = []
        self.ips = []
        self.race_test_concurrent_max = race_test_concurrent_max
        self._oos = out_of_scope_for

    def authorize_url(self, url: str):
        from sentinel.core.scope import OutOfScopeError
        for needle in self._oos:
            if needle in url:
                raise OutOfScopeError(f"refused: {url}")
        return None


def _make_ctx(tmp_path, scope):
    """Build a minimal PentestContext for the race_request tool."""
    import httpx
    from sentinel.agent.pentest import tools as p_tools
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    ctx = p_tools.PentestContext(
        scope=scope,
        audit=_FakeAuditLog(),
        workspace_dir=ws,
        http=httpx.AsyncClient(),
        rate_limit_per_host_sec=0.0,
        fetch_timeout_sec=10.0,
    )
    p_tools.set_context(ctx)
    return ctx


def _patch_fire_parallel(monkeypatch, call_log, *, statuses, hashes):
    """Replace _fire_parallel so we don't make any real network calls.
    Records the (parallel, http_version) it was called with so tests can
    assert burst concurrency."""
    from sentinel.agent.pentest import race_tool

    async def fake_fire_parallel(method, url, headers, body,
                                  parallel, http_version="h2"):
        call_log.append({
            "method": method, "url": url, "headers": dict(headers or {}),
            "body": body, "parallel": parallel,
            "http_version": http_version,
        })
        results = [
            {"idx": i, "status": s, "body_hash": h,
             "body_len": len(h or ""), "elapsed_ms": 100 + i,
             "headers_subset": {}, "error": None}
            for i, (s, h) in enumerate(zip(statuses, hashes))
        ]
        from collections import Counter
        status_counts = Counter(r["status"] for r in results)
        success_hashes = Counter(
            r["body_hash"] for r in results
            if 200 <= r["status"] < 400 and r["body_hash"]
        )
        distinct_statuses = len(status_counts)
        if len(success_hashes) >= 2:
            sig = "STRONG"
        elif distinct_statuses >= 2:
            sig = "MEDIUM"
        else:
            sig = "none"
        distribution = {
            "parallel": parallel,
            "status_counts": dict(status_counts),
            "distinct_statuses": distinct_statuses,
            "distinct_body_hashes": len(set(h for h in hashes if h)),
            "distinct_success_hashes": len(success_hashes),
            "elapsed_ms": {"min": 100, "avg": 100, "max": 100 + len(results)},
            "errors": 0,
            "race_signal_strength": sig,
            "race_signal_reason": "",
        }
        return results, distribution
    monkeypatch.setattr(race_tool, "_fire_parallel", fake_fire_parallel)


def test_race_request_burst_fires_concurrent_requests(tmp_path, monkeypatch):
    """race_request must hand `parallel` off to the burst layer so the
    burst issues N concurrent calls. Asserts the contract — that the
    requested concurrency reaches _fire_parallel."""
    import asyncio
    from sentinel.agent.pentest.race_tool import race_request

    scope = _FakeScope()
    _make_ctx(tmp_path, scope)
    calls: list[dict] = []
    _patch_fire_parallel(
        monkeypatch, calls,
        statuses=[200] * 20, hashes=["a"] * 20,
    )
    out = asyncio.run(race_request.handler({
        "url": "https://example.com/api/claim",
        "method": "POST",
        "headers_json": '{"Authorization":"Bearer x"}',
        "body": '{"code":"PROMO"}',
        "parallel": 20,
        "http_version": "h2",
    }))
    assert out.get("is_error") is not True
    assert len(calls) == 1
    assert calls[0]["parallel"] == 20
    assert calls[0]["method"] == "POST"
    assert calls[0]["url"] == "https://example.com/api/claim"


def test_race_request_refuses_out_of_scope(tmp_path, monkeypatch):
    """Out-of-scope URL must return an _err result without ever invoking
    the burst layer. Defense-in-depth: scope check fires BEFORE any
    network activity."""
    import asyncio
    from sentinel.agent.pentest.race_tool import race_request

    scope = _FakeScope(out_of_scope_for=("forbidden.example",))
    _make_ctx(tmp_path, scope)
    calls: list[dict] = []
    _patch_fire_parallel(
        monkeypatch, calls,
        statuses=[200], hashes=["a"],
    )
    out = asyncio.run(race_request.handler({
        "url": "https://forbidden.example/claim",
        "method": "POST",
        "headers_json": "", "body": "",
        "parallel": 10, "http_version": "h2",
    }))
    assert out.get("is_error") is True
    assert "out-of-scope" in out["content"][0]["text"].lower()
    assert calls == [], "burst layer must not be invoked for OOS URL"


def test_race_request_clamps_parallel_to_default_max(tmp_path, monkeypatch):
    """C6 (2026-XX-XX audit): with NO explicit race_test_concurrent_max opt-in,
    the burst is capped by the scope rate limit — default 5 rps × 5 s window = 25.
    (Before C6 the default cap was 50; the rps cap is the new safe default that
    keeps a race burst within the program's declared rate limit.)"""
    import asyncio
    from sentinel.agent.pentest.race_tool import race_request

    scope = _FakeScope()  # no race opt-in + default 5 rps → rps cap 25
    _make_ctx(tmp_path, scope)
    calls: list[dict] = []
    _patch_fire_parallel(
        monkeypatch, calls,
        statuses=[200] * 50, hashes=["a"] * 50,
    )
    out = asyncio.run(race_request.handler({
        "url": "https://example.com/api/claim",
        "method": "POST",
        "headers_json": "", "body": "",
        "parallel": 9999,
        "http_version": "h2",
    }))
    assert out.get("is_error") is not True
    # default 5 rps → floor(5*5) = 25-request burst cap (no explicit race opt-in)
    assert calls[0]["parallel"] == 25


def test_race_request_respects_scope_concurrent_max_higher(tmp_path, monkeypatch):
    """scope.race_test_concurrent_max=80 must let parallel up to 80."""
    import asyncio
    from sentinel.agent.pentest.race_tool import race_request

    scope = _FakeScope(race_test_concurrent_max=80)
    _make_ctx(tmp_path, scope)
    calls: list[dict] = []
    _patch_fire_parallel(
        monkeypatch, calls,
        statuses=[200] * 80, hashes=["a"] * 80,
    )
    asyncio.run(race_request.handler({
        "url": "https://example.com/api/claim",
        "method": "POST",
        "headers_json": "", "body": "",
        "parallel": 80,
        "http_version": "h2",
    }))
    assert calls[0]["parallel"] == 80


def test_race_request_enforces_hard_ceiling_100(tmp_path, monkeypatch):
    """Even if scope says 9999 (rejected at load) or 100, parallel
    can never exceed 100. Defense for the case where someone bypasses
    the scope loader and constructs the dataclass directly."""
    import asyncio
    from sentinel.agent.pentest.race_tool import race_request

    # Construct an unrealistic scope (loader normally rejects > 100)
    scope = _FakeScope(race_test_concurrent_max=9999)
    _make_ctx(tmp_path, scope)
    calls: list[dict] = []
    _patch_fire_parallel(
        monkeypatch, calls,
        statuses=[200] * 100, hashes=["a"] * 100,
    )
    asyncio.run(race_request.handler({
        "url": "https://example.com/api/claim",
        "method": "POST",
        "headers_json": "", "body": "",
        "parallel": 9999,
        "http_version": "h2",
    }))
    assert calls[0]["parallel"] == 100


def test_race_request_zero_concurrent_max_disables(tmp_path, monkeypatch):
    """scope.race_test_concurrent_max=0 means race testing is disabled —
    the tool refuses without invoking the burst."""
    import asyncio
    from sentinel.agent.pentest.race_tool import race_request

    scope = _FakeScope(race_test_concurrent_max=0)
    _make_ctx(tmp_path, scope)
    calls: list[dict] = []
    _patch_fire_parallel(
        monkeypatch, calls,
        statuses=[200], hashes=["a"],
    )
    out = asyncio.run(race_request.handler({
        "url": "https://example.com/api/claim",
        "method": "POST",
        "headers_json": "", "body": "",
        "parallel": 20,
        "http_version": "h2",
    }))
    assert out.get("is_error") is True
    assert "disabled" in out["content"][0]["text"].lower()
    assert calls == []


def test_race_request_summary_status_distribution(tmp_path, monkeypatch):
    """Distribution summary must include the status_distribution counts
    rendered in the response."""
    import asyncio
    from sentinel.agent.pentest.race_tool import race_request

    scope = _FakeScope()
    _make_ctx(tmp_path, scope)
    calls: list[dict] = []
    _patch_fire_parallel(
        monkeypatch, calls,
        statuses=[200, 200, 429, 429, 429],
        hashes=["aaa", "bbb", "x", "x", "x"],
    )
    out = asyncio.run(race_request.handler({
        "url": "https://example.com/api/claim",
        "method": "POST",
        "headers_json": "", "body": "",
        "parallel": 5,
        "http_version": "h2",
    }))
    text = out["content"][0]["text"]
    # Status counts string-rendered in the markdown
    assert "200" in text and "429" in text
    # Strongest signal class (2 distinct success hashes)
    assert "STRONG" in text


def test_race_request_audit_logged(tmp_path, monkeypatch):
    """Every race_request invocation must append an audit event with
    URL, method, parallel count, and the race_signal verdict."""
    import asyncio
    from sentinel.agent.pentest.race_tool import race_request
    from sentinel.agent.pentest import tools as p_tools

    scope = _FakeScope()
    ctx = _make_ctx(tmp_path, scope)
    calls: list[dict] = []
    _patch_fire_parallel(
        monkeypatch, calls,
        statuses=[200] * 10, hashes=["a"] * 10,
    )
    asyncio.run(race_request.handler({
        "url": "https://example.com/api/claim",
        "method": "POST",
        "headers_json": "", "body": "",
        "parallel": 10,
        "http_version": "h2",
    }))
    assert ctx.audit.events, "audit log must record race_request event"
    event_name, payload = ctx.audit.events[-1]
    assert event_name == "race_request"
    assert payload["url"] == "https://example.com/api/claim"
    assert payload["method"] == "POST"
    assert payload["parallel"] == 10
    assert "race_signal" in payload
