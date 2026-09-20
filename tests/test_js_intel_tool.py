"""Smoke tests for B1 — JS bundle harvester + endpoint/secret extractor.

The interesting paths in `_scan` are pure regex; we test them directly
without instantiating the full PentestContext. The fetch_* tool wrappers
are scope-gated and audit-logged via the same canonical pattern as
tools.http_get; we don't re-test that machinery.
"""

from __future__ import annotations

from sentinel.agent.pentest.js_intel_tool import _scan, _format_scan_summary


# ---- _scan ---------------------------------------------------------------

def test_scan_extracts_fetch_call_endpoints():
    js = """
    async function load() {
      const r = await fetch("/api/users/me");
      const r2 = await fetch('/v2/orders/list');
      return r.json();
    }
    """
    out = _scan(js)
    fetch_hits = out["endpoints"].get("fetch_call", [])
    assert "/api/users/me" in fetch_hits
    assert "/v2/orders/list" in fetch_hits


def test_scan_extracts_websocket_urls():
    js = "const ws = new WebSocket('wss://chat.example.com/socket');"
    out = _scan(js)
    ws_hits = out["endpoints"].get("websocket_url", [])
    assert any("wss://chat.example.com/socket" in hit for hit in ws_hits)


def test_scan_extracts_aws_access_key():
    """AWS access keys have a strict, distinctive format. This is the bug-bounty
    money pattern — recurring P1-P2 finding."""
    js = """const config = {accessKeyId: "AKIAIOSFODNN7EXAMPLE", region: "us-east-1"};"""
    out = _scan(js)
    aws_hits = out["secrets"].get("aws_access_key_id", [])
    assert len(aws_hits) == 1
    # Masked output: first 8 chars + last 4 chars + length tag
    masked = aws_hits[0]
    assert masked.startswith("AKIAIOSF")
    assert masked.endswith("PLE (len=20)")


def test_scan_extracts_jwt_token():
    # A short non-real JWT (3 base64-ish parts separated by dots)
    js = """const t = "eyJhbGciOiJIUzI1NiIsInR.eyJzdWIiOiIxMjM0NTY3.SflKxwRJSMeKKF2QT4f";"""
    out = _scan(js)
    jwt_hits = out["secrets"].get("jwt_token", [])
    assert len(jwt_hits) == 1


def test_scan_detects_postmessage_wildcard():
    """The AcmeProgram bug class — direct match for our AcmeProgram finding."""
    js = """
    function notifyParent(data) {
      window.parent.postMessage(data, "*");
    }
    """
    out = _scan(js)
    pmw = out["postmessage_wildcards"]
    assert len(pmw) == 1
    assert "postMessage" in pmw[0]
    assert '"*"' in pmw[0]


def test_scan_detects_sourcemap_reference():
    js = """
    var x = 1;
    //# sourceMappingURL=app.bundle.js.map
    """
    out = _scan(js)
    assert out["sourcemap_url"] == "app.bundle.js.map"


def test_scan_no_false_positive_on_clean_js():
    js = """
    const sum = (a, b) => a + b;
    console.log(sum(1, 2));
    """
    out = _scan(js)
    # No endpoints, no secrets, no postMessage, no sourcemap
    assert not out["endpoints"]
    assert not out["secrets"]
    assert out["postmessage_wildcards"] == []
    assert out["sourcemap_url"] is None


def test_scan_caps_per_category_at_50():
    """Defensive — even pathological inputs don't blow the prompt size."""
    # 200 unique fetch calls in one body
    js = "\n".join(f'fetch("/api/path{i}")' for i in range(200))
    out = _scan(js)
    assert len(out["endpoints"]["fetch_call"]) == 50


def test_scan_extracts_graphql_operation_names():
    js = """
    const Q = `query GetUserProfile($id: ID!) { user(id: $id) { name email } }`;
    const M = `mutation UpdateProfile($input: UpdateInput!) { updateProfile(input: $input) { id } }`;
    """
    out = _scan(js)
    op_hits = out["endpoints"].get("graphql_op", [])
    # Captures the operation NAME (group 2)
    assert "GetUserProfile" in op_hits
    assert "UpdateProfile" in op_hits


# ---- _format_scan_summary ------------------------------------------------

def test_format_summary_includes_section_for_each_category():
    js = """
    fetch("/api/v1/users");
    const k = "AKIAIOSFODNN7EXAMPLE";
    window.parent.postMessage(d, "*");
    //# sourceMappingURL=foo.map
    """
    summary = _format_scan_summary(_scan(js), bundle_url="https://example.com/x.js")
    assert "https://example.com/x.js" in summary
    assert "Endpoints" in summary
    assert "Secrets" in summary
    assert "postMessage wildcard" in summary
    assert "Source map" in summary
    assert "/api/v1/users" in summary
    # Secrets are masked, not raw
    assert "AKIAIOSFODNN7EXAMPLE" not in summary
    assert "AKIAIOSF" in summary


def test_format_summary_handles_empty_scan():
    """A bundle with nothing interesting still produces a readable result."""
    summary = _format_scan_summary(_scan("var x = 1;"), bundle_url="https://example.com/x.js")
    assert "https://example.com/x.js" in summary
    assert "no extractor hits" in summary


def test_all_tools_export():
    """Pipeline registers via ALL_TOOLS — defensive check that the export shape
    is what _run_phase expects."""
    from sentinel.agent.pentest.js_intel_tool import ALL_TOOLS
    assert isinstance(ALL_TOOLS, list)
    assert len(ALL_TOOLS) >= 2
    # Each entry must have a `.name` attribute (Claude Agent SDK tool)
    for t in ALL_TOOLS:
        assert hasattr(t, "name")
