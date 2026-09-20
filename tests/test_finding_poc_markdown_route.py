"""POC-07 + POC-08 (dashboard arm) — `/findings/<run>/<fp>/markdown` route +
"Copy Reproduction Markdown" button in finding_poc_detail.html.

This is the 5th and final POC-08 test file. The load-bearing assertion lives
in Test 14: the route's response body must be byte-identical to what
`render_poc_section(finding)` returns when called directly. The other 13
tests pin the route surface, the conditional button rendering, button
placement (dedicated section AFTER the header — NOT crammed inside the
header flex container), and the finding-reconstitution sanitizer.

Hermetic — uses `app.dependency_overrides[get_config]` per Plan 03-06's
canonical pattern. No live network, no Ollama, no Chroma, no Claude SDK.

Run with:
    PYTHONPATH=. .venv/bin/python -m pytest tests/test_finding_poc_markdown_route.py -x -q
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from sentinel.web.app import create_app
from sentinel.web.deps import get_config
from sentinel.ui.state import UIConfig
from sentinel.core.findings import Finding, Severity, EvidenceState, Status
from sentinel.reporting import render_poc_section


# ---- Fixture helpers ----------------------------------------------------


FP = "aaaaaaaaaaaaaaaa"  # 16 hex, the canonical test fingerprint
FP_ABSENT = "bbbbbbbbbbbbbbbb"  # 16 hex, never written to the run JSON
ENGAGEMENT_ID = "bench-test"


def _fixture_step_dict(
    *,
    step_number: int = 1,
    description: str = "Send the crafted request and observe the reflected payload",
    command: str = "curl 'https://target.example/search?q=<x>'",
    expected_output: str = "<x>",
    screenshot_path=None,
) -> dict:
    return {
        "step_number": step_number,
        "description": description,
        "command": command,
        "expected_output": expected_output,
        "screenshot_path": screenshot_path,
    }


def _fixture_finding_dict(
    *,
    poc_steps: list[dict] | None = None,
    fingerprint: str = FP,
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
        "poc_steps": poc_steps if poc_steps is not None else [_fixture_step_dict()],
    }
    if extras:
        base.update(extras)
    return base


def _build_fixture_tree(
    tmp_path: Path,
    *,
    findings: list[dict] | None = None,
) -> Path:
    """Hermetic tree: runs/test-run.json + workspaces dir scaffold.

    Returns tmp_path. Pattern adapted from tests/test_web_finding_poc_route.py
    but self-contained — we do not import the private fixture from that
    module, we duplicate the relevant build logic.
    """
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    workspaces_dir = tmp_path / "workspaces"
    workspaces_dir.mkdir(parents=True, exist_ok=True)

    findings_list = findings if findings is not None else [_fixture_finding_dict()]

    run_data = {
        "engagement_id": ENGAGEMENT_ID,
        "scope": {
            "client": "bench-client",
            "engagement_id": ENGAGEMENT_ID,
        },
        "scanners_run": ["exploit", "verify-phase-03"],
        "findings": findings_list,
        "errors": [],
    }
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


@pytest.fixture
def client(tmp_path: Path):
    """Hermetic TestClient with the default fixture finding (one poc_step)."""
    _build_fixture_tree(tmp_path)
    cfg = _make_cfg(tmp_path)
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            yield c, tmp_path, cfg
    finally:
        app.dependency_overrides.clear()


def _reconstitute_finding_for_assertion(f_data: dict) -> Finding:
    """Mirror of the route's _reconstitute_finding helper, lifted into the
    test module so Test 14 can render the finding in-test for byte-identity
    comparison against the route's response."""
    fields = set(Finding.__dataclass_fields__.keys())
    payload = {k: v for k, v in f_data.items() if k in fields}
    if isinstance(payload.get("severity"), str):
        payload["severity"] = Severity.from_string(payload["severity"])
    if isinstance(payload.get("status"), str):
        try:
            payload["status"] = Status(payload["status"])
        except ValueError:
            payload["status"] = Status.NEW
    if isinstance(payload.get("evidence_state"), str):
        payload["evidence_state"] = EvidenceState.from_string(payload["evidence_state"])
    return Finding(**payload)


# ---- Tests --------------------------------------------------------------


def test_markdown_route_returns_text_markdown_content_type(client):
    """GET /findings/<run>/<fp>/markdown returns 200 with
    `text/markdown` Content-Type."""
    c, _, _ = client
    r = c.get(f"/findings/test-run.json/{FP}/markdown")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/markdown"), (
        f"expected text/markdown, got {r.headers.get('content-type')!r}"
    )


def test_markdown_route_body_contains_h1_narrative_headings(client):
    """Body contains the canonical H1-narrative heading set:
    # Proof of Concept, ## Title, ## Description, ### Reproduction,
    ## Impact, ## Attachments. Pins H1-narrative alignment via the route."""
    c, _, _ = client
    r = c.get(f"/findings/test-run.json/{FP}/markdown")
    assert r.status_code == 200
    body = r.text
    for heading in (
        "# Proof of Concept",
        "## Title",
        "## Description",
        "### Reproduction",
        "## Impact",
        "## Attachments",
    ):
        assert heading in body, f"missing heading {heading!r} in route body"


def test_markdown_route_body_walks_poc_steps_in_order(client):
    """The single fixture step's description AND command appear verbatim in
    the body, along with a `#### Probe 1` heading."""
    c, _, _ = client
    r = c.get(f"/findings/test-run.json/{FP}/markdown")
    assert r.status_code == 200
    body = r.text
    assert "#### Probe 1" in body, "missing #### Probe 1 heading"
    assert "Send the crafted request" in body, "step description missing"
    assert "curl 'https://target.example/search?q=<x>'" in body, "command missing"


def test_markdown_route_returns_400_on_bad_fingerprint(client):
    """Fingerprint must be 16 lowercase hex — 'notHexAtAll' fails the regex."""
    c, _, _ = client
    r = c.get("/findings/test-run.json/notHexAtAll/markdown")
    assert r.status_code == 400, (
        f"expected 400 on non-hex fingerprint, got {r.status_code}"
    )


def test_markdown_route_returns_404_on_unknown_fingerprint(client):
    """A valid 16-hex fingerprint that is NOT in the run JSON's findings list
    returns 404 (the run is loaded successfully; the finding just isn't in it)."""
    c, _, _ = client
    r = c.get(f"/findings/test-run.json/{FP_ABSENT}/markdown")
    assert r.status_code == 404, (
        f"expected 404 on unknown fingerprint, got {r.status_code}"
    )


def test_markdown_route_returns_404_on_unknown_run_file(client):
    """Nonexistent run filename returns 404 via the shared
    _resolve_run_filename helper's `is_file()` check."""
    c, _, _ = client
    r = c.get(f"/findings/no-such-run.json/{FP}/markdown")
    assert r.status_code == 404


def test_markdown_route_path_traversal_returns_400(client):
    """URL-encoded `../` in the run_filename param is rejected by the shared
    _resolve_run_filename helper. Accept 400 or 404 (FastAPI's path normalizer
    can fold `..` segments before the route sees them)."""
    c, _, _ = client
    r = c.get(f"/findings/{quote('../evil.json', safe='')}/{FP}/markdown")
    assert r.status_code in (400, 404), (
        f"expected 400/404 on path-traversal, got {r.status_code}"
    )


def test_markdown_route_handles_empty_poc_steps_with_fallback(tmp_path):
    """A finding with `poc_steps: []` still returns 200 — the renderer emits
    the explicit fallback line ('No automated reproduction available —
    manual investigation required.') so operators get context, not a 404."""
    _build_fixture_tree(
        tmp_path,
        findings=[_fixture_finding_dict(poc_steps=[])],
    )
    cfg = _make_cfg(tmp_path)
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}/markdown")
            assert r.status_code == 200, r.text
            body = r.text
            assert "No automated reproduction available" in body, (
                "missing fallback message for empty poc_steps"
            )
    finally:
        app.dependency_overrides.clear()


def test_detail_page_renders_copy_button_when_poc_steps_present(client):
    """The detail page renders the Copy button when the finding has a
    non-empty poc_steps list. The button has data-testid markers AND the
    literal 'Copy Reproduction Markdown' text. The dedicated section
    wrapper data-testid is also present."""
    c, _, _ = client
    r = c.get(f"/findings/test-run.json/{FP}")
    assert r.status_code == 200, r.text
    body = r.text
    assert 'data-testid="copy-reproduction-md-btn"' in body, (
        "missing button data-testid"
    )
    assert "Copy Reproduction Markdown" in body, (
        "missing button label"
    )
    assert 'data-testid="copy-reproduction-md-section"' in body, (
        "missing section wrapper data-testid"
    )


def test_detail_page_hides_copy_button_when_poc_steps_empty(tmp_path):
    """A finding with `poc_steps: []` MUST NOT render the Copy button — the
    `{% if finding and finding.get('poc_steps') %}` guard hides it. Test 10
    pins the conditional rendering invariant."""
    _build_fixture_tree(
        tmp_path,
        findings=[_fixture_finding_dict(poc_steps=[])],
    )
    cfg = _make_cfg(tmp_path)
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}")
            assert r.status_code == 200, r.text
            body = r.text
            assert 'data-testid="copy-reproduction-md-btn"' not in body, (
                "button rendered despite empty poc_steps (guard not honored)"
            )
            # Section wrapper must also be hidden.
            assert 'data-testid="copy-reproduction-md-section"' not in body, (
                "section wrapper rendered despite empty poc_steps"
            )
    finally:
        app.dependency_overrides.clear()


def test_detail_page_button_section_appears_after_header_section(client):
    """Pins the button-placement invariant: the Copy section sits AFTER the
    header section closes — not crowded inside the header flex container.

    Strategy: locate the index of both data-testid markers in the rendered
    HTML. The Copy section's data-testid must appear AFTER the header
    section's data-testid. Additionally, a closing </section> tag must
    appear between them (proving the header section closed before the Copy
    section opened — they are siblings, not nested)."""
    c, _, _ = client
    r = c.get(f"/findings/test-run.json/{FP}")
    assert r.status_code == 200, r.text
    body = r.text
    header_idx = body.find('data-testid="finding-poc-detail-panel"')
    copy_idx = body.find('data-testid="copy-reproduction-md-section"')
    assert header_idx >= 0, "header section data-testid not found"
    assert copy_idx >= 0, "copy section data-testid not found"
    assert copy_idx > header_idx, (
        f"copy section should appear after header section "
        f"(header_idx={header_idx}, copy_idx={copy_idx})"
    )
    # A </section> tag must appear between the header opening and the
    # copy section opening — proving they're siblings, not nested.
    between = body[header_idx:copy_idx]
    assert "</section>" in between, (
        "no </section> between header data-testid and copy section data-testid "
        "— the Copy section appears NESTED INSIDE the header section "
        "(violates the dedicated-section-after-header invariant)"
    )


def test_detail_page_button_data_url_points_to_markdown_route(client):
    """The button's `data-markdown-url` attribute resolves to a URL ending in
    `/findings/test-run.json/<FP>/markdown` — the route name correctly
    resolves to the path via Jinja's url_for."""
    c, _, _ = client
    r = c.get(f"/findings/test-run.json/{FP}")
    assert r.status_code == 200, r.text
    body = r.text
    expected_suffix = f"/findings/test-run.json/{FP}/markdown"
    assert expected_suffix in body, (
        f"button's data-markdown-url does not contain expected suffix "
        f"{expected_suffix!r}"
    )
    # Confirm the suffix is INSIDE a data-markdown-url attribute (not just
    # a stray href somewhere in the page).
    marker = f'data-markdown-url="'
    marker_idx = body.find(marker)
    assert marker_idx >= 0, "data-markdown-url attribute not found"
    # Read until the closing quote of the attribute.
    end_idx = body.find('"', marker_idx + len(marker))
    attr_value = body[marker_idx + len(marker) : end_idx]
    assert attr_value.endswith(expected_suffix), (
        f"data-markdown-url attribute value {attr_value!r} does not end with "
        f"{expected_suffix!r}"
    )


def test_markdown_route_round_trips_finding_via_finding_constructor(tmp_path):
    """The run JSON's finding dict includes `bundle_exists: True` (added by
    Plan 03-06's _annotate_findings_with_bundle_exists, would normally be
    transient but operators sometimes re-save run JSON via the dashboard)
    AND `severity` stored as the string 'high'. The route's
    `_reconstitute_finding` helper must strip the extra field and coerce the
    string severity into a Severity enum before calling Finding(**payload).

    If the sanitizer is missing OR the coercion is missing, Finding(**payload)
    raises TypeError or ValueError and the route returns 500.
    """
    finding_dict = _fixture_finding_dict(
        extras={
            "bundle_exists": True,
            "status": "new",
        },
    )
    _build_fixture_tree(tmp_path, findings=[finding_dict])
    cfg = _make_cfg(tmp_path)
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}/markdown")
            assert r.status_code == 200, (
                f"reconstitution failed for finding with bundle_exists + "
                f"stringly-typed severity: status={r.status_code}, body={r.text}"
            )
            # The body should contain the H1-narrative heading set — proves
            # render_poc_section ran successfully.
            assert "# Proof of Concept" in r.text
    finally:
        app.dependency_overrides.clear()


def test_markdown_route_output_byte_identical_to_render_poc_section(tmp_path):
    """POC-08 cross-renderer load-bearing assertion: the route's response
    body must be BYTE-IDENTICAL to what `render_poc_section(finding)` returns
    when called directly with a Finding reconstituted from the same run JSON
    dict. This is the dashboard <-> markdown-renderer parity arm of POC-08
    (the 4th and final cross-renderer arm; the others are pdf-structural in
    04-03 and markdown==vault in 04-04).

    If the route ever transforms the renderer output (HTML-encoded the angle
    brackets, normalized newlines, added a wrapper banner, etc.) this test
    fails. The contract is verbatim passthrough — operators paste the
    clipboard contents directly into HackerOne's report form, which expects
    canonical Markdown.
    """
    finding_dict = _fixture_finding_dict(
        poc_steps=[
            _fixture_step_dict(
                step_number=1,
                description="First step description",
                command="curl -sS 'https://target.example/probe?q=<x>'",
                expected_output="HTTP/1.1 200 OK",
                screenshot_path="/tmp/shot1.png",
            ),
            _fixture_step_dict(
                step_number=2,
                description="Second step description",
                command="python3 -c \"print('payload')\"",
                expected_output="payload",
                screenshot_path=None,
            ),
        ],
        extras={
            "references": ["https://owasp.org/xss"],
            "impact": "Account takeover possible via stolen session.",
        },
    )
    _build_fixture_tree(tmp_path, findings=[finding_dict])
    cfg = _make_cfg(tmp_path)
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP}/markdown")
            assert r.status_code == 200, r.text
            route_body = r.text

            # Render the same finding directly in-test using the renderer
            # the route is contracted to call.
            finding_obj = _reconstitute_finding_for_assertion(finding_dict)
            expected_body = render_poc_section(finding_obj)

            assert route_body == expected_body, (
                "BYTE-IDENTITY VIOLATION: route response body differs from "
                "render_poc_section output. The route must return the renderer "
                "output verbatim — no wrapping, no transformation. Diff:\n"
                f"--- route_body ---\n{route_body!r}\n"
                f"--- expected ---\n{expected_body!r}"
            )
    finally:
        app.dependency_overrides.clear()
