"""VERIFY-07 — `/findings/<run_filename>/<fingerprint>` PoC bundle dashboard route.

Pins the contract that:

1.  The new `finding_poc_detail` route reads the evidence bundle on disk at
    `workspaces/<engagement_id>/verification/<fingerprint>/` and renders the
    PoC command, stdout/stderr/exit_code, optional refusal text, and the
    audit-log rationale extracted from the matching `poc_run_completed` event.
2.  The new `finding_poc_screenshot` route serves `screenshot.png` via
    `FileResponse` with `Content-Type: image/png` when present, and 404 when
    absent. Screenshots are NOT base64-encoded into the detail HTML — they
    are referenced via a dedicated URL so 1MB-class PNGs don't bloat the
    page render path.
3.  Path-traversal safety is enforced via the existing `_resolve_run_filename`
    helper for the run_filename param AND a new `_FINGERPRINT_RE` regex for
    the fingerprint param. Symlinks that escape the workspaces dir are
    rejected via `Path.resolve().relative_to(...)`.
4.  Stdout content containing HTML special characters (`<script>...`) is
    HTML-escaped via Jinja's autoescape before reaching the operator's
    browser — XSS in the dashboard surface is prevented even when the PoC
    stdout is hostile.
5.  When the evidence bundle directory does NOT exist (e.g. the verify phase
    didn't run for this finding), the route returns HTTP 200 with a
    `bundle_missing` flag rendered in the template — operators get a
    "no PoC bundle yet" message rather than a 404 (the finding exists; only
    the bundle is missing).
6.  The existing `/findings/<run_filename>` listing page is enhanced — each
    finding row gets an evidence_state chip AND a "View PoC" link when the
    bundle exists. Operators spot at-a-glance which findings ran through
    the verify phase.

The fixture builds a hermetic `tmp_path / workspaces / <eng> / verification`
tree so no test touches the real `workspaces/` dir on disk. The TestClient is
wired via `app.dependency_overrides[get_config] = lambda: cfg` so no test
touches the operator's `~/.sentinel/ui-config.json` either.

Runs offline, no network, no Claude SDK, no Ollama, no Chroma.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from sentinel.web.app import create_app
from sentinel.web.deps import get_config
from sentinel.ui.state import UIConfig


# ---- Fixture helpers ----------------------------------------------------


# Synthetic 16-hex fingerprints for the test findings.
FP_VERIFIED = "aaaaaaaaaaaaaaaa"
FP_NO_BUNDLE = "bbbbbbbbbbbbbbbb"
FP_REFUSED = "cccccccccccccccc"
ENGAGEMENT_ID = "bench-test"

# Minimal valid PNG (8-byte signature + 8 zero bytes — not a renderable image,
# but the Content-Type + first 8 bytes are what the test asserts on).
_PNG_HEADER = b"\x89PNG\r\n\x1a\n"
_PNG_FIXTURE_BYTES = _PNG_HEADER + b"\x00" * 8


def _write_audit_entry(
    audit_path: Path,
    *,
    event: str,
    payload: dict,
    prev_hash: str = "GENESIS",
) -> str:
    """Append a single hash-chained JSONL entry. Returns the new this_hash.

    Mirrors the contract of `sentinel.core.scope.AuditLog.write` without
    invoking the class (the route reads JSONL directly; it does not depend on
    AuditLog's instance API).
    """
    ts = datetime.now(timezone.utc).isoformat()
    digest_input = f"{prev_hash}|{ts}|{event}|{json.dumps(payload, sort_keys=True)}"
    this_hash = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
    entry = {
        "ts": ts,
        "event": event,
        "prev_hash": prev_hash,
        "payload": payload,
        "this_hash": this_hash,
    }
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return this_hash


def _build_fixture_tree(
    tmp_path: Path,
    *,
    write_bundle: bool = True,
    write_screenshot: bool = False,
    write_refusal: bool = False,
    stdout_content: str = "HTTP/1.1 200 OK\nbody contents here\n",
    write_audit: bool = True,
    rationale: str = "PoC executed cleanly; expected output regex matched.",
    extra_findings: list[dict] | None = None,
) -> Path:
    """Build a hermetic tmp_path tree with a run JSON, optional verification
    bundle, and an audit log entry. Returns the tmp_path itself.
    """
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    workspaces_dir = tmp_path / "workspaces"
    workspaces_dir.mkdir(parents=True, exist_ok=True)

    # Findings list. FP_VERIFIED is the populated bundle (or absent if write_bundle=False).
    findings_list = [
        {
            "title": "Reflected XSS in search query",
            "description": "Search reflects the q param unescaped.",
            "severity": "high",
            "scanner": "exploit",
            "target": "https://bench-test.example/",
            "location": "/search",
            "fingerprint": FP_VERIFIED,
            "evidence_state": "verified",
        },
        {
            "title": "Missing rate limit on /login",
            "description": "Login endpoint accepts unlimited requests.",
            "severity": "medium",
            "scanner": "exploit",
            "target": "https://bench-test.example/",
            "location": "/login",
            "fingerprint": FP_NO_BUNDLE,
            "evidence_state": "pending",
        },
    ]
    if extra_findings:
        findings_list.extend(extra_findings)

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

    # Evidence bundle for FP_VERIFIED.
    if write_bundle:
        bundle = workspaces_dir / ENGAGEMENT_ID / "verification" / FP_VERIFIED
        bundle.mkdir(parents=True, exist_ok=True)
        if not write_refusal:
            (bundle / "poc.sh").write_text(
                "#!/bin/sh\n"
                "curl -s 'https://bench-test.example/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' | head -20\n"
            )
            (bundle / "stdout.log").write_text(stdout_content)
            (bundle / "stderr.log").write_text("")
            (bundle / "exit_code.txt").write_text("0\n")
        else:
            (bundle / "refusal.txt").write_text(
                "REFUSED: classifier flagged destructive verb 'DROP TABLE'.\n"
                "Manual verification required.\n"
            )
        if write_screenshot:
            (bundle / "screenshot.png").write_bytes(_PNG_FIXTURE_BYTES)

    # Audit log entry for FP_VERIFIED.
    if write_audit and write_bundle:
        audit_path = workspaces_dir / ENGAGEMENT_ID / f".audit-{ENGAGEMENT_ID}.jsonl"
        _write_audit_entry(
            audit_path,
            event="poc_run_started",
            payload={
                "engagement_id": ENGAGEMENT_ID,
                "finding_fingerprint": FP_VERIFIED,
                "language": "shell",
                "command_truncated_512": "curl -s https://...",
                "evidence_bundle_path": str(
                    workspaces_dir / ENGAGEMENT_ID / "verification" / FP_VERIFIED
                ),
            },
        )
        _write_audit_entry(
            audit_path,
            event="poc_run_completed",
            payload={
                "engagement_id": ENGAGEMENT_ID,
                "finding_fingerprint": FP_VERIFIED,
                "evidence_state": "manual-required" if write_refusal else "verified",
                "rationale": rationale,
                "exit_code": 0,
                "duration_sec": 1.23,
                "expected_output_matched": True,
                "evidence_bundle_path": str(
                    workspaces_dir / ENGAGEMENT_ID / "verification" / FP_VERIFIED
                ),
                "destructive_pattern": "sql_drop_table" if write_refusal else None,
                "out_of_scope_url": None,
            },
        )

    return tmp_path


@pytest.fixture
def client(tmp_path: Path):
    """Hermetic TestClient. `get_config` is overridden so no loader touches
    the operator's real filesystem. The fixture populates the bundle by default;
    individual tests rebuild the tree via `_build_fixture_tree` with overrides
    when they need the bundle-missing / refusal / screenshot variants.
    """
    _build_fixture_tree(tmp_path, write_bundle=True, write_screenshot=False)
    cfg = UIConfig(
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
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            yield c, tmp_path, cfg
    finally:
        app.dependency_overrides.clear()


# ---- Tests --------------------------------------------------------------


def test_finding_poc_detail_renders_when_bundle_exists(client):
    """GET /findings/<run>/<fp> with a populated bundle returns 200 + HTML
    containing the PoC command text, stdout content, and an evidence_state
    chip. The chip class matches the FROZEN mapping (verified -> chip-ok)."""
    c, tmp_path, cfg = client
    r = c.get(f"/findings/test-run.json/{FP_VERIFIED}")
    assert r.status_code == 200, r.text
    body = r.text
    # Main panel testid present.
    assert 'data-testid="finding-poc-detail-panel"' in body
    # PoC command from poc.sh is rendered.
    assert "curl -s" in body
    # Stdout content is rendered.
    assert "HTTP/1.1 200 OK" in body
    # Exit code present.
    assert "0" in body  # exit_code.txt content
    # Evidence chip uses the FROZEN class for VERIFIED.
    assert "chip-ok" in body


def test_finding_poc_detail_bundle_missing_returns_200_with_flag(client):
    """When the verification bundle dir doesn't exist for the fingerprint,
    the route returns HTTP 200 (NOT 404) with a friendly missing-bundle
    message and the chip still rendered from the finding's evidence_state."""
    c, tmp_path, cfg = client
    # FP_NO_BUNDLE has no verification dir.
    r = c.get(f"/findings/test-run.json/{FP_NO_BUNDLE}")
    assert r.status_code == 200, r.text
    body = r.text.lower()
    # Some signal that the bundle isn't present.
    assert (
        "no poc bundle" in body
        or "bundle_missing" in body
        or "no verification bundle" in body
        or "bundle missing" in body
    ), "missing-bundle message not rendered"


def test_finding_poc_detail_rejects_non_hex_fingerprint(client):
    """Fingerprint must be 16 lowercase hex chars — 'z' is not hex."""
    c, _, _ = client
    r = c.get("/findings/test-run.json/zzzzzzzzzzzzzzzz")
    assert r.status_code == 400
    assert "fingerprint" in r.text.lower()


def test_finding_poc_detail_rejects_dotdot_in_run_filename(client):
    """The existing _resolve_run_filename helper rejects `..` segments. The
    URL-encoded `..%2F` should be rejected with HTTP 400 (or 404, depending
    on how the routing pipeline normalizes the param)."""
    c, _, _ = client
    # `..%2F` decodes to `../` — must be rejected (existing parent-route
    # helper raises HTTPException 400 on `/` or `..` in run_filename).
    r = c.get(f"/findings/{quote('../run.json', safe='')}/{FP_VERIFIED}")
    assert r.status_code in (400, 404), f"expected 400/404, got {r.status_code}"


def test_finding_poc_detail_rejects_short_fingerprint(client):
    """3-char fingerprint fails the 16-hex regex."""
    c, _, _ = client
    r = c.get("/findings/test-run.json/abc")
    # `abc` is 3 chars; FastAPI matches the path param then the regex rejects.
    # Could be 400 (regex rejection) or 404 (FastAPI route not matched).
    assert r.status_code in (400, 404)


def test_finding_poc_screenshot_route_serves_png_with_correct_content_type(client):
    """The dedicated screenshot route returns 200 + image/png Content-Type
    when the file exists, and the file bytes flow through unmodified. When
    the file is absent, the route returns 404."""
    c, tmp_path, cfg = client
    # First: no screenshot present → 404.
    r = c.get(f"/findings/test-run.json/{FP_VERIFIED}/screenshot.png")
    assert r.status_code == 404

    # Now write the screenshot.
    screenshot = (
        tmp_path
        / "workspaces"
        / ENGAGEMENT_ID
        / "verification"
        / FP_VERIFIED
        / "screenshot.png"
    )
    screenshot.write_bytes(_PNG_FIXTURE_BYTES)

    r = c.get(f"/findings/test-run.json/{FP_VERIFIED}/screenshot.png")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("image/png")
    # PNG byte-prefix flows through (file bytes, not base64).
    assert r.content[:8] == _PNG_HEADER


def test_finding_poc_detail_renders_refusal_text_when_classifier_short_circuited(
    tmp_path,
):
    """When the bundle has refusal.txt (destructive classifier short-circuit),
    the detail route renders the refusal text and the chip shows the
    MANUAL_REQUIRED class (chip-medium per the FROZEN mapping)."""
    _build_fixture_tree(tmp_path, write_bundle=True, write_refusal=True)
    cfg = UIConfig(
        vault_path=str(tmp_path / "vault"),
        corpus_dir=str(tmp_path / "corpus"),
        scopes_dir=str(tmp_path / "scopes"),
        runs_dir=str(tmp_path / "runs"),
        workspaces_dir=str(tmp_path / "workspaces"),
        project_dir=str(tmp_path),
    )
    # The fixture writes evidence_state="verified" on the finding by default;
    # for the refusal branch, the audit-log entry carries
    # evidence_state="manual-required" and the route should reflect THAT in
    # the chip class. Patch the run JSON's finding to manual-required so the
    # chip is unambiguous (the route reads the finding's field, not the audit
    # entry — see the route's `matching_finding.evidence_state` path).
    runs_dir = tmp_path / "runs"
    run_path = runs_dir / "test-run.json"
    run_data = json.loads(run_path.read_text())
    for f in run_data["findings"]:
        if f["fingerprint"] == FP_VERIFIED:
            f["evidence_state"] = "manual-required"
    run_path.write_text(json.dumps(run_data, indent=2))

    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP_VERIFIED}")
            assert r.status_code == 200, r.text
            body = r.text
            assert "REFUSED" in body or "classifier flagged" in body.lower()
            assert "chip-medium" in body
    finally:
        app.dependency_overrides.clear()


def test_finding_poc_detail_escapes_stdout_containing_html(tmp_path):
    """When stdout.log contains `<script>...</script>`, the rendered HTML
    must escape it (no raw `<script>` substring in the body). XSS prevention
    in the dashboard surface."""
    payload = "<script>alert('xss-via-poc-stdout')</script>"
    _build_fixture_tree(tmp_path, stdout_content=payload)
    cfg = UIConfig(
        vault_path=str(tmp_path / "vault"),
        corpus_dir=str(tmp_path / "corpus"),
        scopes_dir=str(tmp_path / "scopes"),
        runs_dir=str(tmp_path / "runs"),
        workspaces_dir=str(tmp_path / "workspaces"),
        project_dir=str(tmp_path),
    )
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP_VERIFIED}")
            assert r.status_code == 200
            body = r.text
            # Escaped form present.
            assert "&lt;script&gt;" in body or "&lt;script" in body
            # Literal `<script>alert(` substring MUST NOT appear (XSS).
            assert "<script>alert(" not in body
    finally:
        app.dependency_overrides.clear()


def test_finding_poc_detail_reads_audit_event_rationale(tmp_path):
    """When a poc_run_completed audit event matches the fingerprint, its
    `rationale` string appears in the rendered HTML."""
    custom_rationale = (
        "PoC executed cleanly; expected output regex 'OK.*body' matched."
    )
    _build_fixture_tree(tmp_path, rationale=custom_rationale)
    cfg = UIConfig(
        vault_path=str(tmp_path / "vault"),
        corpus_dir=str(tmp_path / "corpus"),
        scopes_dir=str(tmp_path / "scopes"),
        runs_dir=str(tmp_path / "runs"),
        workspaces_dir=str(tmp_path / "workspaces"),
        project_dir=str(tmp_path),
    )
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP_VERIFIED}")
            assert r.status_code == 200, r.text
            body = r.text
            assert "PoC executed cleanly" in body
            # At least part of the regex token from the rationale is preserved.
            assert "matched" in body
    finally:
        app.dependency_overrides.clear()


def test_findings_listing_template_renders_evidence_state_chip_per_row(client):
    """The parent /findings/<run> listing now shows an evidence_state chip
    per finding row. FP_VERIFIED has evidence_state='verified' -> chip-ok;
    FP_NO_BUNDLE has evidence_state='pending' -> chip-info (per FROZEN map)."""
    c, _, _ = client
    r = c.get("/findings/test-run.json")
    assert r.status_code == 200, r.text
    body = r.text
    # At least one chip-ok (for FP_VERIFIED) is present in the listing.
    assert "chip-ok" in body
    # And at least one chip-info or chip-low (for FP_NO_BUNDLE's pending).
    assert "chip-info" in body or "chip-low" in body


def test_findings_listing_renders_view_poc_link_only_when_bundle_exists(client):
    """FP_VERIFIED has a bundle on disk -> "View PoC" link in its row.
    FP_NO_BUNDLE has no bundle -> no link for that row."""
    c, _, _ = client
    r = c.get("/findings/test-run.json")
    assert r.status_code == 200, r.text
    body = r.text
    # The View PoC link references FP_VERIFIED's fingerprint.
    assert FP_VERIFIED in body
    assert "View PoC" in body or "view poc" in body.lower()
    # The link target must include the fingerprint of FP_VERIFIED.
    # Both should NOT be linked equally — assert the link for FP_VERIFIED's
    # URL is present and the URL for FP_NO_BUNDLE's bundle-detail is NOT linked.
    assert f"/findings/test-run.json/{FP_VERIFIED}" in body
    # FP_NO_BUNDLE's fingerprint appears in the row metadata BUT the bundle
    # link URL must NOT appear (no `/findings/test-run.json/<FP_NO_BUNDLE>"`
    # with the View PoC anchor wrapping it).
    # We check by asserting that the substring "View PoC" associated with
    # FP_NO_BUNDLE's URL is not present.
    link_for_no_bundle = f'href="/findings/test-run.json/{FP_NO_BUNDLE}"'
    assert link_for_no_bundle not in body, (
        f"FP_NO_BUNDLE has no bundle on disk but got a View PoC link: {link_for_no_bundle}"
    )


@pytest.mark.skipif(sys.platform.startswith("win"), reason="symlink behavior differs on Windows")
def test_finding_poc_detail_path_traversal_via_symlink_rejected(tmp_path):
    """When a symlink at verification/<fp> points outside workspaces dir,
    the route rejects with HTTP 400 via the `is_relative_to` check.

    This is the T-03-06-07 mitigation — even though the fingerprint passes
    the hex regex and the run_filename passes the existing helper, a symlink
    at the bundle path could otherwise let the route serve files from
    outside the workspaces tree.
    """
    _build_fixture_tree(tmp_path, write_bundle=False)
    # Use a 16-hex fingerprint that exists in the run JSON, but make
    # verification/<fp> a symlink to a directory outside workspaces.
    escape_target = tmp_path / "escape-target"
    escape_target.mkdir()
    # Put a stdout.log there so the route would happily render it if the
    # traversal check were missing.
    (escape_target / "stdout.log").write_text("escaped content")
    (escape_target / "poc.sh").write_text("# escaped")
    (escape_target / "exit_code.txt").write_text("0\n")
    (escape_target / "stderr.log").write_text("")

    verification_root = tmp_path / "workspaces" / ENGAGEMENT_ID / "verification"
    verification_root.mkdir(parents=True, exist_ok=True)
    sym = verification_root / FP_VERIFIED
    try:
        os.symlink(str(escape_target), str(sym), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported in this filesystem")

    cfg = UIConfig(
        vault_path=str(tmp_path / "vault"),
        corpus_dir=str(tmp_path / "corpus"),
        scopes_dir=str(tmp_path / "scopes"),
        runs_dir=str(tmp_path / "runs"),
        workspaces_dir=str(tmp_path / "workspaces"),
        project_dir=str(tmp_path),
    )
    app = create_app()
    app.dependency_overrides[get_config] = lambda: cfg
    try:
        with TestClient(app) as c:
            r = c.get(f"/findings/test-run.json/{FP_VERIFIED}")
            assert r.status_code == 400, (
                f"expected 400 on symlink escape, got {r.status_code}: {r.text}"
            )
    finally:
        app.dependency_overrides.clear()
