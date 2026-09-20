"""POC-05 + POC-08 — Hermetic tests for ObsidianReporter per-finding reproduction notes.

Pins the per-engagement-vault behavior added by Plan 04-04:

  - `<engagement>/Findings/<fp>-reproduction.md` is written when a
    finding's `poc_steps` is non-empty.
  - The body of that note (after YAML frontmatter) is BYTE-FOR-BYTE
    identical to `sentinel.reporting.poc_markdown.render_poc_section(finding)`
    output. This is the load-bearing POC-08 cross-renderer byte-identity
    invariant (markdown <-> Obsidian-vault), MOVED to this plan from
    Plan 04-03 because the PDF plan no longer imports the markdown
    renderer; the Obsidian writer naturally owns this assertion because
    it WRITES the markdown render verbatim.
  - The main `<severity>-<fp>-<slug>.md` note gets a `## Reproduction`
    section spliced in BEFORE the `## References` section, containing
    the Obsidian wikilink `[[<fp>-reproduction|reproduction steps]]`.
  - Findings without `poc_steps` produce NEITHER a reproduction note NOR
    a Reproduction section in the main note (purely additive behavior).
  - Stale reproduction notes from prior runs are cleared on rerun
    (the existing `glob("*.md")` cleanup naturally covers them).

Hermetic: no network, no LLM. Test 8 monkeypatches `urllib.request.urlopen`
to raise; `write_report` still succeeds.

Source of truth for the byte-identity invariant: Plan 04-02's
`render_poc_section`. If a future refactor changes the markdown renderer
output, this file MUST stay in lockstep — the assertion catches drift.
"""

from __future__ import annotations

import urllib.request
from datetime import date, timedelta
from pathlib import Path

import pytest

from sentinel.core.findings import Finding, PocStep, Severity
from sentinel.core.orchestrator import RunReport
from sentinel.core.scope import Scope
from sentinel.reporting.obsidian import ObsidianReporter
from sentinel.reporting.poc_markdown import render_poc_section


# ---------------------------------------------------------------------------
# Fixture helpers (mirrors tests/test_poc_pdf.py + tests/test_scope.py)
# ---------------------------------------------------------------------------


def _scope_yaml(tmp_path: Path) -> Path:
    """Write a minimal valid scope.yaml that Scope.load accepts."""
    import yaml
    today = date.today()
    data = {
        "client": "bench",
        "engagement_id": "bench-test",
        "authorized_by": "tester@x.invalid",
        "valid_from": (today - timedelta(days=1)).isoformat(),
        "valid_until": (today + timedelta(days=30)).isoformat(),
        "targets": {
            "domains": ["target.example"],
        },
        "rate_limits": {"requests_per_second": 5},
    }
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def _make_scope(tmp_path: Path) -> Scope:
    return Scope.load(_scope_yaml(tmp_path))


def _make_finding(**overrides) -> Finding:
    base = dict(
        title="A finding",
        description="Some description.",
        severity=Severity.HIGH,
        scanner="exploit",
        target="https://target.example/",
    )
    base.update(overrides)
    return Finding(**base)


def _build_report(scope: Scope, findings: list[Finding]) -> RunReport:
    report = RunReport(scope=scope)
    report.findings = findings
    return report


def _strip_yaml_frontmatter(text: str) -> str:
    """Strip a leading `---\\n...\\n---\\n` YAML frontmatter block.

    Returns the remainder with any leading blank lines stripped so the
    body-after-frontmatter can be compared byte-for-byte with the output
    of `render_poc_section`.
    """
    if not text.startswith("---\n"):
        return text
    end_idx = text.find("\n---\n", 4)
    if end_idx == -1:
        return text
    return text[end_idx + len("\n---\n"):].lstrip("\n")


@pytest.fixture(autouse=True)
def _disable_pii_gate(monkeypatch):
    """The PII gate would mutate finding text fields; 'warn' policy is read-only.

    Mirrors the same fixture in tests/test_poc_pdf.py so the
    byte-identity assertions compare against the un-mutated Finding
    fields.
    """
    monkeypatch.setenv("SENTINEL_PII_GATE_POLICY", "warn")


# Canonical fixtures used across most tests.

_FINDING_WITH_STEPS_KW = dict(
    title="Reflected XSS in /search",
    description="The q parameter is reflected without escaping.",
    severity=Severity.HIGH,
    scanner="exploit",
    target="https://target.example/",
    location="/search",
    cwe="CWE-79",
    poc_steps=[
        PocStep(
            step_number=1,
            description="Send crafted request",
            command="curl 'https://target.example/search?q=<x>'",
            expected_output="<x>",
        ),
        PocStep(
            step_number=2,
            description="Observe reflection",
            command="curl 'https://target.example/search?q=<x>' | grep '<x>'",
            expected_output="<x>",
        ),
    ],
)

_FINDING_WITHOUT_STEPS_KW = dict(
    title="Missing security header",
    description="Strict-Transport-Security header absent.",
    severity=Severity.LOW,
    scanner="headers",
    target="https://target.example/",
    poc_steps=[],
)


def _findings_dir(engagement: Path) -> Path:
    return engagement / "Findings"


# ---------------------------------------------------------------------------
# Test 1: reproduction note is written when poc_steps is non-empty
# ---------------------------------------------------------------------------


def test_obsidian_writes_reproduction_note_when_steps_present(tmp_path):
    scope = _make_scope(tmp_path)
    finding = _make_finding(**_FINDING_WITH_STEPS_KW)
    report = _build_report(scope, [finding])

    vault = tmp_path / "vault"
    engagement = ObsidianReporter(vault).write_report(report)

    repro_path = _findings_dir(engagement) / f"{finding.fingerprint()}-reproduction.md"
    assert repro_path.is_file(), (
        f"Expected reproduction note at {repro_path}, "
        f"got: {list(_findings_dir(engagement).iterdir())}"
    )
    assert repro_path.stat().st_size > 0


# ---------------------------------------------------------------------------
# Test 2: no reproduction note when poc_steps is empty
# ---------------------------------------------------------------------------


def test_obsidian_omits_reproduction_note_when_steps_empty(tmp_path):
    scope = _make_scope(tmp_path)
    finding = _make_finding(**_FINDING_WITHOUT_STEPS_KW)
    report = _build_report(scope, [finding])

    vault = tmp_path / "vault"
    engagement = ObsidianReporter(vault).write_report(report)

    repro_path = _findings_dir(engagement) / f"{finding.fingerprint()}-reproduction.md"
    assert not repro_path.exists(), (
        f"Expected NO reproduction note at {repro_path} (poc_steps was empty), "
        f"but found one"
    )


# ---------------------------------------------------------------------------
# Test 3: reproduction note body equals render_poc_section byte-for-byte
# (POC-08 load-bearing markdown <-> Obsidian cross-renderer invariant)
# ---------------------------------------------------------------------------


def test_obsidian_reproduction_body_is_render_poc_section_output(tmp_path):
    scope = _make_scope(tmp_path)
    finding = _make_finding(**_FINDING_WITH_STEPS_KW)
    report = _build_report(scope, [finding])

    vault = tmp_path / "vault"
    engagement = ObsidianReporter(vault).write_report(report)

    repro_path = _findings_dir(engagement) / f"{finding.fingerprint()}-reproduction.md"
    raw_text = repro_path.read_text()
    body_after_frontmatter = _strip_yaml_frontmatter(raw_text)

    expected_md = render_poc_section(finding)
    assert body_after_frontmatter == expected_md, (
        "POC-08 byte-identity invariant violated: reproduction note body "
        "does NOT match render_poc_section output exactly.\n"
        f"--- on disk (after frontmatter) ---\n{body_after_frontmatter!r}\n"
        f"--- expected ---\n{expected_md!r}"
    )


# ---------------------------------------------------------------------------
# Test 4: reproduction note carries YAML frontmatter with required fields
# ---------------------------------------------------------------------------


def test_obsidian_reproduction_note_carries_yaml_frontmatter(tmp_path):
    scope = _make_scope(tmp_path)
    finding = _make_finding(**_FINDING_WITH_STEPS_KW)
    report = _build_report(scope, [finding])

    vault = tmp_path / "vault"
    engagement = ObsidianReporter(vault).write_report(report)

    repro_path = _findings_dir(engagement) / f"{finding.fingerprint()}-reproduction.md"
    raw = repro_path.read_text()

    assert raw.startswith("---\n"), "Reproduction note must start with YAML frontmatter delimiter"
    # End delimiter present
    assert "\n---\n" in raw[4:], "Reproduction note YAML frontmatter must be closed by `---`"

    # Required frontmatter fields
    assert f"client: {scope.client}" in raw
    assert f"engagement: {scope.engagement_id}" in raw
    assert f"fingerprint: {finding.fingerprint()}" in raw
    assert f"severity: {finding.severity.value}" in raw
    assert f"tags: [security, reproduction, severity/{finding.severity.value}]" in raw


# ---------------------------------------------------------------------------
# Test 5: main finding note links to reproduction note via wikilink
# ---------------------------------------------------------------------------


def test_obsidian_main_finding_note_links_to_reproduction(tmp_path):
    scope = _make_scope(tmp_path)
    finding = _make_finding(**_FINDING_WITH_STEPS_KW)
    report = _build_report(scope, [finding])

    vault = tmp_path / "vault"
    reporter = ObsidianReporter(vault)
    engagement = reporter.write_report(report)

    main_filename = reporter._finding_filename(finding)
    main_path = _findings_dir(engagement) / main_filename
    assert main_path.is_file(), f"Expected main finding note at {main_path}"

    main_body = main_path.read_text()
    wikilink_substr = f"[[{finding.fingerprint()}-reproduction"
    assert wikilink_substr in main_body, (
        f"Expected wikilink {wikilink_substr!r} in main finding note body.\n"
        f"--- body ---\n{main_body!r}"
    )
    # The Reproduction H2 must appear BEFORE the References H2 (splice
    # invariant). Both must be present.
    assert "## Reproduction" in main_body
    assert "## References" in main_body
    assert main_body.index("## Reproduction") < main_body.index("## References"), (
        "Reproduction section must be spliced BEFORE References section"
    )


# ---------------------------------------------------------------------------
# Test 6: main finding note without poc_steps has no Reproduction section
# ---------------------------------------------------------------------------


def test_obsidian_main_finding_note_without_steps_has_no_reproduction_section(tmp_path):
    scope = _make_scope(tmp_path)
    finding = _make_finding(**_FINDING_WITHOUT_STEPS_KW)
    report = _build_report(scope, [finding])

    vault = tmp_path / "vault"
    reporter = ObsidianReporter(vault)
    engagement = reporter.write_report(report)

    main_filename = reporter._finding_filename(finding)
    main_path = _findings_dir(engagement) / main_filename
    main_body = main_path.read_text()

    assert "## Reproduction" not in main_body, (
        "Main finding note must NOT contain '## Reproduction' when poc_steps is empty"
    )
    # And no wikilink either
    assert f"[[{finding.fingerprint()}-reproduction" not in main_body


# ---------------------------------------------------------------------------
# Test 7: stale reproduction notes from prior runs are cleared on rerun
# ---------------------------------------------------------------------------


def test_obsidian_stale_reproduction_notes_cleared_on_rerun(tmp_path):
    scope = _make_scope(tmp_path)
    vault = tmp_path / "vault"
    reporter = ObsidianReporter(vault)

    # Run 1 — finding A with steps
    finding_a = _make_finding(
        title="First-run finding A",
        description="A description.",
        severity=Severity.HIGH,
        scanner="exploit",
        target="https://target.example/",
        location="/a",
        poc_steps=[PocStep(step_number=1, description="probe a", command="curl A", expected_output="ok")],
    )
    engagement = reporter.write_report(_build_report(scope, [finding_a]))
    repro_a = _findings_dir(engagement) / f"{finding_a.fingerprint()}-reproduction.md"
    assert repro_a.is_file()

    # Run 2 — different finding B (different fingerprint), same engagement
    finding_b = _make_finding(
        title="Second-run finding B",
        description="B description.",
        severity=Severity.HIGH,
        scanner="exploit",
        target="https://target.example/",
        location="/b",
        poc_steps=[PocStep(step_number=1, description="probe b", command="curl B", expected_output="ok")],
    )
    # Pre-condition: fingerprints differ
    assert finding_a.fingerprint() != finding_b.fingerprint()
    reporter.write_report(_build_report(scope, [finding_b]))

    # finding_a's reproduction note must have been cleaned up
    assert not repro_a.exists(), (
        "Stale reproduction note from a prior run must be cleared on rerun"
    )
    repro_b = _findings_dir(engagement) / f"{finding_b.fingerprint()}-reproduction.md"
    assert repro_b.is_file()


# ---------------------------------------------------------------------------
# Test 8: rendering is hermetic — no network calls
# ---------------------------------------------------------------------------


def test_obsidian_render_is_hermetic_no_network(tmp_path, monkeypatch):
    def _boom(*a, **kw):
        raise RuntimeError("network blocked in hermetic test")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)

    scope = _make_scope(tmp_path)
    finding = _make_finding(**_FINDING_WITH_STEPS_KW)
    report = _build_report(scope, [finding])
    vault = tmp_path / "vault"

    # Must not raise
    engagement = ObsidianReporter(vault).write_report(report)
    assert engagement.is_dir()
    repro_path = _findings_dir(engagement) / f"{finding.fingerprint()}-reproduction.md"
    assert repro_path.is_file()


# ---------------------------------------------------------------------------
# Test 9: reproduction note filename uses fingerprint exactly
# ---------------------------------------------------------------------------


def test_obsidian_reproduction_note_filename_uses_fingerprint(tmp_path):
    scope = _make_scope(tmp_path)
    finding = _make_finding(**_FINDING_WITH_STEPS_KW)
    report = _build_report(scope, [finding])

    vault = tmp_path / "vault"
    reporter = ObsidianReporter(vault)
    engagement = reporter.write_report(report)

    # Filename contract: exactly `<fingerprint>-reproduction.md`
    fp = finding.fingerprint()
    expected_name = f"{fp}-reproduction.md"
    expected_path = _findings_dir(engagement) / expected_name
    assert expected_path.is_file(), (
        f"Expected reproduction note filename {expected_name!r}, "
        f"got: {[p.name for p in _findings_dir(engagement).iterdir()]}"
    )
    # Helper returns the same name
    assert reporter._reproduction_filename(finding) == expected_name
    # Fingerprint is 16 hex chars (per Finding.fingerprint)
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


# ---------------------------------------------------------------------------
# Test 10: POC-08 cross-renderer byte-identity — call render_poc_section
# directly in the test (not via the writer) and assert equality with what
# the writer persisted to disk. This is the load-bearing markdown <-> vault
# invariant moved from Plan 04-03.
# ---------------------------------------------------------------------------


def test_obsidian_reproduction_structurally_matches_markdown_renderer(tmp_path):
    """POC-08 cross-renderer byte-identity (markdown <-> Obsidian-vault body).

    Build a Finding, render via render_poc_section DIRECTLY in the test
    (no Obsidian indirection), then call write_report, read the
    reproduction note off disk, strip the YAML frontmatter, and assert
    byte-for-byte equality with the markdown render.

    This pins the load-bearing invariant: what the vault stores is exactly
    what render_poc_section produces, which is exactly what the operator pastes
    into HackerOne. Any drift between the two renderers will fail this test.
    """
    scope = _make_scope(tmp_path)
    # Build a finding that exercises many code paths in render_poc_section:
    # multiple steps, screenshot, expected outputs, CWE, references, raw
    # combined_attack_url + affected_storefronts + source_ip + probe_timestamps,
    # impact field, additional_info — i.e. a near-maximal renderer surface.
    finding = _make_finding(
        title="OpenID returnUrl injection",
        description="The returnUrl parameter is not validated.",
        severity=Severity.HIGH,
        scanner="exploit",
        target="https://target.example/",
        location="/auth/openid",
        cwe="CWE-601",
        references=["https://example.invalid/cwe-601", "https://example.invalid/openid-spec"],
        impact="Open redirect chain into phishing endpoints, account takeover risk.",
        raw={
            "combined_attack_url": "https://target.example/auth/openid?returnUrl=https://evil.example/",
            "affected_storefronts": ["us-store", "uk-store"],
            "source_ip": "203.0.113.42",
            "probe_timestamps": "2026-XX-XXT12:00:00Z",
            "additional_info": "Observed across two storefronts.",
        },
        poc_steps=[
            PocStep(
                step_number=1,
                description="Send crafted redirect probe",
                command="curl -s 'https://target.example/auth/openid?returnUrl=https://evil.example/'",
                expected_output="Location: https://evil.example/",
                screenshot_path="/tmp/screenshots/openid-redirect.png",
            ),
            PocStep(
                step_number=2,
                description="Confirm 302 with attacker host",
                command="curl -sI 'https://target.example/auth/openid?returnUrl=https://evil.example/' | grep -i location",
                expected_output="location: https://evil.example/",
            ),
        ],
    )

    # Render in-test FIRST (before write_report mutates anything; PII gate
    # is disabled by the autouse fixture, but render in-test first is the
    # defensive ordering).
    expected_md = render_poc_section(finding)

    report = _build_report(scope, [finding])
    vault = tmp_path / "vault"
    engagement = ObsidianReporter(vault).write_report(report)

    repro_path = _findings_dir(engagement) / f"{finding.fingerprint()}-reproduction.md"
    raw_text = repro_path.read_text()
    body_after_frontmatter = _strip_yaml_frontmatter(raw_text)

    assert body_after_frontmatter == expected_md, (
        "POC-08 markdown <-> Obsidian byte-identity invariant violated."
    )
