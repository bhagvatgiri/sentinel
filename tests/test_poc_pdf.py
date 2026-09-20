"""POC-04 + POC-08 (PDF surface) — PDFReporter._render_poc_section.

Hermetic — every PDF generation goes to tmp_path. Zero live network, zero
LLM (Ollama passed as None). pypdf is the text-extraction tool; Pillow
creates real 1x1 PNG fixtures (NOT hand-crafted byte sequences) for the
embedded-image test.

This module pins the PDF Reproduction tab's structural contract:

  - Findings WITH poc_steps get a 'Reproduction' H2 heading + numbered
    Step blocks (description / monospace command / 'Expected output:' /
    monospace expected_output / optional embedded screenshot / Spacer).
  - Findings WITHOUT poc_steps get the explicit
    'No automated reproduction available' fallback line under the
    'Reproduction' heading — backward-compat with legacy run JSONs.
  - Step content appears in the rendered PDF in step_number order
    (Test 10 — the POC-08 PDF-side structural assertion).

Test 10 does NOT import sentinel.reporting.poc_markdown. The byte-identity
cross-renderer parity test (markdown vs. Obsidian-vault body) is owned by
Plan 04-04; the dashboard==markdown byte-identity test is owned by
Plan 04-05. This plan's contract stands on its own via pypdf text
extraction.
"""

from __future__ import annotations

import os
import textwrap
import urllib.request
from pathlib import Path

import pytest

from sentinel.core.findings import Finding, PocStep, Severity
from sentinel.core.orchestrator import RunReport
from sentinel.core.scope import Scope


# ---------------------------------------------------------------------------
# Fixture helpers (mirrors tests/test_scope.py + tests/test_finding_poc_steps_field.py)
# ---------------------------------------------------------------------------


def _scope_yaml(tmp_path: Path) -> Path:
    """Write a minimal valid scope.yaml that Scope.load accepts."""
    import yaml
    from datetime import date, timedelta
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


def _build_report(tmp_path: Path, findings: list[Finding]) -> RunReport:
    scope = _make_scope(tmp_path)
    report = RunReport(scope=scope)
    report.findings = findings
    return report


def _extract_pdf_text(pdf_path: Path) -> str:
    from pypdf import PdfReader
    reader = PdfReader(str(pdf_path))
    parts = []
    for page in reader.pages:
        try:
            parts.append(page.extract_text() or "")
        except Exception:  # pragma: no cover - defensive
            parts.append("")
    return "\n".join(parts)


@pytest.fixture(autouse=True)
def _disable_pii_gate(monkeypatch):
    """The PII gate would mutate finding text fields; 'warn' policy is read-only."""
    monkeypatch.setenv("SENTINEL_PII_GATE_POLICY", "warn")


# ---------------------------------------------------------------------------
# Reproduction-section presence & fallback
# ---------------------------------------------------------------------------


def test_pdf_emits_reproduction_heading_when_steps_present(tmp_path):
    """A finding with PocSteps produces a PDF whose text contains 'Reproduction'."""
    from sentinel.reporting.pdf import PDFReporter

    finding = _make_finding(
        title="Reflected XSS in /search",
        description="The q parameter is reflected without escaping.",
        cwe="CWE-79",
        poc_steps=[
            PocStep(
                step_number=1,
                description="Send crafted request",
                command="curl 'https://target.example/search?q=<script>alert(1)</script>'",
                expected_output="<script>alert(1)</script>",
            ),
            PocStep(
                step_number=2,
                description="Confirm reflection",
                command="curl ... | grep -o '<script>alert(1)</script>'",
                expected_output="<script>alert(1)</script>",
            ),
        ],
    )
    report = _build_report(tmp_path, [finding])
    pdf_path = PDFReporter(tmp_path, ollama=None).write(report)

    assert pdf_path.is_file()
    assert pdf_path.stat().st_size > 0
    text = _extract_pdf_text(pdf_path)
    assert "Reproduction" in text


def test_pdf_emits_no_automated_reproduction_when_steps_empty(tmp_path):
    """Empty poc_steps -> explicit 'No automated reproduction available' fallback."""
    from sentinel.reporting.pdf import PDFReporter

    finding = _make_finding(
        title="Missing security header",
        description="Strict-Transport-Security header absent.",
        severity=Severity.LOW,
        scanner="headers",
        poc_steps=[],
    )
    report = _build_report(tmp_path, [finding])
    pdf_path = PDFReporter(tmp_path, ollama=None).write(report)

    text = _extract_pdf_text(pdf_path)
    assert "No automated reproduction available" in text


# ---------------------------------------------------------------------------
# Per-step content presence
# ---------------------------------------------------------------------------


def test_pdf_includes_each_step_command(tmp_path):
    """Both PocStep commands appear (substring) in the extracted PDF text."""
    from sentinel.reporting.pdf import PDFReporter

    cmd1 = "curl -s https://target.example/foo"
    cmd2 = "curl -s https://target.example/bar"
    finding = _make_finding(
        poc_steps=[
            PocStep(step_number=1, description="Probe foo", command=cmd1, expected_output="ok-foo"),
            PocStep(step_number=2, description="Probe bar", command=cmd2, expected_output="ok-bar"),
        ],
    )
    report = _build_report(tmp_path, [finding])
    pdf_path = PDFReporter(tmp_path, ollama=None).write(report)

    text = _extract_pdf_text(pdf_path)
    # The text extractor may collapse whitespace; check tokens individually
    # for robustness rather than the full command string verbatim.
    for token in ["curl", "target.example/foo", "target.example/bar"]:
        assert token in text, f"Expected token {token!r} in extracted PDF text"


def test_pdf_includes_each_step_expected_output(tmp_path):
    """Both expected_output strings appear in extracted text."""
    from sentinel.reporting.pdf import PDFReporter

    finding = _make_finding(
        poc_steps=[
            PocStep(step_number=1, description="P1", command="curl A",
                    expected_output="MARKER_OUTPUT_ALPHA_1"),
            PocStep(step_number=2, description="P2", command="curl B",
                    expected_output="MARKER_OUTPUT_BRAVO_2"),
        ],
    )
    report = _build_report(tmp_path, [finding])
    pdf_path = PDFReporter(tmp_path, ollama=None).write(report)

    text = _extract_pdf_text(pdf_path)
    assert "MARKER_OUTPUT_ALPHA_1" in text
    assert "MARKER_OUTPUT_BRAVO_2" in text


def test_pdf_steps_appear_in_step_number_order(tmp_path):
    """Step 1 description precedes Step 2 description in extracted text order."""
    from sentinel.reporting.pdf import PDFReporter

    desc1 = "UNIQUE_STEP_ONE_DESCRIPTION_TOKEN"
    desc2 = "UNIQUE_STEP_TWO_DESCRIPTION_TOKEN"
    finding = _make_finding(
        poc_steps=[
            PocStep(step_number=1, description=desc1,
                    command="curl A", expected_output="oA"),
            PocStep(step_number=2, description=desc2,
                    command="curl B", expected_output="oB"),
        ],
    )
    report = _build_report(tmp_path, [finding])
    pdf_path = PDFReporter(tmp_path, ollama=None).write(report)

    text = _extract_pdf_text(pdf_path)
    idx1 = text.index(desc1)
    idx2 = text.index(desc2)
    assert idx1 < idx2, (
        f"step 1 description ({idx1}) should precede step 2 ({idx2}) "
        f"in extracted PDF text"
    )


# ---------------------------------------------------------------------------
# Backward-compat: findings WITHOUT poc_steps still render
# ---------------------------------------------------------------------------


def test_pdf_renders_for_finding_without_steps_no_crash(tmp_path):
    """Legacy finding (no poc_steps) renders cleanly — PDF is built, at least 1 page."""
    from sentinel.reporting.pdf import PDFReporter
    from pypdf import PdfReader

    finding = _make_finding(poc_steps=[])
    report = _build_report(tmp_path, [finding])

    pdf_path = PDFReporter(tmp_path, ollama=None).write(report)
    assert pdf_path.is_file()
    assert pdf_path.stat().st_size > 0
    reader = PdfReader(str(pdf_path))
    assert len(reader.pages) >= 1


# ---------------------------------------------------------------------------
# Screenshot handling — missing file + present file
# ---------------------------------------------------------------------------


def test_pdf_screenshot_missing_file_emits_fallback_text(tmp_path):
    """A PocStep pointing at a non-existent screenshot produces the fallback text."""
    from sentinel.reporting.pdf import PDFReporter

    finding = _make_finding(
        poc_steps=[
            PocStep(
                step_number=1,
                description="Send the probe",
                command="curl https://target.example/x",
                expected_output="200 OK",
                screenshot_path="/nonexistent/path/never-existed.png",
            ),
        ],
    )
    report = _build_report(tmp_path, [finding])
    pdf_path = PDFReporter(tmp_path, ollama=None).write(report)

    text = _extract_pdf_text(pdf_path)
    assert "screenshot unavailable" in text


def test_pdf_screenshot_present_file_embeds_image(tmp_path):
    """A real PNG on disk gets embedded — pypdf sees an image on at least one page."""
    from sentinel.reporting.pdf import PDFReporter
    from pypdf import PdfReader
    from PIL import Image as PILImage

    screenshot_path = tmp_path / "screenshot.png"
    PILImage.new("RGB", (1, 1), (0, 0, 0)).save(screenshot_path)

    finding = _make_finding(
        poc_steps=[
            PocStep(
                step_number=1,
                description="Run with screenshot",
                command="curl https://target.example/y",
                expected_output="200 OK",
                screenshot_path=str(screenshot_path),
            ),
        ],
    )
    report = _build_report(tmp_path, [finding])
    pdf_path = PDFReporter(tmp_path, ollama=None).write(report)

    assert pdf_path.is_file()
    reader = PdfReader(str(pdf_path))
    image_count = 0
    for page in reader.pages:
        try:
            image_count += len(page.images)
        except Exception:  # pragma: no cover - defensive
            pass
    assert image_count >= 1, "Expected at least one embedded image in the PDF"


# ---------------------------------------------------------------------------
# Hermeticity
# ---------------------------------------------------------------------------


def test_pdf_render_is_hermetic_no_network(tmp_path, monkeypatch):
    """Monkeypatch urlopen to raise; PDFReporter.write still succeeds."""
    from sentinel.reporting.pdf import PDFReporter

    def _boom(*args, **kwargs):
        raise RuntimeError("Hermeticity violation — urlopen called during PDF render")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)

    finding = _make_finding(
        poc_steps=[
            PocStep(
                step_number=1,
                description="Probe",
                command="curl https://target.example/z",
                expected_output="200 OK",
            ),
        ],
    )
    report = _build_report(tmp_path, [finding])
    pdf_path = PDFReporter(tmp_path, ollama=None).write(report)
    assert pdf_path.is_file()
    assert pdf_path.stat().st_size > 0


# ---------------------------------------------------------------------------
# POC-08 PDF-side structural ordering — Test 10
# ---------------------------------------------------------------------------


def test_pdf_reproduction_section_contains_all_step_content_in_order(tmp_path):
    """POC-08 (PDF surface) — pins per-step content + ordering via pypdf.

    Two PocSteps with pairwise-distinct description / command / expected_output
    strings. The extracted PDF text must contain all six substrings AND their
    indices must be monotonically increasing in the order:
      step 1 description < step 1 command < step 1 expected_output
        < step 2 description < step 2 command < step 2 expected_output

    Does NOT import from sentinel.reporting.poc_markdown — the byte-identity
    cross-renderer assertion is owned by Plans 04-04 / 04-05.
    """
    from sentinel.reporting.pdf import PDFReporter

    desc1 = "DESCRIPTION_ALPHA_UNIQUE_TOKEN"
    cmd1 = "CMDALPHA_UNIQUE_TOKEN"
    out1 = "EXPECTED_ALPHA_UNIQUE_TOKEN"
    desc2 = "DESCRIPTION_BRAVO_UNIQUE_TOKEN"
    cmd2 = "CMDBRAVO_UNIQUE_TOKEN"
    out2 = "EXPECTED_BRAVO_UNIQUE_TOKEN"

    finding = _make_finding(
        title="Structural ordering finding",
        description="d",
        poc_steps=[
            PocStep(step_number=1, description=desc1, command=cmd1, expected_output=out1),
            PocStep(step_number=2, description=desc2, command=cmd2, expected_output=out2),
        ],
    )
    report = _build_report(tmp_path, [finding])
    pdf_path = PDFReporter(tmp_path, ollama=None).write(report)

    text = _extract_pdf_text(pdf_path)

    # 'Reproduction' H2 heading literal is present
    assert "Reproduction" in text

    # All 6 per-step substrings present
    for token in (desc1, cmd1, out1, desc2, cmd2, out2):
        assert token in text, f"missing token {token!r} in extracted PDF text"

    # Monotonically increasing indices
    indices = [text.index(t) for t in (desc1, cmd1, out1, desc2, cmd2, out2)]
    assert indices == sorted(indices), (
        f"step content ordering broken: indices={indices}, "
        "expected monotonically increasing "
        "(desc1 < cmd1 < out1 < desc2 < cmd2 < out2)"
    )
