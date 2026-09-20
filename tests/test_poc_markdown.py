"""POC-03 + POC-06 — Hermetic tests for sentinel.reporting.poc_markdown.

Pins the H1-narrative-aligned Markdown renderer that turns a Finding +
its poc_steps into the exact heading hierarchy the operator pastes into
HackerOne. Source of truth for the structure (Test 2 / POC-06) is

    workspaces/2026-XX-XX-ExampleStore-bbp/deliverables/h1-submissions/01-openid-returnurl-injection.md

The 25 tests below cover:

1.  Non-empty string output for a minimal finding with one step.
2.  POC-06 STRUCTURAL ASSERTION: H1 + H2 heading hierarchy
    (# Proof of Concept, ## Title, ## Description, ## Impact, ## Attachments)
    plus ### Reproduction nested under Description and #### Probe N per step.
3.  Output starts with `# Proof of Concept`.
4.  Title section emits finding.title verbatim.
5.  Description section uses finding.description verbatim when set.
6.  Description auto-generates from target + severity + CWE when empty.
7.  Three steps produce three Probe headings in step_number order.
8.  curl command produces a ```bash code fence.
9.  python command produces a ```python code fence.
10. expected_output appears in a plain fence after `**Expected:**`.
11. Empty expected_output renders the `(no output captured)` placeholder.
12. screenshot_path renders as `![Screenshot](path)` within the probe block.
13. Empty poc_steps renders the fallback Reproduction message.
14. Impact includes description-or-impact AND **severity-uppercased**.
15. Impact includes `**CWE:** CWE-601` when cwe is set.
16. Attachments lists deduped screenshot paths as bullets, first-seen order.
17. Attachments renders `No attachments.` literal when no screenshots.
18. Minimal finding OMITS all optional sub-sections.
19. Combined Single-URL Attack rendered when raw['combined_attack_url'] set.
20. Affected Storefronts rendered when raw['affected_storefronts'] list set.
21. Supporting Material/References rendered when references non-empty.
22. NO `## Mitigation` heading EVER appears (anti-AI-slop boundary).
23. NO `## Summary` heading EVER appears (the operator's format does not use it).
24. Hermetic — monkeypatched urllib.urlopen raise does not affect render.
25. Round-trip: to_dict -> json -> Finding(**data) -> renders byte-for-byte
    identical output (pins Plan 04-01's serialization preserves enough
    information for the renderer).
"""

from __future__ import annotations

import json
import re
import urllib.request

import pytest

from sentinel.core.findings import Finding, PocStep, Severity


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def _make_finding(**overrides) -> Finding:
    """Minimal-required-kwargs Finding builder for renderer tests."""
    base = dict(
        title="Test Finding",
        description="Default desc.",
        severity=Severity.HIGH,
        scanner="test",
        target="https://t.example/",
    )
    base.update(overrides)
    return Finding(**base)


def _one_step(**overrides) -> PocStep:
    base = dict(
        step_number=1,
        description="Send the request with curl",
        command="curl -s https://t.example/",
        expected_output="HTTP/1.1 200 OK",
        screenshot_path=None,
    )
    base.update(overrides)
    return PocStep(**base)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_render_poc_section_returns_non_empty_string():
    """Test 1 — minimal Finding with one step renders a non-empty string."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(poc_steps=[_one_step()])
    md = render_poc_section(f)
    assert isinstance(md, str)
    assert md.strip() != ""


def test_render_poc_section_matches_h1_narrative_structure():
    """Test 2 (POC-06) — structural assertion against the operator's H1 reference.

    Pins:
      * exactly one `# Proof of Concept` H1
      * H2 order: Title -> Description -> Impact -> Attachments
      * `### Reproduction` under Description
      * one `#### Probe N — desc` per poc_step
    """
    from sentinel.reporting import render_poc_section

    f = _make_finding(
        poc_steps=[
            _one_step(step_number=1, description="First probe", command="curl https://a"),
            _one_step(step_number=2, description="Second probe", command="curl https://b"),
        ]
    )
    md = render_poc_section(f)

    # Top-level: exactly one "# Proof of Concept" line.
    h1_lines = re.findall(r'^# .+$', md, re.MULTILINE)
    assert h1_lines == ['# Proof of Concept'], (
        f"expected one '# Proof of Concept', got {h1_lines}"
    )

    # H2 sections appear in order Title -> Description -> Impact -> Attachments.
    h2_lines = re.findall(r'^## .+$', md, re.MULTILINE)
    assert h2_lines[:4] == [
        '## Title',
        '## Description',
        '## Impact',
        '## Attachments',
    ], f"expected Title/Description/Impact/Attachments order, got {h2_lines}"

    # ### Reproduction appears under Description.
    desc_idx = md.index('## Description')
    impact_idx = md.index('## Impact')
    repro_match = re.search(r'^### Reproduction$', md[desc_idx:impact_idx], re.MULTILINE)
    assert repro_match is not None, "### Reproduction must appear under Description"

    # One '#### Probe N — desc' line per poc_step.
    probe_lines = re.findall(r'^#### Probe \d+ — .+$', md, re.MULTILINE)
    assert len(probe_lines) == len(f.poc_steps), (
        f"expected {len(f.poc_steps)} probe headings, got {len(probe_lines)}"
    )


def test_render_poc_section_top_level_is_proof_of_concept_h1():
    """Test 3 — output starts with `# Proof of Concept` (after optional whitespace)."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(poc_steps=[_one_step()])
    md = render_poc_section(f)
    assert md.lstrip().startswith("# Proof of Concept")


def test_render_poc_section_title_section_emits_finding_title_verbatim():
    """Test 4 — `## Title` is followed by finding.title verbatim."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(title="My Unique Title 12345", poc_steps=[_one_step()])
    md = render_poc_section(f)
    # The title appears verbatim somewhere after the Title heading.
    title_idx = md.index("## Title")
    body_after_title = md[title_idx:md.index("## Description")]
    assert "My Unique Title 12345" in body_after_title


def test_render_poc_section_description_uses_finding_description_when_set():
    """Test 5 — Finding(description='Custom desc text.') renders verbatim."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(description="Custom desc text.", poc_steps=[_one_step()])
    md = render_poc_section(f)
    desc_idx = md.index("## Description")
    repro_idx = md.index("### Reproduction")
    desc_body = md[desc_idx:repro_idx]
    assert "Custom desc text." in desc_body


def test_render_poc_section_description_autogenerates_when_finding_description_empty():
    """Test 6 — Finding(description='') gets an auto-paragraph with target+severity+CWE."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(
        description="",
        target="https://target.example/path",
        cwe="CWE-601",
        poc_steps=[_one_step()],
    )
    md = render_poc_section(f)
    desc_idx = md.index("## Description")
    repro_idx = md.index("### Reproduction")
    desc_body = md[desc_idx:repro_idx]
    # Auto-paragraph mentions target + severity + CWE.
    assert "https://target.example/path" in desc_body
    assert "HIGH" in desc_body
    assert "CWE-601" in desc_body


def test_render_poc_section_probes_numbered_in_order():
    """Test 7 — three steps produce Probe 1/2/3 headings with the right descriptions."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(
        poc_steps=[
            _one_step(step_number=1, description="Alpha step", command="curl https://a"),
            _one_step(step_number=2, description="Beta step", command="curl https://b"),
            _one_step(step_number=3, description="Gamma step", command="curl https://c"),
        ]
    )
    md = render_poc_section(f)
    probe_headings = re.findall(r'^(#### Probe \d+ — .+)$', md, re.MULTILINE)
    assert probe_headings == [
        "#### Probe 1 — Alpha step",
        "#### Probe 2 — Beta step",
        "#### Probe 3 — Gamma step",
    ]


def test_render_poc_section_probe_command_emits_fenced_code_with_language_tag():
    """Test 8 — curl command emits a ```bash code fence."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(
        poc_steps=[_one_step(command="curl -s https://t.example/api")]
    )
    md = render_poc_section(f)
    assert "```bash" in md
    # And the curl command appears inside it (sanity).
    assert "curl -s https://t.example/api" in md


def test_render_poc_section_python_command_uses_python_language_tag():
    """Test 9 — python command emits a ```python code fence."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(
        poc_steps=[
            _one_step(command="python -m foo", description="Run the Python PoC")
        ]
    )
    md = render_poc_section(f)
    assert "```python" in md


def test_render_poc_section_probe_expected_output_appears_after_expected_line():
    """Test 10 — `**Expected:**` is followed by a fenced block containing the output."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(
        poc_steps=[_one_step(expected_output="UNIQUE_EXPECTED_TOKEN_12345")]
    )
    md = render_poc_section(f)
    # The literal `**Expected:**` must appear AND the expected output must
    # come AFTER it (not before).
    assert "**Expected:**" in md
    expected_idx = md.index("**Expected:**")
    token_idx = md.index("UNIQUE_EXPECTED_TOKEN_12345")
    assert token_idx > expected_idx, (
        "expected_output must appear after the **Expected:** line"
    )


def test_render_poc_section_empty_expected_output_renders_placeholder():
    """Test 11 — empty expected_output -> `(no output captured)` placeholder."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(poc_steps=[_one_step(expected_output="")])
    md = render_poc_section(f)
    assert "(no output captured)" in md


def test_render_poc_section_screenshot_emits_markdown_image_reference():
    """Test 12 — screenshot_path renders as `![Screenshot](path)`."""
    from sentinel.reporting import render_poc_section

    path = "/abs/path/screenshot.png"
    f = _make_finding(poc_steps=[_one_step(screenshot_path=path)])
    md = render_poc_section(f)
    assert f"![Screenshot]({path})" in md


def test_render_poc_section_no_steps_renders_fallback_message():
    """Test 13 — empty poc_steps -> fallback Reproduction message."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(poc_steps=[])
    md = render_poc_section(f)
    assert "### Reproduction" in md
    assert "No automated reproduction available" in md


def test_render_poc_section_impact_includes_description_or_impact_and_severity():
    """Test 14 — Impact section contains impact-or-description AND **SEVERITY**."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(
        description="A descriptive paragraph about the bug.",
        severity=Severity.CRITICAL,
        poc_steps=[_one_step()],
    )
    md = render_poc_section(f)
    impact_idx = md.index("## Impact")
    attach_idx = md.index("## Attachments")
    impact_body = md[impact_idx:attach_idx]
    # Either impact or description content present in Impact section.
    assert "A descriptive paragraph about the bug." in impact_body
    # Severity uppercased AND wrapped in bold markers.
    assert "**CRITICAL**" in impact_body


def test_render_poc_section_impact_uses_impact_field_when_set():
    """Test 14b — when Finding.impact is set, Impact section uses it (not description)."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(
        description="Generic description.",
        impact="Specific impact paragraph that should win.",
        poc_steps=[_one_step()],
    )
    md = render_poc_section(f)
    impact_idx = md.index("## Impact")
    attach_idx = md.index("## Attachments")
    impact_body = md[impact_idx:attach_idx]
    assert "Specific impact paragraph that should win." in impact_body


def test_render_poc_section_impact_includes_cwe_when_set():
    """Test 15 — finding.cwe='CWE-601' -> `**CWE:** CWE-601` literal in Impact."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(cwe="CWE-601", poc_steps=[_one_step()])
    md = render_poc_section(f)
    assert "**CWE:** CWE-601" in md


def test_render_poc_section_attachments_lists_deduped_screenshot_paths():
    """Test 16 — Attachments dedupes screenshot paths, preserves first-seen order."""
    from sentinel.reporting import render_poc_section

    path_a = "/abs/screenshot-A.png"
    path_b = "/abs/screenshot-B.png"
    f = _make_finding(
        poc_steps=[
            _one_step(step_number=1, screenshot_path=path_a),
            _one_step(step_number=2, screenshot_path=path_a),   # duplicate
            _one_step(step_number=3, screenshot_path=None),     # no screenshot
            _one_step(step_number=4, screenshot_path=path_b),
        ]
    )
    md = render_poc_section(f)
    attach_idx = md.index("## Attachments")
    attach_body = md[attach_idx:]
    # Both distinct paths appear as bullets, in first-seen order, ONCE each.
    assert attach_body.count(f"- {path_a}") == 1
    assert attach_body.count(f"- {path_b}") == 1
    # Order: path_a before path_b
    assert attach_body.index(f"- {path_a}") < attach_body.index(f"- {path_b}")


def test_render_poc_section_attachments_renders_none_message_when_no_screenshots():
    """Test 17 — no screenshots -> body is `No attachments.` literal."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(
        poc_steps=[
            _one_step(step_number=1, screenshot_path=None),
            _one_step(step_number=2, screenshot_path=None),
        ]
    )
    md = render_poc_section(f)
    attach_idx = md.index("## Attachments")
    attach_body = md[attach_idx:]
    assert "No attachments." in attach_body
    # And no bullet-list of paths.
    assert "- /" not in attach_body


def test_render_poc_section_omits_optional_subsections_when_data_absent():
    """Test 18 — minimal finding OMITS all optional sub-sections."""
    from sentinel.reporting import render_poc_section

    # Minimal: no raw dict, no references — none of the optional sections apply.
    f = _make_finding(poc_steps=[_one_step()])
    md = render_poc_section(f)
    assert "### Combined Single-URL Attack" not in md
    assert "### Affected Storefronts" not in md
    assert "### Supporting Material/References" not in md
    assert "### IP Address" not in md
    assert "### Timestamp" not in md
    assert "## Additional information" not in md


def test_render_poc_section_renders_combined_attack_url_when_set():
    """Test 19 — raw['combined_attack_url'] set -> `### Combined Single-URL Attack` rendered."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(
        poc_steps=[_one_step()],
        raw={"combined_attack_url": "https://target/?evil=1"},
    )
    md = render_poc_section(f)
    assert "### Combined Single-URL Attack" in md
    assert "https://target/?evil=1" in md


def test_render_poc_section_renders_affected_storefronts_when_list_non_empty():
    """Test 20 — raw['affected_storefronts'] non-empty list -> rendered with bullets."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(
        poc_steps=[_one_step()],
        raw={"affected_storefronts": ["ExampleStore.co.uk", "ExampleStore.ca"]},
    )
    md = render_poc_section(f)
    assert "### Affected Storefronts" in md
    storefront_idx = md.index("### Affected Storefronts")
    storefront_body = md[storefront_idx:]
    assert "- ExampleStore.co.uk" in storefront_body
    assert "- ExampleStore.ca" in storefront_body


def test_render_poc_section_renders_supporting_material_when_references_non_empty():
    """Test 21 — references non-empty -> `### Supporting Material/References` with bullets."""
    from sentinel.reporting import render_poc_section

    f = _make_finding(
        poc_steps=[_one_step()],
        references=["https://owasp.org/x", "https://cwe.mitre.org/y"],
    )
    md = render_poc_section(f)
    assert "### Supporting Material/References" in md
    ref_idx = md.index("### Supporting Material/References")
    ref_body = md[ref_idx:]
    assert "- https://owasp.org/x" in ref_body
    assert "- https://cwe.mitre.org/y" in ref_body


def test_render_poc_section_omits_mitigation_section():
    """Test 22 — NO `## Mitigation` heading EVER appears in the output (no AI-slop)."""
    from sentinel.reporting import render_poc_section

    # Try a variety of findings; none should ever produce a Mitigation H2.
    for f in [
        _make_finding(poc_steps=[]),
        _make_finding(poc_steps=[_one_step()]),
        _make_finding(
            poc_steps=[_one_step(), _one_step(step_number=2, command="python foo.py")],
            cwe="CWE-601",
            references=["https://owasp.org/x"],
            raw={"combined_attack_url": "https://x", "affected_storefronts": ["a"]},
        ),
    ]:
        md = render_poc_section(f)
        assert not re.search(r'^## Mitigation\b', md, re.MULTILINE), (
            f"Mitigation section must NEVER be autogenerated; got:\n{md}"
        )


def test_render_poc_section_omits_summary_section():
    """Test 23 — NO `## Summary` heading EVER appears."""
    from sentinel.reporting import render_poc_section

    for f in [
        _make_finding(poc_steps=[]),
        _make_finding(poc_steps=[_one_step()]),
    ]:
        md = render_poc_section(f)
        assert not re.search(r'^## Summary\b', md, re.MULTILINE), (
            "Summary section must NEVER be autogenerated"
        )


def test_render_poc_section_is_hermetic_no_network(monkeypatch):
    """Test 24 — render_poc_section never touches the network."""

    def boom(*args, **kwargs):
        raise RuntimeError("network access attempted from render_poc_section")

    monkeypatch.setattr(urllib.request, "urlopen", boom)

    from sentinel.reporting import render_poc_section

    f = _make_finding(poc_steps=[_one_step()])
    # Must succeed despite urlopen being broken.
    md = render_poc_section(f)
    assert "# Proof of Concept" in md


def test_render_poc_section_round_trips_finding_after_to_dict_from_dict():
    """Test 25 — Finding round-trip preserves enough info for the renderer.

    Build a Finding with poc_steps, run it through to_dict + json.dumps +
    json.loads + Finding(**data_minus_fingerprint), call render_poc_section
    on the reconstituted Finding, assert byte-for-byte identical output.
    Pins that Plan 04-01's serialization preserves renderer-required
    fields.
    """
    from sentinel.reporting import render_poc_section

    original = _make_finding(
        title="Round-trip test",
        description="A description.",
        cwe="CWE-79",
        severity=Severity.MEDIUM,
        references=["https://owasp.org/xss"],
        raw={"combined_attack_url": "https://x.example/?evil=1"},
        poc_steps=[
            PocStep(
                step_number=1,
                description="Send the request with curl",
                command="curl -sk https://t/",
                expected_output="200 OK",
                screenshot_path="/abs/path/shot.png",
            )
        ],
    )

    rendered_original = render_poc_section(original)

    # Round-trip via to_dict + JSON.
    encoded = json.dumps(original.to_dict())
    decoded = json.loads(encoded)
    decoded.pop("fingerprint", None)
    decoded["severity"] = Severity(decoded["severity"])

    restored = Finding(**decoded)
    rendered_restored = render_poc_section(restored)

    assert rendered_original == rendered_restored
