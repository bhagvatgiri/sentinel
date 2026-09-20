"""VERIFY-03 — PoC generation prompt + parse_poc_block contract.

Pins the structure of the system+user prompt the agent receives at PoC-
generation time AND the parser that extracts the structured `<poc>` block
out of the model's response. The downstream consumer is Plan 03-04's
sandbox (`execute_poc`), which trusts that:

1. `render_poc_prompt(finding)` produces a self-contained, class-aware
   prompt mentioning the 4 accepted languages + the required XML shape.
2. `parse_poc_block(response)` either returns a fully-populated
   `ParsedPoc` OR `None` — it MUST NOT raise on malformed input.
3. `POC_EXAMPLES` carries ≥ 3 worked examples for each of the top-five
   vuln classes (xss / sqli / idor / auth / ssrf), so future PRs cannot
   silently delete the model's reference shapes.

The classifier (Plan 03-03) is not exercised in this file — that lives
in `tests/test_poc_classifier.py`. The sandbox (Plan 03-04 Task 2)
exercises the parser end-to-end via its own monkeypatched subprocess.
"""

from __future__ import annotations

import pytest

from sentinel.agent.poc import (
    ACCEPTED_LANGUAGES,
    POC_EXAMPLES,
    ParsedPoc,
    parse_poc_block,
    render_poc_prompt,
)
from sentinel.core.findings import Finding, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _xss_finding() -> Finding:
    return Finding(
        title="Reflected XSS in /search",
        description="The `q` parameter is echoed unescaped into the HTML body.",
        severity=Severity.HIGH,
        scanner="vuln:xss",
        target="http://target.example.com",
        location="/search?q=<reflected>",
        cwe="CWE-79",
    )


def _idor_finding() -> Finding:
    return Finding(
        title="Possible IDOR on /api/users/{id}",
        description="Numeric user IDs in the URL with no per-user check.",
        severity=Severity.MEDIUM,
        scanner="vuln:idor",
        target="http://target.example.com",
        location="/api/users/1",
        cwe="CWE-639",
    )


# ---------------------------------------------------------------------------
# render_poc_prompt
# ---------------------------------------------------------------------------


def test_render_poc_prompt_returns_nonempty_string():
    """T1: prompt is non-empty, mentions all 4 languages, contains an example."""
    f = _xss_finding()
    prompt = render_poc_prompt(f)
    assert isinstance(prompt, str)
    assert len(prompt) > 0
    assert f.title in prompt
    for lang in ("shell", "python", "playwright", "sqlmap"):
        assert lang in prompt, f"missing language token: {lang}"
    # At least one literal `<poc>` example block (the schema header AND a
    # filled example both contain the literal `<poc>` — count both).
    assert prompt.count("<poc>") >= 1


def test_render_poc_prompt_includes_class_specific_examples():
    """T2: xss finding embeds an XSS example; idor finding embeds an IDOR example."""
    xss_prompt = render_poc_prompt(_xss_finding())
    # Heuristics for "XSS-specific content": either the literal "<script>"
    # payload OR the word "XSS"/"xss" mentioned in the example commentary.
    assert "<script>" in xss_prompt or "xss" in xss_prompt.lower()

    idor_prompt = render_poc_prompt(_idor_finding())
    # Heuristics for "IDOR-specific content": the example mentions changing
    # an object identifier (the canonical /users/1 -> /users/2 pivot).
    assert "/api/users/" in idor_prompt or "idor" in idor_prompt.lower()


def test_render_poc_prompt_documents_required_xml_shape():
    """T3: the four required tags are visible literals in the prompt."""
    prompt = render_poc_prompt(_xss_finding())
    for literal in ("<poc>", "<command>", "<language>", "<expected_output_regex>", "<rationale>"):
        assert literal in prompt, f"missing required schema literal: {literal}"


def test_render_prompt_explicitly_rejects_destructive_examples():
    """T9: prompt enumerates destructive verbs the model MUST NOT emit."""
    prompt = render_poc_prompt(_xss_finding())
    # The prompt mirrors Plan 03-03's DESTRUCTIVE_PATTERNS so the model sees
    # what the upstream classifier will short-circuit on.
    for forbidden in (
        "DROP TABLE",
        "rm -rf",
        "mkfs",
        "pickle.loads",
        "yaml.unsafe_load",
    ):
        assert forbidden in prompt, f"prompt should warn the model away from: {forbidden}"


def test_render_poc_prompt_unknown_class_uses_fallback():
    """The fallback branch fires for scanners outside the POC_EXAMPLES keys.

    Defensive — the prompt must not raise + must still mention the required
    XML shape even when no class-specific examples can be selected.
    """
    f = Finding(
        title="generic finding",
        description="x",
        severity=Severity.LOW,
        scanner="passive:headers",  # NOT a vuln:<class> slug
        target="http://target.example.com",
    )
    prompt = render_poc_prompt(f)
    assert isinstance(prompt, str)
    assert "<poc>" in prompt
    assert "<command>" in prompt


def test_render_poc_prompt_class_prefix_is_cache_stable():
    """Cost (2026-XX-XX): verify-phase-03 spawns one agent PER finding, each
    re-sending this system prompt. For the SDK's automatic system-prompt
    caching to charge the big static prefix ONCE per vuln class (then read it
    at ~0.1x for the 2nd..Nth same-class finding in the fan-out), the prefix
    BEFORE the per-finding '## Finding' block must be byte-identical across two
    DIFFERENT findings of the SAME class. This locks that property — if a
    future edit moves per-finding content back above the summary, the cache
    prefix breaks and this fails.
    """
    f1 = _xss_finding()
    f2 = Finding(
        title="Reflected XSS in /profile",                 # different title
        description="The `name` field is reflected unescaped.",  # different desc
        severity=Severity.MEDIUM,                           # different severity
        scanner="vuln:xss",                                 # SAME class
        target="http://other.example.org",                  # different target
        location="/profile?name=<x>",                       # different location
        cwe="CWE-79",
    )
    p1, p2 = render_poc_prompt(f1), render_poc_prompt(f2)
    prefix1 = p1.split("## Finding", 1)[0]
    prefix2 = p2.split("## Finding", 1)[0]
    assert prefix1 == prefix2, "class-stable prefix diverged → SDK cache prefix broken"
    assert len(prefix1) > 0
    # The per-finding tails DO differ (variable content rides LAST).
    assert p1 != p2
    assert f1.title in p1.split("## Finding", 1)[1]
    assert f2.title in p2.split("## Finding", 1)[1]


def test_render_poc_prompt_different_classes_have_different_prefix():
    """Sanity: different vuln classes carry different example sets, so each
    class caches its OWN prefix (they should not collide)."""
    xss_prefix = render_poc_prompt(_xss_finding()).split("## Finding", 1)[0]
    idor_prefix = render_poc_prompt(_idor_finding()).split("## Finding", 1)[0]
    assert xss_prefix != idor_prefix


# ---------------------------------------------------------------------------
# parse_poc_block
# ---------------------------------------------------------------------------


def test_parse_poc_block_extracts_well_formed_xml_shell():
    """T4a: shell language round-trips correctly."""
    response = (
        "Here's the PoC:\n"
        "<poc>\n"
        "<language>shell</language>\n"
        "<command>curl -s 'http://target/api/users/1?id=2'</command>\n"
        "<expected_output_regex>HTTP/[\\d.]+ 200|\"email\":\"</expected_output_regex>\n"
        "<rationale>IDOR: switch id and read another user's email.</rationale>\n"
        "</poc>\n"
    )
    parsed = parse_poc_block(response)
    assert parsed is not None
    assert isinstance(parsed, ParsedPoc)
    assert parsed.language == "shell"
    assert parsed.command == "curl -s 'http://target/api/users/1?id=2'"
    assert parsed.expected_output_regex.startswith("HTTP/")
    assert "IDOR" in parsed.rationale


def test_parse_poc_block_extracts_well_formed_xml_python():
    """T4b: python language round-trips correctly."""
    response = (
        "<poc>\n"
        "<language>python</language>\n"
        "<command>import requests; print(requests.get('http://x/').status_code)</command>\n"
        "<expected_output_regex>^200$</expected_output_regex>\n"
        "<rationale>test</rationale>\n"
        "</poc>\n"
    )
    p = parse_poc_block(response)
    assert p is not None and p.language == "python"


def test_parse_poc_block_extracts_well_formed_xml_playwright():
    """T4c: playwright language round-trips correctly."""
    response = (
        "<poc>\n"
        "<language>playwright</language>\n"
        "<command>from playwright.sync_api import sync_playwright</command>\n"
        "<expected_output_regex>alert\\(1\\)</expected_output_regex>\n"
        "<rationale>DOM XSS</rationale>\n"
        "</poc>\n"
    )
    p = parse_poc_block(response)
    assert p is not None and p.language == "playwright"


def test_parse_poc_block_extracts_well_formed_xml_sqlmap():
    """T4d: sqlmap language round-trips correctly."""
    response = (
        "<poc>\n"
        "<language>sqlmap</language>\n"
        "<command>sqlmap -u 'http://target/?id=1' --batch --level=1 --risk=1</command>\n"
        "<expected_output_regex>parameter.*is vulnerable</expected_output_regex>\n"
        "<rationale>auto SQLi detection (read-only)</rationale>\n"
        "</poc>\n"
    )
    p = parse_poc_block(response)
    assert p is not None and p.language == "sqlmap"


def test_parse_poc_block_handles_no_block():
    """T5: no `<poc>` tag returns None without raising."""
    assert parse_poc_block("") is None
    assert parse_poc_block("just narrative text, no poc block at all") is None
    assert parse_poc_block(None) is None  # defensive: None input is tolerated


def test_parse_poc_block_handles_missing_command():
    """T6a: missing `<command>` returns None."""
    response = (
        "<poc>\n"
        "<language>shell</language>\n"
        "<expected_output_regex>200</expected_output_regex>\n"
        "<rationale>x</rationale>\n"
        "</poc>\n"
    )
    assert parse_poc_block(response) is None


def test_parse_poc_block_handles_empty_language():
    """T6b: empty `<language>` returns None."""
    response = (
        "<poc>\n"
        "<language></language>\n"
        "<command>curl http://x</command>\n"
        "<expected_output_regex>200</expected_output_regex>\n"
        "<rationale>x</rationale>\n"
        "</poc>\n"
    )
    assert parse_poc_block(response) is None


def test_parse_poc_block_handles_unknown_language():
    """T7: language outside ACCEPTED_LANGUAGES returns None."""
    response = (
        "<poc>\n"
        "<language>perl</language>\n"
        "<command>perl -e 'print 1'</command>\n"
        "<expected_output_regex>1</expected_output_regex>\n"
        "<rationale>x</rationale>\n"
        "</poc>\n"
    )
    assert parse_poc_block(response) is None


def test_parse_poc_block_handles_invalid_regex():
    """Defensive: a syntactically-broken regex returns None without raising."""
    response = (
        "<poc>\n"
        "<language>shell</language>\n"
        "<command>curl http://x</command>\n"
        "<expected_output_regex>[unclosed</expected_output_regex>\n"
        "<rationale>x</rationale>\n"
        "</poc>\n"
    )
    assert parse_poc_block(response) is None


def test_parse_poc_block_strips_whitespace_and_code_fences():
    """T8: model often wraps the block in markdown code fences; parser tolerates."""
    response = (
        "Sure, here's the PoC:\n"
        "```xml\n"
        "<poc>\n"
        "  <language>  shell  </language>\n"
        "  <command>  curl -s http://target/  </command>\n"
        "  <expected_output_regex>  HTTP/1\\.1 200  </expected_output_regex>\n"
        "  <rationale>  whitespace round-trip test  </rationale>\n"
        "</poc>\n"
        "```\n"
    )
    p = parse_poc_block(response)
    assert p is not None
    assert p.language == "shell"  # trimmed
    assert p.command == "curl -s http://target/"  # trimmed
    assert p.expected_output_regex == "HTTP/1\\.1 200"
    assert p.rationale == "whitespace round-trip test"


# ---------------------------------------------------------------------------
# POC_EXAMPLES + ACCEPTED_LANGUAGES contracts
# ---------------------------------------------------------------------------


def test_poc_examples_count_at_least_3_per_top_five_classes():
    """T10: each of xss/sqli/idor/auth/ssrf has ≥ 3 entries."""
    for cls in ("xss", "sqli", "idor", "auth", "ssrf"):
        assert cls in POC_EXAMPLES, f"missing top-five class key: {cls}"
        assert len(POC_EXAMPLES[cls]) >= 3, (
            f"class {cls!r} must have ≥ 3 examples; has {len(POC_EXAMPLES[cls])}"
        )


def test_poc_examples_every_entry_uses_accepted_language():
    """Each example's `language` value sits inside ACCEPTED_LANGUAGES."""
    for cls, entries in POC_EXAMPLES.items():
        for i, entry in enumerate(entries):
            assert entry["language"] in ACCEPTED_LANGUAGES, (
                f"{cls}[{i}] uses language {entry['language']!r} outside ACCEPTED_LANGUAGES"
            )


def test_accepted_languages_is_exactly_four():
    """The accepted languages set must remain exactly the documented four."""
    assert set(ACCEPTED_LANGUAGES) == {"shell", "python", "playwright", "sqlmap"}


def test_poc_examples_no_destructive_payloads():
    """Reference examples must not include destructive verbs the classifier flags.

    The prompt's examples shape what the model emits; destructive examples
    would teach the model the wrong pattern. The classifier (Plan 03-03)
    short-circuits these in production but we still pin them out of the
    reference corpus.
    """
    from sentinel.agent.poc import classify_destructive

    for cls, entries in POC_EXAMPLES.items():
        for i, entry in enumerate(entries):
            v = classify_destructive(entry["command"], entry["language"])
            assert not v.is_destructive, (
                f"{cls}[{i}] example command flagged destructive by Plan 03-03 "
                f"classifier (pattern={v.pattern_name}): {entry['command'][:80]!r}"
            )
