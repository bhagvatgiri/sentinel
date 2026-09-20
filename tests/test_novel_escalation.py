"""Hermetic tests for the novel-finding escalation prompt + JSON-schema validator
(Plan 05-03, NOVEL-04 + NOVEL-08).

ZERO live LLM. ZERO live Ollama. Every test feeds canned response strings into
parse_exploit_chain / validate_exploit_chain, or builds a Finding + NearestMatch
fixture and calls render_escalation_prompt directly.

The escalation_prompt module is PURE PYTHON — it produces a prompt string for
the Sonnet-tier model (Plan 05-04 owns the actual LLM transport call) and
validates the model's response shape against a hand-rolled JSON schema. No
anthropic SDK import, no jsonschema dependency.

Contract pinned per Plan 05-03 <interfaces>:

  render_escalation_prompt(finding, nearest_match) -> str
    Four sections: ROLE, FINDING SUMMARY, NEAREST CORPUS MATCH, REQUIRED OUTPUT.
    Demands a JSON object on a single line with input/behavior/impact keys.

  parse_exploit_chain(response_text) -> Optional[ExploitChain]
    Tolerates ```json...``` fences; falls back to raw json.loads on stripped input.
    Returns None on any parse/schema failure.

  validate_exploit_chain(response_text) -> (bool, Optional[ExploitChain], Optional[str])
    Runs parse + EXPLOIT_CHAIN_SCHEMA walk in one call.
    Returns (True, chain, None) on success or (False, None, error_msg) on failure
    with a specific human-readable message naming the offending key.

  EXPLOIT_CHAIN_SCHEMA — module-level dict mirroring JSON Schema draft-7 shape;
    required=["input","behavior","impact"], all strings minLength=1.
"""

from __future__ import annotations

import numpy as np
import pytest

from sentinel.agent.novelty import (
    EXPLOIT_CHAIN_SCHEMA,
    ExploitChain,
    IndexEntry,
    NearestMatch,
    parse_exploit_chain,
    render_escalation_prompt,
    validate_exploit_chain,
)
from sentinel.core.findings import EvidenceState, Finding, Severity


# --- Fixture factories --------------------------------------------------------


def _make_finding(
    *,
    title: str = "Reflected XSS in /admin search via `q` parameter",
    description: str = (
        "The `q` query parameter on /admin/search reflects unescaped into the "
        "HTML body within a script context, enabling reflected XSS that "
        "executes in an authenticated admin's browser."
    ),
    severity: Severity = Severity.HIGH,
    target: str = "https://admin.example.com",
    cwe: str | None = "CWE-79",
    scanner: str = "vuln:xss",
) -> Finding:
    return Finding(
        title=title,
        description=description,
        severity=severity,
        scanner=scanner,
        target=target,
        cwe=cwe,
        evidence_state=EvidenceState.LIVE_CONFIRMED,
    )


def _make_nearest_match(
    *,
    cosine_distance: float = 0.4231,
    chunk_id: str = "owasp:xss-cheatsheet:0",
    source: str = "owasp",
    title: str = "OWASP Cheat Sheet: Cross Site Scripting Prevention",
    text_preview: str = (
        "Output encoding is the primary defense against XSS. Encode "
        "data when it is being placed into HTML, JavaScript, CSS, URL, "
        "or HTML attribute contexts. Use a tested output-encoding library."
    ),
) -> NearestMatch:
    return NearestMatch(
        cosine_distance=cosine_distance,
        entry=IndexEntry(
            chunk_id=chunk_id,
            source=source,
            title=title,
            text_preview=text_preview,
            url="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            cve_id=None,
        ),
    )


# --- Test 1 -------------------------------------------------------------------
def test_render_escalation_prompt_contains_all_four_sections() -> None:
    """ROLE / FINDING SUMMARY / NEAREST CORPUS MATCH / REQUIRED OUTPUT headers
    are all present in the rendered prompt (case-insensitive marker check)."""
    prompt = render_escalation_prompt(_make_finding(), _make_nearest_match())

    assert "ROLE" in prompt
    assert "FINDING SUMMARY" in prompt
    assert "NEAREST CORPUS MATCH" in prompt
    assert "REQUIRED OUTPUT" in prompt


# --- Test 2 -------------------------------------------------------------------
def test_render_escalation_prompt_embeds_finding_identity() -> None:
    """Finding identity fields (title + severity + target) round-trip verbatim
    into the prompt text so the model has unambiguous context."""
    finding = _make_finding(
        title="Server-side request forgery via /api/fetch?url=...",
        severity=Severity.CRITICAL,
        target="https://api.example.com",
    )
    prompt = render_escalation_prompt(finding, _make_nearest_match())

    assert "Server-side request forgery via /api/fetch?url=..." in prompt
    assert "critical" in prompt.lower()
    assert "https://api.example.com" in prompt


# --- Test 3 -------------------------------------------------------------------
def test_render_escalation_prompt_embeds_nearest_match() -> None:
    """Nearest-match section embeds entry.title + entry.source + the
    cosine_distance to 4 decimals so the model can reason about how close the
    nearest neighbor really is."""
    nm = _make_nearest_match(
        cosine_distance=0.6789,
        title="MITRE ATT&CK T1190 — Exploit Public-Facing Application",
        source="mitre-attack",
    )
    prompt = render_escalation_prompt(_make_finding(), nm)

    assert "MITRE ATT&CK T1190 — Exploit Public-Facing Application" in prompt
    assert "mitre-attack" in prompt
    # cosine_distance formatted to 4 decimals: 0.6789
    assert "0.6789" in prompt


# --- Test 4 -------------------------------------------------------------------
def test_render_escalation_prompt_demands_input_behavior_impact() -> None:
    """REQUIRED OUTPUT section names the three keys + demands non-empty values
    + shows the literal JSON example so the model has minimal guesswork."""
    prompt = render_escalation_prompt(_make_finding(), _make_nearest_match())

    assert "input" in prompt
    assert "behavior" in prompt
    assert "impact" in prompt
    assert "non-empty" in prompt.lower()
    # The literal example JSON object with the three keys must appear
    assert '"input"' in prompt
    assert '"behavior"' in prompt
    assert '"impact"' in prompt


# --- Test 5 -------------------------------------------------------------------
def test_parse_exploit_chain_handles_fenced_json_block() -> None:
    """`'\\nSome preamble\\n```json\\n{...}\\n```\\nTrailing\\n'` parses cleanly."""
    response = (
        "\nSome preamble\n"
        "```json\n"
        '{"input": "GET /admin?q=<script>alert(1)</script>", '
        '"behavior": "200 OK with alert(1) in script context", '
        '"impact": "session hijack of any authenticated admin"}\n'
        "```\n"
        "Trailing\n"
    )

    chain = parse_exploit_chain(response)

    assert chain is not None
    assert isinstance(chain, ExploitChain)
    assert "GET /admin" in chain.input
    assert chain.behavior == "200 OK with alert(1) in script context"
    assert chain.impact == "session hijack of any authenticated admin"


# --- Test 6 -------------------------------------------------------------------
def test_parse_exploit_chain_handles_unfenced_json() -> None:
    """Raw JSON with no fences parses successfully (operator may strip the
    fences manually before pasting; the parser tolerates both shapes)."""
    response = (
        '{"input": "POST /login {\\"username\\":\\"admin\'-- \\"}", '
        '"behavior": "redirects to /dashboard with admin session cookie", '
        '"impact": "authentication bypass to admin role"}'
    )

    chain = parse_exploit_chain(response)

    assert chain is not None
    assert chain.behavior.startswith("redirects to /dashboard")
    assert chain.impact == "authentication bypass to admin role"


# --- Test 7 -------------------------------------------------------------------
def test_validate_exploit_chain_rejects_missing_key() -> None:
    """Missing required key 'impact' returns (False, None, msg) where msg names
    the missing key explicitly so the operator can debug LLM output."""
    response = '{"input": "x", "behavior": "y"}'  # missing impact

    ok, chain, error = validate_exploit_chain(response)

    assert ok is False
    assert chain is None
    assert error is not None
    assert "impact" in error
    assert "missing" in error.lower()


# --- Test 8 -------------------------------------------------------------------
def test_validate_exploit_chain_rejects_empty_string() -> None:
    """Empty string for required key returns (False, None, msg) naming the
    offending key + violation kind (empty / minLength)."""
    response = '{"input": "x", "behavior": "", "impact": "z"}'

    ok, chain, error = validate_exploit_chain(response)

    assert ok is False
    assert chain is None
    assert error is not None
    assert "behavior" in error
    assert ("empty" in error.lower()) or ("minlength" in error.lower())


# --- Test 9 -------------------------------------------------------------------
def test_validate_exploit_chain_accepts_well_formed() -> None:
    """A well-formed response yields (True, ExploitChain(...), None) with all
    three fields populated as strings."""
    response = (
        "```json\n"
        '{"input": "GET /admin?id=1\' OR 1=1--", '
        '"behavior": "200 OK with admin dashboard HTML", '
        '"impact": "authentication bypass to admin role"}\n'
        "```"
    )

    ok, chain, error = validate_exploit_chain(response)

    assert ok is True
    assert error is None
    assert chain is not None
    assert chain.input == "GET /admin?id=1' OR 1=1--"
    assert chain.behavior == "200 OK with admin dashboard HTML"
    assert chain.impact == "authentication bypass to admin role"


# --- Bonus contract checks ---------------------------------------------------
def test_exploit_chain_schema_required_keys_in_order() -> None:
    """The constant is the wire-format contract for Plan 05-04's audit log."""
    assert EXPLOIT_CHAIN_SCHEMA["required"] == ["input", "behavior", "impact"]
    assert EXPLOIT_CHAIN_SCHEMA["type"] == "object"
    for key in ("input", "behavior", "impact"):
        prop = EXPLOIT_CHAIN_SCHEMA["properties"][key]
        assert prop["type"] == "string"
        assert prop["minLength"] == 1
