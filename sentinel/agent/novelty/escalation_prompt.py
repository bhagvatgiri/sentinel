"""Novel-finding escalation prompt + JSON-schema validator (Plan 05-03, NOVEL-04).

Pure-Python prompt-rendering + response-validation. Plan 05-04's pipeline.py
wires:

    render_escalation_prompt(finding, nearest_match)
        -> [Sonnet-tier LLM via SiliconFlow shim, Qwen3.6-35B-A3B]
        -> validate_exploit_chain(response_text)

…to gate which novelty-flagged findings get promoted to operator-facing PoC.
The transport layer is owned by Plan 05-04; this module is the pure half so
the schema contract is testable without any live LLM dependency.

Why a hand-rolled validator (no `jsonschema` dep)
-------------------------------------------------

The schema is a tiny three-key dict with one validation rule per key
(`type=string`, `minLength=1`). A 30-line walker covers it; pulling in
`jsonschema` would add a new pyproject extra for one site. The walker
preserves the same error-shape the `jsonschema` library produces (key name +
violation kind in the message), so future migration to the lib is mechanical.

Threat surfaces (Plan 05-03 threat register)
--------------------------------------------

T-05-03-01 (Tampering): json.loads is stdlib (hardened). Schema walk rejects
  extra-type values + missing keys + empty strings with specific error messages.
T-05-03-02 (DoS): _FENCED_JSON_RE uses a lazy `\\{.*?\\}` group under DOTALL;
  no catastrophic-backtracking surface (no nested quantifiers).
T-05-03-03 (DoS): description truncated to 800 chars at render time;
  text_preview is already 240-char bounded by Plan 05-02. Total prompt < 4 KB.
T-05-03-05 (Repudiation): rendering is deterministic — same input -> same
  output (no timestamps, no random IDs). Plan 05-04's audit log can sha256
  the rendered prompt and re-verify post-hoc.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Constants — the wire-format contract Plan 05-04 audit-logs against
# ---------------------------------------------------------------------------


EXPLOIT_CHAIN_SCHEMA: dict = {
    "type": "object",
    "required": ["input", "behavior", "impact"],
    "properties": {
        "input": {"type": "string", "minLength": 1},
        "behavior": {"type": "string", "minLength": 1},
        "impact": {"type": "string", "minLength": 1},
    },
    # Tolerate extra keys like 'confidence' for future expansion without
    # forcing a schema-version bump.
    "additionalProperties": True,
}


# Bound the finding.description chunk we splice into the prompt — keeps the
# total rendered prompt under ~4 KB so the Sonnet-tier call stays cheap and
# we don't push other context out of the model's attention window.
_MAX_DESCRIPTION_CHARS = 800

# Cap the error_msg's echo of the raw response — prevents log-flood DoS
# from a pathological agent response. validate_exploit_chain never includes
# the full response_text in its error message; this is a belt-and-braces
# cap if we ever need to surface a prefix.
_MAX_ERROR_ECHO_CHARS = 200


# ---------------------------------------------------------------------------
# Data shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExploitChain:
    """Validated triple describing how an attacker proves a novel finding.

    input    — attacker-controlled data (URL params, request body, headers).
    behavior — server response that confirmed the vulnerability.
    impact   — what the attacker can do once the bug is confirmed.
    """

    input: str
    behavior: str
    impact: str


# ---------------------------------------------------------------------------
# Prompt rendering — section-helper composition (mirrors Plan 04-02 pattern)
# ---------------------------------------------------------------------------


def _render_role() -> str:
    return (
        "## ROLE\n"
        "You are a senior security researcher. The Sentinel autonomous "
        "pentest agent has flagged a finding as novel (no close semantic "
        "neighbor in OWASP / MITRE / NVD / writeups). Your job is to "
        "confirm or deny the novelty by reasoning about the exploit chain."
    )


def _coerce_str(value: Any) -> str:
    """Best-effort str() coercion that handles Enum (Severity, EvidenceState)
    members by extracting `.value` for human-readable embedding into the prompt.
    """
    if hasattr(value, "value"):
        return str(value.value)
    return "" if value is None else str(value)


def _render_finding_summary(finding) -> str:  # noqa: ANN001 — Finding type avoids circular import
    description = finding.description or "(no description)"
    if len(description) > _MAX_DESCRIPTION_CHARS:
        description = description[:_MAX_DESCRIPTION_CHARS] + " …[truncated]"

    cwe = finding.cwe or "(unknown)"
    evidence_state = _coerce_str(finding.evidence_state) or "(unspecified)"
    severity = _coerce_str(finding.severity) or "(unspecified)"

    lines = [
        "## FINDING SUMMARY",
        f"- Title: {finding.title}",
        f"- Scanner: {finding.scanner}",
        f"- Target: {finding.target}",
        f"- Severity: {severity}",
        f"- CWE: {cwe}",
        f"- Evidence state: {evidence_state}",
        "- Description:",
        f"    {description}",
    ]
    return "\n".join(lines)


def _render_nearest_match(nearest_match) -> str:  # noqa: ANN001
    entry = nearest_match.entry
    cosine_distance = float(nearest_match.cosine_distance)
    preview = entry.text_preview or "(no preview)"
    url = entry.url or "(no url)"
    cve_id = entry.cve_id or ""
    cve_line = f"\n- CVE: {cve_id}" if cve_id else ""

    return (
        "## NEAREST CORPUS MATCH\n"
        f"- Title: {entry.title}\n"
        f"- Source: {entry.source}\n"
        f"- Cosine distance: {cosine_distance:.4f}"
        f"{cve_line}\n"
        f"- URL: {url}\n"
        "- Text preview:\n"
        f"    {preview}"
    )


def _render_required_output() -> str:
    # Sonnet-tier model contract: emit ONE JSON object with exactly the three
    # required keys, wrapped in a fenced code block. The validator below
    # tolerates both fenced + unfenced shapes, but the prompt nudges fenced
    # for human-readability of the model's output in logs.
    return (
        "## REQUIRED OUTPUT\n"
        "Produce a single JSON object on a single line with exactly these keys:\n"
        "  - input    (string, non-empty): the attacker-controlled data that triggers the bug\n"
        "  - behavior (string, non-empty): the server response or side-effect that confirms exploitation\n"
        "  - impact   (string, non-empty): what the attacker can do once the bug is confirmed\n"
        "\n"
        "Wrap your response in a fenced code block:\n"
        "```json\n"
        '{"input": "...", "behavior": "...", "impact": "..."}\n'
        "```\n"
        "\n"
        "Do NOT include analysis, commentary, or any keys other than "
        "input / behavior / impact."
    )


def render_escalation_prompt(finding, nearest_match) -> str:  # noqa: ANN001
    """Render the 4-section single-call prompt for the Sonnet-tier escalation.

    Deterministic (no timestamps, no random IDs) so Plan 05-04 can sha256 the
    output and audit-log the hash for post-hoc verification.

    Args:
        finding: Finding instance (we read title/scanner/target/severity/cwe/
            evidence_state/description).
        nearest_match: NearestMatch instance from CorpusIndex.nearest()
            (Plan 05-02; we read .entry.title/source/url/cve_id/text_preview +
            .cosine_distance).

    Returns:
        Single-string prompt < 4 KB ready to hand to the LLM transport.
    """
    sections = [
        _render_role(),
        _render_finding_summary(finding),
        _render_nearest_match(nearest_match),
        _render_required_output(),
    ]
    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Parser + validator
# ---------------------------------------------------------------------------


# Fenced JSON block: ```json ... ``` or ``` ... ``` (language tag optional).
# Lazy {.*?} under DOTALL prevents catastrophic backtracking on pathological
# input (T-05-03-02). The regex returns the inner JSON object as group(1).
_FENCED_JSON_RE = re.compile(
    r"```(?:json)?\s*(\{.*?\})\s*```",
    re.DOTALL | re.IGNORECASE,
)

# Fallback: find a {...} block anywhere in the text. Same lazy match.
_RAW_JSON_RE = re.compile(r"(\{.*?\})", re.DOTALL)


def _extract_json_string(response_text: str) -> Optional[str]:
    """Pull the JSON object substring out of a model response.

    Order of attempts:
      1. ```json ... ``` fenced block (the prompt-preferred shape).
      2. ``` ... ``` fenced block (language tag missing).
      3. Stripped raw response (operator stripped the fences manually).
      4. First `{...}` substring anywhere in the text.

    Returns the JSON candidate string, or None if no plausible candidate
    is found.
    """
    if not response_text:
        return None

    # Try fenced first — most likely shape per the prompt.
    m = _FENCED_JSON_RE.search(response_text)
    if m:
        return m.group(1).strip()

    # Try the stripped raw text as a JSON object.
    stripped = response_text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped

    # Final fallback: any {...} substring.
    m2 = _RAW_JSON_RE.search(response_text)
    if m2:
        return m2.group(1).strip()

    return None


def _validate_against_schema(
    payload: Any, schema: dict
) -> tuple[bool, Optional[str]]:
    """Hand-rolled JSON-schema walker covering type=object, required=[...],
    and per-property type=string + minLength=N. Returns (True, None) on pass
    or (False, error_message) on the first violation.

    Mirrors the error-message shape `jsonschema` produces so a future migration
    is mechanical: the message names the key + the violation kind.
    """
    if not isinstance(payload, dict):
        return False, f"expected JSON object (got {type(payload).__name__})"

    required = schema.get("required", []) or []
    for key in required:
        if key not in payload:
            return False, f"missing required key: '{key}'"

    properties = schema.get("properties", {}) or {}
    for key, prop_schema in properties.items():
        if key not in payload:
            continue  # only required keys must be present; others are optional
        value = payload[key]
        expected_type = prop_schema.get("type")
        if expected_type == "string":
            if not isinstance(value, str):
                return False, (
                    f"key '{key}' has wrong type "
                    f"(expected string, got {type(value).__name__})"
                )
            min_length = int(prop_schema.get("minLength", 0))
            if len(value) < min_length:
                return False, (
                    f"empty string for required key: '{key}' "
                    f"(minLength={min_length})"
                )
    return True, None


def parse_exploit_chain(response_text: Optional[str]) -> Optional[ExploitChain]:
    """Extract + validate the LLM response into an ExploitChain.

    Returns the dataclass on success or None on ANY failure (no candidate
    JSON found, malformed JSON, schema violation). Callers that need an
    actionable error message should use validate_exploit_chain instead.
    """
    if not response_text:
        return None

    candidate = _extract_json_string(response_text)
    if candidate is None:
        return None

    try:
        payload = json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        return None

    ok, _err = _validate_against_schema(payload, EXPLOIT_CHAIN_SCHEMA)
    if not ok:
        return None

    return ExploitChain(
        input=str(payload["input"]),
        behavior=str(payload["behavior"]),
        impact=str(payload["impact"]),
    )


def validate_exploit_chain(
    response_text: Optional[str],
) -> tuple[bool, Optional[ExploitChain], Optional[str]]:
    """Parse + schema-validate in one call; returns a structured error message.

    Returns:
        (True, ExploitChain(...), None) on a well-formed response.
        (False, None, error_message) on any failure. error_message names the
          specific key + violation kind so the operator can diagnose the LLM
          output without grepping debug logs.
    """
    if not response_text:
        return False, None, "no JSON found in response (empty input)"

    candidate = _extract_json_string(response_text)
    if candidate is None:
        return False, None, "no JSON found in response"

    try:
        payload = json.loads(candidate)
    except (json.JSONDecodeError, ValueError) as e:
        reason = str(e)
        if len(reason) > _MAX_ERROR_ECHO_CHARS:
            reason = reason[:_MAX_ERROR_ECHO_CHARS] + " …[truncated]"
        return False, None, f"malformed JSON: {reason}"

    ok, err = _validate_against_schema(payload, EXPLOIT_CHAIN_SCHEMA)
    if not ok:
        return False, None, err

    chain = ExploitChain(
        input=str(payload["input"]),
        behavior=str(payload["behavior"]),
        impact=str(payload["impact"]),
    )
    return True, chain, None
