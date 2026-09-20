"""Shared remediation-suggestion builder used by both UIs.

The "Suggest fix" feature exists in two places:
  - FastAPI: POST /findings/<run>/suggest_fix → HTML partial
  - Streamlit: 1_Findings.py → renders into the finding card

Both call into here so the prompt + model + parameters stay identical
across UIs. If the prompt changes, change it once.
"""

from __future__ import annotations

from typing import Optional


DEFAULT_MODEL = "mistral-nemo:12b"
DEFAULT_SYSTEM = (
    "You are a senior application-security engineer. Output ONLY a code-level "
    "fix in markdown — no preamble, no recap of the bug."
)


def build_suggest_fix_prompt(finding: dict) -> str:
    """Render a finding dict into the user-prompt sent to the local LLM.

    `finding` is the standard Sentinel finding shape produced by every
    scanner — dict keys: title, severity, cwe, target, location, description,
    proof_of_concept (optional).
    """
    parts = [
        f"Vulnerability title: {finding.get('title', '?')}",
        f"Severity: {finding.get('severity', '?')}",
        f"CWE: {finding.get('cwe') or 'unknown'}",
        f"Affected location: {finding.get('target', '?')} "
        f"({finding.get('location', 'no location')})",
        "",
        "Description:",
        finding.get("description") or "(none)",
    ]
    if finding.get("proof_of_concept"):
        parts.append("")
        parts.append("Proof of concept:")
        parts.append(finding["proof_of_concept"])
    parts.extend([
        "",
        "Task: propose a code-level fix. Be concrete — name the file, "
        "function, or config key the developer should change. Show the "
        "diff or the corrected snippet. Keep it under 250 words.",
    ])
    return "\n".join(parts)


async def suggest_fix(
    finding: dict,
    *,
    ollama_host: str = "http://localhost:11434",
    model: str = DEFAULT_MODEL,
    system: str = DEFAULT_SYSTEM,
    temperature: float = 0.2,
    max_tokens: int = 600,
) -> str:
    """Call the local Ollama model and return the suggested fix as raw text.

    Raises any exception the OllamaClient raises — caller decides how to
    surface it (HTML error chip vs Streamlit st.error).
    """
    from sentinel.agent.ollama_provider import OllamaClient

    client = OllamaClient(host=ollama_host)
    response = await client.generate(
        model=model,
        prompt=build_suggest_fix_prompt(finding),
        system=system,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return (response or "").strip()


def suggest_fix_sync(
    finding: dict,
    *,
    ollama_host: str = "http://localhost:11434",
    model: str = DEFAULT_MODEL,
    system: str = DEFAULT_SYSTEM,
    temperature: float = 0.2,
    max_tokens: int = 600,
) -> str:
    """Sync wrapper for Streamlit callers (Streamlit isn't async-friendly)."""
    import asyncio
    return asyncio.run(suggest_fix(
        finding, ollama_host=ollama_host, model=model, system=system,
        temperature=temperature, max_tokens=max_tokens,
    ))
