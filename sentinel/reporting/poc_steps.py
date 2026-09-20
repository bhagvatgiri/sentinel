"""POC-02 — Read a Phase 3 evidence bundle from disk into list[PocStep].

This module is the deterministic, hermetic bridge between the Phase 3
sandbox evidence bundle (`workspaces/<engagement>/verification/<fp>/`)
and the Phase 4 renderers (markdown / PDF / Obsidian / dashboard route).

Contract (frozen by Plan 04-01):

    generate_poc_steps(finding, evidence_bundle_path) -> list[PocStep]

      - hermetic: no subprocess, no network, no LLM
      - returns [] when the bundle is missing on disk
      - returns [] when the bundle contains ONLY refusal.txt (destructive
        / out-of-scope short-circuit — there is nothing to reproduce)
      - returns one PocStep per non-empty, non-comment top-level shell line
        when poc.sh is present
      - returns a single PocStep whose .command is the whole script body
        when poc.py is present (per-line python splitting is a future
        enhancement; one-step-per-python-script is the v1 contract)
      - attaches the captured stdout.log to the LAST step only (Phase 3
        stdout is whole-script, not per-line addressable)
      - attaches an absolute screenshot.png path to the LAST step when
        the bundle contains a screenshot; earlier steps get None
      - tolerates missing stdout.log (treats as empty)

Downstream plans (04-02 markdown, 04-03 PDF, 04-04 Obsidian, 04-05
dashboard route) import via `from sentinel.reporting import PocStep,
generate_poc_steps`. They render PocStep verbatim — they do NOT
re-derive the description string, so the auto-summary table below is
load-bearing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Union

from sentinel.core.findings import Finding, PocStep


# ---------------------------------------------------------------------------
# First-token -> human description mapping (POC-02 auto-summary contract)
# ---------------------------------------------------------------------------


_VERB_DESCRIPTIONS: dict[str, str] = {
    "curl": "Send the request with curl",
    "wget": "Send the request with wget",
    "http": "Send the request with http",   # httpie
    "python": "Run the Python PoC",
    "python3": "Run the Python PoC",
    "playwright": "Run the Playwright PoC",
    "sqlmap": "Run the sqlmap probe",
    "bash": "Run the shell command",
    "sh": "Run the shell command",
}


# Compiled once at import. Matches the FIRST non-whitespace token of a line.
_FIRST_TOKEN_RE = re.compile(r"\s*(\S+)")


def _describe_command(command: str) -> str:
    """Derive a one-sentence description from the command's first token.

    Mirrors Plan 04-01 <interfaces>:

        curl|wget|http  -> "Send the request with <verb>"
        python|python3  -> "Run the Python PoC"
        playwright      -> "Run the Playwright PoC"
        sqlmap          -> "Run the sqlmap probe"
        bash|sh         -> "Run the shell command"
        anything else   -> f"Run: {first_token}"
    """
    if not command:
        return "Run the command"
    m = _FIRST_TOKEN_RE.match(command)
    if not m:
        return "Run the command"
    token = m.group(1).lower()
    return _VERB_DESCRIPTIONS.get(token, f"Run: {token}")


def _parse_shell_commands(script: str) -> list[str]:
    """Split a shell script into top-level commands.

    Heuristic: each non-empty, non-comment-prefixed line is one command.
    Shebangs (`#!/bin/sh`) are dropped along with `#`-prefixed comments
    and blank lines. Indentation is preserved on retained lines (rare in
    a Phase-3 sandbox PoC but cheap to preserve).
    """
    out: list[str] = []
    for raw in script.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        out.append(stripped)
    return out


def _read_text_or_empty(path: Path) -> str:
    """Read a text file; return '' when missing or unreadable."""
    try:
        if path.is_file():
            return path.read_text()
    except OSError:
        pass
    return ""


def _build_steps(
    commands: Iterable[str],
    stdout: str,
    screenshot_path: str | None,
    *,
    description_override: str | None = None,
) -> list[PocStep]:
    """Assemble PocStep instances; attach stdout + screenshot to LAST step only.

    ``description_override`` is used for the python-bundle case where the
    command is the WHOLE script body (so the first-token heuristic would
    return whatever the script's first non-blank line happens to start
    with — e.g. ``import``, ``print``, ``from``). The caller knows the
    bundle language; the parser does not.
    """
    commands_list = list(commands)
    if not commands_list:
        return []
    steps: list[PocStep] = []
    last_idx = len(commands_list) - 1
    for i, cmd in enumerate(commands_list):
        if description_override is not None:
            desc = description_override
        else:
            desc = _describe_command(cmd)
        steps.append(
            PocStep(
                step_number=i + 1,
                description=desc,
                command=cmd,
                expected_output=stdout if i == last_idx else "",
                screenshot_path=screenshot_path if i == last_idx else None,
            )
        )
    return steps


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_poc_steps(
    finding: Finding,
    evidence_bundle_path: Union[Path, str],
) -> list[PocStep]:
    """Read a Phase 3 evidence bundle and return structured reproduction steps.

    Args:
        finding: The Finding the bundle belongs to. Currently unused by
            the v1 parser (the bundle is self-describing) but kept on the
            signature so future per-class step augmentation has the
            finding context without a breaking API change.
        evidence_bundle_path: Filesystem path to the bundle directory.
            Accepts Path or str; coerced internally.

    Returns:
        A possibly-empty list of PocStep. Empty when the bundle is
        missing OR is a refusal-only short-circuit OR neither poc.sh
        nor poc.py is on disk.
    """
    bundle = Path(evidence_bundle_path)

    # Missing-or-not-a-directory short-circuit. A path that exists but
    # is a file (e.g. operator pointed at the wrong thing) is treated
    # as "no bundle" rather than raising — the caller has already
    # decided what to do based on the empty list.
    if not bundle.is_dir():
        return []

    poc_sh = bundle / "poc.sh"
    poc_py = bundle / "poc.py"
    refusal = bundle / "refusal.txt"

    # Refusal-only short-circuit: classifier (Plan 03-03) or scope-gating
    # (Plan 03-04) refused to execute the PoC; there's nothing to
    # reproduce in a report. The bundle holds refusal.txt for operator
    # context only.
    if refusal.is_file() and not poc_sh.is_file() and not poc_py.is_file():
        return []

    # Neither PoC script present + no refusal — empty bundle (unexpected,
    # but defensive: still return [] rather than raise).
    if not poc_sh.is_file() and not poc_py.is_file():
        return []

    stdout = _read_text_or_empty(bundle / "stdout.log")

    screenshot_file = bundle / "screenshot.png"
    screenshot_path: str | None = (
        str(screenshot_file.resolve()) if screenshot_file.is_file() else None
    )

    # Prefer poc.sh when both are present — the sandbox writes only one
    # per language, but this keeps behavior deterministic if a future
    # version accidentally writes both.
    if poc_sh.is_file():
        commands = _parse_shell_commands(poc_sh.read_text())
        return _build_steps(commands, stdout, screenshot_path)

    # poc.py — single-step contract: the WHOLE script body is one
    # command. Preserve newlines verbatim so the rendered code block
    # in markdown/PDF/Obsidian shows the runnable script. Description
    # override: the parser knows the bundle language; without the
    # override the first-token heuristic would describe the script's
    # first non-blank line (e.g. ``import``, ``print``) instead of
    # surfacing that this is a Python PoC.
    py_script = poc_py.read_text()
    if not py_script.strip():
        return []
    return _build_steps(
        [py_script],
        stdout,
        screenshot_path,
        description_override=_VERB_DESCRIPTIONS["python"],
    )


__all__ = ["PocStep", "generate_poc_steps"]
