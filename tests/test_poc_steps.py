"""POC-02 — generate_poc_steps reads Phase 3 evidence bundles.

Hermetic — every fixture is built under tmp_path. Zero live network,
zero live subprocess, zero LLM. Test 11 monkeypatches subprocess.run
AND urllib.request.urlopen to raise on any call; the generator MUST
still succeed (proves the implementation is pure filesystem parsing).

The Phase 3 evidence bundle layout (frozen by Plan 03-04, see
sentinel/agent/poc/sandbox.py docstring) is:

    workspaces/<engagement>/verification/<finding_fingerprint>/
      ├── poc.sh                (shell + sqlmap PoCs)
      ├── poc.py                (python + playwright PoCs)
      ├── stdout.log
      ├── stderr.log
      ├── exit_code.txt
      ├── screenshot.png        (optional — Playwright only)
      └── refusal.txt           (ONLY for destructive / out-of-scope
                                 short-circuits; when present the poc.*
                                 + log files are absent)
"""

from __future__ import annotations

import subprocess
import urllib.request
from pathlib import Path

import pytest

from sentinel.core.findings import EvidenceState, Finding, PocStep, Severity
from sentinel.reporting import PocStep as PocStepReexport
from sentinel.reporting import generate_poc_steps
from sentinel.reporting.poc_steps import generate_poc_steps as direct_import


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _make_finding() -> Finding:
    return Finding(
        title="t",
        description="d",
        severity=Severity.LOW,
        scanner="s",
        target="https://example.com",
    )


def _make_bundle(
    tmp_path: Path,
    *,
    poc_sh: str | None = None,
    poc_py: str | None = None,
    stdout: str | None = None,
    exit_code: str = "0",
    screenshot: bool = False,
    refusal_only: bool = False,
) -> Path:
    """Materialize a Phase-3-shaped evidence bundle under tmp_path.

    Returns the bundle directory path. Callers pass exactly one of
    poc_sh or poc_py (or neither, for refusal_only).
    """
    bundle = tmp_path / "workspaces" / "eng-2026-01" / "verification" / "deadbeefcafebabe"
    bundle.mkdir(parents=True, exist_ok=True)

    if refusal_only:
        (bundle / "refusal.txt").write_text(
            "PoC refused by destructive classifier (Plan 03-03).\n"
            "Pattern: sql_drop_table\n"
        )
        return bundle

    if poc_sh is not None:
        (bundle / "poc.sh").write_text(poc_sh)
    if poc_py is not None:
        (bundle / "poc.py").write_text(poc_py)

    if stdout is not None:
        (bundle / "stdout.log").write_text(stdout)
    (bundle / "stderr.log").write_text("")
    (bundle / "exit_code.txt").write_text(exit_code)

    if screenshot:
        # 1x1 PNG-ish — content is irrelevant, only file presence is checked.
        (bundle / "screenshot.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    return bundle


# ---------------------------------------------------------------------------
# Re-export sanity
# ---------------------------------------------------------------------------


def test_sentinel_reporting_reexports_pocstep_and_generate():
    """The public surface lives at sentinel.reporting per the plan contract."""
    assert PocStepReexport is PocStep
    assert generate_poc_steps is direct_import


# ---------------------------------------------------------------------------
# 1: missing bundle
# ---------------------------------------------------------------------------


def test_generate_poc_steps_returns_empty_for_missing_bundle_path(tmp_path: Path):
    """Bundle dir does not exist -> [] (no error, no halt)."""
    missing = tmp_path / "no" / "such" / "bundle"
    assert generate_poc_steps(_make_finding(), missing) == []


# ---------------------------------------------------------------------------
# 2: refusal-only bundle
# ---------------------------------------------------------------------------


def test_generate_poc_steps_returns_empty_for_refusal_only_bundle(tmp_path: Path):
    """Bundle contains ONLY refusal.txt (destructive short-circuit) -> []."""
    bundle = _make_bundle(tmp_path, refusal_only=True)
    assert (bundle / "refusal.txt").is_file()
    assert not (bundle / "poc.sh").exists()
    assert not (bundle / "poc.py").exists()
    assert generate_poc_steps(_make_finding(), bundle) == []


# ---------------------------------------------------------------------------
# 3: shell single command
# ---------------------------------------------------------------------------


def test_generate_poc_steps_shell_single_command(tmp_path: Path):
    """poc.sh with one curl line -> 1 PocStep; expected_output carries stdout."""
    bundle = _make_bundle(
        tmp_path,
        poc_sh="curl -s https://example.com/api\n",
        stdout="HTTP/1.1 200 OK\n{\"email\":\"victim@example.com\"}\n",
    )
    steps = generate_poc_steps(_make_finding(), bundle)
    assert len(steps) == 1
    assert steps[0].step_number == 1
    assert "curl" in steps[0].command
    assert "victim@example.com" in steps[0].expected_output


# ---------------------------------------------------------------------------
# 4: shell multi-line
# ---------------------------------------------------------------------------


def test_generate_poc_steps_shell_multi_line(tmp_path: Path):
    """poc.sh with three commands -> 3 PocSteps; stdout attached to LAST step only."""
    bundle = _make_bundle(
        tmp_path,
        poc_sh=(
            "curl -s https://example.com/login -o /tmp/login.html\n"
            "echo done\n"
            "grep session_id /tmp/cookies\n"
        ),
        stdout="session_id=abc123\n",
    )
    steps = generate_poc_steps(_make_finding(), bundle)
    assert len(steps) == 3
    assert [s.step_number for s in steps] == [1, 2, 3]
    assert "curl" in steps[0].command
    assert "echo" in steps[1].command
    assert "grep" in steps[2].command
    # Phase 3 stdout is whole-script, not per-line addressable. Contract:
    # attach the captured stdout to the LAST step; earlier steps get ''.
    assert steps[0].expected_output == ""
    assert steps[1].expected_output == ""
    assert "session_id=abc123" in steps[2].expected_output


# ---------------------------------------------------------------------------
# 5: shell skips blank + comment lines
# ---------------------------------------------------------------------------


def test_generate_poc_steps_shell_skips_blank_and_comment_lines(tmp_path: Path):
    """Shebangs, blank lines, and # comments are all skipped."""
    bundle = _make_bundle(
        tmp_path,
        poc_sh=(
            "#!/bin/sh\n"
            "\n"
            "# this is a comment line\n"
            "curl -s https://example.com\n"
        ),
        stdout="ok\n",
    )
    steps = generate_poc_steps(_make_finding(), bundle)
    assert len(steps) == 1
    assert "curl" in steps[0].command
    # Shebang + comment must NOT appear in any emitted command.
    for step in steps:
        assert not step.command.startswith("#")


# ---------------------------------------------------------------------------
# 6: python single step
# ---------------------------------------------------------------------------


def test_generate_poc_steps_python_single_step(tmp_path: Path):
    """poc.py (no poc.sh) -> 1 PocStep whose command is the full script body."""
    py_script = (
        "import urllib.request\n"
        "req = urllib.request.Request('https://example.com/api')\n"
        "with urllib.request.urlopen(req) as resp:\n"
        "    print(resp.read().decode())\n"
    )
    bundle = _make_bundle(
        tmp_path,
        poc_py=py_script,
        stdout="{\"vuln\": true}\n",
    )
    steps = generate_poc_steps(_make_finding(), bundle)
    assert len(steps) == 1
    assert steps[0].step_number == 1
    # The WHOLE script body is the single command (multi-line, newlines preserved).
    assert steps[0].command == py_script
    assert "vuln" in steps[0].expected_output


# ---------------------------------------------------------------------------
# 7: screenshot attaches to FINAL step only
# ---------------------------------------------------------------------------


def test_generate_poc_steps_attaches_screenshot_to_final_step(tmp_path: Path):
    """When screenshot.png exists, FINAL step.screenshot_path is its absolute path."""
    bundle = _make_bundle(
        tmp_path,
        poc_py="print('hi')\n",
        stdout="hi\n",
        screenshot=True,
    )
    steps = generate_poc_steps(_make_finding(), bundle)
    assert len(steps) == 1
    final = steps[-1]
    assert final.screenshot_path is not None
    assert final.screenshot_path == str((bundle / "screenshot.png").resolve())


def test_generate_poc_steps_screenshot_only_on_final_step_when_multi_step(tmp_path: Path):
    """For multi-step shell + screenshot, earlier steps remain None; only LAST gets the path."""
    bundle = _make_bundle(
        tmp_path,
        poc_sh="curl https://example.com\necho done\n",
        stdout="ok\n",
        screenshot=True,
    )
    steps = generate_poc_steps(_make_finding(), bundle)
    assert len(steps) == 2
    assert steps[0].screenshot_path is None
    assert steps[1].screenshot_path == str((bundle / "screenshot.png").resolve())


# ---------------------------------------------------------------------------
# 8: no screenshot -> None
# ---------------------------------------------------------------------------


def test_generate_poc_steps_no_screenshot_returns_none(tmp_path: Path):
    """poc.sh, no screenshot.png -> final step's screenshot_path is None."""
    bundle = _make_bundle(
        tmp_path,
        poc_sh="curl https://example.com\n",
        stdout="ok\n",
        screenshot=False,
    )
    steps = generate_poc_steps(_make_finding(), bundle)
    assert len(steps) == 1
    assert steps[0].screenshot_path is None


# ---------------------------------------------------------------------------
# 9: empty stdout handled
# ---------------------------------------------------------------------------


def test_generate_poc_steps_empty_stdout_handled(tmp_path: Path):
    """Empty stdout.log -> expected_output == '' (NOT None — field is non-optional)."""
    bundle = _make_bundle(
        tmp_path,
        poc_sh="curl https://example.com -o /dev/null\n",
        stdout="",
    )
    steps = generate_poc_steps(_make_finding(), bundle)
    assert len(steps) == 1
    assert steps[0].expected_output == ""
    assert steps[0].expected_output is not None


def test_generate_poc_steps_missing_stdout_log_treated_as_empty(tmp_path: Path):
    """If stdout.log doesn't exist on disk, expected_output defaults to ''."""
    # Build a bundle WITHOUT stdout.log via the _make_bundle helper.
    bundle = tmp_path / "workspaces" / "eng-x" / "verification" / "fp"
    bundle.mkdir(parents=True)
    (bundle / "poc.sh").write_text("curl https://example.com\n")
    (bundle / "exit_code.txt").write_text("0")
    steps = generate_poc_steps(_make_finding(), bundle)
    assert len(steps) == 1
    assert steps[0].expected_output == ""


# ---------------------------------------------------------------------------
# 10: description derived from first token
# ---------------------------------------------------------------------------


def test_generate_poc_steps_description_derived_from_first_token_curl(tmp_path: Path):
    """curl ... -> description contains 'curl' (case-insensitive)."""
    bundle = _make_bundle(
        tmp_path, poc_sh="curl -s https://example.com\n", stdout="ok\n"
    )
    steps = generate_poc_steps(_make_finding(), bundle)
    assert "curl" in steps[0].description.lower()


def test_generate_poc_steps_description_derived_from_first_token_python(tmp_path: Path):
    """python ... -> description contains 'python' (case-insensitive)."""
    bundle = _make_bundle(
        tmp_path,
        poc_py="print('x')\n",
        stdout="x\n",
    )
    steps = generate_poc_steps(_make_finding(), bundle)
    assert "python" in steps[0].description.lower()


# ---------------------------------------------------------------------------
# 11: hermetic — no subprocess, no urllib
# ---------------------------------------------------------------------------


def test_generate_poc_steps_is_hermetic(tmp_path: Path, monkeypatch):
    """Monkeypatch subprocess.run + urlopen to raise; generator must still succeed.

    This is the load-bearing contract: the renderer pipeline must not
    re-fetch from the live network or re-execute the PoC. Anything that
    needs network/subprocess belongs in Phase 3.
    """

    def boom(*args, **kwargs):  # pragma: no cover — proves NOT called
        raise RuntimeError("network forbidden in hermetic test")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(urllib.request, "urlopen", boom)

    bundle = _make_bundle(
        tmp_path,
        poc_sh="curl -s https://example.com/api\n",
        stdout="ok\n",
    )
    steps = generate_poc_steps(_make_finding(), bundle)
    assert len(steps) == 1
    assert "curl" in steps[0].command


# ---------------------------------------------------------------------------
# Defensive: str path also accepted (callers may pass str from JSON)
# ---------------------------------------------------------------------------


def test_generate_poc_steps_accepts_string_bundle_path(tmp_path: Path):
    """Coerce str -> Path internally; callers don't have to pre-wrap."""
    bundle = _make_bundle(
        tmp_path,
        poc_sh="curl https://example.com\n",
        stdout="ok\n",
    )
    steps = generate_poc_steps(_make_finding(), str(bundle))
    assert len(steps) == 1
    assert "curl" in steps[0].command


# ---------------------------------------------------------------------------
# Belt-and-suspenders: bundle is a file (not a dir) -> []
# ---------------------------------------------------------------------------


def test_generate_poc_steps_returns_empty_when_path_is_not_directory(tmp_path: Path):
    """If the path exists but is a file, treat as missing bundle and return []."""
    pseudo = tmp_path / "not-a-dir"
    pseudo.write_text("hi")
    assert generate_poc_steps(_make_finding(), pseudo) == []
