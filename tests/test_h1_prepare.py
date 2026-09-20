"""ENG-04/05/06 regression tests for `sentinel.h1.prepare`.

Hermetic — uses tmp_path for all I/O, a FakeScope class with just
`authorize_url(url)` for the scope-gating test (no real Scope.load /
audit log). Tests cover:

  - Curl extraction from fenced ```bash / ```sh / ```http blocks.
  - Evidence-dir bundling into <stem>-evidence.tar.gz.
  - Returns (curls_path, None) when no sibling evidence/ dir exists.
  - Scope-gating: in-scope curls remain as runnable lines; out-of-scope
    curls are replaced with `# OUT-OF-SCOPE: <url> — dropped` comments.
"""

from __future__ import annotations

import os
import tarfile
from pathlib import Path


def _write_basic_report(tmp_path: Path) -> Path:
    """Report with two curl blocks (bash + sh)."""
    md = tmp_path / "01-test.md"
    md.write_text(
        "# Test Report\n\n"
        "**Status:** drafted\n\n"
        "Reproduction:\n\n"
        "```bash\n"
        "curl https://example.com/a\n"
        "```\n\n"
        "Verification:\n\n"
        "```sh\n"
        'curl -i "https://example.com/b?x=1"\n'
        "```\n"
    )
    return md


def test_prepare_extracts_curls(tmp_path: Path):
    from sentinel.h1.prepare import prepare

    rep = _write_basic_report(tmp_path)
    curls_path, tarball_path = prepare(rep)

    assert curls_path.is_file()
    body = curls_path.read_text()
    # Shebang.
    assert body.startswith("#!/usr/bin/env bash")
    # Both curl lines extracted.
    assert "https://example.com/a" in body
    assert "https://example.com/b?x=1" in body
    # Executable bit.
    mode = os.stat(curls_path).st_mode & 0o777
    assert mode & 0o100  # owner exec


def test_prepare_bundles_evidence_dir(tmp_path: Path):
    """When a sibling evidence/ dir exists, prepare creates a tarball
    listing its contents."""
    from sentinel.h1.prepare import prepare

    rep = _write_basic_report(tmp_path)
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "screenshot1.png").write_bytes(b"\x89PNG fake")
    (ev / "log.txt").write_text("log contents\n")

    curls_path, tarball_path = prepare(rep)
    assert tarball_path is not None
    assert tarball_path.is_file()
    with tarfile.open(tarball_path, "r:gz") as tar:
        members = tar.getnames()
    # Files (whatever the path inside, names should appear).
    assert any(m.endswith("screenshot1.png") for m in members)
    assert any(m.endswith("log.txt") for m in members)


def test_prepare_returns_paths_when_no_evidence_dir(tmp_path: Path):
    """No sibling evidence/ → tarball_path is None, curls_path returned."""
    from sentinel.h1.prepare import prepare

    rep = _write_basic_report(tmp_path)
    curls_path, tarball_path = prepare(rep)
    assert curls_path.is_file()
    assert tarball_path is None


def test_prepare_scope_gates_curls(tmp_path: Path):
    """The critical scope-gating test (T-02-01-03).

    A FakeScope's `authorize_url` accepts the in-scope host and raises
    OutOfScopeError for the out-of-scope host. The generated curls.sh
    MUST contain:
      - the in-scope curl line AS A RUNNABLE COMMAND (no '#' prefix),
      - the out-of-scope line REPLACED with `# OUT-OF-SCOPE: <url> — dropped`,
        and NO runnable line referencing the out-of-scope host.
    """
    from sentinel.core.scope import OutOfScopeError
    from sentinel.h1.prepare import prepare

    rep = tmp_path / "01-test.md"
    rep.write_text(
        "# Mixed\n\n"
        "```bash\n"
        "curl https://in-scope.example.com/safe\n"
        "curl https://out-of-scope.example.com/danger\n"
        "```\n"
    )

    class FakeScope:
        def authorize_url(self, url: str) -> None:
            if "out-of-scope" in url:
                raise OutOfScopeError(f"out of scope: {url}")
            # in-scope → no-op (returns None like the real Scope).

    curls_path, _ = prepare(rep, scope=FakeScope())
    body = curls_path.read_text()
    lines = body.splitlines()

    # In-scope curl present as a runnable command (not a comment).
    runnable_lines = [
        ln for ln in lines
        if "curl " in ln and not ln.lstrip().startswith("#")
    ]
    in_scope_runnable = [ln for ln in runnable_lines if "in-scope.example.com" in ln]
    assert len(in_scope_runnable) == 1, (
        f"expected exactly 1 in-scope runnable curl, got "
        f"{len(in_scope_runnable)}: {in_scope_runnable}"
    )

    # Out-of-scope appears ONLY as a comment marker, never as a runnable line.
    out_of_scope_runnable = [
        ln for ln in runnable_lines if "out-of-scope.example.com" in ln
    ]
    assert out_of_scope_runnable == [], (
        f"out-of-scope curl leaked into the runnable script: "
        f"{out_of_scope_runnable}"
    )
    assert any(
        "# OUT-OF-SCOPE:" in ln and "out-of-scope.example.com" in ln
        for ln in lines
    ), "missing the `# OUT-OF-SCOPE: ...` replacement comment"
