"""Repository scanners — Semgrep (SAST) and Gitleaks (secrets)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import Scanner, ScannerError


class SemgrepScanner(Scanner):
    """Static analysis with Semgrep. Uses the 'auto' ruleset by default."""

    tool_name = "semgrep"
    description = "SAST via Semgrep (community + p/security-audit rulesets)"

    def run(
        self,
        scope: Scope,
        target: str,
        config: str = "p/security-audit",
        repo_url: Optional[str] = None,
        **_opts,
    ) -> list[Finding]:
        repo_path = Path(target).resolve()
        if not repo_path.exists():
            raise ScannerError(f"Path does not exist: {repo_path}")

        # Authorize against the repo URL if provided, else against path as artifact.
        if repo_url:
            scope.authorize_repo(repo_url)
        else:
            scope.authorize_artifact("repo_path", str(repo_path))

        argv = [
            self.tool_name,
            "--config", config,
            "--json",
            "--quiet",
            "--no-git-ignore",  # scan everything in scope
            str(repo_path),
        ]
        proc = self._run_subprocess(argv, timeout=900)
        if not proc.stdout:
            return []
        data = self._parse_json(proc.stdout)
        if not isinstance(data, dict):
            return []

        findings: list[Finding] = []
        for r in data.get("results", []):
            extra = r.get("extra", {}) or {}
            metadata = extra.get("metadata", {}) or {}
            sev = Severity.from_string(extra.get("severity"))
            cwe = _first(metadata.get("cwe"))
            owasp = _first(metadata.get("owasp"))

            file_ = r.get("path", "?")
            start = r.get("start", {}) or {}
            line = start.get("line")
            location = f"{file_}:{line}" if line else file_

            findings.append(
                Finding(
                    title=r.get("check_id", "semgrep finding"),
                    description=(extra.get("message") or "").strip(),
                    severity=sev,
                    scanner="semgrep",
                    target=str(repo_path),
                    location=location,
                    cwe=cwe,
                    references=_collect_refs(metadata, owasp),
                    raw=r,
                )
            )
        return findings


class GitleaksScanner(Scanner):
    """Secret detection with Gitleaks (default ruleset)."""

    tool_name = "gitleaks"
    description = "Secret scanning via Gitleaks"

    def run(
        self,
        scope: Scope,
        target: str,
        repo_url: Optional[str] = None,
        scan_history: bool = True,
        **_opts,
    ) -> list[Finding]:
        repo_path = Path(target).resolve()
        if not repo_path.exists():
            raise ScannerError(f"Path does not exist: {repo_path}")

        if repo_url:
            scope.authorize_repo(repo_url)
        else:
            scope.authorize_artifact("repo_path", str(repo_path))

        # Use 'detect' for full-history scan, 'dir' for working-tree only.
        # We write to a temp file because gitleaks JSON output to stdout has been
        # inconsistent across versions; report-format=json + report-path is stable.
        report = repo_path.parent / f".gitleaks-{repo_path.name}.json"
        try:
            mode = "detect" if scan_history and (repo_path / ".git").exists() else "dir"
            argv = [
                self.tool_name,
                mode,
                "--source", str(repo_path),
                "--report-format", "json",
                "--report-path", str(report),
                "--no-banner",
                "--exit-code", "0",  # don't fail just because secrets exist
            ]
            self._run_subprocess(argv, timeout=600)
            if not report.exists():
                return []
            data = json.loads(report.read_text() or "[]")
        finally:
            if report.exists():
                report.unlink()

        findings: list[Finding] = []
        for item in data or []:
            file_ = item.get("File", "?")
            line = item.get("StartLine") or item.get("LineNumber")
            location = f"{file_}:{line}" if line else file_
            rule = item.get("RuleID") or item.get("Description") or "secret"
            findings.append(
                Finding(
                    title=f"Possible secret: {rule}",
                    description=item.get("Description") or "Potential secret detected.",
                    severity=Severity.HIGH,
                    scanner="gitleaks",
                    target=str(repo_path),
                    location=location,
                    raw=item,
                )
            )
        return findings


# ---- helpers --------------------------------------------------------------


def _first(val):
    if isinstance(val, list) and val:
        return str(val[0])
    if val:
        return str(val)
    return None


def _collect_refs(metadata: dict, owasp: Optional[str]) -> list[str]:
    refs: list[str] = []
    for key in ("references", "source-rule-url"):
        v = metadata.get(key)
        if isinstance(v, list):
            refs.extend(str(x) for x in v)
        elif v:
            refs.append(str(v))
    if owasp:
        refs.append(f"OWASP:{owasp}")
    return refs
