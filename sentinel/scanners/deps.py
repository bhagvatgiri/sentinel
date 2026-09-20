"""Dependency / supply-chain scanner via OSV-Scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import Scanner, ScannerError


class OSVScanner(Scanner):
    tool_name = "osv-scanner"
    description = "Dependency CVE / supply-chain analysis via OSV-Scanner"

    def run(
        self,
        scope: Scope,
        target: str,
        repo_url: Optional[str] = None,
        **_opts,
    ) -> list[Finding]:
        path = Path(target).resolve()
        if not path.exists():
            raise ScannerError(f"Path does not exist: {path}")

        if repo_url:
            scope.authorize_repo(repo_url)
        else:
            scope.authorize_artifact("dependencies", str(path))

        argv = [self.tool_name, "--format", "json", "-r", str(path)]
        proc = self._run_subprocess(argv, timeout=600)
        if not proc.stdout:
            return []
        data = self._parse_json(proc.stdout)
        if not isinstance(data, dict):
            return []

        findings: list[Finding] = []
        for result in data.get("results", []):
            source = (result.get("source") or {}).get("path", "?")
            for pkg in result.get("packages", []):
                package_info = pkg.get("package", {}) or {}
                pkg_name = package_info.get("name", "?")
                pkg_ver = package_info.get("version", "?")
                ecosystem = package_info.get("ecosystem", "?")
                for vuln in pkg.get("vulnerabilities", []):
                    vuln_id = vuln.get("id", "?")
                    aliases = vuln.get("aliases", []) or []
                    cve = next((a for a in aliases if a.startswith("CVE-")), None)
                    severity = _osv_severity(vuln)
                    refs = [r.get("url") for r in vuln.get("references", []) if r.get("url")]
                    findings.append(
                        Finding(
                            title=f"{pkg_name} {pkg_ver}: {vuln_id}",
                            description=vuln.get("summary") or vuln.get("details", ""),
                            severity=severity,
                            scanner="osv-scanner",
                            target=str(path),
                            location=source,
                            cve=cve,
                            references=refs,
                            raw={"package": package_info, "vulnerability": vuln, "ecosystem": ecosystem},
                        )
                    )
        return findings


def _osv_severity(vuln: dict) -> Severity:
    """Pull a CVSS-ish severity from OSV output. Falls back to MEDIUM."""
    db = vuln.get("database_specific") or {}
    sev = db.get("severity")
    if isinstance(sev, str):
        return Severity.from_string(sev)
    for s in vuln.get("severity", []) or []:
        score = s.get("score") or ""
        # CVSS vector strings — try to read the base score if present.
        if "/" in score:
            # crude: assume vector — bucket by vector substring
            if "/AV:N/" in score and ("/I:H/" in score or "/A:H/" in score or "/C:H/" in score):
                return Severity.HIGH
        try:
            v = float(score)
            if v >= 9.0:
                return Severity.CRITICAL
            if v >= 7.0:
                return Severity.HIGH
            if v >= 4.0:
                return Severity.MEDIUM
            return Severity.LOW
        except ValueError:
            continue
    return Severity.MEDIUM
