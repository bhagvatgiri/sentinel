"""IaC / config scanners — Checkov (Terraform/K8s/CFN/ARM) and Trivy (configs + images)."""

from __future__ import annotations

from pathlib import Path

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import Scanner, ScannerError


class CheckovScanner(Scanner):
    tool_name = "checkov"
    description = "IaC misconfiguration scanning via Checkov"

    def run(self, scope: Scope, target: str, **_opts) -> list[Finding]:
        path = Path(target).resolve()
        if not path.exists():
            raise ScannerError(f"Path does not exist: {path}")
        scope.authorize_artifact("iac_config", str(path))

        argv = [self.tool_name, "-d", str(path), "-o", "json", "--quiet", "--soft-fail"]
        proc = self._run_subprocess(argv, timeout=900)
        if not proc.stdout:
            return []
        data = self._parse_json(proc.stdout)

        # Checkov returns either dict (single framework) or list (multi).
        runs = data if isinstance(data, list) else [data]
        findings: list[Finding] = []
        for run in runs:
            if not isinstance(run, dict):
                continue
            results = (run.get("results") or {}).get("failed_checks") or []
            for c in results:
                file_ = c.get("file_path", "?")
                line_range = c.get("file_line_range") or []
                line = line_range[0] if line_range else None
                location = f"{file_}:{line}" if line else file_
                sev = Severity.from_string(c.get("severity"))
                findings.append(
                    Finding(
                        title=f"{c.get('check_id', 'CKV')}: {c.get('check_name', 'misconfiguration')}",
                        description=c.get("check_name", ""),
                        severity=sev,
                        scanner="checkov",
                        target=str(path),
                        location=location,
                        references=[g for g in [c.get("guideline")] if g],
                        raw=c,
                    )
                )
        return findings


class TrivyConfigScanner(Scanner):
    tool_name = "trivy"
    description = "Config & filesystem scanning via Trivy"

    def run(self, scope: Scope, target: str, scan_type: str = "config", **_opts) -> list[Finding]:
        path = Path(target).resolve()
        if not path.exists():
            raise ScannerError(f"Path does not exist: {path}")
        scope.authorize_artifact(f"trivy_{scan_type}", str(path))

        if scan_type not in ("config", "fs"):
            raise ScannerError(f"Unsupported trivy scan_type: {scan_type}")

        argv = [self.tool_name, scan_type, "--format", "json", "--quiet", str(path)]
        proc = self._run_subprocess(argv, timeout=900)
        if not proc.stdout:
            return []
        data = self._parse_json(proc.stdout)
        if not isinstance(data, dict):
            return []

        findings: list[Finding] = []
        for r in data.get("Results", []):
            target_name = r.get("Target", "?")
            for misconf in r.get("Misconfigurations", []) or []:
                sev = Severity.from_string(misconf.get("Severity"))
                findings.append(
                    Finding(
                        title=f"{misconf.get('ID', 'misconfig')}: {misconf.get('Title', '')}",
                        description=misconf.get("Description", ""),
                        severity=sev,
                        scanner="trivy",
                        target=str(path),
                        location=target_name,
                        references=misconf.get("References", []) or [],
                        raw=misconf,
                    )
                )
            for vuln in r.get("Vulnerabilities", []) or []:
                sev = Severity.from_string(vuln.get("Severity"))
                cvss_score = None
                cvss_data = vuln.get("CVSS") or {}
                for vendor in cvss_data.values():
                    if isinstance(vendor, dict) and "V3Score" in vendor:
                        cvss_score = vendor["V3Score"]
                        break
                findings.append(
                    Finding(
                        title=f"{vuln.get('PkgName', '?')}: {vuln.get('VulnerabilityID', '?')}",
                        description=vuln.get("Title") or vuln.get("Description", ""),
                        severity=sev,
                        scanner="trivy",
                        target=str(path),
                        location=target_name,
                        cve=vuln.get("VulnerabilityID"),
                        cvss=cvss_score,
                        references=vuln.get("References", []) or [],
                        raw=vuln,
                    )
                )
        return findings
