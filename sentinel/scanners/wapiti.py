"""Wapiti scanner — wraps wapiti3 active web vulnerability scanner.

Wapiti crawls a target and probes for SQL injection, XSS, file inclusion,
command exec, XXE, SSRF, CRLF injection, weak authn, etc.

Install:
  pipx install wapiti3      # recommended (avoids polluting the project venv)
  # or: pip install wapiti3

Output: JSON report (`-f json -o <file>`). The report has a `vulnerabilities`
section keyed by category name, each containing instances with method, path,
parameter, info (the payload + http response evidence), and curl_command.
"""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import RateLimiter, Scanner, ScannerError


log = logging.getLogger(__name__)


# Wapiti's category → severity mapping. Wapiti doesn't tag severity per finding;
# we infer it from the vulnerability class.
_CATEGORY_SEVERITY = {
    "Backup file": Severity.LOW,
    "Blind SQL Injection": Severity.HIGH,
    "Buster": Severity.INFO,
    "Command execution": Severity.CRITICAL,
    "Content Security Policy Configuration": Severity.MEDIUM,
    "Cross Site Request Forgery": Severity.MEDIUM,
    "Cross Site Scripting": Severity.HIGH,
    "Fingerprint web technology": Severity.INFO,
    "Htaccess Bypass": Severity.MEDIUM,
    "HTTP Secure Headers": Severity.LOW,
    "HttpOnly Flag cookie": Severity.LOW,
    "Internal Server Error": Severity.LOW,
    "LDAP Injection": Severity.HIGH,
    "Open Redirect": Severity.MEDIUM,
    "Path Traversal": Severity.HIGH,
    "Potentially dangerous file": Severity.MEDIUM,
    "Resource consumption": Severity.MEDIUM,
    "Secure Flag cookie": Severity.LOW,
    "Server Side Request Forgery": Severity.HIGH,
    "SQL Injection": Severity.HIGH,
    "Subdomain takeover": Severity.HIGH,
    "Unrestricted File Upload": Severity.HIGH,
    "XML External Entity": Severity.HIGH,
}


# Wapiti category → CWE mapping (best-effort; covers the common ones).
_CATEGORY_CWE = {
    "SQL Injection": "CWE-89",
    "Blind SQL Injection": "CWE-89",
    "Cross Site Scripting": "CWE-79",
    "Cross Site Request Forgery": "CWE-352",
    "Command execution": "CWE-78",
    "Path Traversal": "CWE-22",
    "XML External Entity": "CWE-611",
    "LDAP Injection": "CWE-90",
    "Open Redirect": "CWE-601",
    "Server Side Request Forgery": "CWE-918",
    "Unrestricted File Upload": "CWE-434",
    "Subdomain takeover": "CWE-1395",
    "Content Security Policy Configuration": "CWE-1021",
    "HTTP Secure Headers": "CWE-693",
    "HttpOnly Flag cookie": "CWE-1004",
    "Secure Flag cookie": "CWE-614",
}


class WapitiScanner(Scanner):
    tool_name = "wapiti"
    description = "Active web vulnerability scanner (Wapiti)"

    def run(
        self,
        scope: Scope,
        target: str,
        deep: bool = False,
        repo_url: Optional[str] = None,
        **_opts,
    ) -> list[Finding]:
        scope.authorize_url(target)

        rl = RateLimiter(scope.rate_limit_rps)
        rl.wait()

        with tempfile.TemporaryDirectory(prefix="sentinel-wapiti-") as tmp:
            out_dir = Path(tmp)
            json_path = out_dir / "wapiti-report.json"
            argv = [
                "wapiti",
                "-u", target,
                "-f", "json",
                "-o", str(json_path),
                "--flush-session",
            ]
            if not deep:
                # Default: just the high-impact module set, faster.
                argv.extend(["-m", "sql,xss,exec,xxe,ssrf,redirect,permanentxss"])
            # Otherwise let wapiti use its full module list.

            proc = None
            try:
                proc = self._run_subprocess(argv, cwd=out_dir, timeout=60 * 60 * 2)
            except ScannerError as e:
                log.warning("wapiti returned non-zero (often expected): %s", e)

            if not json_path.is_file():
                tail = ""
                if proc is not None:
                    tail = ((proc.stderr or "") + (proc.stdout or ""))[-400:].strip()
                log.warning("wapiti: no report produced. stdout tail: %s", tail or "<empty>")
                return []

            try:
                data = json.loads(json_path.read_text())
            except json.JSONDecodeError as e:
                raise ScannerError(f"wapiti: invalid JSON: {e}") from e

            findings = self._parse_report(target, data)
            if not findings:
                # Surface report shape so we can tell "honest 0" from silent
                # failure. Wapiti returns 0 when the crawler hit nothing
                # (small static site, login-walled, robots blocked, etc.)
                # OR when --flush-session corrupts the run.
                size = json_path.stat().st_size
                vulns = data.get("vulnerabilities") or {}
                cat_summary = ", ".join(f"{k}={len(v or [])}" for k, v in vulns.items())
                infos = data.get("infos") or {}
                paths_crawled = infos.get("crawled_pages_nbr", "?")
                stdout_tail = ""
                if proc is not None:
                    stdout_tail = ((proc.stderr or "") + (proc.stdout or ""))[-400:].strip()
                log.warning(
                    "wapiti: 0 findings parsed (json=%dB, crawled=%s pages, exit=%s). "
                    "categories: %s. stdout tail: %s",
                    size, paths_crawled,
                    proc.returncode if proc else "?",
                    cat_summary or "<none>",
                    stdout_tail or "<empty>",
                )
            return findings

    def _parse_report(self, target: str, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        vulns = data.get("vulnerabilities") or {}
        for category, items in vulns.items():
            if not items:
                continue
            sev = _CATEGORY_SEVERITY.get(category, Severity.MEDIUM)
            cwe = _CATEGORY_CWE.get(category)
            for item in items:
                findings.append(
                    Finding(
                        title=f"{category}: {item.get('info', category)[:80]}",
                        description=item.get("info") or category,
                        severity=sev,
                        scanner="wapiti",
                        target=target,
                        location=item.get("path") or target,
                        cwe=cwe,
                        references=item.get("references") or [],
                        raw={
                            "method": item.get("method"),
                            "param": item.get("parameter"),
                            "request": item.get("http_request"),
                            "response": item.get("info"),  # wapiti embeds evidence in info
                            "curl-command": item.get("curl_command"),
                            "level": item.get("level"),
                        },
                    )
                )
        return findings
