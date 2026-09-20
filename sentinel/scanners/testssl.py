"""testssl.sh — deep TLS analysis (cipher hygiene, vulns, cert issues).

Way more thorough than the pure-Python `tls-audit` scanner. Tests for:
  - Heartbleed, CCS injection, ROBOT, BREACH, FREAK, LOGJAM, BEAST, etc.
  - Cipher suite weakness (RC4, NULL, EXPORT, anon, MD5)
  - Certificate validity, chain trust, OCSP, CT
  - Protocol versions enabled (SSLv2/3, TLS1.0/1.1)
  - Forward secrecy, session resumption
  - Headers presence (HSTS, HPKP, etc.)

Install:
  brew install testssl

Output: JSON-lines via `--jsonfile-pretty=- --quiet`. Each finding has
`id`, `severity` (HIGH/MEDIUM/LOW/INFO/CRITICAL/OK/WARN), `finding`, `cve`.
"""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import RateLimiter, Scanner, ScannerError


log = logging.getLogger(__name__)


_TESTSSL_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "WARN": Severity.LOW,
    "INFO": Severity.INFO,
    "OK": Severity.INFO,  # we still emit these but as INFO; UI filters can hide
}


def _hostport(target: str) -> str:
    if "://" in target:
        u = urlparse(target)
        host = u.hostname or target
        port = u.port or 443
        return f"{host}:{port}"
    if ":" in target:
        return target
    return f"{target}:443"


class TestSSLScanner(Scanner):
    tool_name = "testssl"
    description = "Deep TLS analysis (testssl.sh)"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        for c in ("testssl", "testssl.sh"):
            p = shutil.which(c)
            if p:
                return True, p
        return False, "testssl(.sh) not on PATH (brew install testssl)"

    def run(
        self,
        scope: Scope,
        target: str,
        deep: bool = False,
        repo_url: Optional[str] = None,
        **_opts,
    ) -> list[Finding]:
        scope.authorize_url(target if "://" in target else f"https://{target}")
        rl = RateLimiter(scope.rate_limit_rps)
        rl.wait()

        binary = shutil.which("testssl") or shutil.which("testssl.sh") or "testssl"
        endpoint = _hostport(target)

        with tempfile.TemporaryDirectory(prefix="sentinel-testssl-") as tmp:
            json_path = Path(tmp) / "testssl.json"
            argv = [binary, "--jsonfile-pretty", str(json_path), "--quiet"]
            if not deep:
                # Shorter run: skip slow vulnerability suite by default.
                argv.extend(["--protocols", "--cipher-per-proto", "--server-defaults",
                             "--server-preference", "--headers"])
            else:
                argv.append("--full")  # slow but thorough
                argv.extend(["--severity", "LOW"])
            argv.append(endpoint)

            timeout = 60 * 60 if deep else 30 * 60
            try:
                self._run_subprocess(argv, timeout=timeout)
            except ScannerError as e:
                log.warning("testssl error (may still have output): %s", e)

            if not json_path.is_file():
                return []
            try:
                data = json.loads(json_path.read_text())
            except json.JSONDecodeError as e:
                raise ScannerError(f"testssl: invalid JSON: {e}") from e
            return self._parse(target, endpoint, data)

    def _parse(self, target: str, endpoint: str, data) -> list[Finding]:
        # testssl --jsonfile-pretty emits a list of finding records.
        records = data if isinstance(data, list) else (data.get("scanResult") or [])
        findings: list[Finding] = []
        for r in records:
            sev_str = (r.get("severity") or "INFO").upper()
            if sev_str == "OK":
                continue  # don't surface "OK" entries as findings
            sev = _TESTSSL_SEVERITY.get(sev_str, Severity.INFO)
            check_id = r.get("id") or "?"
            finding_text = r.get("finding") or check_id
            cve = r.get("cve") or None
            cwe_str = r.get("cwe") or None
            cwe = None
            if cwe_str and isinstance(cwe_str, str) and cwe_str.upper().startswith("CWE-"):
                cwe = cwe_str.upper()
            findings.append(
                Finding(
                    title=f"testssl {check_id}: {finding_text[:80]}",
                    description=finding_text,
                    severity=sev,
                    scanner="testssl",
                    target=target,
                    location=endpoint,
                    cwe=cwe,
                    cve=cve.split()[0] if cve else None,
                    raw={
                        "testssl_id": check_id,
                        "testssl_severity": sev_str,
                        "ip": r.get("ip"),
                        "port": r.get("port"),
                        "response": finding_text,
                    },
                )
            )
        return findings
