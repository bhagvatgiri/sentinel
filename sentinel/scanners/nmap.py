"""Nmap scanner — wraps nmap with the NSE `vuln` script category.

Two modes:
  - default: `nmap --script vuln -sV` (service detection + vuln scripts on
             open ports). Moderate speed, decent coverage.
  - deep:    adds `-A` (OS detection + traceroute) and `-p-` (all 65535 ports).
             Much slower; appropriate for thorough engagements.

Install: `brew install nmap` (or apt/dnf equivalent).

Output: XML via `-oX -` (parsed in-process with xml.etree). Each `<host>` has
`<ports><port>` entries and the `vuln` scripts attach `<script>` children with
output text and per-CVE `<table>` data. We map each script-with-output to a
Finding (one per script per port).
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import RateLimiter, Scanner, ScannerError


log = logging.getLogger(__name__)


# Heuristic: script names containing these tokens map to higher severities.
_SCRIPT_SEVERITY_HINTS = [
    (re.compile(r"^http-shellshock|^smb-vuln-ms17-010|cve-2017-5638", re.I), Severity.CRITICAL),
    (re.compile(r"^http-sql-injection|^http-stored-xss|cve-202[0-9]", re.I), Severity.HIGH),
    (re.compile(r"^http-csrf|^http-cookie-flags|^smb-vuln-", re.I), Severity.MEDIUM),
    (re.compile(r"^http-enum|^banner|^http-title|^http-server-header", re.I), Severity.INFO),
]


def _severity_for(script_id: str, output: str) -> Severity:
    for pat, sev in _SCRIPT_SEVERITY_HINTS:
        if pat.search(script_id) or pat.search(output):
            return sev
    if "VULNERABLE" in output.upper():
        return Severity.HIGH
    return Severity.LOW


def _host_of(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target


class NmapScanner(Scanner):
    tool_name = "nmap"
    description = "Service + NSE vuln-category scan (Nmap)"

    def run(
        self,
        scope: Scope,
        target: str,
        deep: bool = False,
        repo_url: Optional[str] = None,
        **_opts,
    ) -> list[Finding]:
        # nmap takes a hostname/IP. Use scope.authorize_url to log + check.
        scope.authorize_url(target if "://" in target else f"https://{target}")
        host = _host_of(target)

        rl = RateLimiter(scope.rate_limit_rps)
        rl.wait()

        with tempfile.TemporaryDirectory(prefix="sentinel-nmap-") as tmp:
            xml_path = Path(tmp) / "nmap.xml"
            argv = [
                "nmap",
                "--script", "vuln",
                "-sV",  # service version detection
                "-oX", str(xml_path),
            ]
            if deep:
                argv.extend(["-A", "-p-"])  # OS detection + all ports
            argv.append(host)

            timeout = 60 * 60 * 2 if deep else 60 * 30
            try:
                self._run_subprocess(argv, timeout=timeout)
            except ScannerError as e:
                log.warning("nmap returned non-zero (may still have output): %s", e)

            if not xml_path.is_file():
                log.warning("nmap: no XML report produced")
                return []
            return self._parse_xml(host, xml_path)

    def _parse_xml(self, host: str, xml_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError as e:
            raise ScannerError(f"nmap: invalid XML output: {e}") from e

        for host_el in root.findall("host"):
            for port_el in host_el.findall("ports/port"):
                portid = port_el.get("portid", "?")
                protocol = port_el.get("protocol", "?")
                state_el = port_el.find("state")
                state = state_el.get("state", "?") if state_el is not None else "?"
                if state != "open":
                    continue
                service_el = port_el.find("service")
                service = service_el.get("name", "?") if service_el is not None else "?"
                version_parts = []
                if service_el is not None:
                    for k in ("product", "version", "extrainfo"):
                        v = service_el.get(k)
                        if v:
                            version_parts.append(v)
                version = " ".join(version_parts)
                location = f"{host}:{portid}/{protocol} ({service}{(' ' + version) if version else ''})"

                for script_el in port_el.findall("script"):
                    script_id = script_el.get("id", "?")
                    output = script_el.get("output", "").strip()
                    if not output:
                        continue
                    cves = re.findall(r"CVE-\d{4}-\d+", output, flags=re.I)
                    cve = cves[0].upper() if cves else None
                    sev = _severity_for(script_id, output)
                    findings.append(
                        Finding(
                            title=f"nmap {script_id} on {service}:{portid}",
                            description=output[:1000],
                            severity=sev,
                            scanner="nmap",
                            target=host,
                            location=location,
                            cve=cve,
                            raw={
                                "script_id": script_id,
                                "port": portid,
                                "protocol": protocol,
                                "service": service,
                                "version": version,
                                "response": output,  # the nmap script output IS the evidence
                                "all_cves": cves,
                            },
                        )
                    )
        return findings
