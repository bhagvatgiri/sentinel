"""Subdomain enumeration — subfinder (default) + amass passive (--deep).

subfinder uses 30+ passive sources (CT logs, DNS aggregators, search engines).
amass adds active brute-force resolution when in --deep mode.

Install:
  brew install subfinder
  brew install amass

Output: each tool emits one subdomain per line. We wrap each as an
info-level Finding so they appear in run reports and the UI Findings page.
This gives the user a single place to see "what's the attack surface for
this domain right now" alongside actual vulnerabilities.
"""

from __future__ import annotations

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


def _apex_of(target: str) -> str:
    """Strip scheme/path/port to a bare domain suitable for subdomain enum."""
    if "://" in target:
        host = urlparse(target).hostname or target
    else:
        host = target
    return host.split(":")[0].rstrip(".")


class SubdomainScanner(Scanner):
    tool_name = "subfinder"
    description = "Passive subdomain enumeration (subfinder + amass)"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        if shutil.which("subfinder"):
            return True, shutil.which("subfinder")
        if shutil.which("amass"):
            return True, shutil.which("amass")
        return False, "subfinder / amass not on PATH (brew install subfinder amass)"

    def run(
        self,
        scope: Scope,
        target: str,
        deep: bool = False,
        repo_url: Optional[str] = None,
        **_opts,
    ) -> list[Finding]:
        # We're not making requests TO the target — we're querying public DBs
        # ABOUT it. But we still authorize the apex so the audit log records it.
        scope.authorize_url(f"https://{_apex_of(target)}")
        rl = RateLimiter(scope.rate_limit_rps)
        rl.wait()

        apex = _apex_of(target)
        all_subs: set[str] = set()

        if shutil.which("subfinder"):
            all_subs.update(self._run_subfinder(apex))
        if deep and shutil.which("amass"):
            all_subs.update(self._run_amass(apex))

        if not all_subs:
            log.info("subdomains: none discovered for %s", apex)
            return []

        return [self._sub_to_finding(apex, sub) for sub in sorted(all_subs)]

    def _run_subfinder(self, apex: str) -> set[str]:
        with tempfile.TemporaryDirectory(prefix="sentinel-subfinder-") as tmp:
            out_path = Path(tmp) / "subs.txt"
            argv = ["subfinder", "-d", apex, "-silent", "-o", str(out_path)]
            try:
                self._run_subprocess(argv, timeout=10 * 60)
            except ScannerError as e:
                log.warning("subfinder error: %s", e)
                return set()
            if not out_path.is_file():
                return set()
            return {line.strip() for line in out_path.read_text().splitlines() if line.strip()}

    def _run_amass(self, apex: str) -> set[str]:
        with tempfile.TemporaryDirectory(prefix="sentinel-amass-") as tmp:
            out_path = Path(tmp) / "subs.txt"
            # `amass enum -passive` is way faster than the default active mode.
            argv = ["amass", "enum", "-passive", "-d", apex, "-o", str(out_path)]
            try:
                self._run_subprocess(argv, timeout=20 * 60)
            except ScannerError as e:
                log.warning("amass error: %s", e)
                return set()
            if not out_path.is_file():
                return set()
            return {line.strip() for line in out_path.read_text().splitlines() if line.strip()}

    def _sub_to_finding(self, apex: str, sub: str) -> Finding:
        return Finding(
            title=f"Subdomain discovered: {sub}",
            description=(
                f"Passive enumeration found {sub} as a subdomain of {apex}. "
                "Visible attack surface; consider whether it should be public, "
                "behind auth, or removed."
            ),
            severity=Severity.INFO,
            scanner="subdomains",
            target=apex,
            location=sub,
            raw={"apex": apex, "subdomain": sub},
        )
