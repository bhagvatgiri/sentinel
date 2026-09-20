"""Kiterunner — API endpoint discovery via wordlist + content-aware probing.

Kiterunner is purpose-built for discovering REST API routes (GET/POST/PUT/DELETE
with sensible default bodies and headers per route schema). Much smarter than
generic dirbusters when the target is an API.

Install:
  brew install kiterunner   # if available
  # or build from source: github.com/assetnote/kiterunner

Wordlists: kiterunner uses `.kite` files (compiled API route schemas).
Common locations:
  - $KITE_WORDLIST env var
  - /opt/homebrew/share/kiterunner/routes-large.kite
  - /usr/share/kiterunner/routes-large.kite
  - https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import RateLimiter, Scanner, ScannerError


log = logging.getLogger(__name__)


_KITE_CANDIDATES = [
    "/opt/homebrew/share/kiterunner/routes-large.kite",
    "/opt/homebrew/share/kiterunner/routes-small.kite",
    "/usr/share/kiterunner/routes-large.kite",
    "/usr/local/share/kiterunner/routes-large.kite",
]


def _find_wordlist(deep: bool) -> Optional[Path]:
    env = os.environ.get("KITE_WORDLIST")
    if env and Path(env).is_file():
        return Path(env)
    # Prefer the larger list when --deep is set.
    candidates = sorted(_KITE_CANDIDATES, key=lambda c: ("large" not in c) ^ deep)
    for c in candidates:
        if Path(c).is_file():
            return Path(c)
    return None


_STATUS_SEVERITY = {
    200: Severity.LOW,
    201: Severity.LOW,
    301: Severity.INFO,
    302: Severity.INFO,
    401: Severity.MEDIUM,  # auth-protected API → high-value
    403: Severity.MEDIUM,
    405: Severity.LOW,
    500: Severity.MEDIUM,
}


class KiterunnerScanner(Scanner):
    tool_name = "kr"  # the binary is `kr`
    description = "API route discovery (kiterunner)"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        for c in ("kr", "kiterunner"):
            p = shutil.which(c)
            if p:
                return True, p
        return False, "kiterunner (kr) not on PATH (brew install kiterunner)"

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

        wordlist = _find_wordlist(deep)
        if not wordlist:
            log.warning("kiterunner: no .kite wordlist found; skipping. Set KITE_WORDLIST or `brew install kiterunner`.")
            return []

        binary = shutil.which("kr") or shutil.which("kiterunner")
        with tempfile.TemporaryDirectory(prefix="sentinel-kiterunner-") as tmp:
            out_path = Path(tmp) / "kr.json"
            argv = [
                binary, "scan",
                target,
                "-w", str(wordlist),
                "-o", "json",
                "--output-file", str(out_path),
                "--quiet",
            ]
            if deep:
                argv.extend(["-x", "20"])  # 20 concurrent goroutines
            try:
                self._run_subprocess(argv, timeout=60 * 30)
            except ScannerError as e:
                log.warning("kiterunner error: %s", e)

            if not out_path.is_file():
                return []
            return self._parse(target, out_path)

    def _parse(self, target: str, json_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        # kiterunner emits one JSON object per line.
        for line in json_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = rec.get("url") or rec.get("URL") or target
            method = rec.get("method") or "GET"
            status = rec.get("status_code") or rec.get("status") or 0
            length = rec.get("length") or rec.get("body_length")
            sev = _STATUS_SEVERITY.get(int(status) if str(status).isdigit() else 0, Severity.LOW)
            findings.append(
                Finding(
                    title=f"API endpoint: {method} {url} ({status})",
                    description=(
                        f"kiterunner discovered REST API route {method} {url} "
                        f"returning HTTP {status}"
                        + (f" ({length} bytes)" if length else "")
                    ),
                    severity=sev,
                    scanner="kiterunner",
                    target=target,
                    location=url,
                    raw={
                        "method": method,
                        "status": status,
                        "length": length,
                        "headers": rec.get("headers"),
                        "response": rec.get("body"),
                    },
                )
            )
        return findings
