"""ffuf scanner — directory + parameter discovery via fuzzing.

Two modes:
  - default: directory busting (`{target}/FUZZ`) with a small wordlist.
  - deep:    larger wordlist + parameter fuzzing (`{target}/?FUZZ=test`).

Wordlist resolution order:
  1. `FFUF_WORDLIST` env var (absolute path)
  2. SecLists common.txt at typical locations
  3. /usr/share/wordlists/dirb/common.txt
  4. The bundled fallback at sentinel/scanners/_ffuf_fallback.txt (small)

Install: `brew install ffuf`. Optionally `brew install seclists`.

Output: JSON via `-of json -o <file>`. Each result has `url`, `status`,
`length`, `words`, `lines`, `redirectlocation`. We surface 200/301/302/401/403
discoveries as info findings (200/401 = high-value, 403 = medium).
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


# Severity heuristics by HTTP status code.
_STATUS_SEVERITY = {
    200: Severity.LOW,      # discovered endpoint — context-dependent
    201: Severity.LOW,
    204: Severity.LOW,
    301: Severity.INFO,     # redirect — informational
    302: Severity.INFO,
    307: Severity.INFO,
    308: Severity.INFO,
    401: Severity.MEDIUM,   # auth-protected endpoint discovered (interesting)
    403: Severity.MEDIUM,   # forbidden (worth a manual look — sometimes bypass-able)
    405: Severity.LOW,
    500: Severity.MEDIUM,   # server error suggests unhandled input
}


_WORDLIST_CANDIDATES = [
    "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
    "/opt/homebrew/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/local/share/seclists/Discovery/Web-Content/common.txt",
]

# Small built-in fallback (safe + tiny — covers common admin/api/debug paths).
_FALLBACK_WORDS = [
    "admin", "api", "backup", "config", "console", "debug", ".env", ".git",
    "health", "login", "logs", "old", "phpinfo", "phpinfo.php", "phpmyadmin",
    "robots.txt", "sitemap.xml", "test", "tmp", "uploads", ".well-known",
    "api/v1", "api/v2", "swagger", "swagger.json", "openapi.json",
    "wp-admin", "wp-login.php", ".DS_Store", "actuator", "actuator/health",
    "metrics", "graphql",
]


def _resolve_wordlist(deep: bool) -> Path:
    env_wl = os.environ.get("FFUF_WORDLIST")
    if env_wl and Path(env_wl).is_file():
        return Path(env_wl)
    for c in _WORDLIST_CANDIDATES:
        if Path(c).is_file():
            return Path(c)
    # Fallback — write a tiny wordlist to a temp file we manage.
    tmp = Path(tempfile.gettempdir()) / "sentinel-ffuf-fallback.txt"
    if not tmp.is_file():
        tmp.write_text("\n".join(_FALLBACK_WORDS) + "\n")
    return tmp


class FfufScanner(Scanner):
    tool_name = "ffuf"
    description = "Directory + parameter fuzzer (ffuf)"

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

        wordlist = _resolve_wordlist(deep)
        log.info("ffuf wordlist: %s", wordlist)

        findings: list[Finding] = []

        # Pass 1: directory busting.
        findings.extend(self._fuzz(
            target=target,
            fuzz_url=f"{target.rstrip('/')}/FUZZ",
            wordlist=wordlist,
            mode="dir",
            scope=scope,
        ))

        if deep:
            # Pass 2: parameter discovery on the root.
            findings.extend(self._fuzz(
                target=target,
                fuzz_url=f"{target.rstrip('/')}/?FUZZ=test",
                wordlist=wordlist,
                mode="param",
                scope=scope,
            ))

        return findings

    def _fuzz(
        self,
        target: str,
        fuzz_url: str,
        wordlist: Path,
        mode: str,
        scope: Scope,
    ) -> list[Finding]:
        with tempfile.TemporaryDirectory(prefix="sentinel-ffuf-") as tmp:
            json_path = Path(tmp) / "ffuf.json"
            argv = [
                "ffuf",
                "-u", fuzz_url,
                "-w", str(wordlist),
                "-of", "json",
                "-o", str(json_path),
                "-rate", str(int(max(1, scope.rate_limit_rps * 4))),  # ffuf uses internal threading
                "-mc", "200,201,204,301,302,307,308,401,403,405,500",
                "-timeout", "10",
                "-s",  # silent (we parse JSON ourselves)
            ]
            try:
                self._run_subprocess(argv, timeout=60 * 30)
            except ScannerError as e:
                log.warning("ffuf returned non-zero: %s", e)

            if not json_path.is_file():
                return []
            try:
                data = json.loads(json_path.read_text())
            except json.JSONDecodeError as e:
                log.warning("ffuf: invalid JSON: %s", e)
                return []
            return self._parse(target, data, mode)

    def _parse(self, target: str, data: dict, mode: str) -> list[Finding]:
        findings: list[Finding] = []
        for r in data.get("results", []) or []:
            url = r.get("url", "")
            status = r.get("status", 0)
            sev = _STATUS_SEVERITY.get(status, Severity.LOW)
            length = r.get("length", "?")
            words = r.get("words", "?")
            redirect = r.get("redirectlocation", "")
            input_word = (r.get("input") or {}).get("FUZZ", "")
            kind = "endpoint" if mode == "dir" else "parameter"
            title = f"ffuf {kind} discovered: {input_word} ({status})"
            findings.append(
                Finding(
                    title=title,
                    description=(
                        f"ffuf {mode} fuzz hit: {url} returned HTTP {status} "
                        f"({length} bytes, {words} words)"
                        + (f"; redirects to {redirect}" if redirect else "")
                    ),
                    severity=sev,
                    scanner="ffuf",
                    target=target,
                    location=url,
                    raw={
                        "ffuf_mode": mode,
                        "ffuf_input": input_word,
                        "status": status,
                        "length": length,
                        "words": words,
                        "lines": r.get("lines"),
                        "redirect": redirect,
                        "response": r.get("resultfile"),
                    },
                )
            )
        return findings
