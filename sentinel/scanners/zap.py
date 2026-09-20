"""ZAP scanner — wraps OWASP ZAP's headless scan scripts.

Two modes:
  - baseline (default): zap-baseline.py — passive crawl, ~5 minutes.
  - full (--deep):      zap-full-scan.py — active scan including injection
                        attempts, longer (10+ minutes for small sites).

Install:
  brew install zaproxy           # macOS — brings zap.sh, zap-baseline.py, zap-full-scan.py
  # OR via Docker:
  docker pull ghcr.io/zaproxy/zaproxy:stable
  alias zap-baseline.py='docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py'

Output: ZAP writes a JSON report (`-J <file>`) with `site[].alerts[]` items,
each carrying name, riskcode, confidence, instances (uri/method/evidence/attack),
solution, reference, cweid, wascid.
"""

from __future__ import annotations

import json
import logging
import shutil
import socket
import tempfile
from pathlib import Path
from typing import Optional

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import RateLimiter, Scanner, ScannerError


log = logging.getLogger(__name__)


# Risk codes per ZAP API: 0=Informational, 1=Low, 2=Medium, 3=High.
_ZAP_RISK_TO_SEVERITY = {
    "0": Severity.INFO, "1": Severity.LOW, "2": Severity.MEDIUM, "3": Severity.HIGH,
    0: Severity.INFO, 1: Severity.LOW, 2: Severity.MEDIUM, 3: Severity.HIGH,
}


_CASK_ZAP_PATHS = [
    "/Applications/ZAP.app/Contents/Java/zap.sh",
    "/Applications/OWASP ZAP.app/Contents/Java/zap.sh",
    "/usr/local/share/zaproxy/zap.sh",
]


def _find_zap_sh() -> Optional[str]:
    p = shutil.which("zap.sh")
    if p:
        return p
    for c in _CASK_ZAP_PATHS:
        if Path(c).is_file():
            return c
    return None


def _free_port() -> int:
    """Ask the kernel for an unused TCP port. ZAP defaults to 8080 which
    is commonly held by other dev servers (incl. Sentinel's own web UI)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ZAPScanner(Scanner):
    # Friendly display name; check_available() handles the binary discovery.
    tool_name = "zap"
    description = "OWASP ZAP scan (baseline / quickscan via zap.sh -cmd)"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        # Prefer the helper scripts when present (they're shorter + nicer output),
        # but fall back to zap.sh -cmd which IS shipped with the brew cask.
        for candidate in ("zap-baseline.py", "zap-full-scan.py"):
            p = shutil.which(candidate)
            if p:
                return True, p
        zap_sh = _find_zap_sh()
        if zap_sh:
            return True, zap_sh
        return False, (
            "zap.sh not found. brew install --cask zap puts it at "
            "/Applications/ZAP.app/Contents/Java/zap.sh — re-install if missing"
        )

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

        helper = shutil.which("zap-full-scan.py" if deep else "zap-baseline.py") \
                 or shutil.which("zap-baseline.py")

        with tempfile.TemporaryDirectory(prefix="sentinel-zap-") as tmp:
            out_dir = Path(tmp)
            json_path = out_dir / "zap-report.json"

            if helper:
                # Helper-script mode (preferred when available).
                argv = [helper, "-t", target, "-J", str(json_path), "-I"]
            else:
                # Fallback: zap.sh -cmd quickscan. Works with the brew cask.
                # -quickurl runs an active scan + spider; report can be JSON.
                # ZAP always starts a local proxy even in -cmd mode; default
                # port 8080 collides with the Sentinel web UI and many dev
                # servers, and ZAP exits 0 silently on BindException — so we
                # always pick a free port up front.
                zap_sh = _find_zap_sh()
                if not zap_sh:
                    raise ScannerError("zap.sh not found")
                port = _free_port()
                argv = [
                    zap_sh,
                    "-cmd",
                    "-port", str(port),
                    "-quickurl", target,
                    "-quickout", str(json_path),
                    "-quickprogress",
                ]
                log.info("zap: helper script not on PATH, using `zap.sh -cmd -quickurl` mode (port=%d)", port)
            # ZAP scripts can take 5-30+ minutes. Be patient.
            timeout = 60 * 60 if deep else 30 * 60
            proc = None
            try:
                proc = self._run_subprocess(argv, cwd=out_dir, timeout=timeout)
            except ScannerError as e:
                # ZAP exits non-zero when alerts exist; tolerate that and parse output.
                log.info("zap returned non-zero (likely findings present): %s", e)

            if not json_path.is_file():
                # ZAP often exits 0 even on hard failures (BindException, OOM,
                # cert errors). Surface its stderr/stdout so the user can act.
                tail = ""
                if proc is not None:
                    err = (proc.stderr or "").strip()
                    out = (proc.stdout or "").strip()
                    tail = (err or out)[-800:]
                log.warning("zap: no JSON report produced at %s. last output:\n%s", json_path, tail)
                if "Address already in use" in tail or "BindException" in tail:
                    raise ScannerError(
                        "ZAP could not start its local proxy (port collision). "
                        "Stop any other ZAP instance and retry."
                    )
                return []

            try:
                data = json.loads(json_path.read_text())
            except json.JSONDecodeError as e:
                raise ScannerError(f"zap: invalid JSON report: {e}") from e

            findings = self._parse_report(target, data)
            if not findings:
                # Surface enough context to tell "honest 0" from silent fail.
                # Common culprit: ZAP's quickurl mode skipping the active
                # phase when the target redirects or when the spider finds
                # nothing. The report file shape itself is the tell.
                size = json_path.stat().st_size
                sites = data.get("site", []) if isinstance(data, dict) else []
                site_count = len(sites)
                alert_count = sum(len((s or {}).get("alerts") or []) for s in sites)
                stdout_tail = ""
                if proc is not None:
                    stdout_tail = ((proc.stdout or "") + (proc.stderr or ""))[-400:].strip()
                log.warning(
                    "zap: 0 findings parsed (json=%dB, sites=%d, raw_alerts=%d, exit=%s). "
                    "stdout tail: %s",
                    size, site_count, alert_count,
                    proc.returncode if proc else "?",
                    stdout_tail or "<empty>",
                )
            return findings

    def _parse_report(self, target: str, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        for site in data.get("site", []) or []:
            for alert in site.get("alerts", []) or []:
                sev = _ZAP_RISK_TO_SEVERITY.get(alert.get("riskcode"), Severity.INFO)
                title = alert.get("name") or alert.get("alert") or "ZAP alert"
                description = self._strip_html(alert.get("desc", ""))
                solution = self._strip_html(alert.get("solution", ""))
                cwe_id = alert.get("cweid")
                cwe = f"CWE-{cwe_id}" if cwe_id and str(cwe_id).isdigit() and int(cwe_id) > 0 else None

                # Each alert can have multiple instances (one per matching URL).
                instances = alert.get("instances") or [{"uri": target}]
                for inst in instances:
                    findings.append(
                        Finding(
                            title=title,
                            description=description,
                            severity=sev,
                            scanner="zap",
                            target=target,
                            location=inst.get("uri") or target,
                            cwe=cwe,
                            references=self._refs(alert.get("reference", "")),
                            remediation=solution or None,
                            raw={
                                "zap_pluginid": alert.get("pluginid"),
                                "zap_alertref": alert.get("alertRef"),
                                "zap_confidence": alert.get("confidence"),
                                "method": inst.get("method"),
                                "request": inst.get("attack"),
                                "response": inst.get("evidence"),
                                "param": inst.get("param"),
                            },
                        )
                    )
        return findings

    @staticmethod
    def _strip_html(s: str) -> str:
        # ZAP descriptions are HTML; quick strip is good enough for indexing.
        import re
        s = re.sub(r"<[^>]+>", "", s or "")
        return s.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").strip()

    @staticmethod
    def _refs(s: str) -> list[str]:
        if not s:
            return []
        # ZAP joins references with newlines.
        return [r.strip() for r in s.split("\n") if r.strip().startswith(("http://", "https://"))]
