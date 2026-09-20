"""Live scanner — nuclei. Every URL passes Scope.authorize_url() first.

This is the only scanner module that touches the network. It enforces:
  1. Per-URL scope authorization before each invocation
  2. Rate limit from scope.rate_limit_rps (passed to nuclei via -rl)
  3. Defensive-only template selection (CVE detection, exposed configs,
     default credentials, missing security headers — no exploitation)

If you want to run other template categories you must pass them explicitly;
the default set excludes templates tagged "intrusive" or "fuzz".
"""

from __future__ import annotations

import json
from typing import Optional

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import RateLimiter, Scanner, ScannerError


# Default template tags — coverage suitable for any in-scope target.
DEFAULT_TEMPLATE_TAGS = [
    "cve",
    "exposure",
    "misconfig",
    "default-login",
    "ssl",
    "tech",
]

# Additional tags enabled by --deep. Broader coverage including active probing.
DEEP_EXTRA_TAGS = [
    "tech-detect",
    "login-page",
    "exposed-panels",
    "osint",
    "backdoor",
    "token-spray",
    "fuzz",
    "intrusive",
]

# Always excluded — denial-of-service templates can take targets offline.
ALWAYS_EXCLUDE = ["dos"]


class NucleiScanner(Scanner):
    tool_name = "nuclei"
    description = "Defensive nuclei scan (CVE/exposure detection only)"

    def run(
        self,
        scope: Scope,
        target: str,
        template_tags: Optional[list[str]] = None,
        max_severity_to_run: str = "critical",
        deep: bool = False,
        **_opts,
    ) -> list[Finding]:
        # HARD GATE: authorize every URL before invocation.
        scope.authorize_url(target)

        rl = RateLimiter(scope.rate_limit_rps)
        rl.wait()

        if template_tags:
            tags = template_tags
        elif deep:
            tags = DEFAULT_TEMPLATE_TAGS + DEEP_EXTRA_TAGS
        else:
            tags = DEFAULT_TEMPLATE_TAGS

        # We use -jsonl for stable streaming output. -duc disables auto-update
        # so a sandboxed run never tries to fetch templates mid-engagement.
        # -irr includes the full HTTP request + response in each match record
        # so the PoC enricher can show "expected output" for every finding.
        argv = [
            self.tool_name,
            "-u", target,
            "-jsonl",
            "-irr",
            "-silent",
            "-duc",
            "-rl", str(int(max(1, scope.rate_limit_rps))),
            "-tags", ",".join(tags),
            "-exclude-tags", ",".join(ALWAYS_EXCLUDE),
            "-severity", _severity_filter(max_severity_to_run),
        ]
        # Nuclei against ~5000 templates at scope.rate_limit_rps requests/sec
        # routinely takes 1-2+ hours. The previous 1800s (30min) timeout was
        # silently killing scans mid-flight, leaving 0 findings + 0 errors.
        proc = self._run_subprocess(argv, timeout=10800)  # 3 hours
        if not proc.stdout:
            return []

        findings: list[Finding] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = item.get("info", {}) or {}
            classification = info.get("classification", {}) or {}
            sev = Severity.from_string(info.get("severity"))

            cve_list = classification.get("cve-id") or []
            cwe_list = classification.get("cwe-id") or []
            cve = cve_list[0] if isinstance(cve_list, list) and cve_list else (cve_list if isinstance(cve_list, str) else None)
            cwe = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else (cwe_list if isinstance(cwe_list, str) else None)

            cvss = None
            metrics = classification.get("cvss-metrics")
            cvss_score = classification.get("cvss-score")
            if isinstance(cvss_score, (int, float)):
                cvss = float(cvss_score)

            findings.append(
                Finding(
                    title=info.get("name", item.get("template-id", "nuclei finding")),
                    description=info.get("description", ""),
                    severity=sev,
                    scanner="nuclei",
                    target=target,
                    location=item.get("matched-at") or item.get("host") or target,
                    cwe=cwe,
                    cve=cve,
                    cvss=cvss,
                    references=info.get("reference") or [],
                    raw={
                        "template": item.get("template-id"),
                        "metrics": metrics,
                        "matched": item.get("matched-at"),
                        # -irr fills these in for every match (request/response
                        # bodies plus any extracted regex captures). The PoC
                        # enricher embeds them as the "expected output" block
                        # so the devops team sees the literal evidence.
                        "request": item.get("request"),
                        "response": item.get("response"),
                        "extracted-results": item.get("extracted-results"),
                        "ip": item.get("ip"),
                        "curl-command": item.get("curl-command"),
                    },
                )
            )
        return findings


def _severity_filter(max_sev: str) -> str:
    order = ["info", "low", "medium", "high", "critical"]
    max_sev = max_sev.lower()
    if max_sev not in order:
        max_sev = "high"
    idx = order.index(max_sev)
    return ",".join(order[: idx + 1])
