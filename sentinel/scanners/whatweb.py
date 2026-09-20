"""WhatWeb scanner — wraps whatweb for web tech fingerprinting.

Identifies the web stack: server, framework, CMS (and version), JS libraries,
analytics, etc. The output makes it trivial for an attacker to look up known
CVEs against the discovered versions, so showing this as a Finding raises
visibility into version-disclosure footguns.

Install:
  brew install whatweb

Output: NDJSON via `--log-json=-` — one JSON object per target with a
`plugins` map. Each plugin entry has `version`, `string`, `account`, etc.
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


# Plugins where a disclosed version is meaningful from a security standpoint.
# (Most plugins just identify which library is in use.)
_VERSION_INTERESTING = {
    "Apache", "nginx", "IIS", "PHP", "WordPress", "Drupal", "Joomla", "Magento",
    "jQuery", "Django", "Flask", "Express", "Spring", "Tomcat", "Jenkins",
    "GitLab", "Confluence", "Jira", "RabbitMQ", "Redis", "OpenSSL",
}


class WhatWebScanner(Scanner):
    tool_name = "whatweb"
    description = "Web tech fingerprinting (whatweb)"

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

        with tempfile.TemporaryDirectory(prefix="sentinel-whatweb-") as tmp:
            out_path = Path(tmp) / "whatweb.json"
            aggression = "4" if deep else "3"  # 3 = stealthy, 4 = heavy
            argv = [
                "whatweb",
                "-a", aggression,
                f"--log-json={out_path}",
                target,
            ]
            try:
                self._run_subprocess(argv, timeout=10 * 60)
            except ScannerError as e:
                log.warning("whatweb error: %s", e)
                return []

            if not out_path.is_file():
                return []
            return self._parse_jsonl(target, out_path.read_text())

    def _parse_jsonl(self, target: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            target_url = rec.get("target") or target
            plugins = rec.get("plugins") or {}
            for plugin_name, info in plugins.items():
                version = self._first_value(info, "version")
                string_val = self._first_value(info, "string")
                account = self._first_value(info, "account")
                title = f"Tech: {plugin_name}" + (f" {version}" if version else "")
                desc_parts = [f"whatweb identified `{plugin_name}`"]
                if version:
                    desc_parts.append(f"version `{version}`")
                if string_val:
                    desc_parts.append(f"banner `{string_val}`")
                if account:
                    desc_parts.append(f"account/identifier `{account}`")
                desc_parts.append(f"on {target_url}")
                description = "; ".join(desc_parts) + "."
                # Disclosed version of an interesting plugin = LOW; otherwise INFO.
                sev = Severity.LOW if (version and plugin_name in _VERSION_INTERESTING) else Severity.INFO
                findings.append(
                    Finding(
                        title=title,
                        description=description,
                        severity=sev,
                        scanner="whatweb",
                        target=target,
                        location=target_url,
                        raw={
                            "plugin": plugin_name,
                            "version": version,
                            "string": string_val,
                            "account": account,
                            "all_plugin_data": info,
                        },
                    )
                )
        return findings

    @staticmethod
    def _first_value(info: dict, key: str) -> Optional[str]:
        v = info.get(key)
        if isinstance(v, list):
            return str(v[0]) if v else None
        return str(v) if v else None
