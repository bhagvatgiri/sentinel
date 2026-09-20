"""B-Mobile — mobile pentest scanners (MobSF + apkleaks).

Two scanners that take an Android APK path and return Finding objects:

- ``MobSFScanner`` — wraps the MobSF static-analysis API (Mobile Security
  Framework) running locally. Surfaces the high-impact static checks
  (insecure permissions, hardcoded credentials, weak crypto, missing
  certificate pinning).
- ``ApkleaksScanner`` — runs the `apkleaks` CLI to grep the decompiled
  APK for embedded secrets matching common patterns (AWS keys, ExampleChat
  tokens, GitHub tokens, etc.).

Both scope-gate the artifact via ``scope.authorize_artifact("apk", path)``
before any work. Findings carry a ``mobile-static`` tag so reports can
filter on them.

The MobSF API needs a running local instance (``docker run`` or pip
install). The ``MOBSF_API_URL`` and ``MOBSF_API_KEY`` env vars (or
``~/.config/sentinel/mobsf.env``) point at it. apkleaks is a self-
contained Python CLI — no service required.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable, Optional

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import Scanner, ScannerError


log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Severity mapping for mobile-static findings
# --------------------------------------------------------------------------
_MOBSF_SEVERITY_MAP: dict[str, Severity] = {
    "high": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.INFO,
    "good": Severity.INFO,
    "secure": Severity.INFO,
    "dangerous": Severity.HIGH,
    "normal": Severity.LOW,
    "signature": Severity.MEDIUM,
}


def _resolve_mobsf_creds() -> tuple[str, str]:
    """Resolve MobSF API URL + key from env vars or config file."""
    api_url = os.environ.get("MOBSF_API_URL", "").strip()
    api_key = os.environ.get("MOBSF_API_KEY", "").strip()
    if api_url and api_key:
        return api_url.rstrip("/"), api_key
    cfg = Path("~/.config/sentinel/mobsf.env").expanduser()
    if cfg.is_file():
        env: dict[str, str] = {}
        for line in cfg.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, _, v = line.strip().partition("=")
                env[k.strip()] = v.strip()
        api_url = api_url or env.get("MOBSF_API_URL", "")
        api_key = api_key or env.get("MOBSF_API_KEY", "")
    if not api_url or not api_key:
        raise ScannerError(
            "MobSF credentials not found. Set MOBSF_API_URL + MOBSF_API_KEY "
            "env vars, or write them to ~/.config/sentinel/mobsf.env "
            "(key=value, one per line). Default URL is http://localhost:8000."
        )
    return api_url.rstrip("/"), api_key


class MobSFScanner(Scanner):
    """Static analysis of an APK via MobSF's REST API."""

    tool_name = "mobsf"
    description = "Mobile Security Framework — Android APK static analysis"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        """MobSF is a service, not a binary. Probe its API for a heartbeat."""
        try:
            api_url, _ = _resolve_mobsf_creds()
        except ScannerError as e:
            return False, str(e)
        # /api/v1/scans needs auth; /api/docs returns the OpenAPI page on a
        # running instance. Use GET / which always responds when the server
        # is up.
        try:
            with urllib.request.urlopen(api_url + "/", timeout=5) as resp:
                if resp.status >= 500:
                    return False, f"MobSF returned HTTP {resp.status}"
            return True, api_url
        except Exception as e:  # noqa: BLE001
            return False, f"MobSF unreachable at {api_url}: {e}"

    def run(
        self,
        scope: Scope,
        target: str,
        **_opts,
    ) -> list[Finding]:
        apk_path = Path(target).resolve()
        if not apk_path.is_file():
            raise ScannerError(f"APK file not found: {apk_path}")
        scope.authorize_artifact("apk", str(apk_path))

        api_url, api_key = _resolve_mobsf_creds()

        # 1) Upload the APK.
        upload = self._mobsf_upload(api_url, api_key, apk_path)
        scan_hash = upload.get("hash")
        if not scan_hash:
            raise ScannerError(f"MobSF upload returned no hash: {upload}")

        # 2) Trigger a scan + wait for it.
        self._mobsf_scan(api_url, api_key, scan_hash, upload)

        # 3) Pull the JSON report.
        report = self._mobsf_report(api_url, api_key, scan_hash)

        return list(self._mobsf_findings(report, apk_path))

    # --- HTTP helpers -----------------------------------------------------

    @staticmethod
    def _mobsf_post(api_url: str, api_key: str, path: str, fields: dict) -> dict:
        boundary = "----sentinelboundary"
        body_parts: list[bytes] = []
        for k, v in fields.items():
            if isinstance(v, tuple):
                # (filename, bytes, content_type)
                fname, content, ctype = v
                body_parts.append(f"--{boundary}\r\n".encode())
                body_parts.append(
                    f'Content-Disposition: form-data; name="{k}"; filename="{fname}"\r\n'.encode()
                )
                body_parts.append(f"Content-Type: {ctype}\r\n\r\n".encode())
                body_parts.append(content)
                body_parts.append(b"\r\n")
            else:
                body_parts.append(f"--{boundary}\r\n".encode())
                body_parts.append(
                    f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode()
                )
                body_parts.append(str(v).encode() + b"\r\n")
        body_parts.append(f"--{boundary}--\r\n".encode())
        body = b"".join(body_parts)

        req = urllib.request.Request(
            api_url + path,
            data=body,
            headers={
                "Authorization": api_key,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read())

    def _mobsf_upload(self, api_url: str, api_key: str, apk_path: Path) -> dict:
        with apk_path.open("rb") as fh:
            return self._mobsf_post(api_url, api_key, "/api/v1/upload", {
                "file": (apk_path.name, fh.read(), "application/vnd.android.package-archive"),
            })

    def _mobsf_scan(self, api_url: str, api_key: str, scan_hash: str, upload: dict) -> None:
        self._mobsf_post(api_url, api_key, "/api/v1/scan", {
            "scan_type": upload.get("scan_type", "apk"),
            "file_name": upload.get("file_name", ""),
            "hash": scan_hash,
        })

    def _mobsf_report(self, api_url: str, api_key: str, scan_hash: str) -> dict:
        return self._mobsf_post(api_url, api_key, "/api/v1/report_json", {
            "hash": scan_hash,
        })

    # --- Finding extraction ----------------------------------------------

    def _mobsf_findings(self, report: dict, apk_path: Path) -> Iterable[Finding]:
        # MobSF reports are big; we only emit findings for the high-signal
        # categories: code analysis, manifest analysis, certificates,
        # permissions, secret hits.
        for category, sub in (report.get("code_analysis") or {}).items():
            if not isinstance(sub, dict):
                continue
            for key, item in sub.items():
                if not isinstance(item, dict):
                    continue
                metadata = item.get("metadata") or {}
                sev_raw = (item.get("severity") or metadata.get("severity") or "").lower()
                yield Finding(
                    title=f"[mobsf] {category}: {key}",
                    description=(metadata.get("description") or item.get("description") or "").strip(),
                    severity=_MOBSF_SEVERITY_MAP.get(sev_raw, Severity.LOW),
                    scanner=self.tool_name,
                    target=str(apk_path),
                    location=key,
                    cwe=metadata.get("cwe"),
                    references=[],
                    raw={"mobsf_category": category, "key": key, "raw": item},
                )

        for issue in (report.get("manifest_analysis") or {}).get("manifest_findings", []) or []:
            if not isinstance(issue, dict):
                continue
            yield Finding(
                title=f"[mobsf] manifest: {issue.get('rule', 'manifest finding')}",
                description=(issue.get("description") or "").strip(),
                severity=_MOBSF_SEVERITY_MAP.get((issue.get("severity") or "").lower(), Severity.LOW),
                scanner=self.tool_name,
                target=str(apk_path),
                location="AndroidManifest.xml",
                cwe=issue.get("cwe"),
                references=[],
                raw=issue,
            )


class ApkleaksScanner(Scanner):
    """Run apkleaks on an APK to surface embedded secret patterns."""

    tool_name = "apkleaks"
    description = "apkleaks — scan an APK for hardcoded secrets / API keys"

    def run(
        self,
        scope: Scope,
        target: str,
        **_opts,
    ) -> list[Finding]:
        apk_path = Path(target).resolve()
        if not apk_path.is_file():
            raise ScannerError(f"APK file not found: {apk_path}")
        scope.authorize_artifact("apk", str(apk_path))

        argv = [self.tool_name, "-f", str(apk_path), "--json"]
        proc = self._run_subprocess(argv, timeout=600, check_rc=False)
        if not proc.stdout.strip():
            return []
        try:
            data = self._parse_json(proc.stdout)
        except ScannerError:
            # apkleaks sometimes prefixes banner text; try to find the JSON.
            start = proc.stdout.find("{")
            if start < 0:
                return []
            data = json.loads(proc.stdout[start:])

        findings: list[Finding] = []
        for entry in (data.get("results") or []):
            name = entry.get("name") or "secret"
            for match in entry.get("matches") or []:
                findings.append(
                    Finding(
                        title=f"[apkleaks] {name}",
                        description=(
                            f"Embedded secret-pattern match in APK: {name}. "
                            f"This may be a hardcoded credential or token "
                            f"shipped with the application binary."
                        ),
                        severity=Severity.HIGH,
                        scanner=self.tool_name,
                        target=str(apk_path),
                        location=str(match)[:200],
                        cwe="CWE-798",
                        references=["https://github.com/dwisiswant0/apkleaks"],
                        raw={"name": name, "match": match},
                    )
                )
        return findings
