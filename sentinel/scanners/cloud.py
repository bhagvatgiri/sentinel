"""B-Cloud — cloud-config / enumeration scanners.

Wraps four upstream tools:

- ``S3ScannerScanner`` — sa7mon/S3Scanner. Brute-forces likely S3 bucket
  names from a list of client keywords + builtin permutations; returns
  open-bucket findings.
- ``CloudEnumScanner`` — initstring/cloud_enum. Enumerates S3 / Azure
  blob / GCP storage open containers.
- ``ProwlerScanner`` — toniblyx/prowler. Full AWS audit (IAM, S3, EC2,
  Lambda, etc.) — needs an AWS profile.
- ``CloudFoxScanner`` — BishopFox/cloudfox. AWS post-exploit recon —
  needs an AWS profile.

All four scope-gate via ``scope.authorize_artifact("cloud_target", ...)``
on the bucket name / account id / profile so the audit log records
exactly what was enumerated.

These scanners shell out to upstream binaries that the operator has
installed locally. ``check_available()`` returns False when the binary
isn't on PATH and the scanner is skipped — non-fatal.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Iterable, Optional

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import Scanner, ScannerError


log = logging.getLogger(__name__)


def _ensure_binary(binary: str) -> tuple[bool, str]:
    path = shutil.which(binary)
    if path:
        return True, path
    return False, f"{binary} not on PATH"


class S3ScannerScanner(Scanner):
    """Brute-force S3 bucket enumeration via the ``s3scanner`` CLI."""

    tool_name = "s3scanner"
    description = "S3Scanner — open-bucket enumeration via permuted bucket-name guesses"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        return _ensure_binary("s3scanner")

    def run(
        self,
        scope: Scope,
        target: str,
        keywords: Optional[list[str]] = None,
        **_opts,
    ) -> list[Finding]:
        kws = [k.strip() for k in (keywords or []) if k.strip()]
        if not kws:
            raise ScannerError("S3ScannerScanner needs at least one bucket keyword")
        scope.authorize_artifact(
            "cloud_target", "s3-scanner:" + ",".join(sorted(kws))
        )

        # s3scanner accepts -bucket <name> in modern releases.
        findings: list[Finding] = []
        for kw in kws:
            argv = [self.tool_name, "-bucket", kw, "-json"]
            proc = self._run_subprocess(argv, timeout=300, check_rc=False)
            if not proc.stdout.strip():
                continue
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not entry.get("exists"):
                    continue
                bucket = entry.get("bucket") or entry.get("name") or kw
                permissions = entry.get("permissions") or {}
                # Severity: if the bucket is publicly readable / writable
                # -> HIGH. If just discoverable, LOW.
                pub_read = bool(permissions.get("read"))
                pub_write = bool(permissions.get("write"))
                if pub_write:
                    sev = Severity.HIGH
                elif pub_read:
                    sev = Severity.MEDIUM
                else:
                    sev = Severity.LOW
                findings.append(Finding(
                    title=f"[s3scanner] open bucket: {bucket}",
                    description=(
                        f"S3 bucket `{bucket}` discovered. "
                        f"Publicly readable: {pub_read}; writable: {pub_write}. "
                        f"Investigate the bucket's contents to determine "
                        f"whether sensitive data is exposed."
                    ),
                    severity=sev,
                    scanner=self.tool_name,
                    target=bucket,
                    location=bucket,
                    cwe="CWE-284",
                    references=["https://github.com/sa7mon/S3Scanner"],
                    raw=entry,
                ))
        return findings


class CloudEnumScanner(Scanner):
    """``cloud_enum`` — multi-cloud open-storage enumeration."""

    tool_name = "cloud_enum"
    description = "cloud_enum — multi-cloud open-storage / DNS-record enumeration"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        return _ensure_binary("cloud_enum")

    def run(
        self,
        scope: Scope,
        target: str,
        keywords: Optional[list[str]] = None,
        **_opts,
    ) -> list[Finding]:
        kws = [k.strip() for k in (keywords or []) if k.strip()]
        if not kws:
            raise ScannerError("CloudEnumScanner needs at least one keyword")
        scope.authorize_artifact(
            "cloud_target", "cloud-enum:" + ",".join(sorted(kws))
        )

        argv = [self.tool_name] + sum((["-k", k] for k in kws), []) + ["-l", "/dev/stdout"]
        proc = self._run_subprocess(argv, timeout=600, check_rc=False)
        # cloud_enum emits human-readable lines; we look for `[+]` markers
        # which indicate confirmed open assets.
        findings: list[Finding] = []
        for line in proc.stdout.splitlines():
            if not line.startswith("[+]"):
                continue
            findings.append(Finding(
                title="[cloud_enum] discovered cloud asset",
                description=line.strip(),
                severity=Severity.MEDIUM,
                scanner=self.tool_name,
                target=", ".join(kws),
                location=line.strip(),
                cwe="CWE-284",
                references=["https://github.com/initstring/cloud_enum"],
                raw={"line": line, "keywords": kws},
            ))
        return findings


class ProwlerScanner(Scanner):
    """Wraps ``prowler`` — full AWS security audit (needs AWS creds)."""

    tool_name = "prowler"
    description = "Prowler — AWS / Azure / GCP security audit"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        return _ensure_binary("prowler")

    def run(
        self,
        scope: Scope,
        target: str,
        aws_profile: str = "",
        **_opts,
    ) -> list[Finding]:
        if not aws_profile:
            raise ScannerError("ProwlerScanner needs --aws-profile")
        scope.authorize_artifact("cloud_target", f"prowler-aws-profile:{aws_profile}")

        argv = [self.tool_name, "aws", "--profile", aws_profile,
                "--output-formats", "json-asff"]
        proc = self._run_subprocess(argv, timeout=1800, check_rc=False)
        # Prowler writes its JSON to a file in CWD; the path is reported
        # on stderr. For a first integration we just hand the raw stdout
        # back as a single Finding the operator inspects.
        if not proc.stdout.strip():
            return []
        return [Finding(
            title="[prowler] AWS audit complete",
            description=(
                "Prowler ran a full AWS audit. Inspect the JSON report on "
                "disk for the per-check findings. This Sentinel finding is "
                "a wrapper — promote individual prowler checks into "
                "their own Findings when the integration is deepened."
            ),
            severity=Severity.INFO,
            scanner=self.tool_name,
            target=f"aws:{aws_profile}",
            location="prowler-output",
            cwe=None,
            references=["https://github.com/prowler-cloud/prowler"],
            raw={"stdout_head": proc.stdout[:4096]},
        )]


class CloudFoxScanner(Scanner):
    """Wraps ``cloudfox`` — AWS post-exploit recon."""

    tool_name = "cloudfox"
    description = "CloudFox — AWS post-exploit recon (IAM / EC2 / Lambda / S3 inventory)"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        return _ensure_binary("cloudfox")

    def run(
        self,
        scope: Scope,
        target: str,
        aws_profile: str = "",
        **_opts,
    ) -> list[Finding]:
        if not aws_profile:
            raise ScannerError("CloudFoxScanner needs --aws-profile")
        scope.authorize_artifact("cloud_target", f"cloudfox-aws-profile:{aws_profile}")

        argv = [self.tool_name, "aws", "all-checks", "--profile", aws_profile]
        proc = self._run_subprocess(argv, timeout=1800, check_rc=False)
        if not proc.stdout.strip():
            return []
        return [Finding(
            title="[cloudfox] AWS post-exploit recon complete",
            description=(
                "CloudFox enumerated the AWS account. Inspect the table "
                "output for IAM, EC2, S3, and Lambda findings. This "
                "Sentinel finding is a wrapper — split into per-check "
                "Findings when the integration is deepened."
            ),
            severity=Severity.INFO,
            scanner=self.tool_name,
            target=f"aws:{aws_profile}",
            location="cloudfox-output",
            cwe=None,
            references=["https://github.com/BishopFox/cloudfox"],
            raw={"stdout_head": proc.stdout[:4096]},
        )]
