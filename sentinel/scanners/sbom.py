"""SBOM generation via Syft — passive enumeration of installed packages.

Produces a machine-readable Bill of Materials as a deliverable artifact.
NOT a vulnerability scanner (see: Trivy, OSV-Scanner). Composes well with those.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import Scanner, ScannerError


class SBOMGenerator(Scanner):
    """Wrapper around Syft to generate Software Bill of Materials."""

    tool_name = "syft"
    description = "SBOM generation via Syft (CycloneDX, SPDX, or Syft-native JSON)"

    SUPPORTED_FORMATS = {
        "cyclonedx-json": "CycloneDX JSON",
        "spdx-json": "SPDX JSON",
        "syft-json": "Syft native JSON",
    }

    def run(
        self,
        scope: Scope,
        target: str,
        output_path: Optional[str] = None,
        format: str = "cyclonedx-json",
        **_opts,
    ) -> list[Finding]:
        """Generate SBOM for a directory or container image reference.

        Args:
            scope: Engagement scope.
            target: Directory path or container image reference (e.g. 'nginx:latest').
            output_path: If set, write SBOM to this file.
            format: Output format (cyclonedx-json, spdx-json, syft-json).

        Returns:
            List with a single INFO-level Finding summarizing the SBOM.
        """
        if format not in self.SUPPORTED_FORMATS:
            raise ScannerError(
                f"Unsupported format '{format}'. Supported: {', '.join(self.SUPPORTED_FORMATS.keys())}"
            )

        scope.authorize_artifact("sbom", str(target))

        argv = [
            self.tool_name,
            str(target),
            "-o", format,
            "--quiet",
        ]
        proc = self._run_subprocess(argv, timeout=600)

        if not proc.stdout:
            raise ScannerError(f"Syft produced no output for {target}")

        sbom_content = proc.stdout

        # Write to output_path if requested.
        if output_path:
            Path(output_path).write_text(sbom_content)

        # Parse JSON to extract summary statistics.
        try:
            sbom_data = json.loads(sbom_content)
        except json.JSONDecodeError as e:
            raise ScannerError(f"Could not parse Syft JSON output: {e}") from e

        summary = self._summarize_sbom(sbom_data, format, output_path or target)

        return [summary]

    def _summarize_sbom(
        self, sbom_data: dict | list, format: str, sbom_identifier: str
    ) -> Finding:
        """Extract summary stats from SBOM and return an INFO Finding."""
        ecosystems: dict[str, int] = {}
        components_list: list[dict] = []
        total = 0

        # CycloneDX format
        if format == "cyclonedx-json" and isinstance(sbom_data, dict):
            components_list = sbom_data.get("components") or []
        # SPDX format
        elif format == "spdx-json" and isinstance(sbom_data, dict):
            packages = sbom_data.get("packages") or []
            components_list = packages
        # Syft native format
        elif format == "syft-json" and isinstance(sbom_data, dict):
            artifacts = sbom_data.get("artifacts") or []
            components_list = artifacts

        for comp in components_list:
            total += 1
            # Syft/CycloneDX: 'purl' or 'cpe' for ecosystem
            purl = comp.get("purl") or comp.get("PURL") or ""
            cpe = comp.get("cpe") or comp.get("CPE") or ""

            ecosystem = self._extract_ecosystem(purl, cpe)
            ecosystems[ecosystem] = ecosystems.get(ecosystem, 0) + 1

        # Sort and take top 10 by count.
        top_10 = sorted(ecosystems.items(), key=lambda x: x[1], reverse=True)[:10]
        top_10_str = ", ".join(f"{eco} ({count})" for eco, count in top_10)

        description = (
            f"SBOM generated for {sbom_identifier}\n"
            f"Total components: {total}\n"
            f"Ecosystems: {len(ecosystems)}\n"
            f"Top 10: {top_10_str}\n"
            f"Artifact: {sbom_identifier}"
        )

        return Finding(
            title=f"SBOM Summary: {total} components",
            description=description,
            severity=Severity.INFO,
            scanner="syft",
            target=sbom_identifier,
            location=None,
        )

    @staticmethod
    def _extract_ecosystem(purl: str, cpe: str) -> str:
        """Extract ecosystem/package manager from purl or cpe."""
        if purl:
            # purl format: pkg:npm/lodash@4.17.21, pkg:maven/org.slf4j/...
            parts = purl.split(":")
            if len(parts) >= 2:
                return parts[1].split("/")[0].upper()
        if cpe:
            # cpe:2.3:a:vendor:product:version:...
            parts = cpe.split(":")
            if len(parts) >= 4:
                return parts[3].upper()
        return "UNKNOWN"
