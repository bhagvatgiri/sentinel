"""Orchestrator — the agent's main run loop."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.core.findings import Finding
from sentinel.core.poc import enrich_finding
from sentinel.core.scope import Scope
from sentinel.core.triage import deduplicate, triage_all
from sentinel.llm.ollama_client import OllamaClient
from sentinel.scanners.base import Scanner, ScannerError


log = logging.getLogger(__name__)


@dataclass
class RunReport:
    scope: Scope
    findings: list[Finding] = field(default_factory=list)
    scanners_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Phase 5 / NOVEL-05 — structured zero-day candidates surfaced by the
    # novelty escalation gate (sentinel/agent/pentest/pipeline.py:_run_novelty_sweep).
    # Default empty list so every existing call site that constructs
    # RunReport(scope=...) without novel_findings (Phases 1-4.5 backward-compat)
    # round-trips without change. The runtime contents are
    # NovelFindingEvidence instances; typed as `list` here (rather than
    # `list[NovelFindingEvidence]`) to avoid a circular import between
    # sentinel.core.orchestrator and sentinel.agent.novelty. The runtime
    # type-check runs in tests/test_novel_finding_evidence.py.
    novel_findings: list = field(default_factory=list)


class Orchestrator:
    def __init__(self, scope: Scope, ollama: Optional[OllamaClient] = None, retriever=None):
        self.scope = scope
        self.ollama = ollama
        self.retriever = retriever  # Optional[sentinel.rag.retriever.Retriever]

    def run_scanners(
        self,
        scanners: list[Scanner],
        target: str,
        repo_url: Optional[str] = None,
        **opts,
    ) -> RunReport:
        report = RunReport(scope=self.scope)
        for scanner in scanners:
            ok, info = scanner.check_available()
            if not ok:
                msg = f"Skipping {scanner.tool_name}: {info}"
                log.warning(msg)
                report.errors.append(msg)
                continue
            try:
                log.info("running scanner: %s", scanner.tool_name)
                results = scanner.run(self.scope, target, repo_url=repo_url, **opts)
                report.findings.extend(results)
                report.scanners_run.append(scanner.tool_name)
            except ScannerError as e:
                report.errors.append(f"{scanner.tool_name}: {e}")
                log.error("scanner %s failed: %s", scanner.tool_name, e)
            except Exception as e:  # pragma: no cover - defensive
                report.errors.append(f"{scanner.tool_name}: unexpected error: {e}")
                log.exception("scanner %s crashed", scanner.tool_name)

        report.findings = deduplicate(report.findings)
        report.findings = triage_all(report.findings, ollama=self.ollama, retriever=self.retriever)
        # Enrich each finding with devops-ready impact / PoC / validation fields
        # (template-based, no LLM call so this is fast and offline-safe).
        for f in report.findings:
            try:
                enrich_finding(f)
            except Exception as e:
                log.warning("PoC enrichment failed for %s: %s", f.fingerprint(), e)
        return report

    # ---- presets -------------------------------------------------------

    def scan_repo(self, repo_path: str, repo_url: Optional[str] = None) -> RunReport:
        from sentinel.scanners.repo import GitleaksScanner, SemgrepScanner
        from sentinel.scanners.deps import OSVScanner

        scanners = [SemgrepScanner(), GitleaksScanner(), OSVScanner()]
        return self.run_scanners(scanners, repo_path, repo_url=repo_url)

    def scan_config(self, path: str) -> RunReport:
        from sentinel.scanners.config import CheckovScanner, TrivyConfigScanner

        return self.run_scanners([CheckovScanner(), TrivyConfigScanner()], path)

    def scan_deps(self, path: str, repo_url: Optional[str] = None) -> RunReport:
        from sentinel.scanners.deps import OSVScanner

        return self.run_scanners([OSVScanner()], path, repo_url=repo_url)

    def scan_live(self, url: str, deep: bool = False, **opts) -> RunReport:
        from sentinel.scanners.live import NucleiScanner

        return self.run_scanners([NucleiScanner()], url, deep=deep, **opts)

    def scan_active(self, url: str, deep: bool = False, **opts) -> RunReport:
        """Active web pentest: Shannon + wapiti + ZAP.

        Distinct from scan_live so the audit log makes the active mode
        explicit. Per-target authorization still goes through the standard
        scope.authorize_url() gate.

        Order matters: Shannon spins up Docker workers and is sensitive to
        memory pressure. ZAP loads a 12GB JVM heap which starves Shannon's
        worker provisioning past its internal 2-min timeout. Run Shannon
        first while the system is idle, then wapiti (light), then ZAP last.
        """
        from sentinel.scanners.shannon import ShannonScanner
        from sentinel.scanners.zap import ZAPScanner
        from sentinel.scanners.wapiti import WapitiScanner

        scanners = [ShannonScanner(), WapitiScanner(), ZAPScanner()]
        return self.run_scanners(scanners, url, deep=deep, **opts)

    def scan_recon(self, target: str, deep: bool = False, **opts) -> RunReport:
        """Recon: subdomains + nmap NSE vuln + ffuf + kiterunner."""
        from sentinel.scanners.subdomains import SubdomainScanner
        from sentinel.scanners.nmap import NmapScanner
        from sentinel.scanners.ffuf import FfufScanner
        from sentinel.scanners.kiterunner import KiterunnerScanner

        scanners = [
            SubdomainScanner(),
            NmapScanner(),
            FfufScanner(),
            KiterunnerScanner(),
        ]
        return self.run_scanners(scanners, target, deep=deep, **opts)

    def scan_full(self, url: str, deep: bool = False, **opts) -> RunReport:
        """Everything: passive web intake + recon + nuclei + active pentest."""
        from sentinel.scanners.tls import TLSScanner
        from sentinel.scanners.headers import HeadersScanner
        from sentinel.scanners.dns_audit import DNSScanner
        from sentinel.scanners.whatweb import WhatWebScanner
        from sentinel.scanners.testssl import TestSSLScanner
        from sentinel.scanners.subdomains import SubdomainScanner
        from sentinel.scanners.nmap import NmapScanner
        from sentinel.scanners.ffuf import FfufScanner
        from sentinel.scanners.kiterunner import KiterunnerScanner
        from sentinel.scanners.live import NucleiScanner
        from sentinel.scanners.zap import ZAPScanner
        from sentinel.scanners.wapiti import WapitiScanner
        from sentinel.scanners.shannon import ShannonScanner

        scanners = [
            # Passive web intake
            TLSScanner(), HeadersScanner(), DNSScanner(),
            WhatWebScanner(), TestSSLScanner(),
            # Recon
            SubdomainScanner(), NmapScanner(), FfufScanner(), KiterunnerScanner(),
            # Template-driven
            NucleiScanner(),
            # Active pentest — Shannon first (Docker worker startup is
            # memory-sensitive; see scan_active() for the rationale).
            ShannonScanner(), WapitiScanner(), ZAPScanner(),
        ]
        return self.run_scanners(scanners, url, deep=deep, **opts)

    def scan_web(self, url: str, deep: bool = False, **opts) -> RunReport:
        """Passive web-app intake: TLS + headers + DNS + whatweb + testssl. Scope-gated."""
        from sentinel.scanners.tls import TLSScanner
        from sentinel.scanners.headers import HeadersScanner
        from sentinel.scanners.dns_audit import DNSScanner
        from sentinel.scanners.whatweb import WhatWebScanner
        from sentinel.scanners.testssl import TestSSLScanner

        scanners = [
            TLSScanner(), HeadersScanner(), DNSScanner(),
            WhatWebScanner(), TestSSLScanner(),
        ]
        return self.run_scanners(scanners, url, deep=deep, **opts)

    def generate_sbom(self, target: str, output_path: Optional[str] = None, format: str = "cyclonedx-json") -> RunReport:
        """Run Syft against a directory or image ref. Emits SBOM file + summary finding."""
        from sentinel.scanners.sbom import SBOMGenerator

        return self.run_scanners(
            [SBOMGenerator()],
            target,
            output_path=output_path,
            format=format,
        )
