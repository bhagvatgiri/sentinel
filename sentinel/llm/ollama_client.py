"""Local LLM client (Ollama) — used for triage, dedup heuristics, remediation.

Keeps client code on-prem. No findings ever leave the machine via this module.
Failure modes are non-fatal: if Ollama isn't running, triage falls back to
rule-based heuristics so the pipeline still produces a report.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Iterator, Optional

from sentinel.core.findings import Finding


log = logging.getLogger(__name__)


class OllamaClient:
    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3.1:8b", timeout: int = 60):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.host}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except (urllib.error.URLError, TimeoutError, OSError):
            return False

    def generate(self, prompt: str, system: Optional[str] = None, json_mode: bool = False) -> Optional[str]:
        body = {"model": self.model, "prompt": prompt, "stream": False}
        if system:
            body["system"] = system
        if json_mode:
            body["format"] = "json"
        try:
            req = urllib.request.Request(
                f"{self.host}/api/generate",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response")
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
            log.warning("ollama generate failed: %s", e)
            return None

    def generate_stream(self, prompt: str, system: Optional[str] = None) -> Iterator[str]:
        """Yield response chunks from /api/generate with stream=true.

        Each line on the wire is a JSON object {"response": str, "done": bool}.
        We yield the `response` strings until `done=true` or transport error.
        Empty iterator on error so callers can degrade ("(model unavailable)").

        Used by Phase A.1 SSE streaming on /chat. The non-streaming
        generate() above stays — triage / summarize / suggest-fix all
        keep using it because they want the complete string.
        """
        body = {"model": self.model, "prompt": prompt, "stream": True}
        if system:
            body["system"] = system
        try:
            req = urllib.request.Request(
                f"{self.host}/api/generate",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            # No global timeout — long answers are valid. Per-read timeout
            # via the underlying socket isn't exposed cleanly through urllib;
            # callers can wrap in their own asyncio.wait_for if needed.
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                for raw_line in resp:
                    if not raw_line:
                        continue
                    try:
                        chunk = json.loads(raw_line.decode("utf-8"))
                    except json.JSONDecodeError:
                        continue
                    text = chunk.get("response")
                    if text:
                        yield text
                    if chunk.get("done"):
                        return
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            log.warning("ollama generate_stream failed: %s", e)
            return

    # ---- finding-specific helpers --------------------------------------

    def triage_finding(self, finding: Finding, rag_context: Optional[str] = None) -> dict:
        """Ask the model: is this likely a false positive, what's the remediation?

        If `rag_context` is provided (from the corpus retriever), the model will
        ground its answer in that material and cite it.
        """
        system = (
            "You are a senior application security engineer. Given a single security "
            "finding, output strict JSON with keys: false_positive_likelihood (0.0-1.0), "
            "remediation (1-3 sentences, concrete and actionable), confidence_notes "
            "(1 sentence). Be conservative: only mark as likely false positive if the "
            "evidence is clearly insufficient. If reference CONTEXT is provided, ground "
            "your remediation in it and reference it briefly in confidence_notes."
        )
        finding_payload = json.dumps(
            {
                "title": finding.title,
                "description": finding.description,
                "scanner": finding.scanner,
                "severity": finding.severity.value,
                "location": finding.location,
                "cwe": finding.cwe,
                "cve": finding.cve,
            },
            indent=2,
        )
        prompt = finding_payload if not rag_context else f"FINDING:\n{finding_payload}\n\nCONTEXT:\n{rag_context}"
        out = self.generate(prompt, system=system, json_mode=True)
        if not out:
            return {}
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return {}

    def summarize_engagement(self, findings: list[Finding], client: str) -> Optional[str]:
        """Executive summary for the report. Strictly informational."""
        if not findings:
            return f"No findings identified during the engagement for {client}."
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        system = (
            "You are writing the executive summary of a security assessment report. "
            "Use plain professional English, 3-5 sentences, no bullet points. Do not "
            "invent details. Mention totals by severity if useful."
        )
        prompt = (
            f"Client: {client}\n"
            f"Findings by severity: {json.dumps(by_sev)}\n"
            f"Top 5 finding titles: {[f.title for f in findings[:5]]}\n"
            f"Write the executive summary."
        )
        return self.generate(prompt, system=system)
