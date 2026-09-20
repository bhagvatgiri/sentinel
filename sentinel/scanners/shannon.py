"""Shannon scanner — autonomous AI-driven web pentest via npx @keygraph/shannon.

Shannon (v1.1.x) is an LLM-driven autonomous pentester. It runs in its own
container, plans attacks with an Anthropic / Google / AWS-Bedrock model the
user has configured via `npx @keygraph/shannon setup`, and writes a
markdown deliverable plus per-workflow logs into ~/.shannon/workspaces/.
Sentinel wraps the CLI, lets Shannon do its run, then copies whatever
deliverables it produced via Shannon's own `--output <dir>` flag.

Per-target authorization still goes through `scope.authorize_url()` — the
audit log records every URL Shannon was pointed at.

CLI shape (from `npx @keygraph/shannon help`):
    start --url <url> --repo <path> [--output <dir>] [--workspace <name>]
          [--config <yaml>] [--pipeline-testing] [--debug]

Both `--url` AND `--repo` are required. For URL-only engagements (no
source available) we synthesize an empty stub repo so Shannon has
something to chew on.

Install:
    npm install -g @keygraph/shannon          # or: npx --yes ...
    npx @keygraph/shannon setup               # interactive credential setup
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import RateLimiter, Scanner, ScannerError


log = logging.getLogger(__name__)


SHANNON_TIMEOUT_SEC = 3 * 60 * 60          # 3 hours; Shannon can run a long time
SHANNON_STATE_DIR = Path.home() / ".shannon"


class ShannonScanner(Scanner):
    # Friendly name for logs / scanners_run / Finding.scanner. Actual binary
    # we shell out to is `npx`; check_available() handles that.
    tool_name = "shannon"
    description = "Active autonomous web pentest (Shannon)"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        """Shannon needs npx, the package, AND a one-time `setup` run that
        creates ~/.shannon/ with the user's AI provider credentials.

        We treat "npx present + ~/.shannon/ exists" as the signal Shannon is
        ready. Without setup, Shannon prints a usage error to stderr and
        exits 0, which used to look like a silent 0-findings run.
        """
        npx = shutil.which("npx")
        if not npx:
            return False, "npx not on PATH (install Node.js 18+)"
        if not SHANNON_STATE_DIR.is_dir():
            return False, (
                "shannon not configured — run `npx @keygraph/shannon setup` once "
                "to provide an AI provider key (Anthropic / Google / Bedrock)"
            )
        return True, npx

    def run(
        self,
        scope: Scope,
        target: str,
        repo_url: Optional[str] = None,
        deep: bool = False,
        **_opts,
    ) -> list[Finding]:
        scope.authorize_url(target)

        rl = RateLimiter(scope.rate_limit_rps)
        rl.wait()

        with tempfile.TemporaryDirectory(prefix="sentinel-shannon-") as tmp:
            tmp_dir = Path(tmp)
            out_dir = tmp_dir / "deliverables"
            out_dir.mkdir()

            # Shannon requires --repo as a local filesystem path. If the
            # caller passed a remote URL or nothing, give it an empty stub
            # so the URL-only attack surface is what gets exercised.
            repo_path = self._resolve_repo(repo_url, tmp_dir)
            workspace = self._workspace_name(scope, target)

            argv = [
                "npx", "--yes", "@keygraph/shannon", "start",
                "--url", target,
                "--repo", str(repo_path),
                "--output", str(out_dir),
                "--workspace", workspace,
            ]
            if not deep:
                # Faster, lighter prompts for routine engagements; deep mode
                # uses the default (full) prompt set.
                argv.append("--pipeline-testing")

            log.info("running: %s", " ".join(argv))
            try:
                proc = self._run_subprocess(argv, cwd=tmp_dir, timeout=SHANNON_TIMEOUT_SEC)
            except ScannerError as e:
                raise ScannerError(f"shannon: {e}") from e

            # Shannon copies deliverables (findings.json, report.md, attack
            # logs) into --output. Walk the dir for whatever it left behind.
            json_findings = self._collect_json_findings(out_dir)
            report_md = self._collect_markdown(out_dir)

            if json_findings:
                return [
                    self._item_to_finding(target, item, report_md)
                    for item in json_findings
                    if item is not None
                ]

            if report_md.strip():
                # No structured JSON but Shannon wrote a deliverable —
                # surface it as one INFO finding the operator can read.
                return [self._report_to_finding(target, report_md)]

            # Nothing produced — surface stderr/stdout so we know why.
            err = (proc.stderr or "").strip()
            out = (proc.stdout or "").strip()
            tail = (err or out)[-1000:]
            if tail:
                log.warning(
                    "shannon: no findings or report for %s (rc=%s, workspace=%s). last output:\n%s",
                    target, proc.returncode, workspace, tail,
                )
            else:
                log.info(
                    "shannon: no findings or report produced for %s (silent exit, workspace=%s)",
                    target, workspace,
                )
            return []

    # ---- helpers --------------------------------------------------------

    @staticmethod
    def _resolve_repo(repo_url: Optional[str], tmp_dir: Path) -> Path:
        """Shannon's --repo wants a local filesystem path that is also a git
        repository (its preflight rejects plain dirs with
        `ConfigurationError: Not a git repository`). For URL-only scans we
        synthesize an empty git repo so Shannon has something to chew on."""
        if repo_url:
            p = Path(repo_url).expanduser()
            if p.is_dir() and (p / ".git").exists():
                return p
            if p.is_dir():
                log.info("shannon: --repo %s exists but is not a git repo, falling back to empty stub", p)
            else:
                log.info("shannon: --repo %r is not a local dir, falling back to empty stub", repo_url)
        stub = tmp_dir / "empty-repo"
        stub.mkdir()
        (stub / "README.md").write_text("# placeholder for shannon --repo (URL-only scan)\n")
        # Quiet `git init` — Shannon only needs the .git/ dir to pass preflight.
        try:
            subprocess.run(
                ["git", "init", "-q", "-b", "main", str(stub)],
                check=True, capture_output=True, timeout=10,
            )
            subprocess.run(
                ["git", "-C", str(stub), "-c", "user.email=sentinel@local",
                 "-c", "user.name=sentinel", "commit", "--allow-empty",
                 "-q", "-m", "stub"],
                check=True, capture_output=True, timeout=10,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            log.warning("shannon: failed to git-init stub repo (%s); shannon may still reject it", e)
        return stub

    @staticmethod
    def _workspace_name(scope: Scope, target: str) -> str:
        """Stable per-(engagement, target) workspace so Shannon can resume
        if interrupted. Truncated SHA1 to keep names short and filesystem-safe."""
        eng = getattr(scope, "engagement_id", "") or ""
        h = hashlib.sha1(f"{eng}|{target}".encode()).hexdigest()[:10]
        slug = re.sub(r"[^a-z0-9]+", "-", target.lower())[:30].strip("-")
        return f"sentinel-{slug}-{h}" if slug else f"sentinel-{h}"

    def _collect_json_findings(self, out_dir: Path) -> list[dict]:
        """Walk Shannon's --output dir for any JSON files containing findings."""
        items: list[dict] = []
        for p in out_dir.rglob("*.json"):
            try:
                data = json.loads(p.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, list):
                items.extend(d for d in data if isinstance(d, dict))
            elif isinstance(data, dict):
                # Common shapes: {findings: [...]}, {vulnerabilities: [...]}, single finding
                for key in ("findings", "vulnerabilities", "issues", "results"):
                    v = data.get(key)
                    if isinstance(v, list):
                        items.extend(d for d in v if isinstance(d, dict))
                        break
                else:
                    if any(k in data for k in ("title", "name", "severity")):
                        items.append(data)
        return items

    @staticmethod
    def _collect_markdown(out_dir: Path) -> str:
        """Concatenate any markdown deliverables Shannon left behind."""
        chunks: list[str] = []
        for p in sorted(out_dir.rglob("*.md")):
            try:
                chunks.append(f"## {p.name}\n\n{p.read_text()}")
            except OSError:
                continue
        return "\n\n---\n\n".join(chunks)

    # ---- mapping --------------------------------------------------------

    # Shannon's vulnerability_type strings → best-fit CWE. Add entries as new
    # types are observed; the default falls back to None (no CWE).
    _VULN_TYPE_TO_CWE = {
        "Abuse_Defenses_Missing": "CWE-307",      # Improper restriction of excessive auth attempts
        "Authentication_Bypass": "CWE-287",
        "Broken_Authentication": "CWE-287",
        "Authorization_Bypass": "CWE-285",
        "IDOR": "CWE-639",
        "Broken_Access_Control": "CWE-285",
        "SQL_Injection": "CWE-89",
        "Command_Injection": "CWE-78",
        "Command_Execution": "CWE-78",
        "Path_Traversal": "CWE-22",
        "XSS": "CWE-79",
        "Cross_Site_Scripting": "CWE-79",
        "Stored": "CWE-79",                        # Shannon shorthand for stored XSS
        "Stored_XSS": "CWE-79",
        "Reflected": "CWE-79",
        "Reflected_XSS": "CWE-79",
        "DOM_XSS": "CWE-79",
        "CSRF": "CWE-352",
        "XXE": "CWE-611",
        "Service_Discovery": "CWE-918",            # SSRF used for internal probing
        "SSRF": "CWE-918",
        "Open_Redirect": "CWE-601",
        "Insecure_Deserialization": "CWE-502",
        "Sensitive_Data_Exposure": "CWE-200",
        "File_Upload": "CWE-434",
        "Subdomain_Takeover": "CWE-1395",
        "Security_Misconfiguration": "CWE-16",
    }

    def _item_to_finding(self, target: str, item: dict, report_md: str) -> Optional[Finding]:
        """Convert a single vuln dict from Shannon's exploitation_queue (or
        a generic JSON shape) into a Sentinel Finding.

        Shannon's exploitation queue entries use this schema:
            ID, vulnerability_type, externally_exploitable, source_endpoint,
            vulnerable_parameter, vulnerable_code_location, missing_defense,
            exploitation_hypothesis, suggested_exploit_technique, confidence,
            notes
        """
        # Shannon-specific fields (rich), with generic fallbacks.
        vuln_id = item.get("ID") or item.get("id") or ""
        vuln_type = item.get("vulnerability_type") or item.get("vulnerability_class") or ""
        title = (
            item.get("title")
            or item.get("name")
            or (f"{vuln_type.replace('_', ' ')}: {vuln_id}" if vuln_type and vuln_id else None)
            or vuln_id
            or "Shannon finding"
        )
        # Compose a richer description from Shannon's structured fields when present.
        desc_parts: list[str] = []
        if item.get("missing_defense"):
            desc_parts.append(item["missing_defense"])
        if item.get("exploitation_hypothesis"):
            desc_parts.append(f"Exploitation hypothesis: {item['exploitation_hypothesis']}")
        if not desc_parts:
            desc_parts.append(item.get("description") or item.get("summary") or "")
        description = "\n\n".join(p for p in desc_parts if p)

        sev = self._severity_from_item(item)
        cwe = self._cwe_from_item(item)
        # Prefer URL-shaped fields. `path` is sometimes Shannon's prose
        # data-flow description (600+ chars) — cap so it stays usable in tables.
        location = (
            item.get("source_endpoint")
            or item.get("url") or item.get("endpoint") or item.get("source")
            or item.get("path") or target
        )
        if isinstance(location, str) and len(location) > 200:
            location = location[:197] + "…"
        notes = item.get("notes") or ""
        # Pull a curl PoC out of notes if Shannon recommended one.
        poc = self._extract_first_command(notes)
        # Walk the markdown report for a richer evidence block matching this ID.
        evidence_block = self._extract_evidence_for_id(report_md, vuln_id) if vuln_id else ""
        if evidence_block:
            poc = poc or self._extract_first_command(evidence_block)

        return Finding(
            title=title,
            description=description,
            severity=sev,
            scanner="shannon",
            target=target,
            location=location,
            cwe=cwe,
            references=item.get("references") or [],
            remediation=self._remediation_for_type(vuln_type),
            impact=self._impact_from_item(item),
            proof_of_concept=poc or None,
            expected_output=evidence_block[:4000] if evidence_block else None,
            validation=item.get("suggested_exploit_technique") or None,
            raw={
                "shannon_id": vuln_id,
                "shannon_vuln_type": vuln_type,
                "shannon_confidence": item.get("confidence"),
                "shannon_externally_exploitable": item.get("externally_exploitable"),
                "shannon_vulnerable_code_location": item.get("vulnerable_code_location"),
                "shannon_vulnerable_parameter": item.get("vulnerable_parameter"),
                "shannon_notes": notes[:4000] if notes else "",
                "shannon_report_md": report_md[:8000] if report_md else "",
            },
        )

    def _report_to_finding(self, target: str, report_md: str) -> Finding:
        """When Shannon only produces a markdown report (no JSON), wrap it as one finding."""
        return Finding(
            title="Shannon engagement report",
            description="Shannon completed an engagement against this target. See raw.shannon_report_md for the full markdown deliverable.",
            severity=Severity.INFO,
            scanner="shannon",
            target=target,
            location=target,
            raw={"shannon_report_md": report_md[:50000]},
        )

    # ---- workspace ingestion --------------------------------------------

    @classmethod
    def parse_workspace(
        cls, workspace_dir: Path, target: Optional[str] = None
    ) -> tuple[list[Finding], dict]:
        """Read a Shannon workspace dir (~/.shannon/workspaces/<name>/) and
        return (findings, metadata). Used by the `sentinel ingest-shannon`
        command to convert a Shannon run done outside Sentinel into the
        standard Finding shape.

        Pulls vulns from every `*_exploitation_queue.json` in deliverables/
        and enriches each finding with the matching `*_exploitation_evidence.md`
        and `*_analysis_deliverable.md` content (PoC, attack metrics,
        impact narrative).
        """
        workspace_dir = Path(workspace_dir).expanduser()
        if not workspace_dir.is_dir():
            raise ValueError(f"shannon workspace not found: {workspace_dir}")
        deliverables = workspace_dir / "deliverables"
        if not deliverables.is_dir():
            raise ValueError(f"shannon deliverables dir not found: {deliverables}")

        # Resolve target from session.json when caller didn't provide one.
        meta: dict = {}
        session_path = workspace_dir / "session.json"
        if session_path.is_file():
            try:
                meta = json.loads(session_path.read_text())
            except (OSError, json.JSONDecodeError):
                meta = {}
        if target is None:
            target = (meta.get("session") or {}).get("webUrl", "unknown")

        # Combine all evidence + analysis markdowns so _item_to_finding can
        # search for per-ID sections inside one big string.
        evidence_md_parts: list[str] = []
        for p in sorted(deliverables.rglob("*.md")):
            try:
                evidence_md_parts.append(f"\n\n## File: {p.name}\n\n{p.read_text()}")
            except OSError:
                continue
        all_evidence = "".join(evidence_md_parts)

        scanner = cls()
        findings: list[Finding] = []
        for q in sorted(deliverables.rglob("*_exploitation_queue.json")):
            try:
                data = json.loads(q.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            items: list[dict] = []
            if isinstance(data, list):
                items = [d for d in data if isinstance(d, dict)]
            elif isinstance(data, dict):
                v = data.get("vulnerabilities") or data.get("findings") or data.get("issues")
                if isinstance(v, list):
                    items = [d for d in v if isinstance(d, dict)]
            for item in items:
                f = scanner._item_to_finding(target, item, all_evidence)
                if f:
                    findings.append(f)
        return findings, meta

    # ---- field derivation helpers ---------------------------------------

    def _severity_from_item(self, item: dict) -> Severity:
        """Map Shannon's confidence + externally_exploitable + vuln_type to severity.

        Highest weight to confidence (Shannon's own assessment) and external
        exploitability, then vulnerability class. If Shannon wrote an explicit
        `severity` key, prefer that.
        """
        explicit = item.get("severity")
        if explicit:
            return Severity.from_string(str(explicit))

        confidence = (item.get("confidence") or "").strip().lower()
        external = bool(item.get("externally_exploitable"))
        vuln_type = (item.get("vulnerability_type") or "").lower()

        # High-confidence externally-exploitable findings → HIGH (or CRITICAL
        # for command exec / SQLi / auth bypass that fully takes over the app).
        critical_types = {"command_execution", "command_injection", "sql_injection",
                          "authentication_bypass", "insecure_deserialization", "xxe"}
        if confidence == "high" and external and vuln_type in critical_types:
            return Severity.CRITICAL
        if confidence == "high" and external:
            return Severity.HIGH
        if confidence == "high":
            return Severity.MEDIUM
        if confidence == "medium":
            return Severity.MEDIUM if external else Severity.LOW
        if confidence == "low":
            return Severity.LOW
        # Unknown confidence — default to MEDIUM so it gets attention.
        return Severity.MEDIUM

    def _cwe_from_item(self, item: dict) -> Optional[str]:
        # Explicit CWE field wins.
        cwe = item.get("cwe") or item.get("cwe_id")
        if cwe is not None:
            if isinstance(cwe, dict):
                cwe = cwe.get("id")
            try:
                return f"CWE-{int(cwe)}"
            except (TypeError, ValueError):
                return str(cwe)
        # Otherwise derive from Shannon's vulnerability_type.
        vuln_type = item.get("vulnerability_type") or item.get("vulnerability_class")
        if vuln_type and vuln_type in self._VULN_TYPE_TO_CWE:
            return self._VULN_TYPE_TO_CWE[vuln_type]
        return None

    @staticmethod
    def _impact_from_item(item: dict) -> Optional[str]:
        """Synthesize a one-paragraph impact statement from Shannon's structured fields."""
        bits = []
        if item.get("externally_exploitable"):
            bits.append("Externally exploitable.")
        if item.get("vulnerable_code_location"):
            bits.append(f"Vulnerable surface: {item['vulnerable_code_location']}")
        if item.get("suggested_exploit_technique"):
            bits.append(f"Suggested technique: {item['suggested_exploit_technique']}.")
        return " ".join(bits) or None

    @staticmethod
    def _remediation_for_type(vuln_type: str) -> Optional[str]:
        """Generic remediation hints keyed off Shannon's vulnerability_type.
        Kept terse — the LLM triage step adds the engagement-specific guidance."""
        hints = {
            "Abuse_Defenses_Missing": (
                "Add rate limiting, account lockout, and progressive delay to authentication "
                "endpoints. Consider CAPTCHA after N failures and IP-based throttling at the edge."
            ),
            "Authentication_Bypass": "Audit and rewrite the auth check; add positive (not negative) authorization checks per route.",
            "SQL_Injection": "Use parameterized queries / ORM bindings; never concatenate user input into SQL.",
            "Command_Injection": "Avoid shell invocation; use exec arrays not strings; whitelist allowed inputs.",
            "Command_Execution": "Avoid shell invocation; use exec arrays not strings; whitelist allowed inputs.",
            "Path_Traversal": "Resolve user paths to absolute, then enforce they sit under an allowed root before opening.",
            "XSS": "Output-encode for the destination context; set a strict Content-Security-Policy.",
            "Cross_Site_Scripting": "Output-encode for the destination context; set a strict Content-Security-Policy.",
            "Stored": "Sanitize stored HTML before rendering (DOMPurify or equivalent on the server side); set a strict Content-Security-Policy that disallows inline scripts.",
            "Stored_XSS": "Sanitize stored HTML before rendering (DOMPurify or equivalent on the server side); set a strict Content-Security-Policy that disallows inline scripts.",
            "Reflected": "Output-encode all user-supplied query/path parameters for the destination context; set a strict Content-Security-Policy.",
            "Reflected_XSS": "Output-encode all user-supplied query/path parameters for the destination context; set a strict Content-Security-Policy.",
            "DOM_XSS": "Avoid sinks like innerHTML/document.write with attacker-influenced strings; use textContent or framework-managed rendering.",
            "CSRF": "Require unguessable per-session tokens on state-changing requests; use SameSite=Lax cookies.",
            "XXE": "Disable external entity resolution in the XML parser.",
            "Service_Discovery": "Add an explicit allowlist of fetchable URLs/paths; deny relative paths to internal endpoints.",
            "SSRF": "Add an explicit allowlist of fetchable URLs/paths; block private IPs and metadata endpoints.",
            "Open_Redirect": "Validate redirect targets against an allowlist; never trust user-supplied next= URLs.",
            "Insecure_Deserialization": "Avoid deserializing untrusted input; use signed payloads if necessary.",
            "Sensitive_Data_Exposure": "Mask or remove sensitive fields from responses; audit logging for the same.",
            "File_Upload": "Allowlist content types, validate magic bytes, store outside webroot, scan for malware.",
            "Subdomain_Takeover": "Remove dangling DNS records pointing at deprovisioned third-party services.",
            "Security_Misconfiguration": "Harden defaults; review per the CIS / Vendor benchmark for the affected component.",
        }
        return hints.get(vuln_type)

    @staticmethod
    def _extract_first_command(text: str) -> str:
        """Pull the first fenced bash/curl/python block out of markdown/notes."""
        if not text:
            return ""
        # Fenced code block — prefer language-tagged blocks first. DOTALL so
        # multi-line code blocks capture (Shannon's evidence files almost
        # always use multi-line bash blocks).
        for lang in ("bash", "shell", "sh", "python", "http", ""):
            pat = rf"```{lang}\n(.*?)```" if lang else r"```\n(.*?)```"
            m = re.search(pat, text, re.DOTALL)
            if m and m.group(1).strip():
                return m.group(1).strip()[:2000]
        # Inline `code` runs as last resort.
        m = re.search(r"`([^`\n]{8,})`", text)
        return m.group(1).strip()[:2000] if m else ""

    @staticmethod
    def _extract_evidence_for_id(report_md: str, vuln_id: str) -> str:
        """Slice out the section of the evidence/analysis markdown that
        documents this specific vulnerability ID. Shannon writes per-ID
        H3 sections like '### AUTH-VULN-01: ...'."""
        if not report_md or not vuln_id:
            return ""
        # NOTE: double-brace `{{1,4}}` inside an f-string is required to
        # produce the literal `{1,4}` regex quantifier — single braces would
        # be interpreted as the tuple expression `(1, 4)` and silently
        # produce a regex that never matches.
        pat = (
            r"(?:^|\n)#{1,4}\s+[^\n]*\b"
            + re.escape(vuln_id)
            + r"\b[^\n]*\n(.*?)(?=\n#{1,3}\s|\Z)"
        )
        m = re.search(pat, report_md, re.DOTALL)
        return m.group(1).strip()[:8000] if m else ""
