"""Sentinel CLI.

Subcommands:
  scan-repo     Run SAST + secret + dep scanners on a local repo
  scan-config   Run IaC/config scanners on a directory
  scan-deps     Run dependency CVE scan on a manifest dir
  scan-live     Run nuclei against an in-scope URL (scope-gated)
  scan-active   Active web pentest: ZAP + wapiti + Shannon (scope-gated)
  scan-recon    Recon: nmap NSE vuln + ffuf directory/parameter discovery (scope-gated)
  scan-full     Everything: passive + nuclei + recon + active pentest (scope-gated)
  scan-dfir     Run the DFIR agent on a pcap or log file (Wave 7)
  verify-audit  Verify the integrity of an audit log
  report        Compile the final PDF deliverable from a run
  ingest        Ingest a corpus source (owasp/mitre-cwe/mitre-attack/nist/nvd/writeups/hackerone/books)
  ask           Q&A grounded in the local corpus
  corpus-stats  Show vector store stats
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import date
from pathlib import Path
from typing import Optional

from sentinel import __version__
from sentinel.core.orchestrator import Orchestrator, RunReport
from sentinel.core.scope import AuditLog, OutOfScopeError, Scope, ScopeError
from sentinel.llm.ollama_client import OllamaClient
from sentinel.reporting.obsidian import ObsidianReporter


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="Defensive security agent (scope-gated).")
    p.add_argument("--version", action="version", version=f"sentinel {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")

    sub = p.add_subparsers(dest="cmd", required=True)

    # ---- common flags for scan/report --------------------------------------
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--scope", required=True, help="Path to scope.yaml")
    common.add_argument("--vault", help="Obsidian vault path (writes engagement notes)")
    common.add_argument("--ollama-host", default="http://localhost:11434")
    common.add_argument("--ollama-model", default="llama3.1:8b")
    common.add_argument("--no-llm", action="store_true", help="Disable Ollama triage entirely")
    common.add_argument("--corpus-dir", help="Path to Chroma corpus dir; enables RAG-augmented triage")
    common.add_argument("--embed-model", default="nomic-embed-text")

    sr = sub.add_parser("scan-repo", parents=[common], help="SAST + secrets + deps on a local repo")
    sr.add_argument("path")
    sr.add_argument("--repo-url", help="Canonical repo URL (e.g. github.com/owner/name) for scope match")

    sc = sub.add_parser("scan-config", parents=[common], help="IaC / config scanning")
    sc.add_argument("path")

    sd = sub.add_parser("scan-deps", parents=[common], help="Dependency CVE scan")
    sd.add_argument("path")
    sd.add_argument("--repo-url")

    sl = sub.add_parser("scan-live", parents=[common], help="Live URL scan (nuclei, scope-gated)")
    sl.add_argument("url")
    sl.add_argument("--max-severity", default="critical",
                    help="Highest severity to report (default critical = include all)")
    sl.add_argument("--deep", action="store_true",
                    help="Expand template tag set (tech-detect, login-page, exposed-panels, osint, fuzz, intrusive). Longer scans, more findings.")

    sa = sub.add_parser("scan-active", parents=[common], help="Active web pentest: ZAP + wapiti + Shannon (scope-gated)")
    sa.add_argument("url")
    sa.add_argument("--repo-url", help="Path or URL to source repo (lets Shannon do white-box analysis)")
    sa.add_argument("--deep", action="store_true",
                    help="ZAP full-scan + wapiti full module set + Shannon comprehensive mode (much longer)")

    sr = sub.add_parser("scan-recon", parents=[common], help="Recon: nmap NSE vuln + ffuf (scope-gated)")
    sr.add_argument("target")
    sr.add_argument("--deep", action="store_true",
                    help="nmap -A -p- (all ports) + ffuf parameter discovery on top of directory busting")

    sf = sub.add_parser("scan-full", parents=[common], help="Everything: passive + nuclei + recon + active (scope-gated)")
    sf.add_argument("url")
    sf.add_argument("--repo-url", help="Path or URL to source repo (Shannon white-box)")
    sf.add_argument("--deep", action="store_true", help="Deep mode for every scanner. Hours.")

    sw = sub.add_parser("scan-web", parents=[common], help="Passive web intake: TLS + headers + DNS + whatweb + testssl (scope-gated)")
    sw.add_argument("url")
    sw.add_argument("--deep", action="store_true",
                    help="whatweb -a 4 (heavier fingerprinting) + testssl --full")

    sb = sub.add_parser("sbom", parents=[common], help="Generate SBOM (Syft) for a directory or image")
    sb.add_argument("target", help="Directory path or image ref (e.g. nginx:latest)")
    sb.add_argument("--sbom-output", help="Write SBOM to this path (default: ./sbom-<client>.json)")
    sb.add_argument("--sbom-format", default="cyclonedx-json", choices=["cyclonedx-json", "spdx-json", "syft-json"])

    cm = sub.add_parser("compliance", parents=[common], help="Map a previous run's findings to compliance frameworks")
    cm.add_argument("--findings-json", required=True)
    cm.add_argument("--output", help="Write the markdown overlay here (default: stdout)")

    va = sub.add_parser("verify-audit", help="Verify the integrity of an audit log")
    va.add_argument("path")
    va.add_argument("--scope", default=None,
                    help="Optional scope.yaml. When provided, the verifier "
                         "ALSO checks that the audit log's first-entry mode "
                         "matches the scope's `engagement_mode:` field "
                         "(Wave 3 anti-tamper: catches a CTF run laundered "
                         "into a production scope post-hoc).")

    rp = sub.add_parser("report", parents=[common], help="Generate PDF report from latest run")
    rp.add_argument("--output-dir", default="./reports")
    rp.add_argument("--findings-json", required=True, help="Path to findings JSON dumped by a scan command")
    rp.add_argument("--diff", dest="diff_against", default=None,
                    help="Path to a prior runs/<id>.json — emit a delta section "
                         "(closed/new/escalated/persisted) and embed it in the report")

    # Pre-submission gate — score a run's findings GO/REVIEW/HOLD before they go
    # to a bug-bounty program, so weak ones never get submitted + nulled.
    tg = sub.add_parser(
        "triage-findings",
        help="Pre-submission gate: score a run's findings GO/REVIEW/HOLD before "
             "submitting to a bounty program",
    )
    tg.add_argument("--findings-json", required=True,
                    help="Path to a run JSON (or exploitation-queue JSON) of findings")
    tg.add_argument("--program-maturity", choices=["high", "medium", "low"],
                    default=None,
                    help="Mature/heavily-researched programs (ExampleChat/AcmeProgram-tier) "
                         "raise duplicate risk for surface findings")
    tg.add_argument("--json", action="store_true", dest="as_json",
                    help="Emit machine-readable JSON instead of the text table")

    # Ingest a Shannon workspace produced outside Sentinel into the standard
    # findings shape (PDF/compliance/Obsidian all work afterwards). `common`
    # already provides --vault, --scope, --ollama-host, --ollama-model, etc.
    ish = sub.add_parser("ingest-shannon", parents=[common],
                         help="Ingest a Shannon workspace dir into Sentinel findings (for runs done outside scan-active)")
    ish.add_argument("workspace",
                     help="Workspace name (under ~/.shannon/workspaces/) OR an absolute path")
    ish.add_argument("--target",
                     help="Override the target URL (default: read from session.json's webUrl)")

    # ---- corpus subcommands ------------------------------------------------
    ig = sub.add_parser("ingest", help="Ingest a corpus source into the local vector store")
    ig.add_argument(
        "--source",
        required=True,
        choices=["owasp", "mitre-cwe", "mitre-attack", "nist", "nvd", "writeups", "hackerone", "books", "past-engagements", "payloads-all-the-things", "all"],
    )
    ig.add_argument("--corpus-dir", required=True, help="Where to persist the Chroma DB")
    ig.add_argument("--vault", help="Also write each ingested doc into this Obsidian vault")
    ig.add_argument("--books-dir", help="Local folder of legally-owned books (required for --source=books)")
    ig.add_argument("--workspaces-dir", default="workspaces",
                    help="Where past pentest workspaces live (for --source=past-engagements)")
    ig.add_argument("--only-engagements", nargs="*", default=None,
                    help="Restrict past-engagements ingest to specific engagement IDs")
    ig.add_argument("--ollama-host", default="http://localhost:11434")
    ig.add_argument("--embed-model", default="nomic-embed-text")
    ig.add_argument("--nvd-since-year", type=int, default=2020)
    ig.add_argument("--nvd-max-records", type=int, default=None, help="Cap CVE count (smoke testing)")
    ig.add_argument("--hackerone-max-reports", type=int, default=None,
                    help="Cap on number of HackerOne reports to ingest (None=all disclosed)")
    ig.add_argument("--hackerone-full-bodies", action="store_true",
                    help="[BROKEN as of 2026-XX-XX] Intended to fetch full report "
                         "bodies via /v1/hackers/reports/{id}, but the H1 REST API "
                         "does not expose vulnerability_information to third-party "
                         "API callers — both list and detail endpoints return None. "
                         "Cached JSONs land at <work_dir>/full-bodies/<id>.json but "
                         "have no body content. See module docstring in "
                         "sentinel/corpus/sources/hackerone.py for body-retrieval "
                         "alternatives (Playwright scrape, GraphQL RE, GitHub mirror).")
    ig.add_argument("--hackerone-full-bodies-max", type=int, default=None,
                    help="Cap on per-report body fetches in a single ingest run. "
                         "Useful for backfilling in chunks.")
    ig.add_argument("--hackerone-full-bodies-rps", type=float, default=1.0,
                    help="Per-report fetch rate (req/sec). Default 1.0; "
                         "anything above 5.0 is excessive on H1.")
    ig.add_argument("--chunk-size", type=int, default=1500)
    ig.add_argument("--chunk-overlap", type=int, default=200)
    ig.add_argument("--work-dir", default=None,
                    help="Persistent work directory for source-specific caches "
                         "(e.g. HackerOne per-report bodies). When omitted, a "
                         "tempdir is used and removed after the run, meaning any "
                         "fetch cache is lost on the next run.")

    aq = sub.add_parser("ask", help="Ask the corpus a question (RAG)")
    aq.add_argument("question")
    aq.add_argument("--corpus-dir", required=True)
    aq.add_argument("--top-k", type=int, default=5)
    aq.add_argument("--ollama-host", default="http://localhost:11434")
    aq.add_argument("--ollama-model", default="llama3.1:8b")
    aq.add_argument("--embed-model", default="nomic-embed-text")
    aq.add_argument("--source-filter", nargs="*", help="Restrict retrieval to listed sources (space-separated)")

    cs = sub.add_parser("corpus-stats", help="Print stats about the vector store")
    cs.add_argument("--corpus-dir", required=True)
    cs.add_argument("--ollama-host", default="http://localhost:11434")
    cs.add_argument("--embed-model", default="nomic-embed-text")


    web = sub.add_parser("web", help="Launch the new FastAPI/HTMX/Tailwind UI")
    web.add_argument("--port", type=int, default=8080)
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--reload", action="store_true", help="Auto-reload on code change (dev)")

    # ---- agents ------------------------------------------------------------
    bg = sub.add_parser(
        "brain-grow",
        help="Autonomous research agent: grows the corpus on a topic by searching + ingesting.",
    )
    bg.add_argument("--topic", required=True,
                    help="Research topic (e.g., 'SSRF bypass techniques 2024-2025')")
    bg.add_argument("--corpus-dir", required=True,
                    help="Where the Chroma DB lives (e.g., ~/sentinel-corpus)")
    bg.add_argument("--ollama-host", default="http://localhost:11434")
    bg.add_argument("--embed-model", default="nomic-embed-text")
    bg.add_argument("--max-pages", type=int, default=25,
                    help="Hard cap on fetch_url calls per session")
    bg.add_argument("--depth", type=int, default=2,
                    help="Max recursion depth for subtopic exploration")
    bg.add_argument("--max-turns", type=int, default=80,
                    help="SDK turn limit (raise for deeper sessions)")
    bg.add_argument("--max-budget-usd", type=float, default=5.0,
                    help="Hard $ cap on LLM spend for this session")
    bg.add_argument("--model", default=None,
                    help="Override the LLM model (default: SDK's Sonnet)")
    bg.add_argument("--rate-limit-per-host-sec", type=float, default=1.0,
                    help="Min seconds between fetches to the same hostname")
    bg.add_argument("--chunk-size", type=int, default=1500)
    bg.add_argument("--chunk-overlap", type=int, default=200)
    bg.add_argument("--brain-backend", choices=["ollama", "claude"], default="ollama",
                    help="LLM backend for the brain loop. Default 'ollama' "
                         "runs locally for $0; 'claude' uses claude-agent-sdk "
                         "(more capable, but costs $ + can hit Anthropic's "
                         "cyber-use safeguard on offensive topics).")
    bg.add_argument("--ollama-brain-model", default="llama3.1:8b",
                    help="Ollama model for the brain loop (when --brain-backend=ollama). "
                         "Default is llama3.1:8b — confirmed to actually execute multi-step "
                         "tool-use loops. mistral-nemo:12b emits one tool call then narrates "
                         "instead of looping. qwen2.5-coder:7b inlines tool calls as text "
                         "(fallback parser handles it).")
    bg.add_argument("--ollama-max-turns", type=int, default=30,
                    help="Max tool-use turns for the Ollama brain loop")
    bg.add_argument("--force-topic", action="store_true",
                    help="Override the topic-density pre-check. By default brain-grow "
                         "refuses topics whose closest corpus chunk is under distance "
                         "0.20, since those runs almost always produce zero new docs. "
                         "Use this to force a run anyway.")
    bg.add_argument("--topic-dense-threshold", type=float, default=0.20,
                    help="Cosine distance below which a topic is considered "
                         "already-densely-covered and the run is skipped (unless "
                         "--force-topic is set). Default: 0.20.")
    bg.add_argument("--mode", choices=["production", "bbp", "ctf", "lab"], default=None,
                    help="Wave 3 — engagement mode label for the brain-grow run. "
                         "Optional; informational for the audit log.")

    ag = sub.add_parser(
        "agent",
        help="Autonomous pentest agent (Phase 1: recon). Scope-gated, audit-logged.",
    )
    ag.add_argument("target", help="Target URL (must be in scope)")
    ag.add_argument("--scope", required=True, help="Path to engagement scope YAML")
    ag.add_argument("--workspaces-root", default="./workspaces",
                    help="Where per-engagement agent state lives")
    ag.add_argument("--max-pages", type=int, default=30,
                    help="Hard cap on http_get calls in this session")
    ag.add_argument("--max-turns", type=int, default=60,
                    help="SDK turn limit (raise for deeper recon)")
    ag.add_argument("--max-budget-usd", type=float, default=5.0,
                    help="Hard $ cap on LLM spend")
    ag.add_argument("--model", default=None,
                    help="Override the LLM model (default: SDK's Sonnet)")
    ag.add_argument("--rate-limit-per-host-sec", type=float, default=1.0)
    ag.add_argument("--mode", choices=["production", "bbp", "ctf", "lab"], default=None,
                    help="Wave 3 — engagement mode (must agree with scope's engagement_mode).")

    sa = sub.add_parser(
        "scan-autonomous",
        help="Full autonomous pentest pipeline (recon + 6 vuln + 6 exploit + correlation + report). "
             "Scope-gated, audit-logged, RAG-augmented if --corpus-dir is provided.",
    )
    sa.add_argument("target", nargs="?", default=None,
                    help="Target URL (must be in scope). Omit + use --all-scope-targets to fan out across every domain in the scope file.")
    sa.add_argument("--all-scope-targets", action="store_true",
                    help="Run a parallel pipeline per domain in scope.targets.domains (wildcards skipped). Combined summary written at the end.")
    sa.add_argument("--max-concurrent", type=int, default=2,
                    help="Maximum parallel pipelines when using --all-scope-targets")
    sa.add_argument("--scope", required=True, help="Path to engagement scope YAML")
    sa.add_argument("--workspaces-root", default="./workspaces")
    sa.add_argument("--corpus-dir", default=None,
                    help="Enables corpus_search tool (RAG). Without this, agents work without RAG context.")
    sa.add_argument("--repo-path", default=None,
                    help="Local source repo for pre-recon SAST. Without this, SAST is skipped.")
    sa.add_argument("--ollama-host", default="http://localhost:11434")
    sa.add_argument("--embed-model", default="nomic-embed-text")
    sa.add_argument("--max-budget-per-phase-usd", type=float, default=6.5,
                    help="Per-phase $ cap (Sonnet ~$3/Mtok input, $15/Mtok output). "
                         "Default 6.5 lands at ~$50–$90 typical scan when combined "
                         "with --max-budget-per-scan-usd 100. Phase A bump 2026-XX-XX.")
    sa.add_argument("--max-budget-per-scan-usd", type=float, default=100.0,
                    help="Hard $ ceiling on TOTAL scan spend. Pipeline gracefully "
                         "skips remaining phases when exceeded. Use 100 for full "
                         "H1 deep scans, 30 for fast triage. Phase A 2026-XX-XX.")
    # Plan 03-02 (COST-01) — operator-explicit STRICT cost cap. Distinct from
    # --max-budget-per-scan-usd (the soft default-cap path) — when set, the
    # between-phase guard writes a `scan_aborted_cost_cap` audit event AND
    # aborts the pipeline instead of emitting the soft
    # `phase_skipped_budget_exhausted` signal. Motivated by the 2026-XX-XX
    # cost finding ($19.94 burned in half a Juice Shop bench scan against
    # the wrong Qwen alias).
    sa.add_argument("--max-cost-usd", type=float, default=None,
                    help="Best-effort hard cost cap (USD). When set, the scan "
                         "ABORTS cleanly between phases when total LLM spend "
                         "crosses this threshold and writes a "
                         "scan_aborted_cost_cap audit event. Contract: no NEW "
                         "phase starts after cap exceeded; a single very-"
                         "expensive phase can overshoot the cap by its own "
                         "delta (checked between phases, not mid-LLM-call). "
                         "Distinct from --max-budget-per-scan-usd (soft "
                         "default-cap path emits phase_skipped_budget_exhausted "
                         "and walks remaining phases as no-ops). Use 5 for a "
                         "Juice Shop bench, 30 for a deep H1 dive. Must be > 0. "
                         "Plan 03-02 (2026-XX-XX cost-finding).")
    # 2026-XX-XX cost control. None = run all 15 vuln classes (default);
    # comma-list = run only those slugs. Each class is one concurrent Opus
    # agent at ~$1-2 each, so narrowing cuts per-scan spend 5-10x.
    sa.add_argument("--vuln-classes", default=None,
                    metavar="SLUG,SLUG,...",
                    help="Comma-separated vuln class slugs to run (default: "
                         "all 15 — auth,authz,idor,injection,xss,ssrf,csrf,"
                         "file_upload,jwt_oauth,cors,crlf,websocket,"
                         "takeover,redirect,graphql). Narrowing controls "
                         "per-scan cost: each class is one concurrent Opus "
                         "agent at ~$1-2.")
    sa.add_argument("--recon-max-pages", type=int, default=40,
                    help="Recon HTTP-GET cap. Phase A bump 30 → 40.")
    sa.add_argument("--recon-max-turns", type=int, default=80,
                    help="Recon SDK turn cap. Phase A bump 60 → 80.")
    sa.add_argument("--vuln-max-pages", type=int, default=30,
                    help="Per-vuln-class HTTP-GET cap. Was hardcoded =10 (bug); "
                         "Phase A 2026-XX-XX makes it configurable + bumps default to 30.")
    sa.add_argument("--vuln-max-turns", type=int, default=70,
                    help="Per-vuln-class SDK turn cap. Phase A bump 50 → 70.")
    sa.add_argument("--exploit-max-turns", type=int, default=110,
                    help="Per-exploit-class SDK turn cap. Phase A bump 80 → 110.")
    sa.add_argument("--correlation-max-turns", type=int, default=40,
                    help="Correlation phase turn cap. Phase A bump 30 → 40.")
    sa.add_argument("--report-max-turns", type=int, default=30,
                    help="Report phase turn cap. Phase A bump 25 → 30.")
    sa.add_argument("--report-style",
                    choices=["full", "exploits-only", "skip-empty"],
                    default="skip-empty",
                    help="Phase 5 report mode (2026-XX-XX). 'skip-empty' "
                         "(default): skip Phase 5 entirely if 0 exploit-confirmed "
                         "findings, else exploits-only. 'exploits-only': always "
                         "run Phase 5 but only write about Status:EXPLOITED entries. "
                         "'full': legacy — write Findings + 4 appendices over every "
                         "queue entry (~3-4× more tokens).")
    sa.add_argument("--model", default=None,
                    help="Override the LLM model (default: SDK's Sonnet)")
    sa.add_argument("--rate-limit-per-host-sec", type=float, default=1.0)
    sa.add_argument("--skip", nargs="*", default=[],
                    help="Phases to skip: recon vuln exploit correlation report pre-recon")
    sa.add_argument("--vault", default=None,
                    help="Obsidian vault to write the engagement folder into")
    sa.add_argument("--auto-brain", action="store_true",
                    help="Auto-extract research keywords from tool results and grow the corpus in the background. Requires --corpus-dir.")
    sa.add_argument("--brain-max-topics", type=int, default=8,
                    help="Max background brain-grow topics per pipeline run (cost cap)")
    sa.add_argument("--brain-budget-per-topic-usd", type=float, default=0.50,
                    help="Per-topic brain-grow budget cap")
    sa.add_argument("--resume", action="store_true",
                    help="Resume an interrupted run — skip phases that already committed in workspace/.completed_phases.json")
    # Phase 2.5 — Live Verification (W1 over-trust fix, 2026-XX-XX).
    sa.add_argument("--no-verify-before-exploit", action="store_true",
                    help="Disable Phase 2.5 live verification. Default: ON. "
                         "When enabled (default), every Phase 2 queue entry is "
                         "walked through a class-specific verifier that "
                         "reproduces the bug end-to-end before Phase 3 runs. "
                         "Phase 3 only exploits live_confirmed entries — "
                         "prevents the W1 over-trust gap that produced the "
                         "ExampleStore.com `maxAuthAge` and `returnUrl→assertion "
                         "capture` over-claims.")
    # Phase 3.5 — chain-attack execution (detection-mode goal-driven attacks).
    sa.add_argument("--chain-goals", default="admin_session_takeover,pii_exfil,lateral_to_internal_service",
                    help="Comma-separated goals for the chain executor. Available: "
                         "admin_session_takeover, pii_exfil, lateral_to_internal_service, "
                         "session_fixation_or_hijack, rce, persistent_backdoor_admin, "
                         "audit_log_tamper, payment_flow_bypass. All run in detection mode "
                         "(non-destructive proofs, canary callbacks, rollback-after-write).")
    sa.add_argument("--chain-max-chains-per-goal", type=int, default=5,
                    help="Top-K chains attempted per goal (ranked by confidence). Default 5.")
    sa.add_argument("--chain-max-steps-per-chain", type=int, default=10,
                    help="Step budget per chain attempt. Default 10.")
    sa.add_argument("--chain-max-wall-clock-sec", type=int, default=900,
                    help="Wall-clock cap per chain attempt in seconds. Default 900.")
    sa.add_argument("--no-chain-execution", action="store_true",
                    help="Disable Phase 3.5 entirely. Phase 4 correlation falls back to its "
                         "pre-3.5 narrative-only behavior.")
    # Phase backend (Claude vs Ollama failover)
    sa.add_argument("--phase-backend", choices=["auto", "claude", "ollama"], default="auto",
                    help="LLM backend for pipeline phases. 'auto' (default): try Claude, "
                         "fall back to Ollama for phases registered in "
                         "ModelRouter.DEFAULT_FALLBACK_PHASE_MODELS (currently report + "
                         "correlation) when Claude exhausts retries. 'claude': Claude only "
                         "— fail loudly if unreachable. 'ollama': skip Claude on the wired "
                         "phases entirely; other phases still attempt Claude.")
    sa.add_argument("--ollama-fallback-model", default="qwen2.5:32b-instruct-q4_K_M",
                    help="Ollama model used by --phase-backend=auto/ollama for the "
                         "failover-wired phases. Default qwen2.5:32b-instruct-q4_K_M is "
                         "the closest local Claude-Sonnet-class model that fits on a "
                         "48 GB Mac alongside other Ollama loads.")
    sa.add_argument("--enable-operator-chat", action="store_true",
                    help="Phase B: open a control channel for operator directives "
                         "(see /agent-runs/<job>/chat). Pipeline drains the channel "
                         "between phases and prepends operator messages to the next "
                         "phase's prompt. Audit-logged as operator_directive. Default off.")
    sa.add_argument("--mode", choices=["production", "bbp", "ctf", "lab"], default=None,
                    help="Wave 3 — engagement mode. MUST agree with the scope "
                         "file's `engagement_mode:` field. CTF / LAB unlock "
                         "dangerous tools (webshells, reverse shells, code "
                         "execution); production / bbp keep them refused. "
                         "Mode-mismatch fails the run before any phase begins.")
    # Wave 9 — Opus teacher per-phase supervisor.
    sa.add_argument("--teacher", choices=["full", "review-only", "plan-only", "off"],
                    default="off",
                    help="Wave 9 — Opus 4.7 teacher mode. full = pre-phase plan + "
                         "mid-phase critique + post-phase review. review-only = "
                         "post-phase review only. plan-only = pre-phase plan only. "
                         "off (DEFAULT — changed 2026-XX-XX cost-cut) = disable. "
                         "Per-scan teacher cost was averaging $2-6 with no impact "
                         "on bug-finding rate; flip back to review-only for runs "
                         "where you specifically want the RLAIF training tuples in "
                         "~/sentinel-train/online.jsonl.")
    sa.add_argument("--teacher-model", default="claude-opus-4-7",
                    help="Wave 9 — Claude model for the teacher (default opus 4.7).")
    sa.add_argument("--teacher-budget-usd", type=float, default=30.0,
                    help="Wave 9 — hard cap on teacher Opus spend per scan. "
                         "First call past cap emits teacher_budget_exhausted and "
                         "all further hooks return None (graceful, not fail).")
    sa.add_argument("--no-teacher", action="store_true",
                    help="Wave 9 — alias for --teacher off.")

    # ---- Cloud routing (2026-XX-XX) ----------------------------------------
    sa.add_argument("--cloud", choices=["sonnet", "siliconflow", "auto"],
                    default="sonnet",
                    help="Cloud backend for LLM calls. "
                         "'sonnet' = real Anthropic (default, ~$5-8/scan). "
                         "'siliconflow' = anthropic-shim → SiliconFlow at ~$0.50-2/scan. "
                         "Requires `bash tools/serving/start-anthropic-shim.sh --bg` first. "
                         "'auto' = use siliconflow if shim is up, else fall back to sonnet. "
                         "Superseded by --model-profile when both are passed.")
    # ---- BENCH-01 (2026-XX-XX): ModelRouter profile selection --------------
    sa.add_argument("--model-profile",
                    choices=["anthropic-baseline", "siliconflow-qwen-235b"],
                    default=None,
                    help="ModelRouter profile selecting which LLM provider drives all "
                         "Claude-tier phase calls. 'anthropic-baseline' = real Anthropic "
                         "Sonnet/Opus/Haiku (the existing default). "
                         "'siliconflow-qwen-235b' = route Sonnet→Qwen3-235B-A22B-Instruct, "
                         "Opus→DeepSeek-R1, Haiku→Qwen3-Coder-30B via anthropic-shim on "
                         "port 4002. Requires `bash tools/serving/start-anthropic-shim.sh "
                         "--bg` first. Supersedes --cloud when both are passed.")
    # 2026-XX-XX — Mode-B transport-freeze fix. The bundled claude CLI's HTTPS
    # connection to api.anthropic.com gets silently dropped on some network
    # paths during long-idle / mid-stream stalls, wedging recon for tens of
    # minutes. This flag routes the CLI through a local force_close + sock_read
    # passthrough proxy (tools/serving/anthropic-keepalive-proxy.py) that
    # eliminates the idle pool + converts stalls into fast errors. Auto-starts
    # the proxy if not running. Default URL when bare-flagged: 127.0.0.1:8788.
    sa.add_argument("--keepalive-proxy", nargs="?",
                    const="http://127.0.0.1:8788", default=None,
                    metavar="URL",
                    help="Route Anthropic API calls through a local keepalive "
                         "proxy that fixes the Mode-B transport freeze "
                         "(force_close + sock_read). Bare flag uses the default "
                         "http://127.0.0.1:8788; pass a URL to override. The "
                         "proxy is auto-started if not already listening.")

    # ---- Shannon-parity convenience subcommands (Phase 11) -----------------
    ws = sub.add_parser("workspaces", help="List autonomous-pentest workspaces with status")
    ws.add_argument("--workspaces-root", default="./workspaces")

    lg = sub.add_parser("logs", help="Tail the structured event log for a workspace")
    lg.add_argument("workspace", help="Workspace dir name (under --workspaces-root) OR an absolute path")
    lg.add_argument("--workspaces-root", default="./workspaces")
    lg.add_argument("--tail", type=int, default=50, help="Lines to show (default 50)")
    lg.add_argument("--follow", action="store_true", help="Keep streaming new events")

    st = sub.add_parser("status", help="Print engagement / scan inventory at a glance")
    st.add_argument("--workspaces-root", default="./workspaces")
    st.add_argument("--runs-dir", default="./runs")

    info = sub.add_parser("info", help="Print Sentinel version + tool inventory")

    # ---- mobile pentest entry (B-Mobile, 2026-XX-XX) ----------------------
    # MobSF static analysis + apkleaks secret scan, both scope-gated via
    # `scope.authorize_artifact("apk", path)`. MobSF requires a running
    # local instance (MOBSF_API_URL + MOBSF_API_KEY env / config file).
    apk = sub.add_parser(
        "scan-apk",
        help="Run MobSF + apkleaks against an APK file (mobile pentest entry).",
    )
    apk.add_argument("apk_path", help="Path to a .apk file (scope-gated as artifact)")
    apk.add_argument("--scope", required=True, help="Path to engagement scope YAML")
    apk.add_argument("--vault", help="Also write each ingested doc into this Obsidian vault")
    apk.add_argument("--corpus-dir", help="Path to Chroma corpus (for triage RAG)")
    apk.add_argument("--ollama-host", default="http://localhost:11434")
    apk.add_argument("--ollama-model", default="llama3.1:8b")
    apk.add_argument("--embed-model", default="nomic-embed-text")
    apk.add_argument("--skip-mobsf", action="store_true",
                     help="Skip MobSF (use when no local MobSF instance is running)")
    apk.add_argument("--skip-apkleaks", action="store_true",
                     help="Skip apkleaks (e.g., when the binary isn't installed yet)")

    # ---- cloud pentest entry (B-Cloud, 2026-XX-XX) -----------------------
    cl = sub.add_parser(
        "scan-cloud",
        help="Cloud-config / enumeration pentest (S3Scanner, cloud_enum, "
             "Prowler, CloudFox). Some scanners need AWS credentials.",
    )
    cl.add_argument("--scope", required=True, help="Path to engagement scope YAML")
    cl.add_argument("--provider", choices=["aws", "azure", "gcp", "any"],
                    default="any", help="Restrict to a single cloud provider.")
    cl.add_argument("--bucket-keywords", nargs="*", default=[],
                    help="Bucket-name keywords to feed into S3Scanner / cloud_enum.")
    cl.add_argument("--aws-profile", default="",
                    help="AWS profile name to use for CloudFox / Prowler.")
    cl.add_argument("--vault", help="Also write each ingested doc into this Obsidian vault")
    cl.add_argument("--corpus-dir", help="Path to Chroma corpus (for triage RAG)")
    cl.add_argument("--ollama-host", default="http://localhost:11434")
    cl.add_argument("--ollama-model", default="llama3.1:8b")
    cl.add_argument("--embed-model", default="nomic-embed-text")

    # ---- new-engagement wizard --------------------------------------------
    # Builds a scope.yaml + workspace dir from a program template
    # (hackerone / bugcrowd / synack / private). Missing fields are
    # prompted on stdin so the operator can scaffold a complete
    # engagement in one command. The web UI's POST /engagements uses
    # the same `sentinel.engagements.wizard` backend so behaviour stays
    # in lockstep across CLI and dashboard.
    ne = sub.add_parser(
        "new-engagement",
        help="Scaffold a new scope.yaml + workspace dir from a program template "
             "(hackerone / bugcrowd / synack / private).",
    )
    ne.add_argument("--template", choices=["hackerone", "bugcrowd", "synack", "private"],
                     default="private", help="Program template (default: private).")
    ne.add_argument("--client", help="Client / program slug (e.g., 'amazon-ExampleStore').")
    ne.add_argument("--id", dest="engagement_id",
                     help="Engagement ID (e.g., '2026-XX-XX-acme-bbp').")
    ne.add_argument("--authorized-by",
                     help="Email of the person who signed the SOW / accepted the BBP terms.")
    ne.add_argument("--authorization-doc", default="",
                     help="Path or short note describing where the authorization lives.")
    ne.add_argument("--valid-from", default="",
                     help="ISO-8601 (default: today).")
    ne.add_argument("--valid-until", default="",
                     help="ISO-8601 (default: today + 90 days).")
    ne.add_argument("--domains", nargs="*", default=[],
                     help="Domain target(s). Can be repeated.")
    ne.add_argument("--repos", nargs="*", default=[],
                     help="Repo target(s) — github.com/owner/name or clone URL.")
    ne.add_argument("--ips", nargs="*", default=[],
                     help="IP / CIDR target(s).")
    ne.add_argument("--out-of-scope", nargs="*", default=[],
                     help="OOS host(s) to add (template defaults are merged in).")
    ne.add_argument("--research-handle", default="",
                     help="Your platform researcher handle (e.g., your H1 username).")
    ne.add_argument("--rate-limit-rps", type=int, default=None,
                     help="Override the template's default rate limit.")
    ne.add_argument("--scopes-dir", default="./engagements",
                     help="Where to write the scope.yaml (default: ./engagements).")
    ne.add_argument("--workspaces-root", default="./workspaces",
                     help="Where to scaffold the workspace dir (default: ./workspaces).")
    ne.add_argument("--non-interactive", action="store_true",
                     help="Fail rather than prompt on stdin for missing required fields.")
    ne.add_argument("--overwrite", action="store_true",
                     help="Overwrite the scope file if it already exists (DESTRUCTIVE).")

    # ---- session continuity (CURRENT_STATE.md) ----------------------------
    # Synthesizes a single human-readable snapshot at <project>/CURRENT_STATE.md
    # from existing on-disk artifacts (workspaces/.completed_phases.json,
    # runs/*.json, runs/events-*.jsonl, ~/.../memory/MEMORY.md). The pipeline
    # auto-refreshes after each phase completion; this CLI is the manual lever.
    state = sub.add_parser(
        "state",
        help="Roll up CURRENT_STATE.md (engagement progress + H1 queue + "
             "recent runs + memory index) for session continuity.",
    )
    state.add_argument("--update", action="store_true",
                        help="Build a fresh snapshot and write CURRENT_STATE.md (default).")
    state.add_argument("--show", action="store_true",
                        help="Print the existing CURRENT_STATE.md to stdout (does not refresh).")
    state.add_argument("--project-dir", default=".",
                        help="Project root (default: cwd).")
    state.add_argument("--workspaces-root", default=None,
                        help="Override <project>/workspaces.")
    state.add_argument("--runs-dir", default=None,
                        help="Override <project>/runs.")
    state.add_argument("--memory-dir", default=None,
                        help="Override the auto-memory directory.")
    state.add_argument("--pacing-hours", type=int, default=None,
                        help="Override h1_pacing_hours from ~/.sentinel/notify.yaml "
                             "(default: 4 if no config). Used to flag drafted H1 "
                             "reports whose pacing window has elapsed.")

    # ---- h1 (Plan 02-01 ENG-01..ENG-06) -----------------------------------
    # HackerOne submission tooling. Three sub-subcommands:
    #   record-submission — append a JSONL row + hash-chained audit event
    #   dup-check         — semantic search against the Chroma corpus
    #   prepare           — bundle evidence + scope-gated curls.sh
    h1 = sub.add_parser(
        "h1",
        help="HackerOne submission tooling (record + dup-check + prepare)",
    )
    h1_sub = h1.add_subparsers(dest="h1_cmd", required=True)

    h1_rec = h1_sub.add_parser(
        "record-submission",
        help="Record an H1 submission timestamp + audit-log event",
    )
    h1_rec.add_argument("engagement_id",
                        help="Engagement id (matches the scope yaml's engagement_id)")
    h1_rec.add_argument("file",
                        help="Report file (basename or full path to the H1 markdown)")
    h1_rec.add_argument("--submitted-at", required=True,
                        help="ISO-8601 UTC submission timestamp (e.g. 2026-XX-XXT15:00:00Z)")
    h1_rec.add_argument("--h1-report-id",
                        help="HackerOne report ID (rewrites the report's Status: line "
                             "to Submitted (H1-<id>))")
    h1_rec.add_argument("--h1-url", help="HackerOne report URL")
    h1_rec.add_argument("--title", help="Report title (extracted from file if omitted)")
    h1_rec.add_argument("--weakness", help="CWE id, e.g. CWE-79")
    h1_rec.add_argument("--severity", help="Severity (critical/high/medium/low/info)")
    h1_rec.add_argument("--operator", help="H1 operator handle")

    h1_dup = h1_sub.add_parser(
        "dup-check",
        help="Semantic duplicate-probability check against the local Chroma corpus",
    )
    h1_dup.add_argument("report_path", help="Path to the drafted H1 report markdown")
    h1_dup.add_argument("--corpus-dir", default=str(Path.home() / "sentinel-corpus"),
                        help="Chroma persist dir (default: ~/sentinel-corpus)")
    h1_dup.add_argument("--top-k", type=int, default=5,
                        help="Number of nearest neighbors to return (default: 5)")
    h1_dup.add_argument("--source-filter", default=None,
                        help="Filter by corpus source (e.g. writeups, hackerone-full)")

    h1_prep = h1_sub.add_parser(
        "prepare",
        help="Bundle evidence + extract scope-gated verification curls",
    )
    h1_prep.add_argument("report_path",
                         help="Path to the H1 report markdown")
    h1_prep.add_argument("--scope", default=None,
                         help="Path to engagement scope yaml (auto-discovered "
                              "from <project>/engagements/<engagement_id>.yaml "
                              "if omitted; curls.sh is NOT scope-gated when no "
                              "scope resolves)")
    h1_prep.add_argument("--output-dir", default=None,
                         help="Where to write <stem>.curls.sh and the evidence "
                              "tarball (default: alongside the report)")

    # ---- datadome-harvest (Tier-2 anti-bot bypass) ------------------------
    # Operator opens a real Chrome session, solves any anti-bot challenge
    # manually, Sentinel captures the resulting cookies (datadome /
    # cf_clearance / _abck / _pxhd / etc.) and persists them into
    # scope.yaml's auth_cookies block. Subsequent http_get + browser_get
    # calls inject those cookies, bypassing the challenge for the cookie's
    # ~1-3 hour lifetime.
    dh = sub.add_parser(
        "datadome-harvest",
        help="Harvest anti-bot cookies (DataDome / Cloudflare / Akamai / "
             "Imperva / PerimeterX / Vercel) from a real-Chrome session and "
             "persist them into scope.yaml's auth_cookies block.",
    )
    dh.add_argument("url", help="Target URL to visit + capture cookies from")
    dh.add_argument("--scope", required=True, help="Path to engagement scope YAML")
    dh.add_argument("--headless", action="store_true",
                     help="Use headless Chromium (FOR TESTING — DataDome blocks "
                          "headless and you'll get no cookies; only useful to "
                          "validate the wire path)")
    dh.add_argument("--wait-after-load", type=int, default=10,
                     help="Seconds to wait after page reaches networkidle "
                          "before reading cookies (default 10)")

    # ---- chrome (Real-Chrome-via-CDP DataDome bypass — 2026-XX-XX) --------
    # Per-engagement Chrome profile, bootstrap-once, attach-many. Operator
    # solves DataDome / signs in once in a visible Chrome window; Sentinel's
    # browser_tool then attaches via CDP and uses the profile's existing
    # cookies for every subsequent scan against that engagement. Defeats
    # fingerprint detection because the browser literally IS real Chrome.
    chrome = sub.add_parser(
        "chrome",
        help="Real-Chrome-via-CDP profile management (DataDome / Cloudflare "
             "/ Akamai bypass via the operator's installed Chrome).",
    )
    chrome_sub = chrome.add_subparsers(dest="chrome_cmd", required=True)

    cb = chrome_sub.add_parser(
        "bootstrap",
        help="Launch the user's installed Chrome with --remote-debugging-port "
             "and the per-engagement profile dir. Operator solves any anti-bot "
             "challenge + signs in manually; profile retains cookies on disk.",
    )
    cb.add_argument("--scope", required=True, help="Engagement scope YAML")
    cb.add_argument("--port", type=int, default=None,
                    help="Override CDP port (default: scope.chrome_cdp_port or 9222)")
    cb.add_argument("--profile-dir", default=None,
                    help="Override profile dir (default: scope.chrome_profile_dir "
                         "or ~/.sentinel/chrome-profiles/<engagement_id>)")
    cb.add_argument("--chrome-binary", default=None,
                    help="Override Chrome binary path (default: auto-discovered)")

    cs = chrome_sub.add_parser(
        "status",
        help="Probe the engagement's CDP-attached Chrome — reports running "
             "status + version + a session-warmth check against the first "
             "in-scope domain.",
    )
    cs.add_argument("--scope", required=True, help="Engagement scope YAML")
    cs.add_argument("--probe-url", default=None,
                    help="URL to probe for session warmth (default: derives "
                         "from scope.targets.domains[0])")
    cs.add_argument("--screenshot", default=None,
                    help="Path to save a screenshot of the probe result")

    ca = chrome_sub.add_parser(
        "attach",
        help="Print the CDP URL + verify Chrome is reachable. Useful to "
             "test attach independently of running a scan.",
    )
    ca.add_argument("--scope", required=True, help="Engagement scope YAML")

    cc = chrome_sub.add_parser(
        "clean",
        help="Shut down the engagement's running Chrome (graceful). With "
             "--purge also delete the profile dir on disk (loses all cookies).",
    )
    cc.add_argument("--scope", required=True, help="Engagement scope YAML")
    cc.add_argument("--purge", action="store_true",
                    help="Also delete the per-engagement profile dir on disk")

    # ---- salvage (mine prior scan queues with local Ollama, $0) ----------
    sal = sub.add_parser(
        "salvage",
        help="Re-rank past-scan exploitation queues with local Ollama "
             "(qwen2.5:32b by default). Mines value from already-paid-for "
             "hypotheses — $0 Claude tokens spent. Output: a markdown "
             "operator-playbook ranking each candidate by score, bounty "
             "potential, and duplicate likelihood, with concrete manual-probe "
             "steps you can run in your authenticated Chrome.",
    )
    sal.add_argument("--target", default=None,
                      help="Substring filter against source_endpoint URL OR "
                           "workspace name (case-insensitive). e.g. 'ExamplePay' "
                           "matches all ExamplePay.com entries + ExamplePay-developer "
                           "workspace. Omit to mine ALL workspaces.")
    sal.add_argument("--min-score", type=int, default=0,
                      help="Filter out entries scored below this in the "
                           "report (default 0 = include everything).")
    sal.add_argument("--workspaces-root", default="./workspaces",
                      help="Where to walk for queue files.")
    sal.add_argument("--model", default=None,
                      help="Ollama model to use (default qwen2.5:32b-instruct-q4_K_M; "
                           "fallback to llama3.1:8b if 32b is too slow).")
    sal.add_argument("--batch-size", type=int, default=4,
                      help="Entries per Ollama batch (default 4 — smaller = "
                           "better per-entry attention quality).")
    sal.add_argument("--output", default=None,
                      help="Markdown report path (default ./salvage-<target>.md "
                           "or ./salvage-all.md).")

    cex = chrome_sub.add_parser(
        "export-cookies",
        help="Snapshot live cookies from the CDP-attached Chrome profile and "
             "print them as a YAML auth_cookies block (paste into scope.yaml "
             "as a fallback when the profile expires).",
    )
    cex.add_argument("--scope", required=True, help="Engagement scope YAML")
    cex.add_argument("--domain-filter", action="append", default=None,
                     help="Only print cookies whose domain matches this "
                          "substring (repeatable, e.g. --domain-filter ExamplePay.com)")

    crf = chrome_sub.add_parser(
        "refresh",
        help="Snapshot live cookies from CDP and patch the scope.yaml's "
             "auth_cookies block in place (in-place edit; backs up to "
             "scope.yaml.bak first).",
    )
    crf.add_argument("--scope", required=True, help="Engagement scope YAML")
    crf.add_argument("--domain-filter", action="append", default=None,
                     help="Only retain cookies matching these domain "
                          "substrings (repeatable). Default: all cookies.")

    # ---- scan-dfir (Wave 7 — DFIR agent direct invocation) -----------------
    # Direct invocation of the DFIR agent on a pcap or log file. Runs IOC
    # extraction + log parsing + timeline reconstruction (and optional yara)
    # and writes an incident-response markdown report to ./runs/.
    dfir = sub.add_parser(
        "scan-dfir",
        help="Run the DFIR agent on a pcap or log file (IOC extraction + "
             "timeline reconstruction + optional YARA matching).",
    )
    dfir.add_argument("input_file",
                      help="Path to a pcap, log file, or arbitrary text "
                           "blob to triage. Must live inside the workspace.")
    dfir.add_argument("--scope", required=True, help="Engagement scope YAML")
    dfir.add_argument("--workspace",
                      help="Workspace dir (defaults to dirname of input_file)")
    dfir.add_argument("--log-format", default="auto",
                      choices=["auto", "apache", "nginx", "syslog", "json"],
                      help="Log format hint (only used for log inputs).")
    dfir.add_argument("--yara-rules-file",
                      help="Optional path to a .yar/.yara file with rules to apply.")
    dfir.add_argument("--incident-id",
                      help="Free-form incident identifier (default: derived "
                           "from filename + timestamp).")
    dfir.add_argument("--suspected-attack", default="(unknown)",
                      help="Free-form description of suspected attack.")
    dfir.add_argument("--out-dir", default="./runs",
                      help="Where to write the incident report (default ./runs).")

    # ---- Phase 5 / NOVEL-02 + NOVEL-03 — novelty-index management --------
    # `sentinel novelty refresh-index` rebuilds the per-finding-novelty vector
    # cache under <corpus_dir>/novelty-index/{vectors.npy,metadata.jsonl}.
    # See sentinel/agent/novelty/ for the underlying CorpusIndex + NvdLoader.
    nv = sub.add_parser(
        "novelty",
        help="Phase 5 novelty-index management (subcommands: refresh-index)",
    )
    nv_sub = nv.add_subparsers(dest="novelty_cmd", required=True)

    nv_refresh = nv_sub.add_parser(
        "refresh-index",
        help="Rebuild the novelty embedding index from the Chroma corpus. "
             "Walks every chunk, partitions by source, filters NVD entries by "
             "--since-year, and persists a flat numpy.float32 (N, D) array + "
             "JSONL metadata sidecar under <corpus-dir>/novelty-index/. "
             "Idempotent: re-running overwrites the prior index files.",
    )
    nv_refresh.add_argument("--corpus-dir", required=True,
                            help="Chroma persist dir (the same path you pass "
                                 "to `sentinel ingest --corpus-dir`)")
    nv_refresh.add_argument("--since-year", type=int, default=2020,
                            help="Drop NVD CVE entries published before this "
                                 "year (default: 2020)")
    nv_refresh.add_argument("--ollama-host", default="http://localhost:11434",
                            help="Ollama base URL (default: http://localhost:11434). "
                                 "Used only when a chunk lacks a cached embedding; "
                                 "the common path reads vectors verbatim from Chroma.")
    nv_refresh.add_argument("--ollama-model", default="nomic-embed-text",
                            help="Embedding model name (default: nomic-embed-text)")

    # ---- Wave 8 / D5-D9 — benchmarks --------------------------------------
    bench = sub.add_parser(
        "benchmark",
        help="Reproducible eval suite (Wave 8). Subcommands: list / run / publish.",
    )
    bench_sub = bench.add_subparsers(dest="bench_cmd", required=True)

    bl = bench_sub.add_parser("list", help="List registered benchmarks")

    br = bench_sub.add_parser("run", help="Run a benchmark with the default stub runner")
    br.add_argument("name", help="Benchmark name (see `benchmark list`)")
    br.add_argument("--model", default=None, help="Model tag for the report")
    br.add_argument("--max-budget", type=float, default=5.0,
                    help="Cumulative cost cap (USD)")
    br.add_argument("--mode", choices=["ctf", "lab", "production", "bbp"],
                    default=None,
                    help="Engagement mode (cybench / ad_ctf require ctf or lab)")
    br.add_argument("--max-tasks", type=int, default=None,
                    help="Cap iteration to N tasks (smoke testing)")
    br.add_argument("--output", default=None,
                    help="Write the result JSON to this path")

    bp = bench_sub.add_parser(
        "publish",
        help="Generate the SVPB-Lite publication artifacts under research/svpb-lite-publish/",
    )
    bp.add_argument("name", choices=["svpb-lite", "svpb_lite"],
                    help="Currently only svpb_lite supports --publish")

    # ---- BENCH-05 (2026-XX-XX): parity-eval subcommand --------------------
    # Plan 02-02 extends --suite to accept comma-separated suite names
    # (e.g. juice-shop,dvwa). Plan 02-02 also lifts the --scope required
    # constraint: when --scope is omitted, the harness derives
    # bench/<suite>/scope.yaml per suite name (raises FileNotFoundError
    # if a derived path doesn't exist).
    bpe = bench_sub.add_parser(
        "parity-eval",
        help="SiliconFlow Qwen 235B parity benchmark (BENCH-05/06). "
             "Runs scan-autonomous twice per target — once per model profile "
             "— and writes a structured eval JSON with per-phase precision / "
             "recall / F1 / verdict.",
    )
    bpe.add_argument("--suite", default="juice-shop",
                     help="Bench suite name. comma-separated list accepted "
                          "(e.g. 'juice-shop,dvwa'). The harness validates "
                          "each suite has a bench/<name>/scope.yaml — unknown "
                          "names fail loud BEFORE any scan-autonomous fires.")
    bpe.add_argument("--baseline",
                     choices=["anthropic-baseline", "siliconflow-qwen-235b"],
                     default="anthropic-baseline",
                     help="ModelRouter profile for the baseline run.")
    bpe.add_argument("--candidate",
                     choices=["anthropic-baseline", "siliconflow-qwen-235b"],
                     default="siliconflow-qwen-235b",
                     help="ModelRouter profile for the candidate run.")
    bpe.add_argument("--scope", default=None,
                     help="Path to ONE bench scope YAML. Optional — when "
                          "omitted (or when --suite specifies multiple "
                          "suites), the harness derives "
                          "bench/<suite>/scope.yaml per suite.")
    bpe.add_argument("--output-dir", default="runs/",
                     help="Directory the eval JSON lands in (default: runs/).")

    # ---- BENCH-09 (Plan 02-04, 2026-XX-XX): default-profile management ----
    # `show-default` prints the current persisted ModelRouter default profile
    # (or 'anthropic-baseline' if the state file is absent / corrupted).
    # `reset-default` removes the state file, reverting to baseline.
    # The auto-flip on verdict='pass' happens inline in the parity-eval
    # branch of `_do_benchmark`.
    bench_sub.add_parser(
        "show-default",
        help="Show the current ModelRouter default profile (from "
             "~/.sentinel/model_profile_default.txt, or 'anthropic-baseline' "
             "if unset).",
    )
    bench_sub.add_parser(
        "reset-default",
        help="Reset the ModelRouter default profile back to "
             "'anthropic-baseline' (removes "
             "~/.sentinel/model_profile_default.txt).",
    )

    # ---- teach-findings (2026-XX-XX) -------------------------------------
    # Turn every finding in a run-result JSON into a learning brief grounded
    # in the local RAG corpus. Local-Ollama, free. Built for the rusty-CEH
    # use case: every Sentinel finding becomes a 5-section markdown lesson
    # (what it is / why exploitable here / manual repro / fix / refs).
    tf = sub.add_parser(
        "teach-findings",
        help="Generate teach-mode briefs for every finding in a run JSON. "
             "Local Ollama (free). Writes deliverables/teach/<fp>.md per "
             "finding + a teach_index.md. Use --corpus-dir for RAG-grounded "
             "explanations from the OWASP/CWE/writeups corpus.",
    )
    tf.add_argument("findings_json",
                    help="Path to a Sentinel run JSON (a list of Finding "
                         "dicts) OR an engagement workspace dir containing "
                         "deliverables/findings.json.")
    tf.add_argument("--workspace-dir", default=None,
                    help="Where to write deliverables/teach/. Defaults to "
                         "the parent dir of findings_json.")
    tf.add_argument("--corpus-dir", default=None,
                    help="Path to the Chroma RAG corpus dir. When set, "
                         "briefs cite real OWASP/CWE/writeups material.")
    tf.add_argument("--ollama-host", default="http://localhost:11434")
    tf.add_argument("--ollama-model", default="mistral-nemo:12b",
                    help="Ollama model for narrative generation (default: "
                         "mistral-nemo:12b — narrative writing per CLAUDE.md).")
    tf.add_argument("--embed-model", default="nomic-embed-text")

    # ---- github-recon (2026-XX-XX) ---------------------------------------
    # Passive intel from a target's public GitHub org(s) — leaked secrets,
    # internal endpoints in old commits, CI configs. Zero target traffic;
    # fits every program policy. Writes deliverables/github_leaks_briefing.md
    gr = sub.add_parser(
        "github-recon",
        help="Passive GitHub-org scan (trufflehog over public repos + commit "
             "history). Zero traffic to the target's app; surfaces leaked "
             "secrets and internal endpoints. Writes "
             "deliverables/github_leaks_briefing.md.",
    )
    gr.add_argument("target", help="Target URL (used to derive org candidates "
                                    "if --org not passed). Scope-authorized.")
    gr.add_argument("--scope", required=True, help="Path to scope.yaml")
    gr.add_argument("--org", action="append",
                    help="Explicit GitHub org/user handle to scan. Repeatable. "
                         "If omitted, candidates are derived from the target host.")
    gr.add_argument("--github-token", default=None,
                    help="GitHub personal-access token (raises API rate limit "
                         "from 60/hr to 5000/hr; also reads $GITHUB_TOKEN).")
    gr.add_argument("--max-repos", type=int, default=50,
                    help="Cap on repos per org (default 50).")
    gr.add_argument("--workspace-dir", default="./workspaces",
                    help="Parent dir for the engagement workspace.")

    return p


def _setup_log(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _ollama_or_none(args) -> Optional[OllamaClient]:
    if getattr(args, "no_llm", False):
        return None
    return OllamaClient(host=args.ollama_host, model=args.ollama_model)


def _make_retriever(args):
    """Build a RAG retriever if --corpus-dir was provided, else None."""
    if not getattr(args, "corpus_dir", None):
        return None
    try:
        from sentinel.corpus.embedder import OllamaEmbedder
        from sentinel.corpus.store import CorpusStore
        from sentinel.rag.retriever import Retriever
    except RuntimeError as e:
        print(f"RAG disabled: {e}", file=sys.stderr)
        return None
    embedder = OllamaEmbedder(host=args.ollama_host, model=args.embed_model)
    store = CorpusStore(args.corpus_dir, embedder)
    return Retriever(store)


def _dump_run(report: RunReport) -> str:
    return json.dumps(
        {
            "scope": {
                "client": report.scope.client,
                "engagement_id": report.scope.engagement_id,
                "scope_sha256": report.scope.source_hash,
            },
            "scanners_run": report.scanners_run,
            "errors": report.errors,
            "findings": [f.to_dict() for f in report.findings],
        },
        indent=2,
    )


def _write_outputs(args, report: RunReport) -> None:
    out_dir = Path("./runs")
    out_dir.mkdir(exist_ok=True)
    fname = f"{report.scope.client}-{report.scope.engagement_id}.json"
    out_path = out_dir / fname
    out_path.write_text(_dump_run(report))
    print(f"Run dumped: {out_path}")

    if getattr(args, "vault", None):
        reporter = ObsidianReporter(args.vault)
        engagement = reporter.write_report(report)
        print(f"Obsidian engagement folder: {engagement}")


def _print_summary(report: RunReport) -> None:
    counts: dict[str, int] = {}
    for f in report.findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    print("\n=== Run summary ===")
    print(f"Client       : {report.scope.client}")
    print(f"Engagement   : {report.scope.engagement_id}")
    print(f"Scanners run : {', '.join(report.scanners_run) or '(none)'}")
    if report.errors:
        print("Errors:")
        for e in report.errors:
            print(f"  - {e}")
    print(f"Findings     : {len(report.findings)}")
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            print(f"  {sev:8s}: {counts[sev]}")


# ---- corpus commands ------------------------------------------------------


def _do_ingest(args) -> int:
    from sentinel.corpus.embedder import OllamaEmbedder
    from sentinel.corpus.ingest import CorpusIngester
    from sentinel.corpus.obsidian_writer import ObsidianCorpusWriter
    from sentinel.corpus.store import CorpusStore

    embedder = OllamaEmbedder(host=args.ollama_host, model=args.embed_model)
    if not embedder.is_available():
        print(
            f"Embed model {args.embed_model} not available at {args.ollama_host}. "
            f"Run: ollama pull {args.embed_model}",
            file=sys.stderr,
        )
        return 2
    store = CorpusStore(args.corpus_dir, embedder)
    obs = ObsidianCorpusWriter(args.vault) if args.vault else None
    ingester = CorpusIngester(store, obsidian_writer=obs, chunk_size=args.chunk_size, chunk_overlap=args.chunk_overlap)

    sources = [args.source] if args.source != "all" else [
        "owasp", "mitre-cwe", "mitre-attack", "nist", "nvd", "writeups",
    ]
    # 'books' deliberately excluded from 'all' since it requires --books-dir.

    total_docs = 0
    total_chunks = 0
    for s in sources:
        src = _instantiate_source(s, args)
        if src is None:
            continue
        print(f"--- ingesting {s} ---")
        per_source_wd = None
        if args.work_dir:
            per_source_wd = Path(args.work_dir) / s
            per_source_wd.mkdir(parents=True, exist_ok=True)
        report = ingester.ingest(src, work_dir=per_source_wd)
        print(
            f"  documents: {report.documents}, chunks stored: {report.chunks_stored}, "
            f"obsidian notes: {report.obsidian_notes}"
        )
        if report.errors:
            for e in report.errors:
                print(f"  ERROR: {e}", file=sys.stderr)
        total_docs += report.documents
        total_chunks += report.chunks_stored
    print(f"\nIngest complete. {total_docs} docs, {total_chunks} chunks indexed.")
    return 0


def _instantiate_source(name: str, args):
    if name == "owasp":
        from sentinel.corpus.sources.owasp import OwaspSource
        return OwaspSource()
    if name == "mitre-cwe":
        from sentinel.corpus.sources.mitre import MitreCweSource
        return MitreCweSource()
    if name == "mitre-attack":
        from sentinel.corpus.sources.mitre import MitreAttackSource
        return MitreAttackSource()
    if name == "nist":
        from sentinel.corpus.sources.nist import NistSource
        return NistSource()
    if name == "nvd":
        from sentinel.corpus.sources.nvd import NvdSource
        return NvdSource(since_year=args.nvd_since_year, max_records=args.nvd_max_records)
    if name == "writeups":
        from sentinel.corpus.sources.writeups import WriteupsSource
        return WriteupsSource()
    if name == "hackerone":
        from sentinel.corpus.sources.hackerone import HackerOneSource
        return HackerOneSource(
            max_reports=args.hackerone_max_reports,
            full_bodies=getattr(args, "hackerone_full_bodies", False),
            full_bodies_max=getattr(args, "hackerone_full_bodies_max", None),
            full_bodies_rps=getattr(args, "hackerone_full_bodies_rps", 1.0),
        )
    if name == "books":
        if not args.books_dir:
            print("--books-dir is required for --source=books", file=sys.stderr)
            return None
        from sentinel.corpus.sources.books import BooksSource
        return BooksSource(args.books_dir)
    if name == "past-engagements":
        from sentinel.corpus.sources.past_engagements import PastEngagementsSource
        workspaces_dir = getattr(args, "workspaces_dir", None) or "workspaces"
        only = getattr(args, "only_engagements", None) or []
        # scopes_dir lets the ingester read the canonical client name
        # from the engagement's scope yaml — avoids the dir-name
        # heuristic mis-labeling clients like "Radiant Global" → "global".
        scopes_dir = getattr(args, "scopes_dir", None) or "engagements"
        return PastEngagementsSource(
            workspaces_dir, only_engagements=only, scopes_dir=scopes_dir,
        )
    if name == "payloads-all-the-things":
        from sentinel.corpus.sources.payloads_all_the_things import PayloadsAllTheThingsSource
        repo_dir = getattr(args, "patt_dir", None) or "library/PayloadsAllTheThings"
        only_cats = getattr(args, "only_categories", None) or []
        return PayloadsAllTheThingsSource(repo_dir, only_categories=only_cats)
    print(f"Unknown source: {name}", file=sys.stderr)
    return None


def _do_ask(args) -> int:
    from sentinel.corpus.embedder import OllamaEmbedder
    from sentinel.corpus.store import CorpusStore
    from sentinel.rag.ask import ask, render_answer_text
    from sentinel.rag.retriever import Retriever

    embedder = OllamaEmbedder(host=args.ollama_host, model=args.embed_model)
    store = CorpusStore(args.corpus_dir, embedder)
    retriever = Retriever(store)
    ollama = OllamaClient(host=args.ollama_host, model=args.ollama_model)
    if not ollama.is_available():
        print("Ollama not reachable. Is it running?", file=sys.stderr)
        return 2

    chunks = retriever.retrieve(args.question, top_k=args.top_k, source_filter=args.source_filter)
    # Reuse ask.ask but we already retrieved; do a tiny inline call instead.
    answer = ask(args.question, retriever, ollama, top_k=args.top_k)
    print(render_answer_text(answer))
    return 0


def _do_web(args) -> int:
    """Launch the FastAPI web UI via uvicorn."""
    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn not installed. Install: pip install -e \".[web]\" "
            "(brings fastapi + jinja2 + uvicorn + python-multipart)",
            file=sys.stderr,
        )
        return 2
    print(f"Launching Sentinel (FastAPI) on http://{args.host}:{args.port}")
    uvicorn.run(
        "sentinel.web.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )
    return 0


def _do_teach_findings(args) -> int:
    """Generate teach-mode briefs for findings in a run JSON (2026-XX-XX)."""
    from sentinel.agent.teach_mode import write_teach_briefs
    from sentinel.core.findings import Finding
    fjs = Path(args.findings_json)
    if fjs.is_dir():
        fjs = fjs / "deliverables" / "findings.json"
    if not fjs.is_file():
        print(f"ERROR: findings JSON not found: {fjs}", file=sys.stderr)
        return 2
    try:
        raw = json.loads(fjs.read_text())
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: failed to parse {fjs}: {e}", file=sys.stderr)
        return 2
    raw_findings = raw if isinstance(raw, list) else (raw.get("findings") or [])
    findings = []
    for d in raw_findings:
        try:
            findings.append(Finding.from_dict(d) if hasattr(Finding, "from_dict")
                            else Finding(**{k: v for k, v in d.items()
                                            if k in Finding.__dataclass_fields__}))
        except Exception:
            continue
    if not findings:
        print(f"ERROR: no parseable findings in {fjs}", file=sys.stderr)
        return 2
    workspace = Path(args.workspace_dir) if args.workspace_dir else fjs.parent.parent
    retriever = None
    if args.corpus_dir:
        try:
            from sentinel.corpus.embedder import OllamaEmbedder
            from sentinel.corpus.store import CorpusStore
            from sentinel.rag.retriever import Retriever
            embedder = OllamaEmbedder(host=args.ollama_host, model=args.embed_model)
            store = CorpusStore(args.corpus_dir, embedder)
            retriever = Retriever(store)
        except Exception as e:  # noqa: BLE001
            print(f"WARNING: corpus init failed ({e}); proceeding without RAG",
                  file=sys.stderr)
    print(f"teach-findings: {len(findings)} findings → "
          f"{workspace}/deliverables/teach/ "
          f"(RAG={'on' if retriever else 'off'}, model={args.ollama_model})",
          file=sys.stderr)
    summary = write_teach_briefs(findings, workspace, retriever=retriever,
                                  ollama_host=args.ollama_host,
                                  ollama_model=args.ollama_model)
    print(f"teach-findings done: {summary['count']} briefs "
          f"({summary['with_rag']} RAG-grounded), "
          f"{len(summary['errors'])} errors. Index: {summary['index']}",
          file=sys.stderr)
    return 0


def _do_github_recon(args) -> int:
    """Run the passive GitHub-org scan (2026-XX-XX).

    Scope-gates the target host, derives org candidates (or uses --org),
    enumerates public repos + runs trufflehog over their commit history,
    writes deliverables/github_leaks_briefing.md inside the engagement
    workspace. Zero traffic to the target.
    """
    from sentinel.agent.github_recon import run_github_recon
    from sentinel.core.scope import OutOfScopeError, Scope
    scope = Scope.load(Path(args.scope))
    try:
        scope.authorize_url(args.target)
    except OutOfScopeError as e:
        print(f"ERROR: target {args.target!r} out of scope: {e}", file=sys.stderr)
        return 2
    workspace = Path(args.workspace_dir) / scope.engagement_id
    token = args.github_token or os.environ.get("GITHUB_TOKEN")
    print(f"github-recon: target={args.target} orgs={args.org or '(auto)'} "
          f"trufflehog={'token-authed' if token else 'unauthed'}", file=sys.stderr)
    scan = run_github_recon(
        target=args.target, workspace=workspace,
        orgs=args.org, token=token, max_repos=args.max_repos,
    )
    th = scan.get("trufflehog") or {}
    findings = th.get("findings") or []
    verified = sum(1 for f in findings if f.get("verified"))
    print(f"github-recon done: orgs={scan.get('orgs_scanned')} "
          f"repos={len(scan.get('repos') or [])} "
          f"findings={len(findings)} ({verified} VERIFIED) "
          f"→ {workspace}/deliverables/github_leaks_briefing.md", file=sys.stderr)
    return 0


def _do_corpus_stats(args) -> int:
    from sentinel.corpus.embedder import OllamaEmbedder
    from sentinel.corpus.store import CorpusStore

    embedder = OllamaEmbedder(host=args.ollama_host, model=args.embed_model)
    store = CorpusStore(args.corpus_dir, embedder)
    s = store.stats()
    print(json.dumps(s, indent=2))
    return 0


def _do_scan_autonomous(args) -> int:
    """Run the full autonomous pentest pipeline (Phases 1-5).

    Single-target by default. With --all-scope-targets, fans out across
    every concrete domain in scope.targets.domains and writes a combined
    cross-target summary.
    """
    try:
        from sentinel.agent.pentest import PentestPipeline, PipelineConfig
    except ImportError as e:
        print(
            f"Pentest pipeline dependencies missing ({e}). Install with: "
            f"pip install -e '.[agent]'",
            file=sys.stderr,
        )
        return 2

    # ---- Plan 03-02 (COST-01) — --max-cost-usd value-validation ----------
    # Fail fast BEFORE the scope file is loaded so the rejection is a clean
    # argparse-level error (no audit-log entry, no model-router state mutation).
    # Negative caps would be always-satisfied (T-03-02-01 threat-model entry);
    # zero would be useless (every scan aborts after the first phase before
    # any real work). Both are rejected.
    max_cost_usd = getattr(args, "max_cost_usd", None)
    if max_cost_usd is not None and max_cost_usd <= 0:
        print(
            f"--max-cost-usd must be > 0 (got {max_cost_usd!r}). "
            f"Use a positive USD threshold (e.g., 5 for bench, 30 for deep H1).",
            file=sys.stderr,
        )
        return 2

    # ---- Keepalive proxy (--keepalive-proxy) ------------------------------
    # 2026-XX-XX: route the bundled `claude` CLI's Anthropic calls through a
    # local force_close + sock_read passthrough proxy to defeat the Mode-B
    # transport freeze. Sets SENTINEL_ANTHROPIC_PROXY so the ModelRouter's
    # _apply_anthropic_baseline picks it up and wires CLAUDE_CODE_BASE_URL +
    # ANTHROPIC_BASE_URL. Auto-starts the proxy subprocess if it's not already
    # listening on the configured URL. Persists across scans (we don't stop
    # it at scan-end) so subsequent runs reuse the warm proxy.
    keepalive_proxy = getattr(args, "keepalive_proxy", None)
    if keepalive_proxy:
        import urllib.parse, urllib.request, subprocess, time as _time
        os.environ["SENTINEL_ANTHROPIC_PROXY"] = keepalive_proxy
        # Auto-start: probe /_proxy_health; if not 200, spawn proxy and wait
        # for it to come up (up to 8s). Failure here is non-fatal — falls
        # through to direct routing with a loud warning.
        parsed = urllib.parse.urlparse(keepalive_proxy)
        health = f"{keepalive_proxy.rstrip('/')}/_proxy_health"
        up = False
        try:
            with urllib.request.urlopen(health, timeout=2) as r:
                up = (r.status == 200)
        except Exception:
            up = False
        if not up:
            proxy_script = (Path(__file__).resolve().parent.parent
                            / "tools" / "serving" / "anthropic-keepalive-proxy.py")
            if proxy_script.is_file():
                env = os.environ.copy()
                env["PROXY_PORT"] = str(parsed.port or 8788)
                # Detached, ignore stdio so the proxy survives this CLI exit.
                with open("/tmp/anthropic_proxy.log", "ab") as logf:
                    subprocess.Popen(
                        [sys.executable, str(proxy_script)],
                        stdout=logf, stderr=logf, stdin=subprocess.DEVNULL,
                        start_new_session=True, env=env,
                    )
                # Poll briefly for readiness.
                for _ in range(16):
                    _time.sleep(0.5)
                    try:
                        with urllib.request.urlopen(health, timeout=1) as r:
                            if r.status == 200:
                                up = True
                                break
                    except Exception:
                        pass
        if up:
            print(f"--keepalive-proxy: Anthropic calls routed via {keepalive_proxy} "
                  f"(Mode-B freeze fix active)", file=sys.stderr)
        else:
            print(f"--keepalive-proxy: WARNING — proxy at {keepalive_proxy} not "
                  f"reachable and auto-start failed; falling through to direct "
                  f"Anthropic routing (Mode-B freeze unmitigated for this scan).",
                  file=sys.stderr)
            # Don't poison downstream apply: clear the env so the baseline
            # profile reverts to direct routing (better than half-broken).
            os.environ.pop("SENTINEL_ANTHROPIC_PROXY", None)

    # ---- BENCH-01 (2026-XX-XX): --model-profile takes precedence -----------
    # Profile-based routing supersedes the older --cloud flag. Both coexist
    # for one release; --model-profile wins on conflict.
    model_profile = getattr(args, "model_profile", None)
    if model_profile is not None:
        from sentinel.agent.model_router import (
            SILICONFLOW_PROXY_URL,
            apply_model_profile,
            siliconflow_proxy_is_up,
        )
        # Warn if operator passed both flags explicitly.
        cloud_arg = getattr(args, "cloud", "sonnet")
        if cloud_arg != "sonnet":  # operator explicitly chose --cloud
            print(
                f"WARNING: --model-profile {model_profile} supersedes --cloud "
                f"{cloud_arg} — using profile.",
                file=sys.stderr,
            )
        if model_profile == "siliconflow-qwen-235b":
            if not siliconflow_proxy_is_up():
                print(
                    f"ERROR: --model-profile siliconflow-qwen-235b requires the "
                    f"anthropic-shim listening at {SILICONFLOW_PROXY_URL}. "
                    f"Start it first:\n"
                    f"  bash tools/serving/start-anthropic-shim.sh --bg",
                    file=sys.stderr,
                )
                return 2
        apply_model_profile(model_profile)
        print(f"--model-profile {model_profile}: ModelRouter activated",
              file=sys.stderr)
    else:
        # ---- BENCH-09 (Plan 02-04, 2026-XX-XX): persisted default profile -
        # When --model-profile is not explicitly passed, consult the
        # persisted default state file (~/.sentinel/model_profile_default.txt).
        # If it points at siliconflow-qwen-235b (set by a prior verdict='pass'
        # parity-eval), apply that BEFORE the legacy --cloud handling so
        # the proven-parity profile takes effect without operator intervention.
        # If the state file is absent / corrupted, this is a no-op apply of
        # anthropic-baseline (== existing behavior).
        from sentinel.agent.model_router import (
            DEFAULT_MODEL_PROFILE,
            apply_default_model_profile,
            current_model_profile,
        )
        # 2026-XX-XX: when --keepalive-proxy was passed, SENTINEL_ANTHROPIC_PROXY
        # is set above — but `_apply_anthropic_baseline` only reads it when
        # actually CALLED. The legacy path below skipped the call when staying
        # on baseline (treating it as a no-op), which meant the keepalive proxy
        # was silently NOT applied. Force the apply when the proxy env is set
        # so the routing is real, not silently dropped.
        if os.environ.get("SENTINEL_ANTHROPIC_PROXY") and \
                DEFAULT_MODEL_PROFILE == "anthropic-baseline":
            from sentinel.agent.model_router import apply_model_profile
            apply_model_profile("anthropic-baseline")
        if DEFAULT_MODEL_PROFILE != "anthropic-baseline":
            # Only loud-log when something interesting happens — staying on
            # baseline is the silent default to avoid noise on every scan.
            print(
                f"Default model profile: {DEFAULT_MODEL_PROFILE} "
                f"(from ~/.sentinel/model_profile_default.txt). "
                f"Pass --model-profile anthropic-baseline to override.",
                file=sys.stderr,
            )
            # Apply ONLY if it's not the baseline — applying baseline does
            # nothing useful and is the legacy default behavior.
            apply_default_model_profile()
            # Verify proxy is up if we just routed to siliconflow.
            if DEFAULT_MODEL_PROFILE == "siliconflow-qwen-235b":
                from sentinel.agent.model_router import (
                    SILICONFLOW_PROXY_URL,
                    siliconflow_proxy_is_up,
                )
                if not siliconflow_proxy_is_up():
                    print(
                        f"ERROR: persisted default profile "
                        f"'siliconflow-qwen-235b' requires the "
                        f"anthropic-shim listening at {SILICONFLOW_PROXY_URL}.\n"
                        f"  Start it first: "
                        f"bash tools/serving/start-anthropic-shim.sh --bg\n"
                        f"  Or revert: sentinel benchmark reset-default",
                        file=sys.stderr,
                    )
                    return 2
        # ---- Cloud backend routing (2026-XX-XX) — legacy --cloud path -----
        cloud = getattr(args, "cloud", "sonnet")
        if cloud == "auto":
            from sentinel.agent.model_router import siliconflow_proxy_is_up
            cloud = "siliconflow" if siliconflow_proxy_is_up() else "sonnet"
            print(f"--cloud auto → resolved to: {cloud}", file=sys.stderr)
        if cloud == "siliconflow":
            from sentinel.agent.model_router import (
                enable_siliconflow_routing, siliconflow_proxy_is_up,
            )
            if not siliconflow_proxy_is_up():
                print(
                    "ERROR: --cloud siliconflow requested but proxy not responding at "
                    "http://127.0.0.1:4002. Start it first:\n"
                    "  bash tools/serving/start-anthropic-shim.sh --bg",
                    file=sys.stderr,
                )
                return 2
            enable_siliconflow_routing()
            print("--cloud siliconflow: Claude SDK redirected to anthropic-shim",
                  file=sys.stderr)

    if args.all_scope_targets:
        return _do_scan_autonomous_multi(args)

    if not args.target:
        print("ERROR: target URL is required (or use --all-scope-targets)", file=sys.stderr)
        return 2

    # Validate chain goals at parse time so typos fail loud.
    chain_goals = [g.strip() for g in (args.chain_goals or "").split(",") if g.strip()]
    if chain_goals:
        from sentinel.agent.pentest.chain_executor import validate_goal_slugs
        _, unknown = validate_goal_slugs(chain_goals)
        if unknown:
            print(
                f"ERROR: unknown chain goals: {unknown}. "
                f"Available: admin_session_takeover, pii_exfil, "
                f"lateral_to_internal_service, session_fixation_or_hijack, rce, "
                f"persistent_backdoor_admin, audit_log_tamper, payment_flow_bypass",
                file=sys.stderr,
            )
            return 2

    # Plan 03-02 (COST-01): when --max-cost-usd N is set, override the soft
    # per-scan budget AND flip cost_cap_strict=True so the between-phase
    # guard writes a `scan_aborted_cost_cap` audit event + raises CostCapAbort
    # instead of emitting the existing soft `phase_skipped_budget_exhausted`
    # signal. When the flag is absent (None), leave both at the soft defaults
    # (max_budget_per_scan_usd=args.max_budget_per_scan_usd, cost_cap_strict=False).
    effective_max_budget_per_scan_usd = args.max_budget_per_scan_usd
    cost_cap_strict = False
    if max_cost_usd is not None:
        effective_max_budget_per_scan_usd = max_cost_usd
        cost_cap_strict = True

    cfg = PipelineConfig(
        target=args.target,
        scope_path=args.scope,
        workspaces_root=args.workspaces_root,
        corpus_dir=args.corpus_dir,
        repo_path=args.repo_path,
        ollama_host=args.ollama_host,
        embed_model=args.embed_model,
        max_budget_per_phase_usd=args.max_budget_per_phase_usd,
        max_budget_per_scan_usd=effective_max_budget_per_scan_usd,
        cost_cap_strict=cost_cap_strict,
        vuln_classes_filter=(
            [s.strip() for s in args.vuln_classes.split(",") if s.strip()]
            if getattr(args, "vuln_classes", None) else None),
        recon_max_pages=args.recon_max_pages,
        recon_max_turns=args.recon_max_turns,
        vuln_max_pages=args.vuln_max_pages,
        vuln_max_turns=args.vuln_max_turns,
        exploit_max_turns=args.exploit_max_turns,
        correlation_max_turns=args.correlation_max_turns,
        report_max_turns=args.report_max_turns,
        report_style=args.report_style,
        model=args.model,
        rate_limit_per_host_sec=args.rate_limit_per_host_sec,
        skip_phases=args.skip,
        auto_brain=args.auto_brain,
        brain_max_topics=args.brain_max_topics,
        brain_budget_per_topic_usd=args.brain_budget_per_topic_usd,
        resume=args.resume,
        verify_before_exploit=not getattr(args, "no_verify_before_exploit", False),
        chain_execution_enabled=not args.no_chain_execution,
        chain_goals=chain_goals or [
            "admin_session_takeover", "pii_exfil", "lateral_to_internal_service",
        ],
        chain_max_chains_per_goal=args.chain_max_chains_per_goal,
        chain_max_steps_per_chain=args.chain_max_steps_per_chain,
        chain_max_wall_clock_sec=args.chain_max_wall_clock_sec,
        phase_backend=args.phase_backend,
        ollama_fallback_model=args.ollama_fallback_model,
        enable_operator_chat=args.enable_operator_chat,
        engagement_mode=getattr(args, "mode", None),
    )

    # Wave 9 — wire the Opus teacher if enabled. --no-teacher overrides --teacher.
    teacher_mode_arg = "off" if getattr(args, "no_teacher", False) else getattr(args, "teacher", "review-only")
    if teacher_mode_arg != "off":
        try:
            from sentinel.agent.pentest.teacher_opus import TeacherOpus
            from sentinel.agent.pentest.online_training_log import OnlineTrainingLog
            scope_mode_for_teacher = (
                getattr(args, "mode", None) or "production"
            )
            # Stash the teacher init args on cfg so PentestPipeline can wire
            # in audit_log + event_log AFTER it constructs them in run().
            # Direct injection here would leave both refs as None.
            cfg.teacher = TeacherOpus(
                model=getattr(args, "teacher_model", "claude-opus-4-7"),
                budget_usd=getattr(args, "teacher_budget_usd", 30.0),
                mode=teacher_mode_arg,
                training_log=OnlineTrainingLog(),
                scope_mode=scope_mode_for_teacher,
            )
            print(f"  [teacher] enabled (mode={teacher_mode_arg}, "
                  f"budget=${getattr(args, 'teacher_budget_usd', 30.0)}, "
                  f"model={getattr(args, 'teacher_model', 'claude-opus-4-7')})")
        except Exception as e:
            print(f"  [teacher] disabled — init failed: {e}")

    import asyncio
    from sentinel.core.engagement_mode import ModeMismatchError, ModeError
    from sentinel.agent.pentest.pipeline import PreflightRefused, CostCapAbort
    try:
        summary = asyncio.run(PentestPipeline(cfg).run())
    except PreflightRefused:
        # Cut #3 (2026-XX-XX): pre-flight gate already printed the
        # friendly refusal message + audit-logged. Exit cleanly with
        # non-zero so CI / wrapper scripts see this as a "scan refused"
        # not a crash. Zero Claude tokens spent.
        return 3
    except CostCapAbort as cap_err:
        # Plan 03-02 (COST-01): operator-explicit --max-cost-usd cap was
        # crossed. The pipeline already wrote the `scan_aborted_cost_cap`
        # audit event and emitted the matching event-log event. Print a
        # friendly summary so the operator sees what happened in CI output.
        # Exit code 3 (matches PreflightRefused — graceful refusal, not crash).
        print(
            f"COST CAP TRIPPED: {cap_err}\n"
            f"(Pipeline aborted between phases per --max-cost-usd. "
            f"Audit event scan_aborted_cost_cap written. "
            f"Partial deliverables on disk under the workspace.)",
            file=sys.stderr,
        )
        return 3
    except ModeMismatchError as e:
        # Wave 3 — operator's --mode disagreed with scope.yaml's
        # engagement_mode field. Fail loudly with both values; never
        # silently default one or the other.
        print(f"MODE MISMATCH: {e}", file=sys.stderr)
        return 2
    except ModeError as e:
        print(f"MODE ERROR: {e}", file=sys.stderr)
        return 2
    except OutOfScopeError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        print("(Logged to audit trail. Pipeline never started.)", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\nInterrupted — partial deliverables + audit log are persisted.", file=sys.stderr)
        return 130
    except RuntimeError as e:
        print(f"Pipeline failed: {e}", file=sys.stderr)
        return 2

    # Phase 5+ — convert deliverables into a Sentinel RunReport so the existing
    # PDF / compliance / Obsidian pipeline works unchanged. Reuses the same
    # ShannonScanner.parse_workspace logic that handles Shannon's output (the
    # workspace shape is intentionally identical).
    try:
        from sentinel.core.orchestrator import RunReport
        from sentinel.core.scope import Scope
        from sentinel.scanners.shannon import ShannonScanner

        scope = Scope.load(args.scope)
        workspace = Path(summary["workspace"])
        findings, _meta = ShannonScanner.parse_workspace(workspace, target=args.target)
        # Override the scanner attribution so Findings show up as 'pentest-agent'
        # rather than 'shannon' — they were produced by Sentinel's own loop.
        for f in findings:
            f.scanner = "pentest-agent"
        # Plan 05-04 (NOVEL-05) — thread the pipeline's novelty escalations
        # onto RunReport.novel_findings. The pipeline serialized each
        # NovelFindingEvidence via to_dict; reconstitute them here so
        # Plan 05-05's dashboard + report renderers see real dataclass
        # instances. Defensive: a malformed entry doesn't kill the report.
        novel_findings: list = []
        for nfe_dict in (summary.get("novel_findings") or []):
            try:
                from sentinel.agent.novelty import NovelFindingEvidence
                novel_findings.append(NovelFindingEvidence.from_dict(nfe_dict))
            except Exception as nfe_err:
                log = logging.getLogger(__name__)
                log.warning(
                    "skipping malformed NovelFindingEvidence entry: %s", nfe_err,
                )
        report = RunReport(scope=scope, findings=findings,
                            scanners_run=["pentest-agent"], errors=[],
                            novel_findings=novel_findings)

        # Reuse _write_outputs (handles runs/*.json + Obsidian engagement folder).
        # Synthesize args attribute the function expects.
        class _A:
            pass
        a = _A()
        a.vault = args.vault
        _write_outputs(a, report)
        _print_summary(report)
    except Exception as e:
        log = logging.getLogger(__name__)
        log.warning("post-pipeline reporting failed: %s", e)

    return 0


def _do_pentest_agent(args) -> int:
    """Run the autonomous pentest agent (Phase 1: recon)."""
    try:
        from sentinel.agent.pentest import PentestAgent, PentestConfig
    except ImportError as e:
        print(
            f"Pentest agent dependencies missing ({e}). Install with: "
            f"pip install -e '.[agent]'",
            file=sys.stderr,
        )
        return 2

    cfg = PentestConfig(
        target=args.target,
        scope_path=args.scope,
        workspaces_root=args.workspaces_root,
        max_pages=args.max_pages,
        max_turns=args.max_turns,
        max_budget_usd=args.max_budget_usd,
        model=args.model,
        rate_limit_per_host_sec=args.rate_limit_per_host_sec,
    )
    import asyncio
    try:
        asyncio.run(PentestAgent(cfg).run())
    except OutOfScopeError as e:
        # The pre-boot scope guard refused — record and exit non-zero.
        print(f"REFUSED: {e}", file=sys.stderr)
        print("(Logged to audit trail. Agent never started.)", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\nInterrupted — partial workspace + audit log are persisted.", file=sys.stderr)
        return 130
    except RuntimeError as e:
        print(f"Pentest agent failed: {e}", file=sys.stderr)
        return 2
    return 0


def _do_scan_autonomous_multi(args) -> int:
    """Fan out scan-autonomous across every domain in scope.targets.domains."""
    from sentinel.agent.pentest import PentestPipeline, PipelineConfig
    from sentinel.agent.pentest.multi_pipeline import (
        expand_scope_to_targets, render_combined_summary, run_multi_pipeline,
    )
    from sentinel.core.scope import Scope

    scope = Scope.load(args.scope)
    targets = expand_scope_to_targets(scope)
    if not targets:
        print("ERROR: no concrete domains in scope.targets.domains "
              "(wildcards are matchers, not targets — list specific hosts).",
              file=sys.stderr)
        return 2

    print(f"Multi-target run: {len(targets)} targets, "
          f"max_concurrent={args.max_concurrent}")
    for t in targets:
        print(f"  - {t}")

    # Plan 03-02 (COST-01): --max-cost-usd applies per-target in multi mode.
    # When set, EACH spawned pipeline gets its own strict cap — so two
    # parallel scans with --max-cost-usd 5 can burn up to $5 each in the
    # worst case (best-effort, between-phase). When unset, the soft-default
    # max_budget_per_scan_usd path is preserved unchanged.
    multi_max_cost = getattr(args, "max_cost_usd", None)
    multi_max_budget_per_scan_usd = args.max_budget_per_scan_usd
    multi_cost_cap_strict = False
    if multi_max_cost is not None:
        multi_max_budget_per_scan_usd = multi_max_cost
        multi_cost_cap_strict = True

    base_cfg = PipelineConfig(
        target="placeholder",  # overridden per-target
        scope_path=args.scope,
        workspaces_root=args.workspaces_root,
        corpus_dir=args.corpus_dir,
        repo_path=args.repo_path,
        ollama_host=args.ollama_host,
        embed_model=args.embed_model,
        max_budget_per_phase_usd=args.max_budget_per_phase_usd,
        max_budget_per_scan_usd=multi_max_budget_per_scan_usd,
        cost_cap_strict=multi_cost_cap_strict,
        report_style=getattr(args, "report_style", "skip-empty"),
        model=args.model,
        rate_limit_per_host_sec=args.rate_limit_per_host_sec,
        skip_phases=args.skip,
        vuln_classes_filter=(
            [s.strip() for s in args.vuln_classes.split(",") if s.strip()]
            if getattr(args, "vuln_classes", None) else None),
        auto_brain=args.auto_brain,
        brain_max_topics=args.brain_max_topics,
        brain_budget_per_topic_usd=args.brain_budget_per_topic_usd,
        resume=args.resume,
        verify_before_exploit=not getattr(args, "no_verify_before_exploit", False),
    )

    import asyncio
    results = asyncio.run(run_multi_pipeline(
        base_cfg, targets, max_concurrent=args.max_concurrent,
    ))

    out_dir = Path(args.workspaces_root)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / f"multi-summary-{scope.engagement_id}.md"
    render_combined_summary(results, summary_path)
    print(f"\nMulti-target summary: {summary_path}")
    failed = sum(1 for r in results if not r.success)
    return 0 if failed == 0 else 1


def _do_brain_grow(args) -> int:
    """Run the BrainAgent on a topic — autonomous corpus expansion."""
    try:
        from sentinel.agent.brain import BrainAgent, BrainConfig
    except ImportError as e:
        print(
            f"Brain agent dependencies missing ({e}). Install with: "
            f"pip install -e '.[agent]'",
            file=sys.stderr,
        )
        return 2

    cfg = BrainConfig(
        topic=args.topic,
        corpus_dir=args.corpus_dir,
        ollama_host=args.ollama_host,
        embed_model=args.embed_model,
        chunk_size=args.chunk_size,
        chunk_overlap=args.chunk_overlap,
        depth=args.depth,
        max_pages=args.max_pages,
        max_turns=args.max_turns,
        max_budget_usd=args.max_budget_usd,
        model=args.model,
        rate_limit_per_host_sec=args.rate_limit_per_host_sec,
        backend=getattr(args, "brain_backend", "ollama"),
        ollama_brain_model=getattr(args, "ollama_brain_model", "llama3.1:8b"),
        ollama_max_turns=getattr(args, "ollama_max_turns", 30),
        topic_dense_threshold=getattr(args, "topic_dense_threshold", 0.20),
        force_topic=getattr(args, "force_topic", False),
    )
    import asyncio
    try:
        asyncio.run(BrainAgent(cfg).run())
    except KeyboardInterrupt:
        print("\nInterrupted — partial corpus changes are persisted.", file=sys.stderr)
        return 130
    except RuntimeError as e:
        print(f"Brain agent failed: {e}", file=sys.stderr)
        return 2
    return 0


def _target_from_event_logs(workspace_name: str) -> Optional[str]:
    """Look at runs/events-*.jsonl files for a pipeline_started event whose
    workspace path ends with `workspace_name`. Returns the target URL, or
    None if no matching event log is found.

    This is the discovery mechanism for Sentinel PentestPipeline workspaces
    (which don't write Shannon's session.json). Picks the most recent log.
    """
    from sentinel.agent import event_log as elog
    # Read DEFAULT_EVENTS_DIR at call time so tests can monkeypatch it.
    runs = elog.list_event_logs(elog.DEFAULT_EVENTS_DIR)
    for entry in runs:
        try:
            log_obj = elog.EventLog.load(entry["path"], max_events=20)
        except Exception:
            continue
        for ev in log_obj.all_events():
            if ev.get("kind") != elog.KIND_PIPELINE_STARTED:
                continue
            ws = ev.get("workspace") or ""
            if ws.endswith("/" + workspace_name) or ws == workspace_name:
                target = ev.get("target")
                if target:
                    return str(target)
    return None


def _do_ingest_shannon(args) -> int:
    """Convert a Shannon workspace dir into a Sentinel run JSON + Obsidian engagement folder.

    The same per-target scope.authorize_url() gate runs on the resolved target,
    so an ingested Shannon run lands in the audit log just like a scanner run.
    """
    from sentinel.core.orchestrator import RunReport
    from sentinel.core.scope import Scope
    from sentinel.scanners.shannon import ShannonScanner, SHANNON_STATE_DIR

    scope = Scope.load(args.scope)

    # Accept either a workspace name (under ~/.shannon/workspaces/) or an absolute path.
    workspace_arg = args.workspace
    candidate = Path(workspace_arg).expanduser()
    if not candidate.is_dir():
        candidate = SHANNON_STATE_DIR / "workspaces" / workspace_arg
    if not candidate.is_dir():
        print(f"Shannon workspace not found: {workspace_arg}", file=sys.stderr)
        print(f"Tried: {Path(workspace_arg).expanduser()} and {SHANNON_STATE_DIR / 'workspaces' / workspace_arg}",
              file=sys.stderr)
        return 2

    findings, meta = ShannonScanner.parse_workspace(candidate, target=args.target)
    # Resolve target in priority order:
    #  1. --target arg explicitly given by the operator
    #  2. Shannon's session.json webUrl (Shannon-native workspaces)
    #  3. Sentinel PentestPipeline event log's pipeline_started.target
    #     (our own workspaces don't write a session.json)
    #  4. Final fallback: "unknown" (will fail the scope guard, surfacing
    #     the missing-target error to the operator)
    target = args.target or (meta.get("session") or {}).get("webUrl")
    if not target:
        target = _target_from_event_logs(candidate.name)
    if not target:
        target = "unknown"

    # Re-authorize so the run is recorded in the engagement audit log.
    try:
        scope.authorize_url(target)
    except OutOfScopeError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 3

    report = RunReport(scope=scope, findings=findings, scanners_run=["shannon"], errors=[])
    _write_outputs(args, report)
    _print_summary(report)
    print(f"\nIngested from: {candidate}")
    if meta:
        s = meta.get("session", {})
        m = meta.get("metrics", {})
        print(f"Shannon status: {s.get('status', '?')}, "
              f"duration: {int((m.get('total_duration_ms') or 0) / 1000)}s, "
              f"notional cost: ${m.get('total_cost_usd', 0):.2f}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    _setup_log(args.verbose)

    if args.cmd == "verify-audit":
        scope_mode: Optional[str] = None
        if getattr(args, "scope", None):
            try:
                from sentinel.core.engagement_mode import EngagementMode
                # Read the scope file directly without loading + writing
                # an audit-log entry (Scope.load auto-emits scope_loaded
                # which would taint the log we're trying to verify).
                import yaml as _yaml
                _data = _yaml.safe_load(Path(args.scope).read_text()) or {}
                scope_mode = EngagementMode.from_string(
                    _data.get("engagement_mode")
                ).value
            except Exception as e:
                print(f"Could not read --scope mode: {e}", file=sys.stderr)
                return 2
        ok, err = AuditLog.verify(args.path, scope_mode=scope_mode)
        if ok:
            mode_label = f" (mode: {scope_mode})" if scope_mode else ""
            print(f"Audit log integrity: OK{mode_label}")
            return 0
        print(f"Audit log integrity: FAIL — {err}", file=sys.stderr)
        return 2

    if args.cmd == "triage-findings":
        return _do_triage_findings(args)

    if args.cmd == "ingest":
        return _do_ingest(args)
    if args.cmd == "ask":
        return _do_ask(args)
    if args.cmd == "corpus-stats":
        return _do_corpus_stats(args)
    if args.cmd == "web":
        return _do_web(args)
    if args.cmd == "github-recon":
        return _do_github_recon(args)
    if args.cmd == "teach-findings":
        return _do_teach_findings(args)
    if args.cmd == "datadome-harvest":
        # Tier-2 anti-bot bypass entrypoint (added 2026-XX-XX).
        from sentinel.agent.datadome_harvest import run_harvest
        import asyncio as _asyncio
        return _asyncio.run(run_harvest(
            args.url, args.scope,
            headed=not args.headless,
            wait_after_load=args.wait_after_load,
        ))
    if args.cmd == "chrome":
        return _do_chrome(args)
    if args.cmd == "ingest-shannon":
        return _do_ingest_shannon(args)
    if args.cmd == "brain-grow":
        return _do_brain_grow(args)
    if args.cmd == "agent":
        return _do_pentest_agent(args)
    if args.cmd == "scan-autonomous":
        return _do_scan_autonomous(args)
    if args.cmd == "salvage":
        return _do_salvage(args)
    if args.cmd == "workspaces":
        return _do_workspaces(args)
    if args.cmd == "logs":
        return _do_logs(args)
    if args.cmd == "status":
        return _do_status(args)
    if args.cmd == "info":
        return _do_info(args)
    if args.cmd == "state":
        return _do_state(args)
    if args.cmd == "h1":
        return _do_h1(args)
    if args.cmd == "new-engagement":
        return _do_new_engagement(args)
    if args.cmd == "scan-apk":
        return _do_scan_apk(args)
    if args.cmd == "scan-cloud":
        return _do_scan_cloud(args)
    if args.cmd == "scan-dfir":
        return _do_scan_dfir(args)
    if args.cmd == "benchmark":
        return _do_benchmark(args)
    if args.cmd == "novelty":
        # Plan 05-02 NOVEL-02 + NOVEL-03 — novelty-index management.
        if args.novelty_cmd == "refresh-index":
            from sentinel.agent.novelty import refresh_index as _refresh_index
            stats = _refresh_index(
                corpus_dir=args.corpus_dir,
                since_year=args.since_year,
                ollama_host=args.ollama_host,
                ollama_model=args.ollama_model,
            )
            print(json.dumps(stats, indent=2))
            return 0
        raise SystemExit(f"unknown novelty subcommand: {args.novelty_cmd!r}")

    # ---- scan/report path: needs scope -----------------------------------
    try:
        scope = Scope.load(args.scope)
    except ScopeError as e:
        print(f"Scope error: {e}", file=sys.stderr)
        return 2

    if not scope.is_currently_valid():
        print(
            f"Scope is not currently valid (window {scope.valid_from} .. {scope.valid_until}). Refusing to run.",
            file=sys.stderr,
        )
        return 2

    ollama = _ollama_or_none(args)
    retriever = _make_retriever(args)
    orch = Orchestrator(scope, ollama=ollama, retriever=retriever)

    try:
        if args.cmd == "scan-repo":
            report = orch.scan_repo(args.path, repo_url=args.repo_url)
        elif args.cmd == "scan-config":
            report = orch.scan_config(args.path)
        elif args.cmd == "scan-deps":
            report = orch.scan_deps(args.path, repo_url=args.repo_url)
        elif args.cmd == "scan-live":
            report = orch.scan_live(args.url, max_severity_to_run=args.max_severity, deep=args.deep)
        elif args.cmd == "scan-active":
            report = orch.scan_active(args.url, repo_url=args.repo_url, deep=args.deep)
        elif args.cmd == "scan-recon":
            report = orch.scan_recon(args.target, deep=args.deep)
        elif args.cmd == "scan-full":
            report = orch.scan_full(args.url, repo_url=args.repo_url, deep=args.deep)
        elif args.cmd == "scan-web":
            report = orch.scan_web(args.url, deep=args.deep)
        elif args.cmd == "sbom":
            sbom_out = args.sbom_output or f"./sbom-{scope.client}-{scope.engagement_id}.json"
            report = orch.generate_sbom(args.target, output_path=sbom_out, format=args.sbom_format)
        elif args.cmd == "compliance":
            return _do_compliance(args, scope)
        elif args.cmd == "report":
            return _do_report(args, scope, ollama)
        else:
            print(f"Unknown command: {args.cmd}", file=sys.stderr)
            return 2
    except OutOfScopeError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        print("(Logged to audit trail. No request was sent.)", file=sys.stderr)
        return 3

    _write_outputs(args, report)
    _print_summary(report)
    return 0


def _do_triage_findings(args) -> int:
    """Pre-submission gate — score each finding GO/REVIEW/HOLD before it goes to
    a bug-bounty program. Reads a run JSON ({"findings":[...]}), an
    exploitation-queue JSON ({"vulnerabilities":[...]}), or a bare list."""
    from sentinel.agent.pentest.submission_gate import assess_run

    path = Path(args.findings_json)
    if not path.is_file():
        print(f"findings JSON not found: {path}", file=sys.stderr)
        return 2
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"invalid JSON in {path}: {e}", file=sys.stderr)
        return 2

    if isinstance(raw, list):
        findings = raw
    else:
        findings = raw.get("findings") or raw.get("vulnerabilities") or []
    if not findings:
        print(f"No findings in {path} (looked for 'findings' / 'vulnerabilities').")
        return 0

    result = assess_run(findings, program_maturity=args.program_maturity)

    if getattr(args, "as_json", False):
        print(json.dumps(result, indent=2))
        return 0

    icon = {"go": "✅ GO    ", "review": "🟡 REVIEW", "hold": "⛔ HOLD  "}
    # Order: HOLD first (what to drop), then REVIEW, then GO (what to submit).
    order = {"hold": 0, "review": 1, "go": 2}
    for v in sorted(result["verdicts"], key=lambda x: order[x["decision"]]):
        print(f"{icon[v['decision']]} [{v['score']:3d}/100]  {v['id']}")
        for r in v["reasons"]:
            print(f"        - {r}")
        if v["guidance"]:
            print(f"        → {v['guidance']}")
        print()

    c = result["counts"]
    print(f"Summary: {c['go']} GO · {c['review']} REVIEW · {c['hold']} HOLD")
    print("Submit GO. Fix the reasons on REVIEW first. Never submit HOLD — those "
          "are what come back Informative/N-A/Duplicate.")
    return 0


def _do_compliance(args, scope: Scope) -> int:
    """Render a compliance overlay (PCI/SOC2/CIS/NIST CSF) from a findings JSON."""
    from sentinel.core.findings import Finding, Severity, Status
    from sentinel.reporting.compliance import render_overlay_markdown

    raw = json.loads(Path(args.findings_json).read_text())
    findings: list[Finding] = []
    for d in raw.get("findings", []):
        findings.append(
            Finding(
                title=d["title"],
                description=d["description"],
                severity=Severity(d["severity"]),
                scanner=d["scanner"],
                target=d["target"],
                location=d.get("location"),
                cwe=d.get("cwe"),
                cve=d.get("cve"),
                cvss=d.get("cvss"),
                references=d.get("references", []),
                raw=d.get("raw", {}),
                status=Status(d.get("status", "new")),
                remediation=d.get("remediation"),
                triage_notes=d.get("triage_notes"),
                reproduces_in_lab=bool(d.get("reproduces_in_lab", False)),
                reproduces_under_operational=bool(d.get("reproduces_under_operational", False)),
                reproduces_complete=bool(d.get("reproduces_complete", False)),
                attack_technique_ids=list(d.get("attack_technique_ids", []) or []),
                capec_ids=list(d.get("capec_ids", []) or []),
                discovered_at=d.get("discovered_at", ""),
            )
        )
    overlay = render_overlay_markdown(findings)
    if args.output:
        Path(args.output).write_text(overlay)
        print(f"Compliance overlay written to: {args.output}")
    else:
        print(overlay)
    return 0


def _do_report(args, scope: Scope, ollama: Optional[OllamaClient]) -> int:
    from sentinel.core.findings import Finding, Severity, Status
    from sentinel.core.orchestrator import RunReport
    from sentinel.reporting.pdf import PDFReporter

    raw = json.loads(Path(args.findings_json).read_text())
    findings: list[Finding] = []
    for d in raw.get("findings", []):
        findings.append(
            Finding(
                title=d["title"],
                description=d["description"],
                severity=Severity(d["severity"]),
                scanner=d["scanner"],
                target=d["target"],
                location=d.get("location"),
                cwe=d.get("cwe"),
                cve=d.get("cve"),
                cvss=d.get("cvss"),
                references=d.get("references", []),
                raw=d.get("raw", {}),
                status=Status(d.get("status", "new")),
                remediation=d.get("remediation"),
                triage_notes=d.get("triage_notes"),
                reproduces_in_lab=bool(d.get("reproduces_in_lab", False)),
                reproduces_under_operational=bool(d.get("reproduces_under_operational", False)),
                reproduces_complete=bool(d.get("reproduces_complete", False)),
                attack_technique_ids=list(d.get("attack_technique_ids", []) or []),
                capec_ids=list(d.get("capec_ids", []) or []),
                discovered_at=d.get("discovered_at", ""),
            )
        )
    report = RunReport(
        scope=scope,
        findings=findings,
        scanners_run=raw.get("scanners_run", []),
        errors=raw.get("errors", []),
    )
    pdf = PDFReporter(args.output_dir, ollama=ollama)
    out = pdf.write(report)
    print(f"Report: {out}")

    # --- Phase 10.4: differential report against a prior run -----------
    if args.diff_against:
        from sentinel.reporting.diff import diff_findings, load_findings, render_diff_markdown
        prior_path = Path(args.diff_against)
        if not prior_path.is_file():
            print(f"--diff: prior run JSON not found: {prior_path}", file=sys.stderr)
            return 1
        prior_findings = load_findings(prior_path)
        delta = diff_findings(prior_findings, findings)
        markdown = render_diff_markdown(
            delta,
            prior_label=prior_path.stem,
            current_label=Path(args.findings_json).stem,
        )
        delta_path = out.with_suffix(".delta.md")
        delta_path.write_text(markdown)
        c = delta.counts()
        print(f"Delta: {delta_path}")
        print(f"  closed={c['closed']} new={c['new']} escalated={c['escalated']} "
              f"reduced={c['reduced']} persisted={c['persisted']}")
    return 0


# ---- Phase 11: Shannon-parity convenience subcommands -----------------------


def _do_salvage(args) -> int:
    """Mine prior scan queues with local Ollama — $0 Claude tokens.

    Walks every `workspaces/*/deliverables/*_exploitation_queue.json`,
    optionally filters by --target substring, sends each entry to Ollama
    for a 0-10 exploitability score + manual probe steps, writes a
    ranked markdown operator-playbook.
    """
    from pathlib import Path
    from sentinel.agent.pentest import past_finding_miner as pfm

    target = (args.target or "").strip() or None
    model = (args.model or pfm.DEFAULT_MODEL).strip()
    workspaces_root = Path(args.workspaces_root).expanduser()

    print(f"Walking {workspaces_root} for queue entries...", file=sys.stderr)
    entries = pfm.walk_all_queues(workspaces_root, target_filter=target)
    if not entries:
        print(f"No queue entries found"
              f"{f' matching {target!r}' if target else ''}.",
              file=sys.stderr)
        return 1
    print(f"Found {len(entries)} entries"
          f"{f' matching {target!r}' if target else ' across all workspaces'}. "
          f"Ranking with {model}...", file=sys.stderr)

    def _progress(b, total, n):
        print(f"  batch {b}/{total} ({n} entries)...", file=sys.stderr)

    verdicts = pfm.rank_entries(entries, model=model,
                                 batch_size=args.batch_size,
                                 progress_cb=_progress)
    if not verdicts:
        print("Ollama returned no usable rankings. Check the model is pulled "
              "(`ollama list`) and reachable at http://localhost:11434",
              file=sys.stderr)
        return 2

    # Filter by min_score (output report still includes a "skip" tier)
    if args.min_score > 0:
        verdicts = [v for v in verdicts if v.score >= args.min_score]

    out_path = Path(args.output) if args.output else Path(
        f"./salvage-{(target or 'all').replace('.','_').replace('/','_')}.md"
    )
    report = pfm.render_report(verdicts, target_filter=target)
    out_path.write_text(report, encoding="utf-8")

    sidecar = out_path.with_suffix(".jsonl")
    pfm.write_jsonl_sidecar(verdicts, sidecar)

    print(f"\nReport written: {out_path}", file=sys.stderr)
    print(f"JSONL sidecar:  {sidecar}", file=sys.stderr)
    n_high = sum(1 for v in verdicts if v.score >= 7)
    n_mid = sum(1 for v in verdicts if 4 <= v.score < 7)
    print(f"Top tier (score≥7): {n_high}  |  worth-a-look (4-6): {n_mid}",
          file=sys.stderr)
    return 0


def _do_workspaces(args) -> int:
    from sentinel.ui.state import list_workspaces
    rows = list_workspaces(args.workspaces_root)
    if not rows:
        root = Path(args.workspaces_root).expanduser()
        print(f"No workspaces under {root}")
        return 0
    print(f"{'Workspace':<48} {'Modified':<18} {'Deliv':<6} Completed-phases")
    print("-" * 100)
    for r in rows:
        comp = ",".join(r["completed_phases"]) or "(none)"
        comp_short = (comp[:40] + "…") if len(comp) > 41 else comp
        # Trim ISO timestamp to date+hh:mm.
        mtime = r["mtime"][:16].replace("T", " ")
        print(f"{r['name']:<48} {mtime:<18} {r['n_deliverables']:<6} {comp_short}")
    return 0


def _do_logs(args) -> int:
    """Tail the structured event log for one workspace.

    Looks for runs/events-<job_id>.jsonl using the workspace's .meta file
    if present; falls back to walking runs/ for the most recent matching log.
    """
    ws_arg = args.workspace
    candidates: list[Path] = []
    p = Path(ws_arg)
    if p.is_absolute() and p.is_dir():
        ws_dir = p
    else:
        ws_dir = Path(args.workspaces_root).expanduser() / ws_arg
    runs_dir = Path("runs")
    if not runs_dir.is_dir():
        print(f"No runs/ dir; nothing to tail.", file=sys.stderr)
        return 1
    # Match by workspace name appearing in the event log filename or its first line.
    for log_path in sorted(runs_dir.glob("events-*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            head = log_path.read_text(errors="replace")[:4096]
        except OSError:
            continue
        if ws_dir.name in head or ws_dir.name in log_path.name:
            candidates.append(log_path)
            break
    if not candidates and runs_dir.is_dir():
        # Fallback: most recent events log.
        all_logs = sorted(runs_dir.glob("events-*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        if all_logs:
            candidates.append(all_logs[0])
    if not candidates:
        print(f"No event log found for workspace {ws_arg}", file=sys.stderr)
        return 1
    log_path = candidates[0]
    print(f"# Event log: {log_path}", file=sys.stderr)

    if args.follow:
        import subprocess
        return subprocess.call(["tail", "-n", str(args.tail), "-f", str(log_path)])
    lines = log_path.read_text(errors="replace").splitlines()
    for line in lines[-args.tail:]:
        print(line)
    return 0


def _do_status(args) -> int:
    workspaces_root = Path(args.workspaces_root).expanduser()
    runs_dir = Path(args.runs_dir).expanduser()
    n_ws = len(list(workspaces_root.glob("*"))) if workspaces_root.is_dir() else 0
    n_runs = len(list(runs_dir.glob("*.json"))) if runs_dir.is_dir() else 0
    n_events = len(list(runs_dir.glob("events-*.jsonl"))) if runs_dir.is_dir() else 0
    print(f"Sentinel status")
    print(f"  workspaces: {n_ws}  ({workspaces_root})")
    print(f"  runs (findings JSON): {n_runs}  ({runs_dir})")
    print(f"  event logs: {n_events}")
    # Show the 5 most-recent runs.
    if runs_dir.is_dir():
        recent = sorted(runs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:5]
        if recent:
            from datetime import datetime
            print(f"\n  Most recent runs:")
            for r in recent:
                ts = datetime.fromtimestamp(r.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                print(f"    {ts}  {r.name}")
    return 0


def _do_scan_apk(args) -> int:
    """Run MobSF + apkleaks against an APK; emit a Sentinel run report."""
    from sentinel.scanners.mobile import MobSFScanner, ApkleaksScanner
    from sentinel.scanners.base import ScannerError

    try:
        scope = Scope.load(args.scope)
    except ScopeError as e:
        print(f"Scope error: {e}", file=sys.stderr)
        return 2
    if not scope.is_currently_valid():
        print(
            f"Scope is not currently valid ({scope.valid_from}..{scope.valid_until}). Refusing.",
            file=sys.stderr,
        )
        return 2

    apk_path = Path(args.apk_path).expanduser().resolve()
    if not apk_path.is_file():
        print(f"APK file not found: {apk_path}", file=sys.stderr)
        return 2

    findings: list = []
    errors: list[str] = []

    if not args.skip_mobsf:
        ok, info = MobSFScanner.check_available()
        if not ok:
            errors.append(f"mobsf: {info}")
            print(f"[mobsf] skipping — {info}", file=sys.stderr)
        else:
            try:
                findings.extend(MobSFScanner().run(scope, str(apk_path)))
            except (ScannerError, OutOfScopeError) as e:
                errors.append(f"mobsf: {e}")
                print(f"[mobsf] failed: {e}", file=sys.stderr)

    if not args.skip_apkleaks:
        try:
            findings.extend(ApkleaksScanner().run(scope, str(apk_path)))
        except (ScannerError, OutOfScopeError) as e:
            errors.append(f"apkleaks: {e}")
            print(f"[apkleaks] failed: {e}", file=sys.stderr)

    print(f"scan-apk complete — {len(findings)} finding(s), {len(errors)} error(s)")
    return 0 if not errors or findings else 1


def _do_scan_cloud(args) -> int:
    """Run cloud-enumeration scanners (S3Scanner / cloud_enum / Prowler / CloudFox)."""
    from sentinel.scanners.cloud import (
        CloudEnumScanner, S3ScannerScanner, ProwlerScanner, CloudFoxScanner,
    )
    from sentinel.scanners.base import ScannerError

    try:
        scope = Scope.load(args.scope)
    except ScopeError as e:
        print(f"Scope error: {e}", file=sys.stderr)
        return 2
    if not scope.is_currently_valid():
        print(
            f"Scope is not currently valid ({scope.valid_from}..{scope.valid_until}). Refusing.",
            file=sys.stderr,
        )
        return 2

    findings: list = []
    errors: list[str] = []

    bucket_kws = list(args.bucket_keywords or [])
    if not bucket_kws:
        # Derive from scope client name as a sensible default.
        bucket_kws = [scope.client.split("-")[0]] if scope.client else []

    runners = []
    if args.provider in ("aws", "any") and bucket_kws:
        runners.append(("s3-scanner", S3ScannerScanner(), {"keywords": bucket_kws}))
    if args.provider == "any" and bucket_kws:
        runners.append(("cloud-enum", CloudEnumScanner(), {"keywords": bucket_kws}))
    if args.provider == "aws" and args.aws_profile:
        runners.append(("prowler", ProwlerScanner(),
                        {"aws_profile": args.aws_profile}))
        runners.append(("cloudfox", CloudFoxScanner(),
                        {"aws_profile": args.aws_profile}))

    for name, scanner, opts in runners:
        try:
            findings.extend(scanner.run(scope, "cloud-enum", **opts))
        except (ScannerError, OutOfScopeError) as e:
            errors.append(f"{name}: {e}")
            print(f"[{name}] failed: {e}", file=sys.stderr)

    print(f"scan-cloud complete — {len(findings)} finding(s), {len(errors)} error(s)")
    return 0 if not errors or findings else 1


def _do_benchmark(args) -> int:
    """Wave 8 — dispatch the benchmark sub-commands (list / run / publish)."""
    from sentinel import benchmark as _bench

    sub = args.bench_cmd
    if sub == "list":
        rows = _bench.list_benchmarks()
        print(f"{'NAME':<14} {'MODE':<14} {'TASKS':>6}  METRIC")
        for r in rows:
            print(f"{r['name']:<14} {r['mode']:<14} {r['tasks']:>6}  {r['metric']}")
        return 0

    if sub == "run":
        from sentinel.web.routes.benchmark import _run_with_default_runner
        try:
            result = _run_with_default_runner(args.name)
        except ValueError as e:
            print(f"benchmark: {e}", file=sys.stderr)
            return 2
        result["model"] = args.model or result.get("model") or "stub-model"
        if args.max_budget is not None:
            result["max_budget_usd"] = args.max_budget

        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(result, indent=2))
            print(f"Wrote {out_path}")
        else:
            print(json.dumps(result, indent=2))
        return 0

    if sub == "publish":
        from sentinel.benchmark import svpb_lite
        out_dir = Path("research/svpb-lite-publish")
        out_dir.mkdir(parents=True, exist_ok=True)
        result = svpb_lite.run(model=args.name)
        artifact = out_dir / f"RESULTS-{args.name.replace('_','-')}.json"
        artifact.write_text(json.dumps(result, indent=2))
        print(f"Published {artifact}")
        print("README + SCORING already exist in research/svpb-lite-publish/.")
        return 0

    if sub == "parity-eval":
        from sentinel.benchmark.parity_eval import run_parity_eval
        # Plan 02-02: pass args.suite verbatim to the harness — the
        # comma-split lives in run_parity_eval._normalize_suite_arg so
        # the parse logic has ONE owner. CLI does NOT pre-split.
        try:
            result = run_parity_eval(
                suite=args.suite,
                baseline_profile=args.baseline,
                candidate_profile=args.candidate,
                scope_path=args.scope,
                output_dir=Path(args.output_dir),
            )
        except ValueError as e:
            print(f"parity-eval: {e}", file=sys.stderr)
            return 2
        except FileNotFoundError as e:
            # Unknown suite OR missing bench/<suite>/scope.yaml — fail loud
            # with exit 2 so caller (CI / dashboard launch) can distinguish
            # from a real scan failure.
            print(f"parity-eval: {e}", file=sys.stderr)
            return 2

        # Per-suite × per-profile verdict summary (one section per suite).
        suite_summary: dict[str, dict[str, dict[str, str]]] = {}
        for run in result["runs"]:
            sname = run.get("suite_name") or result.get("suite", "?")
            prof = run.get("profile", "?")
            verdicts = run.get("per_phase_verdicts", {})
            suite_summary.setdefault(sname, {})[prof] = verdicts

        summary = {
            "schema_version": result["schema_version"],
            "suite": result["suite"],
            "target": result["target"],
            "runs": [r["profile"] for r in result["runs"]],
            "per_suite_verdicts": suite_summary,
            "verdict_overall": result.get("verdict_overall", "unknown"),
        }
        print(json.dumps(summary, indent=2))

        # ---- BENCH-09 (Plan 02-04): auto-flip default on verdict='pass' --
        # Pure logic lives in default_switch.flip_default; the CLI wraps it
        # by also writing a bench_default_profile_flipped audit event to the
        # FIRST suite's audit chain (legal trail). Other verdicts: print a
        # docs-the-gap notice + stay on anthropic-baseline.
        from sentinel.benchmark.default_switch import (
            flip_default,
            should_flip_default,
        )
        if should_flip_default(result):
            # Embed the eval JSON's path so the state file's line 2
            # references the audit-trail eval that triggered the flip.
            # parity_eval writes runs/bench-parity-<ts>.json — derive
            # from markdown_report_path's pair (replace .md → .json).
            md_report_path = result.get("markdown_report_path", "")
            eval_json_path = ""
            if md_report_path and md_report_path.endswith(".md"):
                # The markdown filename is qwen-parity-eval-<ts>.md; its
                # JSON companion is bench-parity-<ts>.json in the same dir.
                from pathlib import Path as _Path
                _md = _Path(md_report_path)
                _ts = _md.stem.replace("qwen-parity-eval-", "")
                eval_json_path = str(_md.parent / f"bench-parity-{_ts}.json")
            # Embed into a copy of result so flip_default can record it.
            _flip_input = dict(result)
            if eval_json_path:
                _flip_input["eval_json_path"] = eval_json_path
            try:
                state_path = flip_default(_flip_input)
            except ValueError as e:
                # Should not happen (we just confirmed verdict='pass') but
                # surface it instead of crashing.
                print(f"parity-eval: default-switch declined: {e}",
                      file=sys.stderr)
            else:
                print(
                    f"\nOK: Default model profile flipped to "
                    f"siliconflow-qwen-235b (verdict_overall=pass).",
                    file=sys.stderr,
                )
                print(f"     State file: {state_path}", file=sys.stderr)
                if eval_json_path:
                    print(f"     Eval JSON:  {eval_json_path}",
                          file=sys.stderr)
                if md_report_path:
                    print(f"     Markdown:   {md_report_path}",
                          file=sys.stderr)
                print(
                    "     Override anytime with: "
                    "sentinel scan-autonomous ... --model-profile "
                    "anthropic-baseline",
                    file=sys.stderr,
                )
                print(
                    "     Revert with:           "
                    "sentinel benchmark reset-default",
                    file=sys.stderr,
                )
                # Write a bench_default_profile_flipped audit event into
                # the FIRST suite's audit log (preserves the legal trail).
                # `result['suite']` may be comma-joined for multi-suite
                # runs — take the first one. Falls back to deriving
                # bench/<suite>/scope.yaml if --scope wasn't passed.
                try:
                    from sentinel.core.scope import Scope as _Scope
                    _first_suite = (result.get("suite") or "").split(",")[0].strip()
                    if args.scope:
                        _scope_p = args.scope
                    elif _first_suite:
                        _scope_p = f"bench/{_first_suite}/scope.yaml"
                    else:
                        _scope_p = None
                    if _scope_p and Path(_scope_p).exists():
                        _scope = _Scope.load(_scope_p)
                        if _scope.audit_log:
                            _scope.audit_log.write(
                                "bench_default_profile_flipped",
                                {
                                    "new_default": "siliconflow-qwen-235b",
                                    "previous_default": "anthropic-baseline",
                                    "eval_json_path": eval_json_path,
                                    "verdict_overall": "pass",
                                    "state_file": str(state_path),
                                },
                                mode=_scope.engagement_mode.value,
                            )
                except Exception as _e:  # noqa: BLE001
                    # Audit write is best-effort — flip already persisted.
                    print(
                        f"     WARNING: audit event write failed: {_e}",
                        file=sys.stderr,
                    )
        else:
            verdict = result.get("verdict_overall", "unknown")
            print(
                f"\nDefault model profile NOT flipped (verdict_overall="
                f"{verdict!r}). Default stays anthropic-baseline.",
                file=sys.stderr,
            )
            print(
                "     See the eval Markdown report for the per-phase gap "
                "breakdown.", file=sys.stderr,
            )
        return 0

    if sub == "show-default":
        from sentinel.benchmark.default_switch import read_current_default
        print(read_current_default())
        return 0

    if sub == "reset-default":
        from sentinel.benchmark.default_switch import reset_default
        reset_default()
        print("Default model profile reset to anthropic-baseline.")
        return 0

    print(f"benchmark: unknown subcommand {sub!r}", file=sys.stderr)
    return 2


def _do_scan_dfir(args) -> int:
    """Run the DFIR agent on a pcap, log file, or text blob.

    Auto-routes input to the right pipeline:
      - .pcap / .pcapng → network_analyzer.parse_pcap + detect_anomalies
      - everything else → dfir_agent.parse_log + extract_iocs + build_timeline

    Always writes a deliverable Markdown report under --out-dir.
    """
    from datetime import datetime, timezone

    from sentinel.agent.pentest.dfir_agent import (
        build_timeline, extract_iocs, match_yara, parse_log,
        render_incident_report,
    )
    from sentinel.agent.pentest.network_analyzer import (
        detect_anomalies, parse_pcap, render_network_report,
    )

    try:
        scope = Scope.load(args.scope)
    except ScopeError as e:
        print(f"Scope error: {e}", file=sys.stderr)
        return 2
    if not scope.is_currently_valid():
        print(
            f"Scope is not currently valid ({scope.valid_from}..{scope.valid_until}). Refusing.",
            file=sys.stderr,
        )
        return 2

    input_path = Path(args.input_file).expanduser().resolve()
    if not input_path.exists():
        print(f"input file not found: {input_path}", file=sys.stderr)
        return 2

    workspace = (Path(args.workspace).expanduser().resolve()
                 if args.workspace else input_path.parent)
    # Authorize as a passive artifact (no network call).
    try:
        scope.authorize_artifact("dfir_input", str(input_path))
    except OutOfScopeError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 3

    incident_id = (args.incident_id or
                    f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-"
                    f"{input_path.stem}")
    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)

    suffix = input_path.suffix.lower()
    if suffix in (".pcap", ".pcapng", ".cap"):
        parsed = parse_pcap(str(input_path), workspace=str(workspace))
        anomalies = detect_anomalies(parsed)
        report_md = render_network_report(
            parsed, anomalies, target=str(input_path.name),
        )
        out_path = out_dir / f"{incident_id}-network.md"
        out_path.write_text(report_md)
        print(f"DFIR network report written: {out_path}")
        print(f"  backend: {parsed.get('backend')}")
        print(f"  anomalies: {anomalies.get('summary')}")
        return 0

    # Log / text path
    parsed_logs = parse_log(str(input_path), format=args.log_format,
                              workspace=str(workspace))
    if parsed_logs.get("error"):
        print(f"log parse failed: {parsed_logs['error']}", file=sys.stderr)
        return 2
    raw_text = input_path.read_text(errors="replace")
    iocs = extract_iocs(raw_text)
    timeline = build_timeline(parsed_logs.get("events") or [])

    yara_matches = None
    if args.yara_rules_file:
        yp = Path(args.yara_rules_file).expanduser()
        if yp.is_file():
            yara_matches = match_yara(
                str(input_path), yp.read_text(),
                workspace=str(workspace),
            )

    report_md = render_incident_report(
        incident_id=incident_id,
        target=str(input_path.name),
        parsed_logs=parsed_logs, iocs=iocs, timeline=timeline,
        yara_matches=yara_matches,
        suspected_attack=args.suspected_attack,
    )
    out_path = out_dir / f"{incident_id}.md"
    out_path.write_text(report_md)
    print(f"DFIR incident report written: {out_path}")
    print(f"  log format    : {parsed_logs.get('format')}")
    print(f"  events parsed : {parsed_logs.get('event_count')}")
    print(f"  IOCs found    : {sum(len(v) for v in iocs.values())}")
    if yara_matches:
        print(f"  YARA matches  : {yara_matches.get('match_count', 0)}")
    return 0


def _do_chrome(args) -> int:
    """Real-Chrome-via-CDP profile management (DataDome bypass).

    Subcommands: bootstrap | status | attach | clean.
    All require --scope; resolves CDP port + profile dir from scope fields,
    falling back to ~/.sentinel/chrome-profiles/<engagement_id> + 9222.
    """
    import asyncio as _asyncio
    from sentinel.agent import chrome_profile as _cp

    try:
        scope = Scope.load(args.scope)
    except ScopeError as e:
        print(f"Scope error: {e}", file=sys.stderr)
        return 2

    eng_id = scope.engagement_id
    cdp_port = int(getattr(args, "port", None) or _cp.resolve_cdp_port(scope))

    sub = getattr(args, "chrome_cmd", None)

    if sub == "bootstrap":
        profile_dir_arg = getattr(args, "profile_dir", None)
        if profile_dir_arg:
            profile_dir = Path(profile_dir_arg).expanduser().resolve()
        else:
            profile_dir = _cp.resolve_profile_dir(scope)
        try:
            scope.audit_log.write(
                "chrome_bootstrap_started",
                {
                    "engagement_id": eng_id,
                    "profile_dir": str(profile_dir),
                    "cdp_port": cdp_port,
                },
                mode=scope.engagement_mode.value,
            )
        except Exception:
            pass
        try:
            result = _cp.bootstrap_profile(
                profile_dir=profile_dir,
                cdp_port=cdp_port,
                chrome_binary=getattr(args, "chrome_binary", None),
            )
        except _cp.ChromeBinaryNotFound as e:
            print(f"chrome bootstrap: {e}", file=sys.stderr)
            return 3
        except RuntimeError as e:
            print(f"chrome bootstrap: {e}", file=sys.stderr)
            return 4
        try:
            scope.audit_log.write(
                "chrome_attached",
                {
                    "engagement_id": eng_id,
                    "pid": result.pid,
                    "cdp_url": result.cdp_url,
                    "profile_dir": str(result.profile_dir),
                    "chrome_binary": result.chrome_binary,
                },
                mode=scope.engagement_mode.value,
            )
        except Exception:
            pass
        print(f"Chrome launched (PID {result.pid})")
        print(f"  CDP URL      : {result.cdp_url}")
        print(f"  Profile dir  : {result.profile_dir}")
        print(f"  Binary       : {result.chrome_binary}")
        print()
        print("Next steps:")
        print("  1. In the opened Chrome window, navigate to your target.")
        print("  2. Solve any DataDome / Cloudflare / Akamai challenge manually.")
        print("  3. Sign in to the application (cookies persist on disk).")
        print("  4. Close the window when done — profile is retained.")
        print(f"  5. Run: sentinel chrome status --scope {args.scope}")
        print()
        print(f"To use in scans, set in {args.scope}:")
        print(f"  browser_strategy: cdp")
        print(f"  chrome_cdp_port: {cdp_port}")
        if profile_dir_arg or scope.chrome_profile_dir:
            print(f"  chrome_profile_dir: {result.profile_dir}")
        return 0

    if sub == "status":
        info = _cp.attach_status(cdp_port)
        if info is None:
            print(f"No Chrome listening on CDP port {cdp_port}.")
            print(f"Run: sentinel chrome bootstrap --scope {args.scope}")
            return 1
        print(f"Chrome attached on CDP port {cdp_port}")
        print(f"  Browser : {info.get('Browser', '?')}")
        print(f"  WS URL  : {info.get('webSocketDebuggerUrl', '?')[:80]}…")
        # Probe for session warmth.
        probe_url = getattr(args, "probe_url", None)
        if not probe_url:
            doms = list(scope.domains or [])
            doms = [d for d in doms if "*" not in d]  # skip wildcard patterns
            if doms:
                probe_url = f"https://{doms[0]}/"
        if probe_url:
            try:
                scope.scope_authorize_or_skip = True
            except Exception:
                pass
            screenshot_arg = getattr(args, "screenshot", None)
            sshot_path = Path(screenshot_arg) if screenshot_arg else None
            print(f"  Probing : {probe_url}")
            verdict = _asyncio.run(_cp.verify_session(
                cdp_port=cdp_port,
                probe_url=probe_url,
                screenshot_path=sshot_path,
            ))
            try:
                scope.audit_log.write(
                    "chrome_session_verified" if verdict.get("ok") else "chrome_attach_failed",
                    {
                        "engagement_id": eng_id,
                        "probe_url": probe_url,
                        "status": verdict.get("status", 0),
                        "final_url": verdict.get("final_url", ""),
                        "looks_authenticated": verdict.get("looks_authenticated", False),
                        "error": verdict.get("error"),
                    },
                    mode=scope.engagement_mode.value,
                )
            except Exception:
                pass
            if not verdict.get("ok"):
                print(f"  ERROR   : {verdict.get('error')}")
                return 5
            print(f"  Status  : HTTP {verdict.get('status')}")
            print(f"  Final   : {verdict.get('final_url')}")
            print(f"  Title   : {verdict.get('title', '')[:80]!r}")
            print(f"  Auth?   : {'YES' if verdict.get('looks_authenticated') else 'NO (redirected to login or non-200)'}")
            if verdict.get("screenshot"):
                print(f"  Shot    : {verdict['screenshot']}")
        else:
            print("  (No probe URL — set scope.targets.domains[0] or pass --probe-url)")
        return 0

    if sub == "attach":
        info = _cp.attach_status(cdp_port)
        if info is None:
            print(f"No Chrome on CDP port {cdp_port}.", file=sys.stderr)
            return 1
        print(f"http://localhost:{cdp_port}")
        print(f"  Browser : {info.get('Browser', '?')}")
        return 0

    if sub == "clean":
        ok = _cp.shutdown_chrome(cdp_port=cdp_port, timeout_sec=8.0)
        if not ok:
            print(f"No Chrome running on port {cdp_port} (or it didn't shut down cleanly).")
        else:
            print(f"Chrome on port {cdp_port} shut down.")
        if getattr(args, "purge", False):
            profile_dir = _cp.resolve_profile_dir(scope)
            if profile_dir.exists():
                import shutil as _sh
                _sh.rmtree(profile_dir)
                print(f"Profile dir purged: {profile_dir}")
        return 0

    if sub in ("export-cookies", "refresh"):
        if _cp.attach_status(cdp_port) is None:
            print(f"No Chrome on CDP port {cdp_port}. Run `sentinel chrome bootstrap` first.",
                  file=sys.stderr)
            return 1
        cookies = _cp.snapshot_cookies(cdp_port)
        if not cookies:
            print(f"Snapshot returned 0 cookies (Chrome reachable but no profile contexts?).",
                  file=sys.stderr)
            return 5
        domain_filters = getattr(args, "domain_filter", None) or []
        if domain_filters:
            cookies = [
                c for c in cookies
                if any(f.lower() in (c.get("domain", "") or "").lower()
                       for f in domain_filters)
            ]
        print(f"# Snapshotted {len(cookies)} cookies from Chrome on port {cdp_port}",
              file=sys.stderr)
        if sub == "export-cookies":
            import yaml as _yaml
            yaml_block = _yaml.safe_dump(
                {"auth_cookies": cookies},
                default_flow_style=False, sort_keys=False, width=200,
            )
            print(yaml_block)
            return 0
        # refresh path — patch scope.yaml in place
        import yaml as _yaml
        backup = Path(args.scope + ".bak")
        scope_path = Path(args.scope)
        backup.write_bytes(scope_path.read_bytes())
        sd = _yaml.safe_load(scope_path.read_bytes()) or {}
        sd["auth_cookies"] = cookies
        scope_path.write_text(_yaml.safe_dump(sd, default_flow_style=False, sort_keys=False, width=200))
        print(f"Patched {scope_path} (backup: {backup}). auth_cookies now has {len(cookies)} entries.")
        try:
            scope.audit_log.write(
                "chrome_cookies_refreshed",
                {"engagement_id": eng_id, "count": len(cookies),
                 "scope_path": str(scope_path), "backup_path": str(backup)},
                mode=scope.engagement_mode.value,
            )
        except Exception:
            pass
        return 0

    print(f"Unknown chrome subcommand: {sub!r}", file=sys.stderr)
    return 2


def _do_new_engagement(args) -> int:
    """Scaffold a new engagement (scope.yaml + workspace dir) via the wizard."""
    from sentinel.engagements import (
        EngagementSpec, create_engagement, template_for,
    )

    interactive = not args.non_interactive

    def _prompt(label: str, default: str = "") -> str:
        if not interactive:
            return default
        suffix = f" [{default}]" if default else ""
        try:
            ans = input(f"{label}{suffix}: ").strip()
        except EOFError:
            return default
        return ans or default

    client = (args.client or "").strip() or _prompt("Client / program slug")
    if not client:
        print("client is required", file=sys.stderr)
        return 2
    eng_id = (args.engagement_id or "").strip() or _prompt(
        "Engagement ID",
        default=date.today().strftime("%Y-%m-%d-") + _slug_default(client),
    )
    if not eng_id:
        print("engagement_id is required", file=sys.stderr)
        return 2
    authorized_by = (args.authorized_by or "").strip() or _prompt(
        "Authorized-by email"
    )
    if not authorized_by:
        print("authorized_by is required", file=sys.stderr)
        return 2

    research_handle = (args.research_handle or "").strip()
    tpl = template_for(args.template)
    if interactive and tpl.research_header_name and not research_handle:
        research_handle = _prompt(
            f"Researcher handle for {tpl.display} (used in {tpl.research_header_name})",
        )

    domains = list(args.domains or [])
    repos = list(args.repos or [])
    ips = list(args.ips or [])
    if interactive and not (domains or repos or ips):
        line = _prompt(
            "Domain targets (space-separated; leave blank to skip)"
        )
        if line:
            domains = line.split()
    if not (domains or repos or ips):
        print("at least one target (--domains / --repos / --ips) is required",
              file=sys.stderr)
        return 2

    spec = EngagementSpec(
        template=args.template,
        client=client,
        engagement_id=eng_id,
        authorized_by=authorized_by,
        authorization_doc=args.authorization_doc,
        valid_from=args.valid_from,
        valid_until=args.valid_until,
        repos=tuple(repos),
        domains=tuple(domains),
        ips=tuple(ips),
        out_of_scope=tuple(args.out_of_scope or []),
        research_handle=research_handle,
        rate_limit_rps_override=args.rate_limit_rps,
    )
    try:
        result = create_engagement(
            spec,
            scopes_dir=args.scopes_dir,
            workspaces_root=args.workspaces_root,
            overwrite=args.overwrite,
        )
    except (FileExistsError, ValueError) as exc:
        print(f"new-engagement failed: {exc}", file=sys.stderr)
        return 2

    print(f"Created scope:    {result.scope_path}")
    print(f"Workspace dir:    {result.workspace_dir}")
    print(f"YAML SHA-256:     {result.sha256}")
    print(f"Template:         {tpl.display}")
    if tpl.notes:
        print()
        print(tpl.notes)
    return 0


def _slug_default(client: str) -> str:
    import re as _re
    s = (client or "").lower().strip()
    s = _re.sub(r"[^\w\s-]", "", s)
    s = _re.sub(r"[-\s]+", "-", s)
    return (s.strip("-") or "engagement") + "-bbp"


def _do_state(args) -> int:
    """Synthesize CURRENT_STATE.md (or print the existing one with --show)."""
    from sentinel.state import build_snapshot, render_markdown, update_current_state

    project_dir = Path(args.project_dir).expanduser().resolve()
    target = project_dir / "CURRENT_STATE.md"

    if args.show and not args.update:
        if not target.is_file():
            print(f"No {target} yet. Run `sentinel state --update` first.",
                  file=sys.stderr)
            return 1
        print(target.read_text())
        return 0

    # STATE-03: optional --pacing-hours overrides notify.yaml / default 4.
    # Only forward when explicitly set; None lets build_snapshot fall through
    # to `_load_pacing_hours_from_yaml()` / `DEFAULT_H1_PACING_HOURS`.
    kwargs: dict = {
        "workspaces_root": args.workspaces_root,
        "runs_dir": args.runs_dir,
        "memory_dir": args.memory_dir,
    }
    pacing_hours = getattr(args, "pacing_hours", None)
    if pacing_hours is not None:
        kwargs["pacing_hours"] = pacing_hours

    out = update_current_state(project_dir, **kwargs)
    print(f"Wrote {out}")
    return 0


def _do_h1(args) -> int:
    """Dispatch the `h1` subcommand group (Plan 02-01 ENG-01..ENG-06).

    Three sub-subcommands:
      record-submission — append JSONL row + write hash-chained audit event
      dup-check         — semantic search against the local Chroma corpus
      prepare           — bundle evidence + emit scope-gated curls.sh
    """
    # Late-imported so `sentinel --help` doesn't pay the h1 / corpus
    # import cost (chromadb is heavy).
    from sentinel.h1 import record_submission as _record_submission
    from sentinel.h1 import dup_check as _dup_check
    from sentinel import h1 as _h1_pkg

    if args.h1_cmd == "record-submission":
        ledger_path = Path.home() / ".sentinel" / "h1-submissions.jsonl"
        # CLAUDE.md convention: audit log lives next to the scope file
        # (cwd-relative for the engagement). Operator runs sentinel from
        # the project root, so `.audit-<id>.jsonl` in cwd is canonical.
        audit_log_path = Path.cwd() / f".audit-{args.engagement_id}.jsonl"
        try:
            row = _record_submission(
                args.engagement_id,
                args.file,
                args.submitted_at,
                ledger_path=ledger_path,
                audit_log_path=audit_log_path,
                title=args.title,
                weakness=args.weakness,
                severity=args.severity,
                h1_url=args.h1_url,
                h1_report_id=args.h1_report_id,
                operator=args.operator,
            )
        except ValueError as e:
            print(f"record-submission failed: {e}", file=sys.stderr)
            return 2
        print(
            f"recorded: {row['engagement_id']}/{row['file']} "
            f"at {row['submitted_at']}"
        )
        return 0

    if args.h1_cmd == "dup-check":
        report_path = Path(args.report_path)
        if not report_path.is_file():
            print(f"dup-check failed: report not found: {report_path}",
                  file=sys.stderr)
            return 2
        rows = _dup_check(
            report_path,
            corpus_dir=args.corpus_dir,
            top_k=args.top_k,
            source_filter=args.source_filter,
        )
        if not rows:
            print("dup-check: corpus unavailable OR no results "
                  "(install with `pip install -e '.[corpus]'` and ingest writeups)")
            return 0
        # Markdown table, sorted ascending by distance.
        print("| Distance | Risk | Source | Title | URL |")
        print("|---:|:-:|---|---|---|")
        for r in rows:
            risk = "HIGH" if r["high_duplicate_risk"] else "low"
            title = (r["title"][:60] + "...") if len(r["title"]) > 60 else r["title"]
            url = r["url"] or "—"
            print(
                f"| {r['distance']:.3f} | {risk} | "
                f"{r['source']} | {title} | {url} |"
            )
        return 0

    if args.h1_cmd == "prepare":
        report_path = Path(args.report_path)
        if not report_path.is_file():
            print(f"prepare failed: report not found: {report_path}",
                  file=sys.stderr)
            return 2

        # Resolve a Scope from --scope, or auto-discover from
        # <cwd>/engagements/<engagement_id>.yaml (engagement_id read
        # from the report's parent workspace directory name).
        scope = None
        scope_path = args.scope
        if scope_path is None:
            # Walk up: workspaces/<engagement_id>/deliverables/h1-submissions/file.md
            for ancestor in report_path.resolve().parents:
                candidate = (
                    Path.cwd() / "engagements" / f"{ancestor.name}.yaml"
                )
                if candidate.is_file():
                    scope_path = str(candidate)
                    break
        if scope_path:
            try:
                scope = Scope.load(scope_path)
            except ScopeError as e:
                print(
                    f"WARNING: could not load scope {scope_path}: {e} — "
                    f"curls.sh will NOT be scope-gated; operator MUST "
                    f"eyeball every URL before running",
                    file=sys.stderr,
                )
                scope = None
        else:
            print(
                "WARNING: no scope yaml resolved — curls.sh will NOT be "
                "programmatically scope-gated; operator MUST eyeball every "
                "URL before running",
                file=sys.stderr,
            )

        # Access via the package re-export so tests can monkeypatch
        # `sentinel.h1.prepare` and the same function is invoked here.
        curls_path, tarball_path = _h1_pkg.prepare(
            report_path,
            scope=scope,
            output_dir=args.output_dir,
        )
        print(f"curls.sh: {curls_path}")
        if tarball_path:
            print(f"evidence: {tarball_path}")
        else:
            print("evidence: (no sibling evidence/ dir)")
        # Count dropped lines so the operator sees the scope-gate result.
        try:
            n_dropped = sum(
                1 for ln in curls_path.read_text().splitlines()
                if ln.lstrip().startswith("# OUT-OF-SCOPE:")
            )
        except OSError:
            n_dropped = 0
        if n_dropped:
            print(f"scope-gate: dropped {n_dropped} out-of-scope curl line(s)")
        return 0

    print(f"unknown h1 subcommand: {args.h1_cmd}", file=sys.stderr)
    return 2


def _do_info(args) -> int:
    """Print Sentinel version + tool inventory (which scanners are on PATH)."""
    from sentinel.core.tool_inventory import check_all_grouped
    try:
        from sentinel import __version__
    except Exception:
        __version__ = "unknown"
    print(f"Sentinel {__version__}")
    print(f"  Python: {sys.version.split()[0]}")
    print()
    print("Tool inventory (✓ = on PATH, ✗ = missing):")
    grouped = check_all_grouped()
    for tier in ("passive", "active", "network", "ai"):
        rows = grouped.get(tier, [])
        if not rows:
            continue
        print(f"\n  [{tier}]")
        for r in rows:
            marker = "✓" if r["ok"] else "✗"
            label = f"{r['name']:<14} {r['label']}"
            print(f"  {marker} {label}")
    # Ollama check.
    try:
        from sentinel.agent.ollama_provider import OllamaClient
        client = OllamaClient(host="http://localhost:11434")
        import asyncio
        models = asyncio.run(client.list_models())
        print(f"\nOllama models ({len(models)}):")
        for m in models:
            print(f"  • {m}")
    except Exception as e:
        print(f"\nOllama: not reachable ({e})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
