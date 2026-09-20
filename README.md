# Sentinel

**An autonomous, scope-gated penetration-testing platform.** Sentinel runs a full application-security engagement end to end — recon → vulnerability discovery → exploitation → cross-finding correlation → reporting — by pairing deterministic open-source scanners with multi-agent LLM reasoning, all behind a strict authorization and audit boundary.

> ⚠️ **Authorized use only.** Sentinel performs active security testing. Every operation is gated by a scope file you control, and it must only be pointed at assets you are explicitly authorized to test. See [Safety model](#safety-model).

> 📦 **Note:** engagement data, corpora, model weights, and credentials are not part of this repository (see [What's excluded](#whats-excluded)). The scanners, agent pipeline, RAG plumbing, reporting, and dashboard are all here.

---

## What it is

Sentinel wraps a stack of industry OSS scanners and drives them with an agentic pipeline. Raw scanner output is deduplicated, triaged, and enriched by a local LLM grounded in a security knowledge corpus (RAG), then a reasoning model composes findings into exploit chains and drafts client-ready deliverables. A custom **model router** assigns each phase to the most appropriate model — balancing reasoning quality against token cost and latency — and runs mechanical work on local models while reserving frontier models for multi-step exploit reasoning.

The design goal: the throughput of automation with the auditability a real engagement demands.

## Key features

- **End-to-end autonomous pipeline** — recon, per-class vulnerability discovery, exploitation, correlation/chaining, and reporting, each as a coordinated agent phase.
- **Deterministic + probabilistic fusion** — 10+ OSS analyzers (Semgrep, Trivy, OSV-Scanner, Checkov, Gitleaks, nuclei, OWASP ZAP, and pure-Python TLS/headers/DNS modules) feed an LLM triage layer that cuts false positives and prioritizes genuinely exploitable issues.
- **RAG-grounded triage** — findings are enriched against a local vector corpus of security reference material (OWASP, MITRE CWE/ATT&CK, curated write-ups) so remediation advice is grounded, not hallucinated.
- **Multi-provider model router** — per-phase routing across cloud reasoning models and local models (via Ollama), with explicit cost/latency awareness.
- **Scope-gating + hash-chained audit log** — every active operation is authorized against a scope file and recorded in an append-only, tamper-evident log (see below).
- **Deliverable generation** — PDF reports, CWE→PCI/SOC 2/NIST CSF compliance mappings, and HackerOne-format report drafts, served through a FastAPI/HTMX dashboard.

## Architecture

```
                    ┌──────────────────────────────────────────────┐
   scope.yaml ─────▶│  Scope gate  +  append-only hash-chained log  │
                    └──────────────────────────────────────────────┘
                                        │ (every active op authorized + logged)
                                        ▼
   targets ──▶ recon ──▶ vuln discovery ──▶ exploitation ──▶ correlation ──▶ reporting
                 │           (per class)        │                │              │
                 └──────────── model router (cloud reasoning / local models) ───┘
                                        │
             OSS scanners ──▶ dedup + LLM triage (RAG-grounded) ──▶ findings store
                                        │
                                FastAPI / HTMX dashboard
```

## Repository layout

```
sentinel/
├── core/          # scope authorization, audit log, findings model, severity normalization
├── scanners/      # wrappers for Semgrep, Trivy, OSV, Checkov, Gitleaks, nuclei, ZAP, TLS/headers/DNS
├── agent/         # the agentic pipeline
│   ├── pentest/   # recon → vuln → exploit → correlation phases, verifiers, payloads
│   ├── brain/     # background research loop that grows the RAG corpus
│   └── novelty/   # duplicate/novelty checking
├── corpus/        # RAG ingestion pipeline + sources
├── rag/           # retrieval + grounded Q&A
├── llm/           # local model client (Ollama)
├── reporting/     # PDF, compliance overlay, HackerOne report drafts
├── h1/            # HackerOne report formatting + duplicate checking
├── engagements/   # engagement setup wizard + state
├── benchmark/     # evaluation harness against public testbeds
└── web/           # FastAPI/HTMX dashboard (routes, templates, static)
tests/             # unit + integration tests
scripts/           # helper scripts
skills/            # agent operating guidelines
```

## Safety model

Two boundaries are treated as non-negotiable and are the reason the platform is safe to run:

1. **Scope-gating.** Every network or file operation passes through `Scope.authorize_url()` / `authorize_repo()` / `authorize_artifact()`. Out-of-scope targets raise `OutOfScopeError` and the refusal is logged. Adding a target means editing the scope YAML — there is no bypass flag.
2. **Audit-log integrity.** Every authorization decision (approve *and* deny) is written to an append-only, hash-chained JSONL log (`this_hash = sha256(prev_hash ‖ ts ‖ event ‖ payload)`). `verify-audit` re-walks the chain. There is no purge or edit path.

See [`scope.example.yaml`](scope.example.yaml) for the scope-file format.

## Quick start

```bash
# 1. Install external scanners (idempotent; --check previews without installing)
./install-tools.sh

# 2. Install the Python package
pip install -e ".[all,dev]"

# 3. (Optional) local LLM triage + embeddings
ollama pull llama3.1:8b
ollama pull nomic-embed-text

# 4. Configure credentials (never commit real values)
cp .env.example .env    # then fill in

# 5. Create a scope file for an authorized target
cp scope.example.yaml scope.yaml   # edit targets + authorization

# 6. Run a scan (all commands require --scope)
sentinel scan-repo  ./path/to/repo --scope scope.yaml
sentinel scan-web   https://example.com --scope scope.yaml
sentinel verify-audit .audit-<engagement>.jsonl

# 7. Launch the dashboard
sentinel web        # http://localhost:8080
```

## What's excluded

To keep this repository safe to publish and reasonably sized, the following are **not** included and are ignored by [`.gitignore`](.gitignore):

- **Engagement data** — `engagements/`, `runs/`, `reports/`, `deliverables/`, `workspaces/`, and all `.audit-*.jsonl` logs (client-confidential).
- **RAG corpus & knowledge vault** — reference notes and any ingested books/papers (bring your own; ingest with the corpus pipeline).
- **Fine-tuned model weights** and training data.
- **Credentials** — all secrets are read from environment variables (see `.env.example`); none are committed.
- **One-off operational scripts** tied to specific engagements.

The scanners, agent pipeline, RAG plumbing, reporting, and dashboard are all present, so the architecture is fully legible from the code.

## Disclaimer

Sentinel is a security research tool. Use it only against systems you own or are explicitly authorized to test. The author accepts no liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
