#!/usr/bin/env bash
# Sentinel bootstrap — one-shot setup on a fresh Mac.
#
# What this does:
#   1. Creates a Python venv in ./.venv
#   2. Installs sentinel + corpus + books extras
#   3. Verifies Ollama is running and pulls the models we need
#   4. (optional) Runs the corpus ingest for all public sources
#
# Usage:
#   chmod +x bootstrap.sh
#   ./bootstrap.sh                           # install only, no ingest
#   ./bootstrap.sh --ingest                  # install + ingest public corpus
#   ./bootstrap.sh --ingest --books-dir ~/Books/Security   # also ingest your books
#
# Idempotent — safe to re-run.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORPUS_DIR="${CORPUS_DIR:-$HOME/sentinel-corpus}"
VAULT_DIR="${VAULT_DIR:-$HOME/Obsidian/security-vault}"
DO_INGEST=false
BOOKS_DIR=""
NVD_SINCE_YEAR="${NVD_SINCE_YEAR:-2022}"

# ---- arg parsing ---------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ingest) DO_INGEST=true; shift ;;
    --books-dir) BOOKS_DIR="$2"; shift 2 ;;
    --corpus-dir) CORPUS_DIR="$2"; shift 2 ;;
    --vault) VAULT_DIR="$2"; shift 2 ;;
    --nvd-since-year) NVD_SINCE_YEAR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

log() { printf "\033[1;36m[bootstrap]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[warn]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[err]\033[0m %s\n" "$*" >&2; }

cd "$PROJECT_DIR"

# ---- 1. python -----------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  err "python3 not found. Install Python 3.10+ first (brew install python@3.11)."
  exit 1
fi

PY_VER=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
log "Python ${PY_VER} detected"
if [[ "$(printf '%s\n' "3.10" "$PY_VER" | sort -V | head -n1)" != "3.10" ]]; then
  err "Python 3.10+ required, found ${PY_VER}"
  exit 1
fi

# ---- 2. venv -------------------------------------------------------------
if [[ ! -d .venv ]]; then
  log "creating venv at .venv"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
log "venv activated: $(which python)"

# ---- 3. pip install ------------------------------------------------------
log "upgrading pip / wheel"
python -m pip install --upgrade pip wheel >/dev/null

log "installing sentinel + all extras (corpus + books + web)"
pip install -e ".[all]"

# ---- 4. ollama check + pulls --------------------------------------------
if ! command -v ollama >/dev/null 2>&1; then
  warn "ollama not found on PATH. Install from https://ollama.ai then re-run."
  warn "Skipping model pulls."
else
  if ! curl -sf http://localhost:11434/api/tags >/dev/null; then
    warn "Ollama not responding on localhost:11434. Start it (open Ollama.app) then re-run for model pulls."
  else
    log "ollama running; pulling models (skipped if already present)"
    ollama pull llama3.1:8b
    ollama pull nomic-embed-text
  fi
fi

# ---- 5. CLI smoke check --------------------------------------------------
log "verifying sentinel CLI"
sentinel --help >/dev/null
log "sentinel CLI OK"

# ---- 6. optional corpus ingest ------------------------------------------
if [[ "$DO_INGEST" == "true" ]]; then
  mkdir -p "$VAULT_DIR" "$CORPUS_DIR"
  log "ingesting public corpus into ${CORPUS_DIR}"
  log "  vault: ${VAULT_DIR}"
  log "  NVD since year: ${NVD_SINCE_YEAR}"

  for src in owasp mitre-cwe mitre-attack nist writeups; do
    log "--- ingesting ${src} ---"
    sentinel ingest --source "$src" \
      --corpus-dir "$CORPUS_DIR" \
      --vault "$VAULT_DIR" || warn "ingest ${src} reported errors; continuing"
  done

  log "--- ingesting NVD (since ${NVD_SINCE_YEAR}) ---"
  sentinel ingest --source nvd \
    --corpus-dir "$CORPUS_DIR" \
    --vault "$VAULT_DIR" \
    --nvd-since-year "$NVD_SINCE_YEAR" || warn "NVD ingest reported errors"

  if [[ -n "$BOOKS_DIR" ]]; then
    if [[ -d "$BOOKS_DIR" ]]; then
      log "--- ingesting books from ${BOOKS_DIR} ---"
      sentinel ingest --source books \
        --books-dir "$BOOKS_DIR" \
        --corpus-dir "$CORPUS_DIR" \
        --vault "$VAULT_DIR" || warn "books ingest reported errors"
    else
      warn "books dir does not exist: ${BOOKS_DIR}"
    fi
  fi

  log "ingest complete. Stats:"
  sentinel corpus-stats --corpus-dir "$CORPUS_DIR" || true
fi

cat <<EOF

==================================================================
Sentinel is ready.

Activate the venv in any new terminal with:
    source $(pwd)/.venv/bin/activate

Useful next steps:
    sentinel --help
    sentinel ask "How do I prevent SSRF in a Node.js API?" \\
        --corpus-dir ${CORPUS_DIR}

For a scan, copy scope.example.yaml to a real engagement file first.
==================================================================
EOF
