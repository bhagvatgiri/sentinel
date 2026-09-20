#!/usr/bin/env bash
# Install every external tool Sentinel can wrap.
#
# Idempotent: re-running skips already-installed packages.
# Safe to run before the project venv exists; only handles binaries.
#
# Usage:
#   ./install-tools.sh              # install everything
#   ./install-tools.sh --skip-shannon  # everything except the Shannon npm package
#   ./install-tools.sh --check      # just print what's installed/missing, don't install
#
# After this, run:
#   pip install -e ".[all,dev]"   # Python deps + project venv editable install
#
# Tools installed (and what each enables):
#   brew:
#     gitleaks      → secret scanning in scan-repo
#     osv-scanner   → dependency CVE scan (scan-deps, scan-repo)
#     trivy         → container/IaC CVE scan (scan-config)
#     nuclei        → live URL scan (scan-live)
#     syft          → SBOM generation (sbom)
#     zaproxy       → OWASP ZAP active scan (scan-active, scan-full)
#     nmap          → service + NSE vuln scan (scan-recon, scan-full)
#     ffuf          → directory + parameter fuzzing (scan-recon, scan-full)
#     seclists      → wordlists for ffuf
#     subfinder     → passive subdomain enum (scan-recon)
#     amass         → deeper passive subdomain enum (scan-recon --deep)
#     whatweb      → web tech fingerprint (scan-web)
#     testssl       → deep TLS analysis (scan-web)
#     kiterunner    → API endpoint discovery (scan-recon)
#     ollama        → local LLM for triage + RAG embeddings
#     pipx          → bridge for Python CLI tools that need their own envs
#   pipx:
#     semgrep       → SAST (scan-repo)
#     checkov       → IaC scan (scan-config)
#     wapiti3       → active web fuzzer (scan-active, scan-full)
#   npm:
#     @keygraph/shannon → autonomous AI pentester (scan-active, scan-full)
#
# Wordlists / setup:
#   - SecLists installed via brew (used by ffuf, kiterunner)
#   - Kiterunner .kite wordlist needs separate download — see end of script

# Note: NOT set -e. We want to continue even if a single install/check fails,
# so the user sees the full picture instead of stopping at the first error.
set -u

SKIP_SHANNON=0
CHECK_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --skip-shannon) SKIP_SHANNON=1 ;;
    --check) CHECK_ONLY=1 ;;
    --help|-h)
      sed -n '2,/^$/p' "$0" | sed 's/^# //'
      exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
heading() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

check_or_install() {
  local kind="$1" name="$2" install_cmd="$3" check_cmd="${4:-$2}"
  if have "$check_cmd"; then
    green "  [OK] $name (already installed: $(command -v $check_cmd))"
    return 0
  fi
  if [ "$CHECK_ONLY" -eq 1 ]; then
    yellow "  [X] $name (missing — would install via: $install_cmd)"
    return 1
  fi
  yellow "  installing $name..."
  if eval "$install_cmd"; then
    green "  [OK] $name installed"
  else
    red "  [X] $name install failed"
    return 1
  fi
}

heading "Sentinel external tool installer"
[ "$CHECK_ONLY" -eq 1 ] && yellow "(check-only mode — nothing will be installed)"

# ---- Prereq: Homebrew ----
heading "Checking Homebrew"
if ! have brew; then
  red "Homebrew not installed. Install from https://brew.sh first, then re-run."
  exit 1
fi
green "  [OK] brew $(brew --version | head -1 | awk '{print $2}')"

# ---- pipx (needed for Python CLI tools that conflict with venv deps) ----
heading "Bootstrap pipx"
check_or_install brew pipx "brew install pipx" pipx

# ---- Node + npm (for Shannon) ----
if [ "$SKIP_SHANNON" -eq 0 ]; then
  heading "Checking Node.js (for Shannon)"
  check_or_install brew node "brew install node" node
fi

# ---- Ollama (local LLM) ----
heading "Local LLM stack"
check_or_install brew ollama "brew install ollama --cask 2>/dev/null || brew install ollama" ollama

# ---- Brew-installed scanner binaries ----
heading "Phase 1 scanners (existing)"
check_or_install brew gitleaks      "brew install gitleaks"      gitleaks
check_or_install brew osv-scanner   "brew install osv-scanner"   osv-scanner
check_or_install brew trivy         "brew install trivy"         trivy
check_or_install brew nuclei        "brew install nuclei"        nuclei
check_or_install brew syft          "brew install syft"          syft

heading "Phase 2 scanners (active web + recon)"
# OWASP ZAP ships as a cask (GUI app). The binary CLI is at
# /Applications/ZAP.app/Contents/Java/zap.sh after install.
if have zap.sh || [ -f /Applications/ZAP.app/Contents/Java/zap.sh ]; then
  green "  [OK] zap (already installed)"
  ZAP_BIN=$(command -v zap.sh || echo "/Applications/ZAP.app/Contents/Java/zap.sh")
  green "    binary: $ZAP_BIN"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing OWASP ZAP cask..."
  brew install --cask zap 2>&1 | tail -3 || red "  [X] zap install failed"
else
  yellow "  [X] zap missing — would install via: brew install --cask zap"
fi
check_or_install brew nmap "brew install nmap" nmap
check_or_install brew ffuf "brew install ffuf" ffuf
# SecLists: not in homebrew-core; in the daniellocator/danielmiessler tap.
if [ -d /opt/homebrew/share/seclists ] || [ -d /usr/local/share/seclists ] || [ -d /opt/homebrew/share/SecLists ]; then
  green "  [OK] seclists wordlists present"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing SecLists from danielmiessler tap..."
  brew tap danielmiessler/seclists 2>/dev/null || true
  brew install seclists 2>&1 | tail -3 || \
    (yellow "    tap install failed — falling back to git clone into ~/SecLists"; \
     git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$HOME/SecLists" 2>&1 | tail -3 && \
     green "  [OK] SecLists cloned to ~/SecLists (set FFUF_WORDLIST=~/SecLists/Discovery/Web-Content/common.txt)")
else
  yellow "  [X] seclists missing — would tap danielmiessler/seclists or git clone"
fi

heading "Phase 3 scanners (recon + tech fingerprint)"
check_or_install brew subfinder "brew install subfinder" subfinder
check_or_install brew amass     "brew install amass"     amass
# whatweb is a Ruby tool; not in homebrew-core. Install via gem.
if have whatweb; then
  green "  [OK] whatweb (already installed)"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing whatweb via gem (ruby)..."
  if have gem; then
    gem install --user-install whatweb 2>&1 | tail -3 || red "  [X] whatweb gem install failed"
    yellow "    NOTE: ensure ~/.gem/ruby/<version>/bin is on PATH"
  else
    red "  [X] ruby gem not available — install ruby first"
  fi
else
  yellow "  [X] whatweb missing — would install via: gem install --user-install whatweb"
fi
# brew installs testssl as `testssl.sh` (not `testssl`); check both names
if have testssl || have testssl.sh; then
  green "  [OK] testssl"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing testssl..."
  brew install testssl 2>&1 | tail -3 && green "  [OK] testssl installed"
else
  yellow "  [X] testssl missing — would install via: brew install testssl"
fi
# kiterunner: not in core, build from source if go is available.
if have kr || have kiterunner; then
  green "  [OK] kiterunner (already installed)"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing kiterunner (build from source via go)..."
  if have go; then
    go install github.com/assetnote/kiterunner/cmd/kr@latest 2>&1 | tail -3 \
      && green "    kiterunner built — ensure ~/go/bin on PATH" \
      || red "    [X] go install failed"
  else
    yellow "    [X] go not installed (brew install go); skipping kiterunner build"
    yellow "    or download a binary from https://github.com/assetnote/kiterunner/releases"
  fi
else
  yellow "  [X] kiterunner missing — would build via go install"
fi

# ---- pipx-installed scanners ----
heading "pipx-installed Python tools (isolated envs)"
check_or_install pipx semgrep "pipx install semgrep" semgrep
check_or_install pipx checkov "pipx install checkov" checkov
# wapiti3 has C extensions (zstandard, cffi) that fail to build on Python 3.13
# in older releases. Pin a recent version with prebuilt 3.13 wheels OR use 3.12.
if have wapiti; then
  green "  [OK] wapiti (already installed)"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing wapiti3 (latest, with Python 3.12 fallback if 3.13 build fails)..."
  pipx install wapiti3 2>&1 | tail -3 || \
    (yellow "    Python 3.13 install failed — retrying with python 3.12..."; \
     (have python3.12 || brew install python@3.12) && \
     pipx install --python python3.12 wapiti3 2>&1 | tail -3) || \
    red "    [X] wapiti install failed — try `pipx install --python python3.12 wapiti3` manually"
else
  yellow "  [X] wapiti missing — would install via: pipx install wapiti3 (or pin python3.12)"
fi

# ---- npm-installed scanners ----
if [ "$SKIP_SHANNON" -eq 0 ]; then
  heading "npm-installed scanners"
  # Shannon doesn't expose --version; check the package presence instead.
  if [ -d "$(npm root -g 2>/dev/null)/@keygraph/shannon" ] 2>/dev/null; then
    green "  [OK] shannon (npm package present)"
  elif [ "$CHECK_ONLY" -eq 0 ]; then
    yellow "  installing @keygraph/shannon globally..."
    npm install -g @keygraph/shannon 2>&1 | tail -3 \
      || red "  [X] shannon install failed (you may need: sudo npm install -g @keygraph/shannon)"
  else
    yellow "  [X] shannon missing — would install via: npm install -g @keygraph/shannon"
  fi
  yellow "  NOTE: Shannon needs an AI provider key (Anthropic / Google / AWS)."
  yellow "        See https://github.com/KeygraphHQ/shannon for setup."
fi

# ===================================================================
# Tier-1 install pass (2026-05-08) — fills the gaps surfaced by the
# 8-task pentest expansion. Each bucket below is a self-contained
# group; idempotent re-runs skip already-installed tools.
# ===================================================================

# ---- iOS / mobile (rounds out Phase B-Mobile) ----
heading "iOS / mobile pentest tools"
check_or_install pipx frida-tools "pipx install frida-tools" frida
check_or_install pipx objection   "pipx install objection"   objection
check_or_install brew jadx        "brew install jadx"        jadx
check_or_install brew apktool     "brew install apktool"     apktool
if have ipsw; then
  green "  [OK] ipsw (already installed)"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing ipsw via blacktop tap..."
  brew tap blacktop/tap 2>/dev/null || true
  brew install ipsw 2>&1 | tail -3 || red "  [X] ipsw install failed"
else
  yellow "  [X] ipsw missing — would install via: brew install blacktop/tap/ipsw"
fi

# ---- Container / Kubernetes ----
heading "Container / Kubernetes tools"
check_or_install brew kube-bench  "brew install kube-bench"  kube-bench
check_or_install pipx kube-hunter "pipx install kube-hunter" kube-hunter
check_or_install brew dive        "brew install dive"        dive

# ---- Active Directory / internal pentest ----
# impacket installs ~30 scripts into pipx's bin dir; we probe
# secretsdump.py as the canary. The user MUST re-run `pipx ensurepath`
# and source their shell rc if any of these aren't on PATH.
heading "Active Directory / internal pentest tools"
check_or_install pipx impacket    "pipx install impacket"    secretsdump.py
check_or_install pipx bloodhound  "pipx install bloodhound"  bloodhound-python
# NetExec is NOT published on PyPI under that name — install from GitHub.
check_or_install pipx netexec     "pipx install git+https://github.com/Pennyw0rth/NetExec.git"     nxc
check_or_install pipx smbmap      "pipx install smbmap"      smbmap
# enum4linux-ng PyPI package is sparse — install from GitHub for the CLI entry point.
check_or_install pipx enum4linux-ng "pipx install git+https://github.com/cddmp/enum4linux-ng.git" enum4linux-ng
# ldapsearch ships in openldap; macOS may already have it from /usr/bin.
if have ldapsearch; then
  green "  [OK] ldapsearch (already installed)"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing openldap (provides ldapsearch)..."
  brew install openldap 2>&1 | tail -3 || red "  [X] openldap install failed"
  yellow "    NOTE: brew openldap is keg-only; add to PATH:"
  yellow "      export PATH=\"\$(brew --prefix)/opt/openldap/bin:\$PATH\""
else
  yellow "  [X] ldapsearch missing — would install via: brew install openldap"
fi

# ---- OSINT depth ----
heading "OSINT depth tools"
check_or_install pipx shodan       "pipx install shodan"       shodan
# theHarvester PyPI package is library-only (no entry point); install from GitHub.
check_or_install pipx theHarvester "pipx install git+https://github.com/laramies/theHarvester.git" theHarvester
check_or_install pipx holehe       "pipx install holehe"       holehe
check_or_install pipx sherlock     "pipx install sherlock-project" sherlock

# ---- Web3 / smart contracts ----
heading "Web3 / smart-contract analysis"
check_or_install pipx slither-analyzer "pipx install slither-analyzer" slither
# mythril needs the coincurve C build (autoconf + libtool) on macOS.
if have myth; then
  green "  [OK] mythril (already installed)"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing mythril (requires autoconf + libtool for coincurve build)..."
  brew install autoconf automake libtool 2>&1 | tail -3 || true
  pipx install mythril 2>&1 | tail -3 \
    && green "  [OK] mythril installed" \
    || red "  [X] mythril install failed — see brew/pipx logs above"
else
  yellow "  [X] mythril missing — would install via: pipx install mythril (after brew install autoconf automake libtool)"
fi

# ---- Source-code review (multi-lang) ----
heading "Source-code review (multi-lang)"
check_or_install pipx bandit "pipx install bandit" bandit
# brakeman is a Ruby gem. macOS ships ruby 2.6.10, but modern brakeman
# requires ruby >= 3.2. We pin to brakeman 5.4.1 (last version that
# supports ruby 2.6) so it installs out of the box. Operators wanting
# the latest brakeman should `brew install ruby@3.2` first and re-run.
if have brakeman; then
  green "  [OK] brakeman (already installed)"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing brakeman 5.4.1 (last version supporting macOS ruby 2.6)..."
  if have gem; then
    gem install --user-install brakeman -v 5.4.1 2>&1 | tail -3 \
      && green "  [OK] brakeman 5.4.1 installed" \
      || red "  [X] brakeman gem install failed"
    yellow "    NOTE: ensure ~/.gem/ruby/<version>/bin is on PATH"
    yellow "    For latest brakeman: brew install ruby@3.2 && gem install brakeman"
  else
    red "  [X] ruby gem not available — install ruby first"
  fi
else
  yellow "  [X] brakeman missing — would install via: gem install --user-install brakeman -v 5.4.1"
fi
# gosec — go install. Already-have-go check from kiterunner block.
if have gosec; then
  green "  [OK] gosec (already installed)"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing gosec via go..."
  if have go; then
    go install github.com/securego/gosec/v2/cmd/gosec@latest 2>&1 | tail -3 \
      || red "  [X] gosec go install failed"
  else
    yellow "    [X] go not available; brew install go first"
  fi
else
  yellow "  [X] gosec missing — would install via: go install github.com/securego/gosec/v2/cmd/gosec@latest"
fi

# ---- Web / API specific ----
heading "Web / API tools"
check_or_install brew dalfox        "brew install dalfox"        dalfox
check_or_install pipx schemathesis  "pipx install schemathesis"  schemathesis
if have hakrawler; then
  green "  [OK] hakrawler (already installed)"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing hakrawler via go..."
  if have go; then
    go install github.com/hakluke/hakrawler@latest 2>&1 | tail -3 \
      || red "  [X] hakrawler go install failed"
  else
    yellow "    [X] go not available"
  fi
else
  yellow "  [X] hakrawler missing — would install via: go install github.com/hakluke/hakrawler@latest"
fi
check_or_install pipx dirsearch "pipx install dirsearch" dirsearch

# ---- Recon depth ----
heading "Recon depth tools"
check_or_install brew findomain "brew install findomain" findomain
if have chaos; then
  green "  [OK] chaos (already installed)"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing chaos-client via go..."
  if have go; then
    go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest 2>&1 | tail -3 \
      || red "  [X] chaos go install failed"
  else
    yellow "    [X] go not available"
  fi
else
  yellow "  [X] chaos missing — would install via: go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
fi
# Aquatone — original repo (michenriksen/aquatone) doesn't compile on Go 1.20+
# due to a stale dependency on github.com/mvdan/xurls. We use shelld3v's
# maintained fork which is compatible with modern Go.
if have aquatone; then
  green "  [OK] aquatone (already installed)"
elif [ "$CHECK_ONLY" -eq 0 ]; then
  yellow "  installing aquatone (shelld3v fork — modern Go compatible) via go..."
  if have go; then
    go install github.com/shelld3v/aquatone@latest 2>&1 | tail -3 \
      || red "  [X] aquatone go install failed"
  else
    yellow "    [X] go not available"
  fi
else
  yellow "  [X] aquatone missing — would install via: go install github.com/shelld3v/aquatone@latest"
fi

# ---- Cloud depth ----
heading "Cloud-pentest tools"
check_or_install pipx scoutsuite "pipx install scoutsuite" scout
check_or_install pipx pacu       "pipx install pacu"       pacu

# ---- Kiterunner wordlist ----
heading "Kiterunner wordlists"
KITE_DIR=/opt/homebrew/share/kiterunner
[ -d /usr/local/share/kiterunner ] && KITE_DIR=/usr/local/share/kiterunner
if [ -f "$KITE_DIR/routes-large.kite" ] || [ -f "$KITE_DIR/routes-small.kite" ]; then
  green "  [OK] .kite wordlist present in $KITE_DIR"
elif have kr; then
  yellow "  no .kite wordlist found. Download with:"
  yellow "    mkdir -p $KITE_DIR"
  yellow "    curl -L -o $KITE_DIR/routes-large.kite https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite"
  yellow "    curl -L -o $KITE_DIR/routes-small.kite https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite"
  yellow "  Or set KITE_WORDLIST=/path/to/yours.kite"
fi

# ---- Final report ----
heading "Final availability check"
ALL_TOOLS=(
  ollama gitleaks osv-scanner trivy nuclei syft
  nmap ffuf
  subfinder amass whatweb
  semgrep checkov wapiti
  # Tier-1 install pass (2026-05-08)
  frida objection jadx apktool ipsw
  kube-bench kube-hunter dive
  bloodhound-python nxc smbmap enum4linux-ng ldapsearch
  shodan theHarvester holehe sherlock
  slither myth
  bandit brakeman gosec
  dalfox schemathesis hakrawler dirsearch
  findomain chaos aquatone
  scout pacu
)
[ "$SKIP_SHANNON" -eq 0 ] && ALL_TOOLS+=(node)

MISSING=0
for t in "${ALL_TOOLS[@]}"; do
  if have "$t"; then
    green "  [OK] $t"
  else
    red "  [X] $t"
    MISSING=$((MISSING + 1))
  fi
done

# testssl — brew names it testssl.sh, not testssl
if have testssl || have testssl.sh; then
  green "  [OK] testssl"
else
  red "  [X] testssl"
  MISSING=$((MISSING + 1))
fi

# ZAP — check both PATH (zap.sh symlink) and /Applications cask install.
if have zap.sh || [ -f /Applications/ZAP.app/Contents/Java/zap.sh ]; then
  green "  [OK] zap"
else
  red "  [X] zap"
  MISSING=$((MISSING + 1))
fi

# kiterunner: binary `kr` or `kiterunner`
if have kr || have kiterunner; then
  green "  [OK] kiterunner (kr)"
else
  red "  [X] kiterunner (kr)"
  MISSING=$((MISSING + 1))
fi

# shannon: check the npm package exists, not its --version (it doesn't expose one)
if [ "$SKIP_SHANNON" -eq 0 ]; then
  if [ -d "$(npm root -g 2>/dev/null)/@keygraph/shannon" ] 2>/dev/null; then
    green "  [OK] shannon (npm pkg)"
  else
    red "  [X] shannon (npm pkg)"
    MISSING=$((MISSING + 1))
  fi
fi

heading "Next steps"
if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "  Re-run without --check to install missing tools."
elif [ "$MISSING" -eq 0 ]; then
  green "  All tools available!"
else
  yellow "  $MISSING tool(s) still missing — see errors above."
fi
echo
echo "  1. Activate the project venv:        source .venv/bin/activate"
echo "  2. Install Python deps + project:    pip install -e \".[all,dev]\""
echo "  3. Pull Ollama models if not yet:    ollama pull llama3.1:8b && ollama pull nomic-embed-text"
echo "  4. (For Shannon) configure your AI provider key per its README"
echo "  5. Verify:                           sentinel --version && sentinel ui"
