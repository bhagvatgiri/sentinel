"""Canonical inventory of every external tool Sentinel can drive.

Single source of truth for the FastAPI Tools page, the Streamlit Tools page,
and the `sentinel info` CLI subcommand. When a new scanner gets wrapped, add
it here once — both UIs and the CLI inventory pick it up automatically.

Every entry:
    name          : the binary name(s) we look for on PATH (first match wins)
    label         : short human-readable description
    install_hint  : copy-pasteable install command (brew/go/pipx/npm)
    tier          : "passive" | "active" | "network" | "ai" — for UI grouping

Tier definitions:
    passive  — read-only static / dependency / config / passive-network scanners
               (semgrep, gitleaks, osv-scanner, checkov, trivy, syft, testssl,
                whatweb, subfinder, amass)
    active   — sends payloads or brute-force traffic at the target
               (nuclei, hydra, sqlmap, nikto, gobuster, ffuf, kr, wapiti, zap)
    network  — network-layer probes (nmap)
    ai       — orchestration / AI-driven scanners (shannon)
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


Tier = Literal["passive", "active", "network", "ai"]


@dataclass(frozen=True)
class Tool:
    name: str                 # canonical key (e.g. "testssl")
    label: str                # short description
    install_hint: str         # "brew install ..."
    tier: Tier
    binaries: tuple[str, ...] = ()  # binary names to search on PATH; defaults to (name,)

    def search_names(self) -> tuple[str, ...]:
        return self.binaries or (self.name,)


# ---- canonical inventory ---------------------------------------------------

TOOL_INVENTORY: list[Tool] = [
    # Passive — static / dep / config / passive-network
    Tool("semgrep",     "SAST",                  "pipx install semgrep",                "passive"),
    Tool("gitleaks",    "Secrets scanner",       "brew install gitleaks",               "passive"),
    Tool("osv-scanner", "Dependency CVEs",       "brew install osv-scanner",            "passive"),
    Tool("checkov",     "IaC scanner",           "pipx install checkov",                "passive"),
    Tool("trivy",       "Container/IaC CVE",     "brew install trivy",                  "passive"),
    Tool("syft",        "SBOM generator",        "brew install syft",                   "passive"),
    Tool("testssl",     "Deep TLS audit",        "brew install testssl",                "passive",
         binaries=("testssl", "testssl.sh")),
    Tool("whatweb",     "Tech fingerprint",      "gem install --user-install whatweb",  "passive"),
    Tool("subfinder",   "Subdomain enum (passive)", "brew install subfinder",            "passive"),
    Tool("amass",       "Subdomain enum (passive)", "brew install amass",                "passive"),
    Tool("wafw00f",     "WAF fingerprinting",    "pipx install wafw00f",                "passive"),
    Tool("searchsploit","Offline ExploitDB lookup","brew install exploitdb",            "passive"),
    Tool("dnsx",        "DNS toolkit (PD)",      "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
         "passive"),
    Tool("gau",         "URLs from web archives","go install github.com/lc/gau/v2/cmd/gau@latest",
         "passive"),
    Tool("waybackurls", "URLs from wayback",     "go install github.com/tomnomnom/waybackurls@latest",
         "passive"),

    # Active — sends payloads / brute traffic
    Tool("nuclei",      "Defensive web tmpl",    "brew install nuclei",                 "active"),
    Tool("hydra",       "Brute force",           "brew install hydra",                  "active"),
    Tool("sqlmap",      "SQL injection",         "brew install sqlmap",                 "active"),
    Tool("nikto",       "Legacy web scanner",    "brew install nikto",                  "active"),
    Tool("gobuster",    "Dir/DNS bruteforce",    "brew install gobuster",               "active"),
    Tool("ffuf",        "Dir/param fuzzer",      "brew install ffuf",                   "active"),
    Tool("feroxbuster", "Recursive content disc","brew install feroxbuster",            "active"),
    Tool("masscan",     "Fast port scanner",     "brew install masscan",                "active"),
    Tool("naabu",       "Port scanner (PD)",     "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
         "active"),
    Tool("katana",      "Crawler (PD)",          "go install github.com/projectdiscovery/katana/cmd/katana@latest",
         "active"),
    Tool("httpx-pd",    "HTTP probe / tech detect (PD)",
         "go install github.com/projectdiscovery/httpx/cmd/httpx@latest && mv $(go env GOPATH)/bin/httpx $(go env GOPATH)/bin/httpx-pd",
         "passive", binaries=("httpx-pd",)),  # renamed at install — plain 'httpx' collides w/ python httpx lib
    Tool("wpscan",      "WordPress vuln scan",   "gem install --user-install wpscan",   "active"),
    Tool("kiterunner",  "API endpoint discovery","go install github.com/assetnote/kiterunner/cmd/kr@latest",
         "active", binaries=("kr", "kiterunner")),
    Tool("wapiti",      "Active web fuzz",       "pipx install --python python3.12 wapiti3", "active"),
    Tool("zap",         "Active web (ZAP)",      "brew install --cask zap",             "active",
         binaries=("zap.sh",)),

    # Network
    Tool("nmap",        "Port + NSE vuln scan",  "brew install nmap",                   "network"),

    # AI / orchestration
    Tool("shannon",     "AI pentest orchestrator","npm install -g @keygraph/shannon",   "ai",
         binaries=("npx",)),

    # ---------------------------------------------------------------
    # Tier-1 install pass (2026-XX-XX) — see install-tools.sh + plan.
    # Each Tool below is reachable via `sentinel info` + /tools page
    # the moment its binary lands on PATH.
    # ---------------------------------------------------------------

    # iOS / mobile
    Tool("frida",       "Dynamic instrumentation (iOS/Android)",
         "pipx install frida-tools",
         "active", binaries=("frida", "frida-ps", "frida-trace")),
    Tool("objection",   "Frida-based mobile runtime exploration",
         "pipx install objection", "active"),
    Tool("jadx",        "Android APK / dex decompiler",
         "brew install jadx", "passive",
         binaries=("jadx", "jadx-cli")),
    Tool("apktool",     "APK resource extractor / rebuilder",
         "brew install apktool", "passive"),
    Tool("ipsw",        "iOS firmware analysis toolkit",
         "brew install blacktop/tap/ipsw", "passive"),

    # Container / Kubernetes
    Tool("kube-bench",  "Kubernetes CIS benchmark scan",
         "brew install kube-bench", "passive"),
    Tool("kube-hunter", "Kubernetes attack-surface enum",
         "pipx install kube-hunter", "active"),
    Tool("dive",        "Container image layer inspector",
         "brew install dive", "passive"),

    # Active Directory / internal pentest
    Tool("impacket",    "AD attack toolkit (secretsdump, GetUserSPNs, ...)",
         "pipx install impacket", "network",
         binaries=("secretsdump.py", "GetUserSPNs.py")),
    Tool("bloodhound-python", "BloodHound AD ingestor",
         "pipx install bloodhound", "network",
         binaries=("bloodhound-python",)),
    Tool("netexec",     "NetExec — SMB/WinRM/LDAP/MSSQL (formerly CrackMapExec)",
         "pipx install netexec", "network",
         binaries=("nxc",)),
    Tool("smbmap",      "SMB share enum + brute",
         "pipx install smbmap", "network"),
    Tool("enum4linux-ng", "SMB / NetBIOS enumeration",
         "pipx install enum4linux-ng", "network"),
    Tool("ldapsearch",  "LDAP enumeration",
         "brew install openldap", "network"),

    # OSINT depth
    Tool("shodan",      "Shodan API CLI",
         "pipx install shodan", "passive"),
    Tool("theHarvester","Email / employee / subdomain OSINT",
         "pipx install theHarvester", "passive"),
    Tool("holehe",      "Email-based account-presence OSINT",
         "pipx install holehe", "passive"),
    Tool("sherlock",    "Username search across 400+ sites",
         "pipx install sherlock-project", "passive"),

    # Web3 / smart contracts
    Tool("slither",     "Solidity static analysis",
         "pipx install slither-analyzer", "passive"),
    Tool("mythril",     "Solidity symbolic execution",
         "pipx install mythril", "passive",
         binaries=("myth",)),

    # Source-code review (multi-lang)
    Tool("bandit",      "Python SAST",
         "pipx install bandit", "passive"),
    Tool("brakeman",    "Ruby on Rails SAST",
         "gem install brakeman", "passive"),
    Tool("gosec",       "Go SAST",
         "go install github.com/securego/gosec/v2/cmd/gosec@latest",
         "passive"),

    # Web / API specific
    Tool("dalfox",      "XSS scanner (Go)",
         "brew install dalfox", "active"),
    Tool("schemathesis","OpenAPI / GraphQL fuzzer",
         "pipx install schemathesis", "active"),
    Tool("hakrawler",   "JS-aware crawler (Go)",
         "go install github.com/hakluke/hakrawler@latest", "active"),
    Tool("dirsearch",   "Directory brute-forcer (Python)",
         "pipx install dirsearch", "active"),

    # Recon depth
    Tool("findomain",   "Subdomain enum (Rust, fast)",
         "brew install findomain", "passive"),
    Tool("chaos",       "ProjectDiscovery Chaos subdomain DB client",
         "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
         "passive"),
    Tool("aquatone",    "Visual recon — screenshots + tech tags",
         "go install github.com/shelld3v/aquatone@latest", "passive"),

    # Cloud depth
    Tool("scoutsuite",  "Multi-cloud security audit",
         "pipx install scoutsuite", "passive",
         binaries=("scout",)),
    Tool("pacu",        "AWS exploitation framework",
         "pipx install pacu", "active"),

    # ---- Tier-1 pass (2026-XX-XX) — best-in-field pentest tools ----
    Tool("arjun",        "HTTP parameter discovery",                "pipx install arjun",                                                "active"),
    Tool("jwt_tool",     "JWT auditing",                             "pipx install git+https://github.com/ticarpi/jwt_tool.git",         "active"),
    Tool("linkfinder",   "JS endpoint extractor",                    "pipx install git+https://github.com/GerbenJavado/LinkFinder.git",  "passive"),
    Tool("mantra",       "JS endpoint+secret discovery (Go)",        "go install github.com/MrEmpy/mantra@latest",                       "passive"),
    Tool("paramspider",  "Wayback URL parameter mining",             "pipx install git+https://github.com/devanshbatham/paramspider.git","passive"),
    Tool("secretfinder", "JS secret regex extractor",                "operator: git clone https://github.com/m4ll0k/SecretFinder.git external/secretfinder && pipx install $(pwd)/external/secretfinder",  "passive",
         binaries=("SecretFinder.py", "secretfinder")),
    Tool("subjack",      "Subdomain takeover scanner",               "go install github.com/haccer/subjack@latest",                      "active"),
    Tool("subzy",        "Subdomain takeover scanner",               "go install github.com/PentestPad/subzy@latest",                    "active"),

    # ---- OOB callback infrastructure (2026-XX-XX) — blind-vuln oracle ----
    Tool("interactsh-client", "OOB callback server client (blind-vuln oracle)", "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest", "active"),

    # ---- bbot recon orchestrator (2026-XX-XX) — 60+ OSINT modules in one pipeline ----
    Tool("bbot",             "Modular OSINT framework (60+ modules)",       "pipx install bbot",                                                "passive"),

    # ---- Visual recon (2026-XX-XX) — gowitness pairs w/ llava:13b for visual triage ----
    Tool("gowitness",        "Subdomain screenshot tool (Go)",              "go install github.com/sensepost/gowitness@latest",                 "passive"),
]


_BY_NAME: dict[str, Tool] = {t.name: t for t in TOOL_INVENTORY}


# ---- public API ------------------------------------------------------------

def all_tools() -> list[Tool]:
    """Every Tool, in canonical order (passive → active → network → ai)."""
    return list(TOOL_INVENTORY)


def by_tier() -> dict[Tier, list[Tool]]:
    """{tier → [tools]} in canonical order. Empty tiers omitted."""
    out: dict[Tier, list[Tool]] = {}
    for t in TOOL_INVENTORY:
        out.setdefault(t.tier, []).append(t)
    return out


def get(name: str) -> Tool | None:
    return _BY_NAME.get(name)


def check_tool(tool: Tool) -> tuple[bool, str]:
    """Return (installed, path). Honours ZAP.app cask fallback + ~/go/bin probe."""
    for binary in tool.search_names():
        p = shutil.which(binary)
        if p:
            return True, p
    # ZAP cask install lives outside PATH — special-case it.
    if "zap.sh" in tool.search_names():
        zap_app = Path("/Applications/ZAP.app/Contents/Java/zap.sh")
        if zap_app.is_file():
            return True, str(zap_app)
    # Go-installed binaries land in $GOPATH/bin (default ~/go/bin) which
    # often isn't on PATH on first install. Probe directly so the dashboard
    # doesn't lie about gosec / chaos / hakrawler / aquatone availability.
    go_bin = Path.home() / "go" / "bin"
    if go_bin.is_dir():
        for binary in tool.search_names():
            candidate = go_bin / binary
            if candidate.is_file():
                return True, str(candidate)
    return False, ""


def check_all() -> list[dict]:
    """Status row per tool. Shape:
        {name, label, install_hint, tier, ok, path}
    Used by the FastAPI Tools page, the Streamlit Tools page, and the CLI's
    `sentinel info` subcommand. UIs render whichever subset of fields they need.
    """
    rows: list[dict] = []
    for tool in TOOL_INVENTORY:
        ok, path = check_tool(tool)
        rows.append({
            "name": tool.name,
            "label": tool.label,
            "install_hint": tool.install_hint,
            "tier": tool.tier,
            "ok": ok,
            "path": path,
        })
    return rows


def check_all_grouped() -> dict[Tier, list[dict]]:
    """check_all() bucketed by tier — convenience for tier-grouped UIs."""
    grouped: dict[Tier, list[dict]] = {}
    for row in check_all():
        grouped.setdefault(row["tier"], []).append(row)
    return grouped
