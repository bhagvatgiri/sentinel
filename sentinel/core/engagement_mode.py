"""Wave 3 — engagement-mode enum + dangerous-tool gating.

CTF mode unlocks tactics that are FORBIDDEN in production engagements
(webshells, reverse shells, code execution, persistent backdoors). The
whole point of the gating is that the audit log + scope.yaml + dashboard
make it IMPOSSIBLE to silently launder a CTF finding into a client report.

Mode taxonomy
-------------
production : default. paid pentest engagements with NDAs / SOWs.
              CTF-only tools refused at registration time AND at the
              tool's entry point (belt-and-suspenders).
bbp        : public/private bug-bounty programs. SAME restrictions as
              production — H1 / Bugcrowd / Synack / Intigriti programs
              ban dangerous tactics by policy.
ctf        : CTF challenges (HTB, picoCTF, CSAW, VulnHub, private CTFs).
              Dangerous tools enabled.
lab        : the operator's personal lab / boxes (vulnhub VMs, his own
              hosted-on-RFC1918 deliberately-broken targets). Dangerous
              tools enabled, BUT scope MUST be limited to 127.0.0.1 /
              ::1 / RFC1918 — refuses to load if scope contains a
              public IP or domain.

Mode propagation contract
-------------------------
1. scope.yaml carries `engagement_mode: <mode>` (default production).
2. CLI `--mode <mode>` is required to match the scope's declared mode.
   Disagreement → fail loudly with both values + exit 2 (never silently
   assume one).
3. Every AuditLog entry written by the pipeline includes the mode field.
4. Every PDF deliverable for non-production mode prepends a giant red
   "NOT A CLIENT DELIVERABLE" banner (so accidental hand-off is
   structurally impossible).
5. `verify-audit` rejects any audit log whose first entry's mode field
   disagrees with the scope file's declared mode (anti-tamper).

Belt-and-suspenders gating
--------------------------
- `is_tool_allowed(name, mode)` is consulted at TWO different layers:
    a) Pipeline tool-registry build time (filter the tool union before
       passing to claude_agent_sdk's MCP server).
    b) The CTF-only tool's body re-checks the active mode and raises
       if invoked under a wrong mode.
  This means even if a tool slips into a phase's tool union by mistake
  (e.g. a code change forgets the filter), the runtime check stops
  it. Both layers audit-log the refusal so a violated invariant is
  visible after the fact.
"""

from __future__ import annotations

import ipaddress
from enum import Enum
from typing import Optional


class ModeError(ValueError):
    """Raised on unknown / mismatched / scope-violating mode values."""


class ModeMismatchError(ModeError):
    """Raised when CLI --mode disagrees with scope yaml engagement_mode."""


class EngagementMode(str, Enum):
    PRODUCTION = "production"
    BBP = "bbp"
    CTF = "ctf"
    LAB = "lab"

    @classmethod
    def from_string(cls, s: Optional[str]) -> "EngagementMode":
        """Coerce an operator-supplied string. Default = PRODUCTION.

        Case-insensitive. Raises ModeError on unknown values so a typo
        in scope.yaml is caught at load time rather than silently
        defaulting to production (which would unlock dangerous tools
        nowhere — fine — but mask a misconfigured CTF run).
        """
        if s is None or s == "":
            return cls.PRODUCTION
        if not isinstance(s, str):
            raise ModeError(f"engagement_mode must be a string, got {type(s).__name__}")
        normalized = s.strip().lower()
        if not normalized:
            return cls.PRODUCTION
        for m in cls:
            if m.value == normalized:
                return m
        valid = ", ".join(m.value for m in cls)
        raise ModeError(
            f"unknown engagement_mode {s!r}; valid values: {valid}"
        )

    @property
    def allows_ctf_tools(self) -> bool:
        """True when this mode unlocks the CTF-only tool set."""
        return self in (EngagementMode.CTF, EngagementMode.LAB)


# ---- Tool-name registries -------------------------------------------------

# The 26 existing typed MCP tools that ship in production / bbp engagements.
# Names match the @tool("<name>", ...) decorator string used by each tool
# module. Synthesizing this from imports at runtime would create a
# circular dep; the explicit list is the source of truth + a quick way
# for a code reviewer to spot a typo.
PRODUCTION_TOOL_SET: set[str] = {
    # tools.py — base agent surface
    "authorize_url", "http_get", "read_file", "write_deliverable",
    "request_brain_research", "list_primitives", "record_chain_step",
    # bash_tool.py
    "run_bash",
    # browser_tool.py
    "browser_get",
    # bypass_tool.py — WAF / origin-IP bypass intelligence
    "discover_bypass_tokens", "try_waf_bypass", "discover_origin_ip",
    # auth_tool.py
    "login",
    # js_intel_tool.py / jwt_tool.py / takeover_tool.py / secrets_tool.py
    "fetch_js_bundle", "analyze_jwt", "check_takeover", "verify_secrets",
    # ssti_tool.py / cors_tool.py / crlf_tool.py / dns_tool.py
    "test_ssti", "test_cors", "test_crlf", "dns_lookup",
    # websocket_tool.py / param_discovery_tool.py / spec_discovery_tool.py
    "test_websocket", "discover_hidden_params", "discover_api_spec",
    # graphql_tool.py / oast_tool.py / race_tool.py / smuggling_tool.py
    "graphql_introspect", "graphql_field_authz_diff",
    "oast_register_token", "oast_poll",
    "race_request", "smuggling_probe",
    # payload_tool.py / rag_tool.py / recipes_tool.py / sast_tool.py
    "get_payloads", "corpus_search", "get_tech_recipe", "query_sast_findings",
    # handoff.py / verifier_tool.py
    "transfer_to_retester", "transfer_to_vuln", "transfer_to_exploit",
    "verify_finding",
}


# CTF-only tools shipped in Wave 3. Only registered when engagement_mode
# is CTF or LAB. drop_persistent_backdoor + memory_dump are reserved for
# Wave 5 (CodeAct / red-team agents) but listed here so the gating set
# is final from the moment Wave 3 lands — Wave 5 wires the implementations.
CTF_ONLY_TOOL_SET: set[str] = {
    "drop_webshell",
    "open_reverse_shell_listener",
    "reverse_shell_send",                  # session-scoped command sender
    "reverse_shell_history",               # session-scoped history dump
    "ssh_with_credentials",
    "execute_arbitrary_code",
    "drop_persistent_backdoor",            # Wave 5
    "exfil_file_via_oast",
    "memory_dump",                         # Wave 5 (reserved)
    "flag_discriminator",
    "netcat_raw",
    "ctf_writeup",
    # ---- Wave 5 — CodeAct + replay + red-team + niche agents ----
    "execute_python_code",                 # Wave 5 — CodeAct sandbox
    "pcap_parse",                          # Wave 5 — replay-attack agent
    "replay_request",                      # Wave 5 — replay-attack agent
    "analyze_radio_capture",               # Wave 5 — sub-GHz SDR agent
    "wifi_handshake_crack",                # Wave 5 — WiFi agent
    # ---- Wave 5 — handoff hooks for CTF-only specialist agents ----
    "transfer_to_codeact",
    "transfer_to_red_teamer",
    "transfer_to_replay_attack",
    "transfer_to_subghz",
    "transfer_to_wifi",
}


# Mapping of mode → allowed tool name set. Production / BBP use the same
# set (BBP policy mirrors production restrictions). CTF / LAB get the
# union with CTF_ONLY_TOOL_SET.
TOOLS_ALLOWED_IN_MODE: dict[EngagementMode, set[str]] = {
    EngagementMode.PRODUCTION: set(PRODUCTION_TOOL_SET),
    EngagementMode.BBP:        set(PRODUCTION_TOOL_SET),
    EngagementMode.CTF:        set(PRODUCTION_TOOL_SET) | set(CTF_ONLY_TOOL_SET),
    EngagementMode.LAB:        set(PRODUCTION_TOOL_SET) | set(CTF_ONLY_TOOL_SET),
}


def is_tool_allowed(name: str, mode: EngagementMode) -> bool:
    """Return True if `name` is registrable + invokable under `mode`.

    Unknown tool names (not in either registry) default to True — the
    gating set is for explicit dangerous tools, not an exhaustive
    allowlist; downstream tools added by future waves keep working
    until they're explicitly added to one of the sets.
    """
    if not name:
        return False
    if name in CTF_ONLY_TOOL_SET:
        return mode.allows_ctf_tools
    # Either explicitly in PRODUCTION_TOOL_SET or unknown (future tool):
    # allow under every mode.
    return True


# ---- LAB-mode scope guard ------------------------------------------------

# Hosts that pass the LAB scope guard. Plain literals get an exact match;
# `assert_lab_mode_scope` also allows any RFC1918 / loopback / link-local
# IP via ipaddress comparisons.
_LAB_LOOPBACK_HOSTS: set[str] = {"localhost", "127.0.0.1", "::1"}


def _is_private_or_loopback_host(token: str) -> bool:
    """Tolerant private-host check.

    Accepts:
      - 'localhost', '127.0.0.1', '::1'
      - bare IPv4 / IPv6 in any RFC1918 / loopback / link-local range
      - CIDR strings ('10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12')
        whose entire range falls inside private space.

    Rejects FQDNs (e.g. 'box.htb' is a routable domain even if the box
    only listens on RFC1918 — LAB mode wants the loopback contract
    enforced strictly).
    """
    t = (token or "").strip().lower()
    if not t:
        return False
    if t in _LAB_LOOPBACK_HOSTS:
        return True
    # CIDR? the whole network must be private.
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            return False
        return bool(net.is_private or net.is_loopback or net.is_link_local)
    # Bare IP?
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


def assert_lab_mode_scope(scope) -> None:
    """LAB mode safety net — refuse to load a scope that contains any
    target outside loopback / RFC1918.

    `scope` is a `sentinel.core.scope.Scope` instance (lazy-typed to
    avoid circular import). Raises `OutOfScopeError` with a descriptive
    message if any target violates the constraint.
    """
    # Lazy import to dodge circular dep.
    from sentinel.core.scope import OutOfScopeError

    bad: list[str] = []
    # Domains: any wildcard or FQDN is rejected. Only `localhost` is OK.
    for d in (scope.domains or []):
        token = (d or "").strip().lstrip("*.").lower()
        if token in _LAB_LOOPBACK_HOSTS:
            continue
        bad.append(f"domain:{d}")
    # IPs: must be private/loopback/link-local — and CIDRs must fit
    # entirely in private space.
    for ip in (scope.ips or []):
        if not _is_private_or_loopback_host(ip):
            bad.append(f"ip:{ip}")

    if bad:
        raise OutOfScopeError(
            "LAB mode requires scope to be limited to 127.0.0.1 / ::1 / "
            "RFC1918 only. Out-of-scope tokens: " + ", ".join(bad)
        )


# ---- Convenience helpers used by CLI / pipeline / tools -------------------

def filter_tools_for_mode(tools, mode: EngagementMode):
    """Filter a list of MCP tool objects to those allowed under `mode`.

    `tools` is the list emitted by claude_agent_sdk's `@tool(name, ...)`
    decorator — each element carries a `.name` attribute that matches
    the registry strings above. Unknown attribute → fall back to True
    (don't drop tools just because their name lookup failed).
    """
    out = []
    for t in tools:
        name = getattr(t, "name", None) or ""
        if is_tool_allowed(name, mode):
            out.append(t)
    return out


def assert_tool_allowed_at_runtime(name: str, mode: EngagementMode) -> None:
    """Belt-and-suspenders body-of-tool check.

    CTF-only tool implementations call this on entry. If a CTF tool
    somehow ended up in the active tool union under production / bbp,
    runtime invocation fails loudly. Caller is responsible for
    audit-logging the refusal — this function only raises.
    """
    if not is_tool_allowed(name, mode):
        raise ModeError(
            f"tool {name!r} is not allowed under engagement_mode={mode.value!r}"
        )
