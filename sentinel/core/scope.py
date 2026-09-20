"""Scope enforcement — the legal/safety boundary for active operations.

Every scanner that touches a live target MUST go through Scope.authorize()
before sending a single byte. Refusals are logged with a tamper-evident hash
chain so the audit log can be presented to clients as evidence of due
diligence.

The audit log uses an append-only JSONL format with each entry containing the
SHA-256 of the previous entry, making any tampering detectable.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

import yaml

from sentinel.core.engagement_mode import (
    EngagementMode,
    ModeError,
    ModeMismatchError,
    assert_lab_mode_scope,
)


class ScopeError(Exception):
    """Raised when scope cannot be loaded or is invalid."""


class OutOfScopeError(Exception):
    """Raised when a target is rejected. Caller MUST NOT retry without a new scope."""


@dataclass
class Scope:
    """Loaded engagement scope. Immutable after construction."""

    client: str
    engagement_id: str
    authorized_by: str
    authorization_doc: Optional[str]
    valid_from: date
    valid_until: date
    repos: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    rate_limit_rps: float = 5.0
    raw: dict = field(default_factory=dict)
    source_path: Optional[Path] = None
    source_hash: str = ""
    audit_log: Optional["AuditLog"] = None
    # Optional auth credentials for the engagement. List of dicts:
    #   - name: str               (e.g., "admin", "user1")
    #     method: str             (form|basic|bearer|oauth_sso)
    #     url: str                (login form URL or token endpoint; basic uses target URL)
    #     username: str           (form/basic only)
    #     password_env: str       (env var name holding the password — never plaintext)
    #     token_env: str          (bearer only — env var with the token)
    #     ... method-specific extras
    # Loaded from `auth_credentials` block in the scope YAML.
    auth_credentials: list[dict] = field(default_factory=list)
    # Researcher-identifying / program-required HTTP headers that get
    # injected on every outgoing test request from http_get / browser_get /
    # run_bash-curl / brain-grow-fetch when the host is in scope.
    # Example for a HackerOne program:
    #   research_headers:
    #     X-HackerOne-Research: my-h1-username
    # Bugcrowd / Synack / Intigriti use similar tagged-traffic headers;
    # this block is the operator-configurable place for any of them.
    research_headers: dict[str, str] = field(default_factory=dict)

    # Tier-2 anti-bot bypass (added 2026-XX-XX). Cookies the operator has
    # manually solved (via `sentinel datadome-harvest` or by inspecting
    # DevTools after a real-Chrome solve) and persists in the scope file.
    # http_get and browser_get inject these on every matching-domain request,
    # so the agent looks like a returning human rather than a bot.
    #
    # Each entry: {"domain": ".ExamplePay.com", "name": "datadome",
    #              "value": "<token>", "path": "/", "secure": true,
    #              "httpOnly": false, "expires": "<iso8601 optional>"}
    # Domain match is browser-cookie-style: leading "." matches subdomains.
    # Cookies that have `expires` in the past are skipped + logged.
    auth_cookies: list[dict] = field(default_factory=list)

    # Short-lived-token refresh (2026-XX-XX). For targets with very short
    # access-token TTLs refreshed transparently by server middleware (e.g.
    # ExampleMarket's 5-min __Secure-access-token). The TokenRefresher seeds from
    # auth_cookies, then keeps the session alive by GETting refresh_url and
    # harvesting rotated tokens from Set-Cookie. See token_refresher.py.
    # Shape: {host, refresh_url, access_token_cookie, auth_header_name,
    #         auth_header_value, margin_sec, rotated_cookies: [...]}
    # May be a single dict (one account) OR a list[dict] of named accounts
    # (attacker + victim for cross-member BOLA/IDOR).
    auth_refresh: Any = field(default_factory=dict)

    # OAST callback endpoint (Phase B3, 2026-XX-XX). When set, the agent's
    # `oast_register_token` tool mints unique callback URLs at this server
    # and `oast_poll` drains pending callbacks. Required for blind-class
    # vulnerability detection (blind SSRF / SSTI / XXE / SQLi).
    # Example values: 'https://oast.fun' (project discovery's free server),
    # 'https://app.interactsh.com', or self-hosted interactsh-server URL.
    oast_endpoint: Optional[str] = None

    # Wave 3 — engagement mode (production / bbp / ctf / lab). CTF mode
    # unlocks dangerous tools (webshells, reverse shells, code execution,
    # backdoors) that production scope refuses by class. The mode is
    # stamped on every audit-log entry and rendered as a badge on every
    # dashboard run card. PDF deliverables for non-production runs
    # prepend a giant red "NOT A CLIENT DELIVERABLE" banner.
    engagement_mode: EngagementMode = EngagementMode.PRODUCTION
    # CTF-only metadata, optional. ctf_platform is the host where the
    # box lives ('hackthebox', 'picoctf', 'csaw', 'vulnhub', etc.) so
    # write-ups land in the right vault subdir. ctf_flag_format lets
    # the flag_discriminator know what shape to look for (e.g.
    # 'HTB{...}', 'flag{...}', 'picoCTF{...}'). ctf_box_writeup_dir
    # is the directory the ctf_writeup tool drops box write-ups in.
    ctf_platform: Optional[str] = None
    ctf_flag_format: Optional[str] = None
    ctf_box_writeup_dir: Optional[str] = None

    # Real-Chrome-via-CDP DataDome bypass (added 2026-XX-XX). When
    # browser_strategy == "cdp", browser_tool.py's _BrowserSession attaches
    # to a user-launched Chrome at localhost:<chrome_cdp_port> via Playwright's
    # connect_over_cdp() and uses browser.contexts[0] (the profile's default
    # context, which has all cookies including any DataDome solve the operator
    # already completed in the visible Chrome window). Defeats fingerprint
    # detection — the browser literally IS real Chrome. The "agent_browser_cdp"
    # value is reserved for a future PR that swaps Playwright for the
    # vercel-labs/agent-browser CLI; today it falls back to "cdp" semantics.
    # When unset / "playwright_spawn", current chromium.launch() path runs
    # — full back-compat for every existing scope.yaml.
    #
    # chrome_profile_dir defaults to ~/.sentinel/chrome-profiles/<engagement_id>
    # at runtime if browser_strategy == "cdp" and this field is unset.
    browser_strategy: Optional[str] = None
    chrome_profile_dir: Optional[str] = None
    chrome_cdp_port: int = 9222

    # Bright Data Web Unlocker opt-in. brightdata_tool._is_enabled() reads
    # this; token lives in BRIGHTDATA_API_TOKEN env (or scope.bright_data
    # nested dict for per-engagement override). Default False — third-party
    # proxy use changes the audit story and isn't right for every program.
    bright_data_enabled: bool = False
    bright_data: dict = field(default_factory=dict)

    # Plan 03-05 (VERIFY-08) — correlation input filter. Governs which
    # evidence_state values reach the correlation agent. Three modes:
    #   verified_only (default)   — VERIFIED + LIVE_CONFIRMED only
    #   include_manual_required   — adds MANUAL_REQUIRED, MANUAL_VERIFICATION_REQUIRED,
    #                                REQUIRES_TEST_CREDENTIALS, REQUIRES_TWO_ACCOUNTS
    #   all                       — every value (offline-pentest workflows)
    # Validated at scope load — invalid values raise ScopeError. The filter
    # governs ONLY which findings the correlation prompt sees; UNREPRODUCIBLE /
    # LIVE_DISPROVEN findings still appear in the run report + Obsidian vault.
    correlation_input_filter: str = "verified_only"

    # Phase 5 / NOVEL-04 — novelty escalation threshold. Default 0.75 matches
    # the NOVEL-04 spec; operator overrides via `novelty_threshold: 0.5` in
    # scope.yaml. Range-validated at load (must be in [0.0, 1.0]); out-of-range
    # raises ScopeError so a typo'd 1.5 fails loud at scope-load time rather
    # than silently disabling escalation. The Plan 05-04 evaluate_novelty_gate
    # function reads this field to decide which findings to escalate.
    novelty_threshold: float = 0.75
    # Phase 5 / NOVEL-04 + VERIFY-08 — which evidence_state values are eligible
    # for novelty escalation. Default ["verified"] matches VERIFY-08's
    # verified_only correlation filter contract: only Phase 3 sandbox-verified
    # findings escalate by default. Operators can opt in to
    # ["verified", "manual_required"] for offline-pentest workflows where
    # manual-required findings still warrant zero-day reasoning. Each value
    # is validated against the EvidenceState enum at load time; unknown
    # values raise ScopeError.
    escalate_on_evidence_states: list = field(default_factory=lambda: ["verified"])

    # Quick 260517-f7a (2026-XX-XX) — authenticated-target enablement.
    #
    # captcha_solver: opt-in NopeCHA Chromium-extension captcha solver.
    #   Default None → existing chromium.launch + new_context path runs
    #   (full back-compat). "nopecha" → _BrowserSession switches to
    #   launch_persistent_context with --load-extension pointing at
    #   external/nopecha-extension/ (operator-installed via
    #   tools/install-nopecha-extension.sh). Headed Chromium (extensions
    #   don't load in headless). NOPECHA_KEY env var seeds the paid tier.
    #   No other values supported today — unknown values raise ScopeError.
    #
    # allow_human_signup: opt-in for the human_signup tool. Default False →
    #   the tool refuses with _err and the agent falls back to unauth
    #   probes. True → vuln/exploit agents can pause and ask the operator
    #   to manually create an account; credentials persist to
    #   ~/.sentinel/<engagement_id>.creds.json (mode 0o600) and a
    #   scope.auth_credentials entry is synthesized for the existing
    #   login tool.
    captcha_solver: Optional[str] = None
    allow_human_signup: bool = False

    # OOB callback infrastructure — opt out for NDA engagements where
    # third-party data flow to interact.sh is unacceptable per SOW.
    # None = enabled (default), "disabled" = OOB tool refuses to register tokens.
    oob_callbacks: Optional[str] = None

    # Operator-registered OAuth test apps (2026-XX-XX). Each entry declares an
    # OAuth 2.0 app the agent can install programmatically via oauth_install_tool
    # to obtain fresh opaque-style refresh tokens for token-lifecycle
    # verification (RFC 6749 §10.4 rotation-invalidation testing — the bug found
    # manually against ExampleChat on 2026-XX-XX). Credentials (client_id /
    # client_secret) live in env vars referenced by name — NEVER in the yaml.
    # Each entry: {name, client_id_env, client_secret_env, authorize_url,
    #              redirect_uri, token_url}.
    oauth_test_apps: list[dict] = field(default_factory=list)

    # Tier 2 (2026-XX-XX) — race-condition burst tool concurrent-request cap.
    # The race_request tool legitimately must bypass scope.rate_limits.
    # requests_per_second (a race burst is one logical "test" but happens
    # too fast for per-second throttling). This bypass is restricted to ONE
    # tool used by ONE vuln class (vuln:race + exploit:race); every other
    # tool still obeys the per-second rate limit. Default None → tool's
    # built-in default 50 concurrent requests applies. Operators on
    # permissive programs (e.g. ExampleMarket's 100 RPS/endpoint) can raise this
    # to 100 (hard ceiling enforced by the tool); strict programs can lower
    # to 10 or set to 0 to disable race testing entirely.
    race_test_concurrent_max: Optional[int] = None

    # ---- loading ---------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path, audit_log_path: str | Path | None = None) -> "Scope":
        path = Path(path)
        if not path.is_file():
            raise ScopeError(f"Scope file not found: {path}")

        raw_bytes = path.read_bytes()
        source_hash = hashlib.sha256(raw_bytes).hexdigest()
        try:
            data = yaml.safe_load(raw_bytes) or {}
        except yaml.YAMLError as e:
            raise ScopeError(f"Invalid YAML in scope file: {e}") from e

        required = ["client", "engagement_id", "authorized_by", "valid_from", "valid_until"]
        missing = [k for k in required if k not in data]
        if missing:
            raise ScopeError(f"Scope missing required fields: {missing}")

        targets = data.get("targets") or {}
        # Wave 3 — engagement mode parsing. Default = PRODUCTION when the
        # field is missing (backwards-compat for every existing scope.yaml).
        # Unknown values raise ModeError → wrapped as ScopeError so the
        # caller doesn't have to catch two exception classes.
        try:
            mode = EngagementMode.from_string(data.get("engagement_mode"))
        except ModeError as e:
            raise ScopeError(str(e)) from e

        scope = cls(
            client=str(data["client"]),
            engagement_id=str(data["engagement_id"]),
            authorized_by=str(data["authorized_by"]),
            authorization_doc=data.get("authorization_doc"),
            valid_from=_to_date(data["valid_from"], "valid_from"),
            valid_until=_to_date(data["valid_until"], "valid_until"),
            repos=list(targets.get("repos") or []),
            domains=list(targets.get("domains") or []),
            ips=list(targets.get("ips") or []),
            out_of_scope=list(data.get("out_of_scope") or []),
            rate_limit_rps=float((data.get("rate_limits") or {}).get("requests_per_second", 5.0)),
            raw=data,
            source_path=path,
            source_hash=source_hash,
            auth_credentials=list(data.get("auth_credentials") or []),
            research_headers=_load_research_headers(data.get("research_headers")),
            auth_cookies=_load_auth_cookies(data.get("auth_cookies")),
            # dict (single account) OR list[dict] (attacker+victim for BOLA).
            auth_refresh=(data.get("auth_refresh") or {}),
            oast_endpoint=(str(data["oast_endpoint"]).strip() if data.get("oast_endpoint") else None),
            engagement_mode=mode,
            ctf_platform=(str(data["ctf_platform"]).strip() if data.get("ctf_platform") else None),
            ctf_flag_format=(str(data["ctf_flag_format"]).strip() if data.get("ctf_flag_format") else None),
            ctf_box_writeup_dir=(str(data["ctf_box_writeup_dir"]).strip() if data.get("ctf_box_writeup_dir") else None),
            browser_strategy=_load_browser_strategy(data.get("browser_strategy")),
            chrome_profile_dir=(str(data["chrome_profile_dir"]).strip() if data.get("chrome_profile_dir") else None),
            chrome_cdp_port=_load_chrome_cdp_port(data.get("chrome_cdp_port")),
            bright_data_enabled=bool(data.get("bright_data_enabled", False)),
            bright_data=dict(data.get("bright_data") or {}),
            correlation_input_filter=_load_correlation_input_filter(
                data.get("correlation_input_filter"),
            ),
            # Phase 5 / NOVEL-04 — novelty escalation gate config.
            novelty_threshold=_load_novelty_threshold(
                data.get("novelty_threshold"),
            ),
            escalate_on_evidence_states=_load_escalate_on_evidence_states(
                data.get("escalate_on_evidence_states"),
            ),
            # Quick 260517-f7a (2026-XX-XX) — authenticated-target enablement.
            captcha_solver=_load_captcha_solver(data.get("captcha_solver")),
            allow_human_signup=_load_allow_human_signup(
                data.get("allow_human_signup"),
            ),
            # OOB callback infrastructure (interactsh) — opt-out for NDA engagements.
            oob_callbacks=_load_oob_callbacks(data.get("oob_callbacks")),
            # OAuth test apps (2026-XX-XX) — for token-lifecycle verification.
            oauth_test_apps=_load_oauth_test_apps(data.get("oauth_test_apps")),
            # Tier 2 (2026-XX-XX) — race-condition burst-tool concurrent cap.
            race_test_concurrent_max=_load_race_test_concurrent_max(
                data.get("race_test_concurrent_max"),
            ),
        )

        if scope.valid_until < scope.valid_from:
            raise ScopeError("valid_until is before valid_from")

        # LAB-mode safety net: refuse to load a scope that contains any
        # non-loopback / non-RFC1918 target. Raises OutOfScopeError —
        # which short-circuits before audit log is opened, intentional
        # (a misconfigured LAB scope file should never produce ANY
        # audit-log entry that claims it's a lab run).
        if mode == EngagementMode.LAB:
            assert_lab_mode_scope(scope)

        log_path = Path(audit_log_path) if audit_log_path else path.parent / f".audit-{scope.engagement_id}.jsonl"
        scope.audit_log = AuditLog(log_path)
        scope.audit_log.write(
            "scope_loaded",
            {
                "client": scope.client,
                "engagement_id": scope.engagement_id,
                "scope_sha256": scope.source_hash,
                "scope_path": str(path),
                "valid_from": scope.valid_from.isoformat(),
                "valid_until": scope.valid_until.isoformat(),
                "authorized_by": scope.authorized_by,
            },
            # Wave 3 — mode is stamped on every entry. The first entry's
            # mode field is what verify-audit cross-checks against the
            # scope file (anti-tamper for laundering attempts).
            mode=mode.value,
        )
        return scope

    # ---- mode propagation ------------------------------------------------

    def assert_mode_matches(self, cli_mode: Optional[str | EngagementMode]) -> None:
        """Validate that the operator's `--mode` flag matches the scope file.

        Disagreement is loud + fatal: the operator either typo'd the
        flag OR is trying to launder a CTF scope into a production run.
        Either way, refuse with a message that names BOTH values so the
        operator immediately sees the conflict.

        None / empty cli_mode is permissive (operator omitted the flag —
        scope's declared mode wins).
        """
        if cli_mode is None or cli_mode == "":
            return
        try:
            cli = (
                cli_mode if isinstance(cli_mode, EngagementMode)
                else EngagementMode.from_string(cli_mode)
            )
        except ModeError as e:
            raise ModeMismatchError(str(e)) from e
        if cli is not self.engagement_mode:
            raise ModeMismatchError(
                f"--mode {cli.value!r} disagrees with scope.yaml "
                f"engagement_mode {self.engagement_mode.value!r}. "
                f"Both must agree (or omit --mode to accept the scope's "
                f"declared mode)."
            )

    # ---- temporal validity -----------------------------------------------

    def is_currently_valid(self, today: Optional[date] = None) -> bool:
        today = today or datetime.now(timezone.utc).date()
        return self.valid_from <= today <= self.valid_until

    def assert_valid_now(self) -> None:
        if not self.is_currently_valid():
            self._log("denied", {"reason": "scope_expired_or_not_yet_valid"})
            raise OutOfScopeError(
                f"Scope window is {self.valid_from} .. {self.valid_until}; today is outside it."
            )

    # ---- target authorization --------------------------------------------

    def authorize_repo(self, repo_url_or_path: str) -> None:
        """Authorize a GitHub repo (URL or local clone path mapped to URL)."""
        self.assert_valid_now()
        normalized = _normalize_repo(repo_url_or_path)
        for allowed in self.repos:
            if _normalize_repo(allowed) == normalized:
                self._log("authorized", {"kind": "repo", "target": normalized})
                return
        self._log("denied", {"kind": "repo", "target": normalized, "reason": "not_in_scope"})
        raise OutOfScopeError(f"Repo not in scope: {normalized}")

    def authorize_url(self, url: str) -> None:
        """Authorize a URL for active probing. Resolves host and checks domain + IP."""
        self.assert_valid_now()
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = parsed.hostname
        if not host:
            self._log("denied", {"kind": "url", "target": url, "reason": "no_host"})
            raise OutOfScopeError(f"URL has no host: {url}")

        # Out-of-scope wins, always.
        for pattern in self.out_of_scope:
            if _domain_matches(host, pattern):
                self._log("denied", {"kind": "url", "target": url, "reason": "out_of_scope_match", "pattern": pattern})
                raise OutOfScopeError(f"URL is explicitly out of scope ({pattern}): {url}")

        # Domain match.
        domain_ok = any(_domain_matches(host, pattern) for pattern in self.domains)

        # IP match (after resolving). We only resolve once and only when needed.
        ip_ok = False
        resolved_ips: list[str] = []
        if self.ips:
            try:
                resolved_ips = list({info[4][0] for info in socket.getaddrinfo(host, None)})
            except socket.gaierror:
                resolved_ips = []
            for resolved in resolved_ips:
                for cidr in self.ips:
                    if _ip_in_cidr(resolved, cidr):
                        ip_ok = True
                        break
                if ip_ok:
                    break

        if not (domain_ok or ip_ok):
            self._log(
                "denied",
                {
                    "kind": "url",
                    "target": url,
                    "host": host,
                    "resolved_ips": resolved_ips,
                    "reason": "not_in_scope",
                },
            )
            raise OutOfScopeError(f"URL not in scope: {url}")

        self._log(
            "authorized",
            {"kind": "url", "target": url, "host": host, "matched_by": "domain" if domain_ok else "ip"},
        )

    def authorize_artifact(self, kind: str, identifier: str) -> None:
        """For passive analysis (config files, dependency manifests).

        Still logged so the engagement record shows what was reviewed, but no
        network check is performed. Caller is responsible for ensuring the
        artifact came from an in-scope source.
        """
        self.assert_valid_now()
        self._log("authorized", {"kind": kind, "target": identifier, "mode": "passive"})

    # ---- oauth test apps --------------------------------------------------

    def matches_oauth_test_app(self, url: str) -> Optional[dict]:
        """Return the oauth_test_apps entry whose token_url host matches `url`'s
        host, else None.

        Used by the token-lifecycle verifier to find the operator-registered
        OAuth app for a finding's endpoint (so it can read the captured refresh
        tokens and run the RFC 6749 §10.4 rotation/replay probe). Host-only
        comparison — query strings / paths are ignored.
        """
        if not url:
            return None
        target_host = (urlparse(url if "://" in url else f"https://{url}").hostname or "").lower()
        if not target_host:
            return None
        for app in self.oauth_test_apps:
            app_host = (urlparse(app.get("token_url", "")).hostname or "").lower()
            if app_host and app_host == target_host:
                return app
        return None

    # ---- internals --------------------------------------------------------

    def _log(self, event: str, payload: dict) -> None:
        if self.audit_log:
            self.audit_log.write(
                event,
                {"engagement_id": self.engagement_id, **payload},
                mode=self.engagement_mode.value,
            )


# ---- helpers --------------------------------------------------------------


def _load_research_headers(raw: Any) -> dict[str, str]:
    """Coerce the research_headers yaml block to a clean str→str dict.

    Empty / None → empty dict (default behavior; no headers injected).
    Anything that isn't dict-shaped raises ScopeError so a typo doesn't
    silently disable researcher tagging on every test request.
    """
    if raw is None or raw == "":
        return {}
    if not isinstance(raw, dict):
        raise ScopeError(
            f"research_headers must be a mapping (key: value pairs), got {type(raw).__name__}"
        )
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not k.strip():
            raise ScopeError(f"research_headers contains non-string or empty key: {k!r}")
        out[k.strip()] = "" if v is None else str(v).strip()
    return out


def _load_auth_cookies(raw: Any) -> list[dict]:
    """Coerce the auth_cookies yaml block to a normalized list of dicts.

    Each entry must have at minimum `name` and `value`. `domain` defaults
    to "" (which means "match any host"). Other fields default sensibly.
    Anything malformed raises ScopeError so a typo doesn't silently
    disable bypass on every request.

    Schema (one entry):
        - name: datadome              # required
          value: '<token>'            # required
          domain: '.ExamplePay.com'       # optional, leading-dot matches subdomains
          path: /                     # optional, default '/'
          secure: true                # optional, default true
          httpOnly: false             # optional, default false
          expires: '2026-XX-XXT03:00:00Z'  # optional ISO8601, past = skipped
    """
    if raw is None or raw == "":
        return []
    if not isinstance(raw, list):
        raise ScopeError(
            f"auth_cookies must be a list of cookie objects, got {type(raw).__name__}"
        )
    out: list[dict] = []
    for i, c in enumerate(raw):
        if not isinstance(c, dict):
            raise ScopeError(f"auth_cookies[{i}] must be a mapping, got {type(c).__name__}")
        name = c.get("name")
        value = c.get("value")
        if not name or not isinstance(name, str):
            raise ScopeError(f"auth_cookies[{i}] missing or invalid 'name'")
        if value is None:
            raise ScopeError(f"auth_cookies[{i}] missing 'value' (use empty string for blank)")
        normalized = {
            "name": str(name).strip(),
            "value": str(value),
            "domain": str(c.get("domain", "")).strip(),
            "path": str(c.get("path", "/")).strip() or "/",
            "secure": bool(c.get("secure", True)),
            "httpOnly": bool(c.get("httpOnly", False)),
        }
        if "expires" in c and c["expires"]:
            normalized["expires"] = str(c["expires"])
        out.append(normalized)
    return out


_ALLOWED_BROWSER_STRATEGIES = {"playwright_spawn", "cdp", "agent_browser_cdp"}


# Quick 260517-f7a (2026-XX-XX) — supported captcha-solver backends.
# Only NopeCHA today; extend the set when a second solver lands.
_ALLOWED_CAPTCHA_SOLVERS = {"nopecha"}


def _load_captcha_solver(raw: Any) -> Optional[str]:
    """Normalize + validate the captcha_solver field.

    None / empty → None (no NopeCHA activation; back-compat default).
    Anything not in _ALLOWED_CAPTCHA_SOLVERS raises ScopeError naming
    the supported set so the operator's misspelling fails loudly at
    scope-load time rather than silently disabling captcha solving.
    """
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise ScopeError(
            f"captcha_solver must be a string, got {type(raw).__name__}"
        )
    value = raw.strip().lower()
    if value not in _ALLOWED_CAPTCHA_SOLVERS:
        raise ScopeError(
            f"unknown captcha_solver {raw!r} — supported: "
            f"{sorted(_ALLOWED_CAPTCHA_SOLVERS)}"
        )
    return value


def _load_allow_human_signup(raw: Any) -> bool:
    """Normalize + validate the allow_human_signup field.

    None / empty → False (back-compat default; human_signup tool refuses).
    Explicit YAML bool (true / false) accepted. NO string coercion —
    "yes" / 1 / 0 all raise ScopeError so a typo doesn't silently enable
    an operator-pause path that should require explicit opt-in.
    """
    if raw is None or raw == "":
        return False
    if isinstance(raw, bool):
        return raw
    raise ScopeError(
        f"allow_human_signup must be true or false, "
        f"got {type(raw).__name__}: {raw!r}"
    )


def _load_oob_callbacks(raw: Any) -> Optional[str]:
    """Normalize + validate the oob_callbacks field.

    None / empty → None (OOB enabled; default behavior — agent gets a fresh
    interactsh token per payload and reads DNS/HTTP/SMTP callbacks against
    interact.sh public infra).

    "disabled" → register_oob_token + check_oob_callback refuse with _err.
    Used on NDA engagements where third-party data flow to a public callback
    server is unacceptable per SOW.

    Anything else → ScopeError. A typo like "enabled" or "off" must fail
    loudly at scope-load time rather than silently leaving OOB enabled when
    the operator thought they were opting out.
    """
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise ScopeError(
            f"oob_callbacks must be a string ('disabled') or unset, "
            f"got {type(raw).__name__}: {raw!r}"
        )
    value = raw.strip().lower()
    if value != "disabled":
        raise ScopeError(
            f"oob_callbacks must be unset or 'disabled', got {raw!r}"
        )
    return value


_OAUTH_TEST_APP_REQUIRED_FIELDS = (
    "name", "client_id_env", "client_secret_env",
    "authorize_url", "redirect_uri", "token_url",
)


def _load_oauth_test_apps(raw: Any) -> list[dict]:
    """Normalize + validate the oauth_test_apps yaml block (2026-XX-XX).

    None / empty → [] (no OAuth install capability; back-compat default).

    Each entry must be a dict with all six required fields. Duplicate `name`
    values are rejected (the verifier + oauth_install_app look apps up by name,
    so collisions would silently shadow one). Anything malformed raises
    ScopeError so a typo fails loud at scope-load time rather than silently
    disabling token-lifecycle verification.
    """
    if raw is None or raw == "":
        return []
    if not isinstance(raw, list):
        raise ScopeError(
            f"oauth_test_apps must be a list of app objects, got {type(raw).__name__}"
        )
    seen_names: set[str] = set()
    out: list[dict] = []
    for i, app in enumerate(raw):
        if not isinstance(app, dict):
            raise ScopeError(
                f"oauth_test_apps[{i}] must be a mapping, got {type(app).__name__}"
            )
        missing = [f for f in _OAUTH_TEST_APP_REQUIRED_FIELDS if not app.get(f)]
        if missing:
            raise ScopeError(
                f"oauth_test_apps[{i}] missing required field(s): {missing}"
            )
        name = str(app["name"]).strip()
        if name in seen_names:
            raise ScopeError(f"oauth_test_apps has duplicate name: {name!r}")
        seen_names.add(name)
        out.append({
            "name": name,
            "client_id_env": str(app["client_id_env"]).strip(),
            "client_secret_env": str(app["client_secret_env"]).strip(),
            "authorize_url": str(app["authorize_url"]).strip(),
            "redirect_uri": str(app["redirect_uri"]).strip(),
            "token_url": str(app["token_url"]).strip(),
            "workspace_login_required": bool(app.get("workspace_login_required", False)),
        })
    return out


def _load_race_test_concurrent_max(raw: Any) -> Optional[int]:
    """Normalize + validate the race_test_concurrent_max field (2026-XX-XX).

    None / empty / missing → None (tool falls back to its built-in default 50).

    Integer in [0, 100] → that exact value (0 disables race testing
    entirely; the tool refuses bursts). Hard ceiling of 100 enforced here
    so a typo'd 10000 fails loud rather than silently DDoSing a target.

    Anything else (negative, > 100, string, float) → ScopeError. We do NOT
    string-coerce ('50' → 50) because the rate-limit-bypass semantics make
    this a security-relevant setting and silent coercion is the wrong default.
    """
    if raw is None or raw == "":
        return None
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ScopeError(
            f"race_test_concurrent_max must be an integer in [0, 100], "
            f"got {type(raw).__name__}: {raw!r}"
        )
    if raw < 0 or raw > 100:
        raise ScopeError(
            f"race_test_concurrent_max must be in [0, 100] (got {raw}). "
            f"0 disables race testing; 100 is the hard ceiling."
        )
    return raw


def _load_browser_strategy(raw: Any) -> Optional[str]:
    """Normalize + validate browser_strategy field.

    None / empty / 'playwright_spawn' all mean "use the existing Playwright
    spawn path" — None is the canonical back-compat value. 'cdp' attaches
    to a user-launched real Chrome via CDP. 'agent_browser_cdp' is reserved
    for a future PR (today behaves like 'cdp').
    """
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise ScopeError(
            f"browser_strategy must be a string, got {type(raw).__name__}"
        )
    value = raw.strip().lower()
    if value not in _ALLOWED_BROWSER_STRATEGIES:
        raise ScopeError(
            f"browser_strategy must be one of "
            f"{sorted(_ALLOWED_BROWSER_STRATEGIES)}, got {raw!r}"
        )
    return value


_ALLOWED_CORRELATION_INPUT_FILTERS = {
    "verified_only", "include_manual_required", "all",
}
_DEFAULT_CORRELATION_INPUT_FILTER = "verified_only"


def _load_correlation_input_filter(raw: Any) -> str:
    """Plan 03-05 (VERIFY-08) — validate correlation_input_filter.

    None / empty → default 'verified_only'. Unknown value raises ScopeError
    naming the valid options so the operator's misspelling fails loudly at
    scope-load time rather than silently falling through to the default.
    """
    if raw is None or raw == "":
        return _DEFAULT_CORRELATION_INPUT_FILTER
    if not isinstance(raw, str):
        raise ScopeError(
            f"correlation_input_filter must be a string, "
            f"got {type(raw).__name__}"
        )
    value = raw.strip().lower()
    if value not in _ALLOWED_CORRELATION_INPUT_FILTERS:
        raise ScopeError(
            f"correlation_input_filter must be one of "
            f"{sorted(_ALLOWED_CORRELATION_INPUT_FILTERS)}, got {raw!r}"
        )
    return value


def _load_novelty_threshold(raw: Any) -> float:
    """Phase 5 / NOVEL-04 — validate novelty_threshold.

    None / missing → default 0.75 (NOVEL-04 spec). Out-of-range raises
    ScopeError mentioning the valid [0.0, 1.0] range so the operator's
    misconfigured value fails loud at scope-load time rather than
    silently disabling escalation.
    """
    if raw is None or raw == "":
        return 0.75
    try:
        value = float(raw)
    except (TypeError, ValueError) as e:
        raise ScopeError(
            f"novelty_threshold must be a number in [0.0, 1.0], got {raw!r}"
        ) from e
    if not (0.0 <= value <= 1.0):
        raise ScopeError(
            f"novelty_threshold must be in [0.0, 1.0], got {value!r}"
        )
    return value


def _load_escalate_on_evidence_states(raw: Any) -> list:
    """Phase 5 / NOVEL-04 — validate escalate_on_evidence_states.

    None / missing → default ["verified"] (VERIFY-08 contract). Each entry
    must validate against the EvidenceState enum; unknown values raise
    ScopeError so a typo doesn't silently disable escalation on every
    finding.
    """
    if raw is None or raw == "":
        return ["verified"]
    if not isinstance(raw, list):
        raise ScopeError(
            f"escalate_on_evidence_states must be a list of evidence_state "
            f"strings, got {type(raw).__name__}"
        )
    # Import locally to avoid a circular import at module load time
    # (findings.py imports nothing from scope.py, but defensive).
    from sentinel.core.findings import EvidenceState

    out: list = []
    for entry in raw:
        if not isinstance(entry, str):
            raise ScopeError(
                f"escalate_on_evidence_states entry must be a string, "
                f"got {type(entry).__name__}: {entry!r}"
            )
        try:
            # EvidenceState.from_string is permissive and falls back to
            # RECON_INFERRED for unknown strings — that's not what we want
            # here (we want LOUD failure for a typo). Use the strict
            # constructor with the snake_case→hyphen normalization Plan
            # 03-05 added in EvidenceState.from_string.
            normalized = entry.lower().strip()
            if normalized == "manual_required":
                normalized = "manual-required"
            try:
                EvidenceState(normalized)
            except ValueError as e:
                raise ScopeError(
                    f"unknown evidence_state in escalate_on_evidence_states: "
                    f"{entry!r} (valid values: "
                    f"{sorted(s.value for s in EvidenceState)})"
                ) from e
        except ScopeError:
            raise
        out.append(entry)
    return out


def _load_chrome_cdp_port(raw: Any) -> int:
    """Normalize + validate chrome_cdp_port. Default 9222."""
    if raw is None or raw == "":
        return 9222
    try:
        port = int(raw)
    except (TypeError, ValueError) as e:
        raise ScopeError(f"chrome_cdp_port must be an integer, got {raw!r}") from e
    if not (1 <= port <= 65535):
        raise ScopeError(f"chrome_cdp_port must be 1-65535, got {port}")
    return port


def _to_date(value: Any, field_name: str) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError as e:
            raise ScopeError(f"{field_name} must be ISO date (YYYY-MM-DD): {e}") from e
    raise ScopeError(f"{field_name} has unsupported type: {type(value).__name__}")


_REPO_RE = re.compile(r"(?:https?://|git@|ssh://git@)?([a-zA-Z0-9_.\-]+)[:/]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$")


def _normalize_repo(s: str) -> str:
    """Normalize a repo reference to 'host/owner/name' (lowercase). Best effort."""
    s = s.strip()
    m = _REPO_RE.match(s)
    if m:
        host, owner, name = m.group(1), m.group(2), m.group(3)
        return f"{host.lower()}/{owner.lower()}/{name.lower()}"
    return s.lower()


def _domain_matches(host: str, pattern: str) -> bool:
    """Match host against pattern. Supports leading '*.' wildcard.

    Wildcard is single-label only, matching DNS/TLS-certificate convention:
      *.example.com       matches example.com, foo.example.com
      *.example.com       does NOT match foo.bar.example.com
    To cover deeper levels the scope must list them explicitly. This is
    intentional — scope ambiguity is a vector for accidental over-scanning.
    """
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if host == suffix:
            return True
        if not host.endswith("." + suffix):
            return False
        # Allow exactly one extra label between host and suffix.
        prefix = host[: -(len(suffix) + 1)]  # strip trailing '.suffix'
        return "." not in prefix and prefix != ""
    return host == pattern


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


# ---- audit log ------------------------------------------------------------


class AuditLog:
    """Append-only JSONL log with hash-chained entries.

    Each line is JSON with: ts, event, prev_hash, payload, this_hash.
    `this_hash = sha256(prev_hash || ts || event || json(payload))`.

    To verify integrity later: walk the file, recompute each `this_hash`,
    confirm it matches and that each line's `prev_hash` equals the previous
    line's `this_hash`. Tampering with any line invalidates everything after.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"
        last = ""
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if not last:
            return "GENESIS"
        try:
            return json.loads(last)["this_hash"]
        except (json.JSONDecodeError, KeyError):
            return "CORRUPT"

    def write(self, event: str, payload: dict, *, mode: Optional[str] = None) -> None:
        """Append an entry. Wave 3 — the optional `mode` argument stamps
        the engagement mode on every entry; `Scope._log` passes its own
        `engagement_mode.value` through. Hash chain still covers every
        field (mode included), so any tamper-attempt that drops the
        mode field is detectable by `AuditLog.verify`.

        Direct callers (tools that hold an AuditLog reference but not
        a Scope) can pass mode explicitly; if omitted, the entry has
        no mode field. Pre-Wave-3 callers continue to work unchanged.
        """
        ts = datetime.now(timezone.utc).isoformat()
        body: dict[str, Any] = {
            "ts": ts,
            "event": event,
            "prev_hash": self._last_hash,
            "payload": payload,
        }
        if mode is not None:
            body["mode"] = str(mode)
        digest_input = (
            f"{self._last_hash}|{ts}|{event}|{json.dumps(payload, sort_keys=True)}"
        )
        if mode is not None:
            digest_input += f"|{mode}"
        body["this_hash"] = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, sort_keys=True) + "\n")
        self._last_hash = body["this_hash"]

    @staticmethod
    def verify(
        path: str | Path,
        *,
        scope_mode: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        """Return (ok, error_msg). Re-walks the chain to detect tampering.

        Wave 3 — when `scope_mode` is provided (the operator's scope file
        currently declares this mode), the verifier ALSO checks that the
        first entry's `mode` field matches. Mismatch → fail with a clear
        message ("audit log claims production but scope declares ctf"),
        which catches the laundering attempt where someone edits scope.yaml
        after a CTF run to claim it was a production run.

        Backwards-compat: entries without a `mode` field hash without
        the mode salt, so pre-Wave-3 audit logs still verify cleanly.
        """
        path = Path(path)
        if not path.exists():
            return False, "audit log does not exist"
        prev = "GENESIS"
        first_mode: Optional[str] = None
        with path.open("r", encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    return False, f"line {i}: invalid JSON: {e}"
                if entry.get("prev_hash") != prev:
                    return False, f"line {i}: prev_hash mismatch"
                digest_input = (
                    f"{entry['prev_hash']}|{entry['ts']}|{entry['event']}|"
                    f"{json.dumps(entry['payload'], sort_keys=True)}"
                )
                if "mode" in entry:
                    digest_input += f"|{entry['mode']}"
                expected = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
                if expected != entry.get("this_hash"):
                    return False, f"line {i}: this_hash mismatch"
                if i == 1:
                    first_mode = entry.get("mode")
                prev = entry["this_hash"]

        if scope_mode is not None and first_mode is not None and first_mode != scope_mode:
            return False, (
                f"mode mismatch: audit log first entry mode={first_mode!r} "
                f"but scope file declares engagement_mode={scope_mode!r}"
            )
        return True, None
