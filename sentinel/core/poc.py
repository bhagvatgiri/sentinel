"""Proof-of-concept enricher.

Per Finding, generate four devops-ready fields:

    impact            — 1-2 sentence "what an attacker can do" / business risk
    proof_of_concept  — copy-pasteable command that demonstrates the issue (curl,
                        dig, openssl s_client, etc.)
    expected_output   — what the PoC's output literally looks like when the
                        finding is real (so a devops engineer running the PoC
                        knows exactly what "vulnerable" looks like)
    validation        — copy-pasteable command that should produce "FIXED" output
                        after the remediation is applied

Pattern-based dispatch keyed on (scanner, title-keyword) — no LLM call needed
for the common header/dns/tls findings, so this runs fast and deterministically
even when Ollama is unavailable. For findings the patterns don't recognise we
fall back to a generic skeleton that still gives the devops team something to
copy.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

from sentinel.core.findings import Finding


def enrich_finding(f: Finding) -> Finding:
    """Mutate the Finding with impact / proof_of_concept / expected_output / validation."""
    if f.proof_of_concept and f.impact and f.validation and f.expected_output:
        return f  # already enriched (idempotent)

    builder = _BUILDERS.get(f.scanner)
    if builder is None:
        builder = _generic
    impact, poc, expected, validation = builder(f)
    if impact and not f.impact:
        f.impact = impact
    if poc and not f.proof_of_concept:
        f.proof_of_concept = poc
    if expected and not f.expected_output:
        f.expected_output = expected
    if validation and not f.validation:
        f.validation = validation
    return f


# ---- helpers ----------------------------------------------------------------


def _host_of(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return parsed.hostname or target


def _url_with_path(target: str, path: Optional[str]) -> str:
    if not path or path.startswith(("http://", "https://")):
        return path or target
    base = target.rstrip("/")
    return base + (path if path.startswith("/") else f"/{path}")


# ---- per-scanner builders (4-tuple: impact, poc, expected_output, validation) ----


def _headers(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """HTTP security-headers findings."""
    title = f.title.lower()
    url = _url_with_path(f.target, f.location)

    # (title-needle, header_name, friendly, impact)
    header_specs = [
        ("strict-transport-security", "Strict-Transport-Security", "HSTS",
         "An attacker on the same network (open WiFi, malicious ISP, hostile gov network) can downgrade the user's connection from HTTPS to HTTP and intercept session cookies, credentials, or rewritten content."),
        ("content-security-policy", "Content-Security-Policy", "CSP",
         "Without a CSP, any reflected/stored XSS in your app can pull and execute scripts from arbitrary origins — your defense-in-depth against XSS is missing."),
        ("x-content-type-options", "X-Content-Type-Options", "nosniff",
         "Browsers MIME-sniff responses without this header. An attacker who can upload a file (avatar, document) may have it executed as JS or HTML."),
        ("x-frame-options", "X-Frame-Options", "X-Frame-Options",
         "An attacker can iframe your authenticated pages and trick users into clicking buttons (clickjacking) — e.g. \"transfer funds\" while the user thinks they're playing a game."),
        ("frame protection", "X-Frame-Options", "frame protection",
         "An attacker can iframe your authenticated pages and trick users into clicking buttons (clickjacking) — e.g. \"transfer funds\" while the user thinks they're playing a game."),
        ("referrer-policy", "Referrer-Policy", "Referrer-Policy",
         "Outbound clicks leak the full referrer (including any tokens in the path/query) to third-party sites in your HTML — analytics scripts, embedded images, ads."),
        ("permissions-policy", "Permissions-Policy", "Permissions-Policy",
         "Third-party iframes embedded on your pages can request camera, mic, geolocation, etc. without restriction. Tightening this is defense-in-depth for compromised dependencies."),
        ("includesubdomains", "Strict-Transport-Security", "HSTS includeSubDomains",
         "Subdomains of this site (e.g. api.{host}, dev.{host}) are not protected by HSTS, so an attacker can downgrade them and steal subdomain cookies — which often share auth state via cookie scope."),
        ("samesite", "Set-Cookie", "Cookie SameSite",
         "Without SameSite=Lax/Strict, an attacker can craft cross-site requests that include this app's session cookie — full CSRF surface on every state-changing endpoint."),
        ("server version", "Server", "Server header",
         "Disclosed server version lets an attacker look up known CVEs against your exact version and skip the reconnaissance step. Low-risk by itself but accelerates targeted attacks."),
        ("x-powered-by", "X-Powered-By", "X-Powered-By",
         "Same as server version disclosure: tells attackers exactly what stack/framework to target with version-specific exploits."),
    ]

    for needle, header_name, friendly, impact in header_specs:
        if needle in title:
            poc = (
                f"# Show that {header_name!r} is missing or misconfigured\n"
                f"curl -sI {url} | grep -i '{header_name}' || echo 'MISSING: {header_name}'"
            )
            expected = (
                f"MISSING: {header_name}\n"
                f"# (the grep returned no header line, so the fallback echo fired)"
            )
            validation = (
                f"# After remediation, this should print the header value (no MISSING)\n"
                f"curl -sI {url} | grep -i '{header_name}'"
            )
            return impact, poc, expected, validation

    poc = f"curl -sIv {url} 2>&1 | head -40"
    return None, poc, "(headers dump — vulnerable when expected security headers are absent)", f"curl -sI {url}"


def _dns(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """DNS / email-security findings."""
    title = f.title.lower()
    host = _host_of(f.target)

    if "dmarc" in title:
        return (
            f"Without DMARC, attackers can spoof email from @{host} and the receiving "
            f"mail servers will deliver it. Phishing campaigns impersonating your domain "
            f"will bypass receiver-side filtering.",
            f"# Show that no DMARC record exists\n"
            f"dig +short TXT _dmarc.{host} || echo 'no DMARC record'",
            f"no DMARC record\n"
            f"# (dig returned no TXT, fallback echo fired)",
            f"# After publishing the policy, should print v=DMARC1; p=reject; ...\n"
            f"dig +short TXT _dmarc.{host}",
        )
    if "spf" in title:
        return (
            f"Without an SPF record (or with a soft-fail ~all instead of hard-fail -all), "
            f"attackers can send mail claiming to be from @{host} from any server, and "
            f"recipients will accept it. Direct phishing risk.",
            f"# Show current SPF (or absence thereof)\n"
            f"dig +short TXT {host} | grep -i 'v=spf1' || echo 'no SPF record'",
            f"no SPF record\n"
            f"# OR for soft-fail: \"v=spf1 ... ~all\" (the ~all is the issue — should be -all)",
            f"# Should print 'v=spf1 ... -all' after fix (note hard-fail -all, not ~all)\n"
            f"dig +short TXT {host} | grep -i 'v=spf1'",
        )
    if "dkim" in title:
        return (
            f"Without DKIM, recipients can't verify that mail from @{host} actually came "
            f"from your servers. Combined with missing SPF/DMARC, this enables silent "
            f"impersonation.",
            f"# Probe common DKIM selectors\n"
            f"for s in default google selector1 selector2 mail; do\n"
            f"  echo \"$s:\"; dig +short TXT $s._domainkey.{host}\n"
            f"done",
            f"default:\ngoogle:\nselector1:\nselector2:\nmail:\n"
            f"# (every selector returned empty — no DKIM configured under common names)",
            f"# After setup, the chosen selector should return v=DKIM1;k=rsa;p=...\n"
            f"dig +short TXT default._domainkey.{host}",
        )
    if "caa" in title:
        return (
            f"Without CAA records, ANY public CA can issue a certificate for {host}. "
            f"A compromised or malicious CA could issue a cert for your domain "
            f"undetected. CAA tells CAs whether they're authorised.",
            f"dig +short CAA {host} || echo 'no CAA records'",
            f"no CAA records",
            f"# Should list CAs you authorise, e.g. 0 issue \"letsencrypt.org\"\n"
            f"dig +short CAA {host}",
        )
    if "dnssec" in title:
        return (
            f"Without DNSSEC signing, an on-path attacker (rogue resolver, BGP hijack) can "
            f"return forged DNS responses for {host}. DNSSEC lets resolvers verify the "
            f"records weren't tampered with.",
            f"dig +short DS {host} || echo 'not DNSSEC-signed'",
            f"not DNSSEC-signed",
            f"# Should print DS record set after enabling DNSSEC at the registrar\n"
            f"dig +short DS {host}",
        )
    if "wildcard" in title:
        return (
            f"A wildcard DNS record (*.{host}) means any subdomain you haven't "
            f"explicitly defined still resolves. If you have subdomain-based auth or "
            f"cookie scoping, this can be abused for subdomain takeover and cookie theft.",
            f"# Confirm wildcard by querying a non-existent subdomain\n"
            f"dig +short totally-fake-name-12345.{host}",
            f"<some IP address>\n"
            f"# (a made-up subdomain resolved to an IP — only possible if a wildcard exists)",
            f"# After narrowing, the made-up name above should return nothing\n"
            f"dig +short totally-fake-name-12345.{host}",
        )
    if "mx" in title:
        return (
            f"No MX records means {host} cannot receive mail directly. If your domain is "
            f"meant to handle mail, add MX. If not (web-only domain), add a null MX "
            f"(\"0 .\") to explicitly refuse mail and prevent spoofing.",
            f"dig +short MX {host}",
            f"# (no output — no MX records exist)",
            f"dig +short MX {host}  # should list real MX servers OR return '0 .'",
        )

    return None, f"dig +short ANY {host}", f"# (dig output for {host}; vulnerable per scanner-specific rule)", f"dig +short ANY {host}"


def _tls(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """TLS hygiene findings."""
    host = _host_of(f.target)
    title = f.title.lower()

    if "hsts" in title:
        return (
            f"Same as the headers-audit HSTS finding: an attacker on a hostile network "
            f"can downgrade users from HTTPS to HTTP on the first request.",
            f"openssl s_client -connect {host}:443 -servername {host} </dev/null 2>/dev/null "
            f"| openssl x509 -noout -dates -subject -issuer\n"
            f"curl -sI https://{host}/ | grep -i 'strict-transport-security' || echo 'MISSING'",
            f"notBefore=...\nnotAfter=...\nsubject=CN={host}\nissuer=...\n"
            f"MISSING\n"
            f"# (cert details print, then HSTS check returns MISSING)",
            f"curl -sI https://{host}/ | grep -i 'strict-transport-security'",
        )
    return None, (
        f"openssl s_client -connect {host}:443 -servername {host} -showcerts </dev/null 2>/dev/null "
        f"| openssl x509 -noout -text | head -40"
    ), (
        f"# (X.509 cert dump — vulnerable per scanner-specific rule, see description)"
    ), (
        f"openssl s_client -connect {host}:443 -servername {host} </dev/null 2>/dev/null "
        f"| openssl x509 -noout -dates"
    )


def _nuclei(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """nuclei findings — embed the captured request/response when available."""
    template = (f.raw or {}).get("template") or "?"
    matched = (f.raw or {}).get("matched") or f.location or f.target
    request = (f.raw or {}).get("request") or ""
    response = (f.raw or {}).get("response") or ""
    extracted = (f.raw or {}).get("extracted-results") or []

    impact = None
    if f.cve:
        impact = (
            f"This finding maps to {f.cve}; an attacker with knowledge of the CVE can "
            f"likely exploit the affected component. Validate manually before remediating."
        )
    poc = (
        f"# Re-run just this template to confirm the match\n"
        f"nuclei -u {f.target} -id {template} -irr -v\n"
        f"# Original match location:\n#   {matched}"
    )

    expected_parts = []
    if extracted:
        expected_parts.append("# Extracted values (proof of detection):")
        for v in (extracted if isinstance(extracted, list) else [extracted]):
            expected_parts.append(f"#   {v}")
    if request:
        expected_parts.append("# === HTTP request that triggered the match ===")
        expected_parts.append(str(request)[:2000])
    if response:
        expected_parts.append("# === HTTP response showing the vulnerable signature ===")
        expected_parts.append(str(response)[:2000])
    if not expected_parts:
        expected_parts.append(f"# Template {template} matched at {matched}; re-run with -irr to see request/response.")
    expected = "\n".join(expected_parts)

    validation = (
        f"# After patching, the same template should return no match\n"
        f"nuclei -u {f.target} -id {template}"
    )
    return impact, poc, expected, validation


def _shannon(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Shannon (active autonomous pentest) findings."""
    raw = f.raw or {}
    request = raw.get("request") or ""
    response = raw.get("response") or ""
    shannon_md = raw.get("shannon_report_md") or ""
    impact = (
        f"Shannon successfully exploited this vulnerability against the target. "
        f"This is not a heuristic detection — Shannon obtained evidence of impact "
        f"(state mutation, data access, or auth bypass) during the run."
    )
    poc = (
        f"# Re-run Shannon against just this finding's target\n"
        f"npx @keygraph/shannon start --target {f.target} --focus '{f.title}'"
    )

    expected_parts = []
    if shannon_md:
        expected_parts.append("# === Shannon's reproduction notes ===")
        expected_parts.append(shannon_md[:3000])
    if request:
        expected_parts.append("# === Exploit request ===")
        expected_parts.append(str(request)[:2000])
    if response:
        expected_parts.append("# === Server response (proof of exploitation) ===")
        expected_parts.append(str(response)[:2000])
    if not expected_parts:
        expected_parts.append("# Shannon reported a successful exploitation; see triage_notes for details.")
    expected = "\n".join(expected_parts)

    validation = (
        f"# After remediation, Shannon should NOT be able to reproduce the exploit\n"
        f"npx @keygraph/shannon start --target {f.target} --focus '{f.title}'"
    )
    return impact, poc, expected, validation


def _semgrep(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    impact = "An attacker familiar with this code path may be able to exploit the pattern. Severity reflects the rule, not necessarily the production impact — review the data flow."
    loc = f.location or "<file>"
    poc = f"# View the flagged code\nsed -n '$(echo {loc} | cut -d: -f2)p' $(echo {loc} | cut -d: -f1)"
    expected = "# (the printed line is the vulnerable code — match it against the rule's intent)"
    validation = "# Re-run semgrep on the same path\nsemgrep --config p/security-audit <path>"
    return impact, poc, expected, validation


def _gitleaks(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    impact = (
        "A leaked credential in source control is assumed compromised. Treat as breach: "
        "rotate the credential immediately, then scrub history with git-filter-repo or BFG, "
        "then audit logs for unauthorized use of the secret."
    )
    poc = "git log -p -- <file> | grep -i <secret-prefix>   # find the commit that introduced it"
    expected = "# A line of git diff output containing the secret string — proof it was committed."
    validation = "gitleaks dir --source <repo> | grep <fingerprint>   # should be empty after rotation+scrub"
    return impact, poc, expected, validation


def _osv(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    cve = f.cve or "<CVE>"
    impact = (
        f"Vulnerable dependency. Risk depends on whether the affected code path is "
        f"reachable in your usage. Look up {cve} for exploitation details."
    )
    poc = f"osv-scanner -L <lockfile>   # confirm the package version is still vulnerable"
    expected = f"# osv-scanner output containing {cve} for the affected package — proof it's still in your tree."
    validation = f"osv-scanner -L <lockfile> | grep {cve}   # should be empty after upgrade"
    return impact, poc, expected, validation


def _zap(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """OWASP ZAP findings — embed the captured request/evidence."""
    raw = f.raw or {}
    method = raw.get("method") or "GET"
    request = raw.get("request") or ""  # ZAP puts the attack payload here
    response = raw.get("response") or ""  # ZAP puts the matching evidence here
    param = raw.get("param") or ""
    plugin = raw.get("zap_pluginid") or "?"
    location = f.location or f.target

    impact = f"ZAP plugin {plugin} flagged this. Confidence: {raw.get('zap_confidence','?')}. Manually verify the evidence before reporting."
    poc = (
        f"# Reproduce with the same request ZAP sent:\n"
        f"curl -sSiX {method} '{location}'"
        + (f" --data '{request}'" if request and method.upper() != "GET" else "")
        + (f"   # parameter under test: {param}" if param else "")
    )

    expected_parts = []
    if request:
        expected_parts.append("# === ZAP attack payload ===")
        expected_parts.append(str(request)[:1500])
    if response:
        expected_parts.append("# === Evidence in response ===")
        expected_parts.append(str(response)[:1500])
    if not expected_parts:
        expected_parts.append(f"# ZAP plugin {plugin} matched at {location}")
    expected = "\n".join(expected_parts)

    validation = f"# After patching, re-run zap-baseline.py and confirm this alert is gone:\nzap-baseline.py -t {f.target}"
    return impact, poc, expected, validation


def _wapiti(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Wapiti findings — surface the http_request + curl_command if present."""
    raw = f.raw or {}
    method = raw.get("method") or "GET"
    param = raw.get("param") or ""
    request = raw.get("request") or ""
    response = raw.get("response") or ""
    curl = raw.get("curl-command") or ""
    location = f.location or f.target

    impact = (
        f"Wapiti probed for {f.title.split(':',1)[0].strip()} via parameter "
        f"{param!r} and got back evidence of vulnerability. "
        f"Active vulnerability — exploit may be reachable in production."
    )
    poc = curl or (
        f"# Reproduce manually with the same method/parameter:\n"
        f"curl -sSiX {method} '{location}'"
        + (f"   # vulnerable parameter: {param}" if param else "")
    )

    expected_parts = []
    if request:
        expected_parts.append("# === Wapiti's request ===")
        expected_parts.append(str(request)[:1500])
    if response:
        expected_parts.append("# === Server response (evidence) ===")
        expected_parts.append(str(response)[:1500])
    if not expected_parts:
        expected_parts.append(f"# {f.description[:500]}")
    expected = "\n".join(expected_parts)

    validation = f"# After fix, wapiti should not re-detect:\nwapiti -u {f.target} -m {f.title.split(':',1)[0].strip().lower()}"
    return impact, poc, expected, validation


def _nmap(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Nmap NSE vuln-script findings — the script output IS the evidence."""
    raw = f.raw or {}
    script_id = raw.get("script_id") or "?"
    port = raw.get("port") or "?"
    response = raw.get("response") or f.description or ""

    impact = (
        f"Nmap NSE script {script_id} flagged this on port {port}."
        + (f" Linked CVE: {f.cve}." if f.cve else "")
        + " Service version may be exploitable; verify via vendor advisory."
    )
    poc = (
        f"# Re-run just this NSE script against the same host\n"
        f"nmap --script {script_id} -p {port} -sV {f.target}"
    )
    expected = (
        f"# Output from `--script {script_id}` confirming the finding:\n"
        f"{response[:2000]}"
    )
    validation = (
        f"# After remediation, the script should print no VULNERABLE marker:\n"
        f"nmap --script {script_id} -p {port} {f.target} | grep -i vulnerable"
    )
    return impact, poc, expected, validation


def _ffuf(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """ffuf discovered-endpoint findings — show how to fetch the discovered URL."""
    raw = f.raw or {}
    url = f.location or f.target
    status = raw.get("status") or "?"
    mode = raw.get("ffuf_mode") or "dir"

    impact = (
        f"ffuf discovered an undocumented {mode}: {url} (HTTP {status}). "
        f"Worth a manual review for sensitive data, auth bypass, or unintended exposure."
    )
    poc = f"curl -sSi '{url}'"
    expected = (
        f"# HTTP {status} response from the discovered URL — the fact that it exists is the finding.\n"
        f"# size: {raw.get('length','?')} bytes, words: {raw.get('words','?')}"
        + (f", redirects to {raw.get('redirect')}" if raw.get('redirect') else "")
    )
    validation = (
        f"# After review (remove, restrict, or document), confirm intended behavior:\n"
        f"curl -sSi '{url}'"
    )
    return impact, poc, expected, validation


def _subdomains(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Subdomain discovery findings."""
    raw = f.raw or {}
    sub = raw.get("subdomain") or f.location or "?"
    apex = raw.get("apex") or f.target
    impact = (
        f"Discovered subdomain {sub} adds to the public attack surface for {apex}. "
        f"If it's an old/abandoned host, subdomain takeover or stale software risk; "
        f"if it's a dev/staging environment, it may have weaker controls than prod."
    )
    poc = (
        f"# Confirm the subdomain resolves and check what's there\n"
        f"dig +short {sub}\n"
        f"curl -sI https://{sub}/ 2>&1 | head -10"
    )
    expected = (
        f"<one or more IPs>\n"
        f"HTTP/...\n"
        f"# (subdomain resolved → it exists; HTTP response shows what's serving it)"
    )
    validation = (
        f"# After decommissioning or restricting, the host should fail to resolve OR return 404/403:\n"
        f"dig +short {sub}\n"
        f"curl -sI https://{sub}/"
    )
    return impact, poc, expected, validation


def _whatweb(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """whatweb tech-fingerprint findings."""
    raw = f.raw or {}
    plugin = raw.get("plugin") or "?"
    version = raw.get("version") or ""
    location = f.location or f.target
    impact = (
        f"Disclosed: {plugin}" + (f" {version}" if version else "") +
        ". An attacker can look up known CVEs against this exact version "
        "and skip the reconnaissance step."
    )
    poc = (
        f"# Confirm the tech disclosure manually\n"
        f"curl -sI '{location}' | grep -iE 'server|x-powered-by'\n"
        f"whatweb -a 3 '{location}'"
    )
    expected = (
        f"# whatweb output containing `{plugin}`"
        + (f" version `{version}`" if version else "")
        + " — the plugin's signature in headers, body, or both."
    )
    validation = (
        f"# After scrubbing version disclosures (server tokens off, etc.):\n"
        f"whatweb -a 3 '{location}' | grep -i '{plugin}'"
    )
    return impact, poc, expected, validation


def _testssl(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """testssl.sh deep TLS findings."""
    raw = f.raw or {}
    check_id = raw.get("testssl_id") or "?"
    endpoint = f.location or f.target
    response = raw.get("response") or f.description or ""

    impact = (
        f"testssl flagged check `{check_id}` on `{endpoint}`. "
        + (f"Linked CVE: {f.cve}. " if f.cve else "")
        + "TLS-layer issues are exploitable from any network position the user's "
        "traffic crosses."
    )
    poc = (
        f"# Re-run just this check\n"
        f"testssl --quiet --severity LOW {endpoint}\n"
        f"# Or for a one-line confirm of cipher/protocol issues:\n"
        f"openssl s_client -connect {endpoint} </dev/null 2>/dev/null | head -30"
    )
    expected = (
        f"# testssl output for {check_id}:\n"
        f"{response[:1500]}"
    )
    validation = (
        f"# After remediation, the check should report OK:\n"
        f"testssl --quiet {endpoint} | grep -i '{check_id}'"
    )
    return impact, poc, expected, validation


def _kiterunner(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """kiterunner API endpoint discovery findings."""
    raw = f.raw or {}
    method = raw.get("method") or "GET"
    status = raw.get("status") or "?"
    url = f.location or f.target
    impact = (
        f"Undocumented API route {method} {url} returned HTTP {status}. "
        "If it's an admin/internal endpoint, it likely lacks public-API hardening "
        "(input validation, rate limiting, auth depth checks)."
    )
    poc = f"curl -sSiX {method} '{url}'"
    expected = (
        f"HTTP/1.1 {status} ...\n"
        f"# (the endpoint responded — proof it exists and is reachable)"
    )
    validation = (
        f"# After review (remove, restrict, or document), confirm intended behavior:\n"
        f"curl -sSiX {method} '{url}'"
    )
    return impact, poc, expected, validation


def _generic(f: Finding) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    sev = f.severity.value if hasattr(f.severity, "value") else f.severity
    return (
        f"Severity {sev}. See description and references for impact context.",
        f"# Re-run the original scanner against this target to reproduce:\n"
        f"#   target:   {f.target}\n"
        f"#   location: {f.location or '?'}",
        "# (scanner-specific output; see scanner docs for what 'vulnerable' looks like)",
        f"# After remediation, re-scan and confirm this finding no longer appears.",
    )


_BUILDERS = {
    "headers-audit": _headers,
    "dns-audit": _dns,
    "tls-audit": _tls,
    "nuclei": _nuclei,
    "shannon": _shannon,
    "zap": _zap,
    "wapiti": _wapiti,
    "nmap": _nmap,
    "ffuf": _ffuf,
    "subdomains": _subdomains,
    "whatweb": _whatweb,
    "testssl": _testssl,
    "kiterunner": _kiterunner,
    "semgrep": _semgrep,
    "gitleaks": _gitleaks,
    "osv-scanner": _osv,
    "trivy": _osv,
    "checkov": _generic,
}
