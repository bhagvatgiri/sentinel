"""HTTP security headers and CSP analyzer.

Passive single-request header analysis with scope-gated access. Fetches a target
URL exactly once, captures all response headers, and checks for:
  - Strict-Transport-Security (HSTS) presence, age, includeSubDomains
  - Content-Security-Policy (CSP) directives (unsafe-inline, unsafe-eval, *)
  - X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
  - Cookie security (Secure, HttpOnly, SameSite)
  - Server/version info leakage (Server, X-Powered-By, X-Runtime, etc.)
  - Cache-Control on auth endpoints

Follows up to 3 redirects; final URL must remain in scope.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import OutOfScopeError, Scope
from sentinel.scanners.base import RateLimiter, Scanner


class HeadersScanner(Scanner):
    tool_name = "headers-audit"
    description = "HTTP security headers and CSP passive analysis"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        """Pure Python stdlib — always available."""
        return (True, "stdlib")

    def run(self, scope: Scope, target: str, **_opts) -> list[Finding]:
        """Fetch target URL and analyze HTTP response headers."""
        # Gate: authorize before any network activity
        scope.authorize_url(target)

        rl = RateLimiter(scope.rate_limit_rps)
        rl.wait()

        findings: list[Finding] = []

        try:
            final_url, headers = self._fetch_with_redirects(target, scope)
        except OutOfScopeError:
            raise
        except Exception as e:
            # Network error, timeout, etc. — can't analyze what we can't reach.
            return findings

        # Extract and analyze headers
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Determine if HTTPS
        is_https = final_url.startswith("https://")

        # HSTS checks
        hsts = headers_lower.get("strict-transport-security", "")
        if is_https:
            if not hsts:
                findings.append(
                    Finding(
                        title="Missing Strict-Transport-Security header",
                        description="HSTS is not configured on this HTTPS endpoint. "
                        "This allows potential downgrade attacks.",
                        severity=Severity.MEDIUM,
                        scanner=self.tool_name,
                        target=final_url,
                        location=urllib.parse.urlparse(final_url).path or "/",
                        cwe="CWE-319",
                        references=[
                            "https://owasp.org/www-project-secure-headers/",
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                        ],
                    )
                )
            else:
                # Check max-age
                max_age = self._extract_hsts_max_age(hsts)
                if max_age is not None and max_age < 31536000:
                    findings.append(
                        Finding(
                            title="HSTS max-age is less than one year",
                            description=f"max-age={max_age}s is below the recommended 31536000s (1 year).",
                            severity=Severity.INFO,
                            scanner=self.tool_name,
                            target=final_url,
                            location=urllib.parse.urlparse(final_url).path or "/",
                            cwe="CWE-319",
                            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                        )
                    )

                # Check includeSubDomains
                if "includesubdomains" not in hsts.lower():
                    findings.append(
                        Finding(
                            title="HSTS missing includeSubDomains",
                            description="HSTS should protect all subdomains with includeSubDomains directive.",
                            severity=Severity.LOW,
                            scanner=self.tool_name,
                            target=final_url,
                            location=urllib.parse.urlparse(final_url).path or "/",
                            cwe="CWE-319",
                            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                        )
                    )

        # CSP checks
        csp = headers_lower.get("content-security-policy", "")
        if not csp:
            findings.append(
                Finding(
                    title="Missing Content-Security-Policy header",
                    description="CSP is not configured. This weakens protection against XSS attacks.",
                    severity=Severity.MEDIUM,
                    scanner=self.tool_name,
                    target=final_url,
                    location=urllib.parse.urlparse(final_url).path or "/",
                    cwe="CWE-1021",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    ],
                )
            )
        else:
            findings.extend(self._check_csp(csp, final_url))

        # X-Content-Type-Options
        xct = headers_lower.get("x-content-type-options", "").lower()
        if xct != "nosniff":
            findings.append(
                Finding(
                    title="Missing X-Content-Type-Options: nosniff",
                    description="Without nosniff, browsers may MIME-sniff responses and execute scripts.",
                    severity=Severity.LOW,
                    scanner=self.tool_name,
                    target=final_url,
                    location=urllib.parse.urlparse(final_url).path or "/",
                    cwe="CWE-430",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
                    ],
                )
            )

        # X-Frame-Options / CSP frame-ancestors
        xfo = headers_lower.get("x-frame-options", "").upper()
        csp_has_frame_ancestors = "frame-ancestors" in csp.lower() if csp else False

        if not xfo and not csp_has_frame_ancestors:
            findings.append(
                Finding(
                    title="Missing frame protection (X-Frame-Options or CSP frame-ancestors)",
                    description="No protection against clickjacking attacks (frame injection).",
                    severity=Severity.MEDIUM,
                    scanner=self.tool_name,
                    target=final_url,
                    location=urllib.parse.urlparse(final_url).path or "/",
                    cwe="CWE-1021",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                    ],
                )
            )
        elif xfo and xfo not in ("DENY", "SAMEORIGIN"):
            findings.append(
                Finding(
                    title="Weak X-Frame-Options directive",
                    description=f"X-Frame-Options set to '{xfo}' which may not provide adequate clickjacking protection.",
                    severity=Severity.MEDIUM,
                    scanner=self.tool_name,
                    target=final_url,
                    location=urllib.parse.urlparse(final_url).path or "/",
                    cwe="CWE-1021",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
                )
            )

        # Version info leakage
        for header_name in ["server", "x-powered-by", "x-aspnet-version", "x-runtime", "x-aspnet-mvc-version"]:
            if header_name in headers_lower:
                findings.append(
                    Finding(
                        title=f"Server version info leaked in {header_name.upper()} header",
                        description=f"The {header_name} header exposes version information: {headers_lower[header_name][:100]}",
                        severity=Severity.INFO,
                        scanner=self.tool_name,
                        target=final_url,
                        location=urllib.parse.urlparse(final_url).path or "/",
                        cwe="CWE-200",
                        references=["https://owasp.org/www-project-secure-headers/"],
                    )
                )

        # Referrer-Policy
        if "referrer-policy" not in headers_lower:
            findings.append(
                Finding(
                    title="Missing Referrer-Policy header",
                    description="Referrer-Policy is not configured, potentially leaking referrer information.",
                    severity=Severity.LOW,
                    scanner=self.tool_name,
                    target=final_url,
                    location=urllib.parse.urlparse(final_url).path or "/",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                    ],
                )
            )

        # Permissions-Policy
        if "permissions-policy" not in headers_lower and "feature-policy" not in headers_lower:
            findings.append(
                Finding(
                    title="Missing Permissions-Policy header",
                    description="Permissions-Policy is not configured to restrict browser capabilities.",
                    severity=Severity.INFO,
                    scanner=self.tool_name,
                    target=final_url,
                    location=urllib.parse.urlparse(final_url).path or "/",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                    ],
                )
            )

        # Cookie security checks
        set_cookie_headers = [v for k, v in headers.items() if k.lower() == "set-cookie"]
        for cookie_header in set_cookie_headers:
            if is_https and "secure" not in cookie_header.lower():
                findings.append(
                    Finding(
                        title="Set-Cookie missing Secure flag on HTTPS",
                        description=f"Cookie may be transmitted over insecure channels: {cookie_header[:80]}",
                        severity=Severity.MEDIUM,
                        scanner=self.tool_name,
                        target=final_url,
                        location=urllib.parse.urlparse(final_url).path or "/",
                        cwe="CWE-614",
                        references=[
                            "https://owasp.org/www-project-secure-headers/",
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
                        ],
                    )
                )

            if "httponly" not in cookie_header.lower():
                findings.append(
                    Finding(
                        title="Set-Cookie missing HttpOnly flag",
                        description=f"Cookie is accessible to JavaScript, risking XSS theft: {cookie_header[:80]}",
                        severity=Severity.LOW,
                        scanner=self.tool_name,
                        target=final_url,
                        location=urllib.parse.urlparse(final_url).path or "/",
                        cwe="CWE-1004",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
                        ],
                    )
                )

            samesite = self._extract_samesite(cookie_header)
            if samesite is None or samesite.lower() == "none":
                if is_https and samesite and samesite.lower() == "none" and "secure" in cookie_header.lower():
                    pass  # None + Secure is valid cross-site scenario
                else:
                    findings.append(
                        Finding(
                            title="Set-Cookie missing or weak SameSite attribute",
                            description=f"SameSite should be 'Strict' or 'Lax' to prevent CSRF: {cookie_header[:80]}",
                            severity=Severity.MEDIUM,
                            scanner=self.tool_name,
                            target=final_url,
                            location=urllib.parse.urlparse(final_url).path or "/",
                            cwe="CWE-1275",
                            references=[
                                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
                            ],
                        )
                    )

        # Cache-Control on apparent auth endpoints
        path = urllib.parse.urlparse(final_url).path.lower()
        if any(keyword in path for keyword in ["/login", "/auth", "/session"]):
            cc = headers_lower.get("cache-control", "").lower()
            if not cc or ("no-store" not in cc and "no-cache" not in cc):
                findings.append(
                    Finding(
                        title="Weak Cache-Control on auth endpoint",
                        description="Auth endpoints should have Cache-Control: no-store to prevent sensitive data caching.",
                        severity=Severity.INFO,
                        scanner=self.tool_name,
                        target=final_url,
                        location=path or "/",
                        references=[
                            "https://owasp.org/www-project-secure-headers/",
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
                        ],
                    )
                )

        return findings

    def _fetch_with_redirects(self, url: str, scope: Scope, max_redirects: int = 3) -> tuple[str, dict]:
        """Fetch URL with redirect following. Verify final URL is still in scope."""
        current_url = url
        for _ in range(max_redirects + 1):
            try:
                req = urllib.request.Request(
                    current_url,
                    headers={"User-Agent": "sentinel-headers/0.2"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    headers = dict(resp.headers)
                    return resp.geturl(), headers
            except urllib.error.HTTPError as e:
                # Follow redirects manually to check scope at each step
                if e.code in (301, 302, 303, 307, 308):
                    location = e.headers.get("Location")
                    if location:
                        # Resolve relative redirects
                        current_url = urllib.parse.urljoin(current_url, location)
                        # Check the redirect target is still in scope
                        try:
                            scope.authorize_url(current_url)
                        except OutOfScopeError:
                            raise
                        continue
                # If not a redirect we can follow, treat as error
                raise

        raise urllib.error.HTTPError(url, -1, "Too many redirects", {}, None)

    def _check_csp(self, csp_header: str, url: str) -> list[Finding]:
        """Parse CSP and check for dangerous directives."""
        findings: list[Finding] = []
        location = urllib.parse.urlparse(url).path or "/"

        # Parse CSP: split by semicolon, then by whitespace
        directives = {}
        for part in csp_header.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directive = tokens[0].lower()
                values = [t.lower() for t in tokens[1:]]
                directives[directive] = values

        # Check script-src and default-src for dangerous patterns
        script_src = directives.get("script-src", [])
        default_src = directives.get("default-src", [])

        # Combine: script-src takes precedence, otherwise use default-src
        effective_script = script_src if script_src else default_src

        if "unsafe-inline" in effective_script or "unsafe-inline" in default_src:
            findings.append(
                Finding(
                    title="CSP allows unsafe-inline in script-src",
                    description="'unsafe-inline' in CSP script-src negates much of CSP's XSS protection.",
                    severity=Severity.MEDIUM,
                    scanner=self.tool_name,
                    target=url,
                    location=location,
                    cwe="CWE-79",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                        "https://cwe.mitre.org/data/definitions/79.html",
                    ],
                )
            )

        if "unsafe-eval" in effective_script or "unsafe-eval" in default_src:
            findings.append(
                Finding(
                    title="CSP allows unsafe-eval",
                    description="'unsafe-eval' in CSP allows dynamic code execution via eval(), Function(), setTimeout(), etc.",
                    severity=Severity.MEDIUM,
                    scanner=self.tool_name,
                    target=url,
                    location=location,
                    cwe="CWE-94",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    ],
                )
            )

        if "*" in effective_script or "*" in default_src:
            findings.append(
                Finding(
                    title="CSP allows wildcard in script-src",
                    description="Wildcard '*' in script-src means any domain can provide scripts; essentially no CSP protection.",
                    severity=Severity.HIGH,
                    scanner=self.tool_name,
                    target=url,
                    location=location,
                    cwe="CWE-1021",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    ],
                )
            )

        return findings

    def _extract_hsts_max_age(self, hsts_header: str) -> Optional[int]:
        """Extract max-age value from HSTS header."""
        for part in hsts_header.split(";"):
            part = part.strip()
            if part.lower().startswith("max-age="):
                try:
                    return int(part.split("=", 1)[1])
                except (ValueError, IndexError):
                    pass
        return None

    def _extract_samesite(self, cookie_header: str) -> Optional[str]:
        """Extract SameSite value from Set-Cookie header."""
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.lower().startswith("samesite="):
                return part.split("=", 1)[1]
        return None
