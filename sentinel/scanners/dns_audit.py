"""DNS and email security audit scanner.

Passive DNS lookups only (TXT, MX, CAA, DS/DNSSEC records). No zone transfers,
no subdomain enumeration, no probing. Scope-gated: authorizes domain before
lookup. Pure Python using stdlib socket + optional dnspython.

Checks: SPF (v=spf1), DMARC (_dmarc TXT), DKIM (common selectors), CAA, DNSSEC,
MX, wildcard misconfiguration.
"""

from __future__ import annotations

import socket
import time
from typing import Optional
from urllib.parse import urlparse

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import RateLimiter, Scanner

dns_resolver = None
try:
    import dns.resolver
    import dns.rdatatype
    import dns.exception
    dns_resolver = dns.resolver
except ImportError:
    pass


class DNSScanner(Scanner):
    tool_name = "dns-audit"
    description = "DNS and email security audit (passive)"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        if dns_resolver is None:
            return (False, "dnspython not installed; pip install dnspython")
        return (True, "dnspython")

    def run(self, scope: Scope, target: str, **_opts) -> list[Finding]:
        host = self._extract_host(target)
        if not host:
            return []

        scope.authorize_url(f"https://{host}")

        rl = RateLimiter(scope.rate_limit_rps)
        findings: list[Finding] = []

        resolver = dns_resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0

        findings.extend(self._check_spf(resolver, target, host, rl))
        findings.extend(self._check_dmarc(resolver, target, host, rl))
        findings.extend(self._check_dkim(resolver, target, host, rl))
        findings.extend(self._check_caa(resolver, target, host, rl))
        findings.extend(self._check_dnssec(resolver, target, host, rl))
        findings.extend(self._check_mx(resolver, target, host, rl))
        findings.extend(self._check_wildcard(resolver, target, host, rl))

        return findings

    def _extract_host(self, target: str) -> Optional[str]:
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname
        return target.strip(".")

    def _query_dns(self, resolver, name: str, rdtype) -> list[str]:
        try:
            answers = resolver.resolve(name, rdtype)
            return [str(rr).strip('"') if rdtype == dns.rdatatype.TXT else str(rr) for rr in answers]
        except (dns.exception.DNSException, Exception):
            return []

    def _check_spf(self, resolver, target: str, host: str, rl: RateLimiter) -> list[Finding]:
        rl.wait()
        findings: list[Finding] = []
        txt_records = self._query_dns(resolver, host, dns.rdatatype.TXT)

        spf_records = [r for r in txt_records if r.startswith("v=spf1")]

        if not spf_records:
            findings.append(
                Finding(
                    title="Missing SPF record",
                    description=f"No SPF (v=spf1) TXT record found at {host}. Domain is vulnerable to email spoofing.",
                    severity=Severity.HIGH,
                    scanner="dns-audit",
                    target=target,
                    location=f"{host} TXT",
                    cwe="CWE-290",
                    references=["https://tools.ietf.org/html/rfc7208"],
                )
            )
            return findings

        if len(spf_records) > 1:
            findings.append(
                Finding(
                    title="Multiple SPF records",
                    description=f"Domain has {len(spf_records)} SPF records. RFC 7208 requires exactly one; behavior is undefined.",
                    severity=Severity.HIGH,
                    scanner="dns-audit",
                    target=target,
                    location=f"{host} TXT",
                    cwe="CWE-290",
                    references=["https://tools.ietf.org/html/rfc7208"],
                )
            )

        spf = spf_records[0]

        if " ~all" in spf:
            findings.append(
                Finding(
                    title="SPF uses soft-fail (~all) instead of hard-fail",
                    description="SPF record ends with ~all (softfail). Use -all (hardfail) to enforce spoofing prevention.",
                    severity=Severity.MEDIUM,
                    scanner="dns-audit",
                    target=target,
                    location=f"{host} TXT",
                    cwe="CWE-290",
                    references=["https://tools.ietf.org/html/rfc7208"],
                )
            )
        elif " -all" not in spf and "~all" not in spf and "-all" not in spf:
            findings.append(
                Finding(
                    title="SPF record lacks terminating mechanism",
                    description="SPF record has no all, -all, or ~all. Implicit pass allows any sender.",
                    severity=Severity.HIGH,
                    scanner="dns-audit",
                    target=target,
                    location=f"{host} TXT",
                    cwe="CWE-290",
                    references=["https://tools.ietf.org/html/rfc7208"],
                )
            )

        return findings

    def _check_dmarc(self, resolver, target: str, host: str, rl: RateLimiter) -> list[Finding]:
        rl.wait()
        findings: list[Finding] = []
        dmarc_name = f"_dmarc.{host}"
        txt_records = self._query_dns(resolver, dmarc_name, dns.rdatatype.TXT)

        dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

        if not dmarc_records:
            findings.append(
                Finding(
                    title="Missing DMARC record",
                    description=f"No DMARC policy found at {dmarc_name}. Domain cannot enforce SPF/DKIM alignment.",
                    severity=Severity.HIGH,
                    scanner="dns-audit",
                    target=target,
                    location=f"{dmarc_name} TXT",
                    cwe="CWE-290",
                    references=["https://tools.ietf.org/html/rfc7489"],
                )
            )
            return findings

        dmarc = dmarc_records[0]

        if "p=none" in dmarc:
            findings.append(
                Finding(
                    title="DMARC policy is p=none (monitoring only)",
                    description="DMARC is in monitoring mode (p=none). Enable enforcement with p=quarantine or p=reject.",
                    severity=Severity.MEDIUM,
                    scanner="dns-audit",
                    target=target,
                    location=f"{dmarc_name} TXT",
                    references=["https://tools.ietf.org/html/rfc7489"],
                )
            )
        elif "p=quarantine" in dmarc:
            findings.append(
                Finding(
                    title="DMARC policy is p=quarantine (partial enforcement)",
                    description="DMARC quarantines failing mail. Consider p=reject for stricter enforcement.",
                    severity=Severity.INFO,
                    scanner="dns-audit",
                    target=target,
                    location=f"{dmarc_name} TXT",
                    references=["https://tools.ietf.org/html/rfc7489"],
                )
            )

        if "pct=" in dmarc:
            try:
                pct_part = [p for p in dmarc.split(";") if "pct=" in p][0]
                pct = int(pct_part.split("=")[1].strip())
                if pct < 100 and not "p=none" in dmarc:
                    findings.append(
                        Finding(
                            title="DMARC pct below 100% (partial deployment)",
                            description=f"DMARC policy applies to only {pct}% of mail. Ramp to 100% for full coverage.",
                            severity=Severity.LOW,
                            scanner="dns-audit",
                            target=target,
                            location=f"{dmarc_name} TXT",
                            references=["https://tools.ietf.org/html/rfc7489"],
                        )
                    )
            except Exception:
                pass

        if "rua=" not in dmarc:
            findings.append(
                Finding(
                    title="DMARC missing rua (aggregate reporting)",
                    description="No aggregate report URI. Enable reporting to monitor SPF/DKIM failures.",
                    severity=Severity.INFO,
                    scanner="dns-audit",
                    target=target,
                    location=f"{dmarc_name} TXT",
                    references=["https://tools.ietf.org/html/rfc7489"],
                )
            )

        return findings

    def _check_dkim(self, resolver, target: str, host: str, rl: RateLimiter) -> list[Finding]:
        rl.wait()
        findings: list[Finding] = []

        selectors = ["default", "google", "selector1", "selector2", "s1", "s2", "mail", "dkim"]
        found_any = False

        for sel in selectors:
            rl.wait()
            dkim_name = f"{sel}._domainkey.{host}"
            txt_records = self._query_dns(resolver, dkim_name, dns.rdatatype.TXT)
            if any(r.startswith("v=DKIM1") for r in txt_records):
                found_any = True
                break

        if not found_any:
            findings.append(
                Finding(
                    title="No DKIM public keys found (common selectors)",
                    description=f"Checked selectors {selectors}; none returned v=DKIM1 TXT. "
                    "Domain may lack DKIM or use non-standard selectors.",
                    severity=Severity.INFO,
                    scanner="dns-audit",
                    target=target,
                    location=f"*._domainkey.{host} TXT",
                    references=["https://tools.ietf.org/html/rfc6376"],
                )
            )

        return findings

    def _check_caa(self, resolver, target: str, host: str, rl: RateLimiter) -> list[Finding]:
        rl.wait()
        findings: list[Finding] = []
        caa_records = self._query_dns(resolver, host, dns.rdatatype.CAA)

        if not caa_records:
            findings.append(
                Finding(
                    title="No CAA records (anyone can issue certs)",
                    description=f"No CAA records at {host}. Any CA can issue certificates for this domain.",
                    severity=Severity.LOW,
                    scanner="dns-audit",
                    target=target,
                    location=f"{host} CAA",
                    cwe="CWE-295",
                    references=["https://tools.ietf.org/html/rfc8499"],
                )
            )

        return findings

    def _check_dnssec(self, resolver, target: str, host: str, rl: RateLimiter) -> list[Finding]:
        rl.wait()
        findings: list[Finding] = []
        ds_records = self._query_dns(resolver, host, dns.rdatatype.DS)

        if not ds_records:
            findings.append(
                Finding(
                    title="No DNSSEC DS record (not signed)",
                    description=f"No DS record at parent zone for {host}. DNSSEC not enabled.",
                    severity=Severity.LOW,
                    scanner="dns-audit",
                    target=target,
                    location=f"{host} DS",
                    references=["https://tools.ietf.org/html/rfc4034"],
                )
            )

        return findings

    def _check_mx(self, resolver, target: str, host: str, rl: RateLimiter) -> list[Finding]:
        rl.wait()
        findings: list[Finding] = []
        mx_records = self._query_dns(resolver, host, dns.rdatatype.MX)

        if not mx_records:
            findings.append(
                Finding(
                    title="No MX records",
                    description=f"Domain {host} has no MX records. Mail delivery may fail.",
                    severity=Severity.INFO,
                    scanner="dns-audit",
                    target=target,
                    location=f"{host} MX",
                    references=["https://tools.ietf.org/html/rfc5321"],
                )
            )

        return findings

    def _check_wildcard(self, resolver, target: str, host: str, rl: RateLimiter) -> list[Finding]:
        rl.wait()
        findings: list[Finding] = []

        wildcard_name = f"*.{host}"
        a_records = self._query_dns(resolver, wildcard_name, dns.rdatatype.A)
        aaaa_records = self._query_dns(resolver, wildcard_name, dns.rdatatype.AAAA)

        if a_records or aaaa_records:
            findings.append(
                Finding(
                    title="Wildcard DNS record present",
                    description=f"*.{host} resolves to {a_records + aaaa_records}. "
                    "May indicate misconfiguration or intentional catch-all.",
                    severity=Severity.LOW,
                    scanner="dns-audit",
                    target=target,
                    location=f"*.{host} A/AAAA",
                    references=["https://tools.ietf.org/html/rfc1034"],
                )
            )

        return findings
