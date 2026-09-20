"""Passive TLS/cert audit: stdlib socket+ssl, scope-gated, no exploitation.

Checks: cert expiry, self-signed, hostname, weak ciphers, deprecated TLS
versions, and HSTS header presence/strength. Handshake per version probes
what server supports; malformed connections treated as 'not supported'.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from sentinel.core.findings import Finding, Severity
from sentinel.core.scope import Scope
from sentinel.scanners.base import RateLimiter, Scanner


class TLSScanner(Scanner):
    tool_name = "tls-audit"
    description = "TLS/certificate configuration audit (passive)"

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        """Pure Python; always available."""
        return (True, "stdlib")

    def run(self, scope: Scope, target: str, **_opts) -> list[Finding]:
        # HARD GATE: authorize target before any network I/O.
        scope.authorize_url(target)

        rl = RateLimiter(scope.rate_limit_rps)
        rl.wait()

        findings: list[Finding] = []
        host, port = self._parse_target(target)
        if not host:
            return findings

        location = f"{host}:{port}"
        cert_info = self._fetch_cert(host, port)
        if not cert_info:
            return findings

        cert_dict = cert_info["dict"]
        findings.extend(self._check_expiry(target, location, cert_dict))
        findings.extend(self._check_self_signed(target, location, cert_dict))
        if host:
            findings.extend(self._check_hostname_mismatch(target, location, host, cert_dict))

        # Probe TLS versions and weak ciphers.
        tls_info = self._probe_tls_versions(host, port)
        findings.extend(self._check_tls_versions(target, location, tls_info))
        findings.extend(self._check_weak_ciphers(target, location, tls_info))

        # Probe HSTS header.
        hsts = self._probe_hsts(host, port)
        findings.extend(self._check_hsts(target, location, hsts))

        return findings

    # ---- target parsing ---------------------------------------------------

    def _parse_target(self, target: str) -> tuple[str, int]:
        """Extract host and port."""
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname
            return (host, parsed.port or 443) if host else ("", 443)
        if ":" in target:
            parts = target.rsplit(":", 1)
            try:
                return (parts[0], int(parts[1]))
            except ValueError:
                return ("", 443)
        return (target, 443)

    # ---- cert retrieval ---------------------------------------------------

    def _fetch_cert(self, host: str, port: int) -> Optional[dict]:
        """Fetch cert and metadata; return None on failure."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            cert_der = ssock.getpeercert(binary_form=True)
            cert_dict = ssock.getpeercert()
            ssock.close()
            sock.close()
            return {"pem": ssl.DER_cert_to_PEM_cert(cert_der), "dict": cert_dict}
        except (socket.timeout, socket.error, ssl.SSLError):
            return None

    # ---- cert checks -------------------------------------------------------

    def _check_expiry(self, target: str, location: str, cert_dict: dict) -> list[Finding]:
        findings = []
        try:
            not_after_str = cert_dict.get("notAfter", "")
            if not_after_str:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.utcnow()).days
                if days_left < 0:
                    sev, title = Severity.CRITICAL, "Expired"
                elif days_left < 30:
                    sev, title = Severity.HIGH, f"Expires {days_left}d"
                else:
                    sev = None
                if sev:
                    findings.append(Finding(title=title, description=not_after_str, severity=sev,
                        scanner="tls-audit", target=target, location=location, cwe="CWE-295",
                        references=["https://tools.ietf.org/html/rfc5280"]))
        except Exception:
            pass
        return findings

    def _check_self_signed(self, target: str, location: str, cert_dict: dict) -> list[Finding]:
        findings = []
        try:
            s = dict(x[0] for x in cert_dict.get("subject", []))
            i = dict(x[0] for x in cert_dict.get("issuer", []))
            if s == i and s.get("commonName"):
                findings.append(Finding(title="Self-signed", description="Subject==Issuer",
                    severity=Severity.MEDIUM, scanner="tls-audit", target=target,
                    location=location, cwe="CWE-295", references=["https://tools.ietf.org/html/rfc5280"]))
        except Exception:
            pass
        return findings

    # ---- hostname check ---------------------------------------------------

    def _check_hostname_mismatch(self, target: str, location: str, hostname: str, cert_dict: dict) -> list[Finding]:
        findings = []
        try:
            ssl.match_hostname(cert_dict, hostname)
        except ssl.CertificateError as e:
            findings.append(Finding(title="Hostname mismatch", description=str(e),
                severity=Severity.HIGH, scanner="tls-audit", target=target, location=location,
                cwe="CWE-295", references=["https://tools.ietf.org/html/rfc6125"]))
        except Exception:
            pass
        return findings

    # ---- TLS version probing ----------------------------------------------

    def _probe_tls_versions(self, host: str, port: int) -> dict:
        """Probe TLS versions. Return {version: {cipher, version}}."""
        result = {}
        for label, (min_v, max_v) in [
            ("TLS 1.0", (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1)),
            ("TLS 1.1", (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1)),
            ("TLS 1.2", (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)),
            ("TLS 1.3", (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)),
        ]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = min_v
                ctx.maximum_version = max_v
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((host, port))
                ssock = ctx.wrap_socket(sock, server_hostname=host)
                result[label] = {"cipher": ssock.cipher(), "version": ssock.version()}
                ssock.close()
                sock.close()
            except (socket.timeout, socket.error, ssl.SSLError):
                pass
        return result

    # ---- TLS and cipher checks -----------------------------------------------

    def _check_tls_versions(self, target: str, location: str, tls_info: dict) -> list[Finding]:
        findings = []
        for version in ["TLS 1.0", "TLS 1.1"]:
            if version in tls_info:
                findings.append(Finding(title=f"Deprecated {version}", description="Use TLS 1.2+",
                    severity=Severity.MEDIUM, scanner="tls-audit", target=target,
                    location=location, cwe="CWE-327", references=["https://mozilla.github.io/server-side-tls/"]))
        return findings

    def _check_weak_ciphers(self, target: str, location: str, tls_info: dict) -> list[Finding]:
        findings: list[Finding] = []
        weak = ["RC4", "3DES", "NULL", "EXPORT"]
        for ver, info in tls_info.items():
            cipher = info.get("cipher")
            if cipher and any(p in cipher[0] for p in weak):
                findings.append(Finding(
                    title=f"Weak cipher: {cipher[0]}",
                    description=f"{ver} uses {cipher[0]}",
                    severity=Severity.HIGH,
                    scanner="tls-audit",
                    target=target,
                    location=location,
                    cwe="CWE-326",
                    references=["https://mozilla.github.io/server-side-tls/"],
                ))
        return findings

    # ---- HSTS checks -------------------------------------------------------

    def _probe_hsts(self, host: str, port: int) -> Optional[str]:
        """Issue HTTPS HEAD; extract Strict-Transport-Security."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            ssock.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            response = b""
            while (chunk := ssock.recv(4096)):
                response += chunk
            ssock.close()
            sock.close()
            for line in response.decode("utf-8", errors="ignore").split("\r\n"):
                if line.lower().startswith("strict-transport-security"):
                    return line.split(":", 1)[1].strip()
        except Exception:
            pass
        return None

    def _check_hsts(self, target: str, location: str, hsts: Optional[str]) -> list[Finding]:
        findings = []
        if not hsts:
            findings.append(Finding(title="Missing HSTS", description="Header absent",
                severity=Severity.LOW, scanner="tls-audit", target=target, location=location,
                cwe="CWE-697", references=["https://tools.ietf.org/html/rfc6797"]))
        elif "max-age=" in hsts.lower():
            try:
                ma = int([p for p in hsts.split(";") if "max-age=" in p.lower()][0].split("=")[1])
                if ma < 31536000:
                    findings.append(Finding(title="HSTS <1yr", description=f"max-age={ma}s",
                        severity=Severity.INFO, scanner="tls-audit", target=target, location=location,
                        references=["https://tools.ietf.org/html/rfc6797"]))
            except Exception:
                pass
        return findings
