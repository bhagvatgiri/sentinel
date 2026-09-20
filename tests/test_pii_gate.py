"""D1 — Pre-deliverable PII gate tests.

Covers:
- Detection of undeclared PII in deliverable text.
- In-scope URLs / IPs are NOT redacted (false positives would tank the
  signal-to-noise ratio of the deliverable).
- ``policy="block"`` refuses the write.
- ``policy="redact"`` rewrites inline.
- ``policy="warn"`` returns findings without modifying text.
- Audit-log calls happen for every decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from sentinel.agent.pentest import pii_gate


# ---- a tiny stand-in scope object ----------------------------------------

@dataclass
class _StubScope:
    """Minimal duck-type for the PII gate. The real Scope object exposes
    ``targets`` as a dict; the gate only reads ``targets["domains"]``
    and ``targets["ips"]``. Anything else is irrelevant here."""
    targets: dict


@dataclass
class _StubAuditLog:
    events: list

    def write(self, event: str, payload: dict):
        self.events.append((event, payload))


# ---- in-scope vs undeclared ----------------------------------------------

def test_in_scope_url_not_flagged():
    scope = _StubScope(targets={"domains": ["example.com"], "ips": []})
    text = "Found endpoint: https://api.example.com/v1/users"
    dec = pii_gate.apply_gate(text, scope=scope, policy="redact")
    assert dec.allowed
    assert dec.redacted_text == text          # untouched
    assert not dec.findings


def test_undeclared_url_redacted():
    scope = _StubScope(targets={"domains": ["example.com"], "ips": []})
    text = (
        "Cross-engagement leak: see "
        "https://internal.othercompany.com/secret"
    )
    dec = pii_gate.apply_gate(text, scope=scope, policy="redact")
    assert dec.allowed
    assert "othercompany.com" not in dec.redacted_text
    assert "[URL]" in dec.redacted_text
    assert dec.findings


def test_undeclared_ip_redacted():
    scope = _StubScope(targets={"domains": [], "ips": ["10.0.50.0/24"]})
    text = "non-target IP detected: 8.8.8.8"
    dec = pii_gate.apply_gate(text, scope=scope, policy="redact")
    assert "[IP_ADDRESS]" in dec.redacted_text
    assert "8.8.8.8" not in dec.redacted_text


def test_in_scope_ip_not_flagged():
    scope = _StubScope(targets={"domains": [], "ips": ["10.0.50.5"]})
    text = "scanning 10.0.50.5 ..."
    dec = pii_gate.apply_gate(text, scope=scope, policy="redact")
    assert dec.allowed
    assert "10.0.50.5" in dec.redacted_text
    assert not dec.findings


# ---- policies ------------------------------------------------------------

def test_block_policy_refuses():
    scope = _StubScope(targets={"domains": [], "ips": []})
    text = "leak: visit https://leaks.example.com/path"
    dec = pii_gate.apply_gate(text, scope=scope, policy="block")
    assert not dec.allowed
    assert dec.refused_reason
    assert "leaks.example.com" in dec.redacted_text   # block keeps original


def test_warn_policy_passes_text_unchanged():
    scope = _StubScope(targets={"domains": [], "ips": []})
    text = "hash: 5d41402abc4b2a76b9719d911017c592"
    dec = pii_gate.apply_gate(text, scope=scope, policy="warn")
    assert dec.allowed
    assert dec.redacted_text == text
    assert dec.findings        # caller should log a warning


def test_unknown_policy_raises():
    with pytest.raises(ValueError):
        pii_gate.apply_gate("x", policy="explode")


# ---- audit hooks ---------------------------------------------------------

def test_clean_text_writes_clean_audit_event():
    scope = _StubScope(targets={"domains": ["example.com"], "ips": []})
    audit = _StubAuditLog(events=[])
    text = "the endpoint is https://example.com/health"
    dec = pii_gate.apply_gate(text, scope=scope, policy="redact", audit=audit)
    assert dec.allowed
    assert any(e[0] == "pii_gate_clean" for e in audit.events)


def test_redact_writes_redacted_audit_event():
    scope = _StubScope(targets={"domains": [], "ips": []})
    audit = _StubAuditLog(events=[])
    text = "leak: 1.1.1.1"
    pii_gate.apply_gate(
        text, scope=scope, policy="redact", audit=audit,
        artifact_name="report.pdf",
    )
    assert any(e[0] == "pii_gate_redacted" for e in audit.events)
    payload = next(e[1] for e in audit.events if e[0] == "pii_gate_redacted")
    assert payload["artifact"] == "report.pdf"
    assert payload["n_redacted"] >= 1


def test_block_writes_blocked_audit_event():
    scope = _StubScope(targets={"domains": [], "ips": []})
    audit = _StubAuditLog(events=[])
    pii_gate.apply_gate(
        "non-target ip 1.2.3.4", scope=scope, policy="block",
        audit=audit, artifact_name="report.pdf",
    )
    assert any(e[0] == "pii_gate_blocked" for e in audit.events)


# ---- always-redact labels ------------------------------------------------

def test_crypto_labels_always_redacted_even_with_scope():
    """CRYPTO / hash / token labels are never 'in-scope' — they're
    always sensitive."""
    scope = _StubScope(targets={"domains": ["example.com"], "ips": []})
    text = "Auth: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signaturepartherelongenough123"
    dec = pii_gate.apply_gate(text, scope=scope, policy="redact")
    assert "[CRYPTO]" in dec.redacted_text


# ---- end-to-end synthetic deliverable ------------------------------------

def test_synthetic_deliverable_with_embedded_non_target_pii():
    """Spec requirement: a synthetic deliverable with embedded
    non-target PII must trigger the gate."""
    scope = _StubScope(
        targets={"domains": ["ExampleCorp.com"], "ips": []},
    )
    deliverable = """# ExampleCorp pentest — finding #3

The endpoint `https://api.ExampleCorp.com/users/{id}` returns user data.

NOTE TO SELF (debug): I tested against my personal box at
https://homelab.example.dev/ and observed similar behavior.
Saw an internal IP 192.168.1.50 in the response.

"""
    dec = pii_gate.apply_gate(
        deliverable, scope=scope, policy="redact",
        artifact_name="finding-3.md",
    )
    # Should remain allowed but rewrite the personal+internal stuff.
    assert dec.allowed
    assert "homelab.example.dev" not in dec.redacted_text
    assert "192.168.1.50" not in dec.redacted_text
    # In-scope URL preserved.
    assert "api.ExampleCorp.com" in dec.redacted_text
    # Findings populated for the operator.
    labels = {f["label"] for f in dec.findings}
    assert {"URL", "IP_ADDRESS"}.issubset(labels)
