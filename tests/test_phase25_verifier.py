"""Phase 2.5 Live Verification — schema + dispatcher + auth verifier tests.

Network calls are mocked. The integration smoke proves the W1 over-trust
gap (the ExampleStore.com `maxAuthAge` and `returnUrl→assertion capture`
over-claims) gets caught by the verifier before reaching Phase 3.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest import mock

import pytest

from sentinel.core.findings import EvidenceState, Finding, Severity
from sentinel.agent.pentest import verifier_tool
from sentinel.agent.pentest.verifiers import auth as auth_verifier


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------


def test_finding_default_evidence_state_is_recon_inferred():
    f = Finding(title="t", description="d", severity=Severity.HIGH,
                scanner="s", target="https://x")
    assert f.evidence_state is EvidenceState.RECON_INFERRED
    assert f.to_dict()["evidence_state"] == "recon_inferred"


def test_finding_evidence_state_serializes():
    f = Finding(title="t", description="d", severity=Severity.HIGH,
                scanner="s", target="https://x",
                evidence_state=EvidenceState.LIVE_CONFIRMED)
    assert f.to_dict()["evidence_state"] == "live_confirmed"


def test_evidence_state_from_string_round_trip():
    for state in EvidenceState:
        assert EvidenceState.from_string(state.value) is state
    # Unknown / None defaults to recon_inferred.
    assert EvidenceState.from_string(None) is EvidenceState.RECON_INFERRED
    assert EvidenceState.from_string("garbage") is EvidenceState.RECON_INFERRED


# --------------------------------------------------------------------------
# Dispatcher — registry + missing-queue handling
# --------------------------------------------------------------------------


def test_registry_has_all_canonical_classes():
    # Importing verifier_tool triggers the package import which registers each.
    verifier_tool._ensure_verifiers_loaded()
    expected = {
        "auth", "authz", "idor", "injection", "xss", "ssrf", "csrf",
        "file_upload", "jwt_oauth", "cors", "crlf", "websocket",
    }
    missing = expected - set(verifier_tool.VERIFIERS.keys())
    assert not missing, f"verifier registry missing: {missing}"


def test_dispatcher_skips_missing_queue(tmp_path):
    workspace = tmp_path / "ws"
    (workspace / "deliverables").mkdir(parents=True)
    fake_scope = mock.MagicMock()
    fake_scope.auth_credentials = []
    fake_scope.research_headers = {}

    out = asyncio.run(verifier_tool.verify_class_queue(
        scope=fake_scope, target="https://example.com",
        workspace_dir=workspace, vuln_class="auth",
    ))
    assert out.get("missing_queue") is True


def test_dispatcher_handles_unregistered_class(tmp_path):
    workspace = tmp_path / "ws"
    deliv = workspace / "deliverables"
    deliv.mkdir(parents=True)
    queue_path = deliv / "totally_unknown_exploitation_queue.json"
    queue_path.write_text(json.dumps({"vulnerabilities": [{
        "ID": "X-VULN-01", "evidence_state": "recon_inferred",
    }]}))

    fake_scope = mock.MagicMock()
    fake_scope.auth_credentials = []
    fake_scope.research_headers = {}

    out = asyncio.run(verifier_tool.verify_class_queue(
        scope=fake_scope, target="https://example.com",
        workspace_dir=workspace, vuln_class="totally_unknown",
    ))
    assert out.get("no_verifier") is True
    # Unregistered class → all entries marked manual_verification_required.
    data = json.loads(queue_path.read_text())
    assert data["vulnerabilities"][0]["evidence_state"] == \
        EvidenceState.MANUAL_VERIFICATION_REQUIRED.value


# --------------------------------------------------------------------------
# Auth verifier — entry-kind classification
# --------------------------------------------------------------------------


def test_entry_kind_open_redirect():
    entry = {
        "vulnerability_type": "Open redirect via returnUrl",
        "exploitation_hypothesis": "openid.return_to is reflected",
        "notes": "see openid assertion capture",
    }
    assert auth_verifier._entry_kind(entry) == "open_redirect"


def test_entry_kind_max_auth_age():
    entry = {
        "vulnerability_type": "Auth freshness bypass",
        "exploitation_hypothesis": "max_auth_age can be inflated",
        "notes": "stale session window",
    }
    assert auth_verifier._entry_kind(entry) == "max_auth_age"


def test_entry_kind_falls_back_to_generic():
    """Entries with no recognized sub-type keywords fall through to 'generic'.

    Note: 'Default credentials' used to fall through to generic too, but
    after I2 (2026-XX-XX) it correctly classifies as 'default_creds' with
    its own non-destructive verifier path. This test now uses a genuinely
    unclassifiable entry (password-reset hint — generic + handled by
    _verify_generic_auth's existing ND-mode for password-reset / token-
    reissue / MFA / session-fixation sub-types).
    """
    entry = {
        "vulnerability_type": "Password reset token exposure",
        "notes": "password-reset endpoint returns reset_token in JSON response",
    }
    assert auth_verifier._entry_kind(entry) == "generic"


# --------------------------------------------------------------------------
# Auth verifier — open-redirect chain interpretation
# --------------------------------------------------------------------------


def test_open_redirect_op_404_marks_disproven(monkeypatch, tmp_path):
    """The exact failure mode that bit us today: chain dead-ends at OP 404."""

    fake_scope = mock.MagicMock()
    fake_scope.authorize_url.return_value = None  # in-scope

    workspace = tmp_path / "ws"
    (workspace / "deliverables" / "verification" / "auth").mkdir(parents=True)

    ctx = verifier_tool.VerificationContext(
        scope=fake_scope,
        target="https://www.ExampleStore.com",
        workspace_dir=workspace,
        vuln_class="auth",
        queue_entry={
            "ID": "AUTH-VULN-01",
            "vulnerability_type": "Open redirect via returnUrl",
            "exploitation_hypothesis": "Amazon redirects to attacker URL",
            "notes": "openid.return_to assertion capture",
            "source_endpoint": "GET /ExampleStore/signinRedirect",
        },
        entry_id="AUTH-VULN-01",
        evidence_dir=workspace / "deliverables" / "verification" / "auth",
        auth_credentials=[],
        research_headers={"User-Agent": "researcher_test"},
    )

    # Mock httpx.AsyncClient.get to walk a chain that ends at OP 404.
    class _FakeResp:
        def __init__(self, status, location="", body=""):
            self.status_code = status
            self.headers = {"location": location} if location else {}
            self.text = body

    hop_count = {"n": 0}

    async def fake_get(self, url, headers=None):
        hop_count["n"] += 1
        if hop_count["n"] == 1:
            # ExampleStore returns 302 with attacker URL in openid.return_to
            return _FakeResp(
                302,
                location=("https://www.amazon.com/ap/signin?openid.return_to="
                          "https%3A%2F%2Fexample-attacker-localdemo.invalid%2Fcaptured"),
            )
        # Amazon returns the OP 404 page
        return _FakeResp(
            200, location="",
            body="\nLooking for Something?\nWe're sorry. The Web address you entered "
                 "is not a functioning page on our site",
        )

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    result = asyncio.run(auth_verifier._verify_open_redirect(ctx))
    assert result.state is EvidenceState.LIVE_DISPROVEN, \
        f"expected disproven (OP 404 caught the chain), got {result.state}"
    assert "OP allowlist 404" in result.summary or "does NOT reproduce" in result.summary


def test_open_redirect_attacker_landing_marks_confirmed(monkeypatch, tmp_path):
    """If the chain DOES reach attacker host, mark confirmed."""

    fake_scope = mock.MagicMock()
    fake_scope.authorize_url.return_value = None

    workspace = tmp_path / "ws"
    (workspace / "deliverables" / "verification" / "auth").mkdir(parents=True)

    ctx = verifier_tool.VerificationContext(
        scope=fake_scope,
        target="https://example.com",
        workspace_dir=workspace,
        vuln_class="auth",
        queue_entry={
            "ID": "AUTH-VULN-02",
            "vulnerability_type": "Open redirect",
            "notes": "openid.return_to reflected verbatim",
            "source_endpoint": "GET /ExampleStore/signinRedirect",
        },
        entry_id="AUTH-VULN-02",
        evidence_dir=workspace / "deliverables" / "verification" / "auth",
        auth_credentials=[],
        research_headers={"User-Agent": "test"},
    )

    class _FakeResp:
        def __init__(self, status, location="", body=""):
            self.status_code = status
            self.headers = {"location": location} if location else {}
            self.text = body

    hop_count = {"n": 0}

    async def fake_get(self, url, headers=None):
        hop_count["n"] += 1
        if hop_count["n"] == 1:
            return _FakeResp(302, location="https://example-attacker-localdemo.invalid/captured?token=abc")
        return _FakeResp(200, body="captured by attacker")

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    result = asyncio.run(auth_verifier._verify_open_redirect(ctx))
    assert result.state is EvidenceState.LIVE_CONFIRMED


# --------------------------------------------------------------------------
# Auth verifier — max_auth_age injection (the maxAuthAge over-claim case)
# --------------------------------------------------------------------------


def test_max_auth_age_neither_param_reflects_marks_disproven(monkeypatch, tmp_path):
    """Today's exact failure: agent flagged ?maxAuthAge=N but server normalises to 0."""

    fake_scope = mock.MagicMock()
    fake_scope.authorize_url.return_value = None

    workspace = tmp_path / "ws"
    (workspace / "deliverables" / "verification" / "auth").mkdir(parents=True)

    ctx = verifier_tool.VerificationContext(
        scope=fake_scope,
        target="https://www.ExampleStore.com",
        workspace_dir=workspace,
        vuln_class="auth",
        queue_entry={
            "ID": "AUTH-VULN-03",
            "vulnerability_type": "max_auth_age injection",
            "exploitation_hypothesis": "?maxAuthAge=99999999 is reflected",
            "notes": "max_auth_age can be inflated to bypass freshness gate",
            "source_endpoint": "GET /ExampleStore/signinRedirect",
        },
        entry_id="AUTH-VULN-03",
        evidence_dir=workspace / "deliverables" / "verification" / "auth",
        auth_credentials=[],
        research_headers={"User-Agent": "test"},
    )

    async def fake_quick_probe(url, headers=None, follow_redirects=False, timeout=15.0):
        # Server normalises max_auth_age to 0 regardless of input
        return {
            "status_code": 302,
            "location": ("https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0"
                         "&openid.return_to=https%3A%2F%2Fwww.ExampleStore.com%2F"),
            "body_snippet": "",
            "headers": {},
        }

    monkeypatch.setattr(auth_verifier, "quick_probe", fake_quick_probe)

    result = asyncio.run(auth_verifier._verify_max_auth_age(ctx))
    assert result.state is EvidenceState.LIVE_DISPROVEN, \
        f"expected disproven (no reflection), got {result.state}"
    assert "does NOT reproduce" in result.summary or "normalised" in result.summary


def test_max_auth_age_maxage_param_reflects_marks_confirmed(monkeypatch, tmp_path):
    """If `maxAge` (the working param name) reflects, mark confirmed."""

    fake_scope = mock.MagicMock()
    fake_scope.authorize_url.return_value = None

    workspace = tmp_path / "ws"
    (workspace / "deliverables" / "verification" / "auth").mkdir(parents=True)

    ctx = verifier_tool.VerificationContext(
        scope=fake_scope,
        target="https://www.ExampleStore.com",
        workspace_dir=workspace,
        vuln_class="auth",
        queue_entry={
            "ID": "AUTH-VULN-04",
            "vulnerability_type": "max_auth_age injection",
            "exploitation_hypothesis": "maxAge param is reflected",
            "notes": "freshness bypass",
            "source_endpoint": "GET /ExampleStore/signinRedirect",
        },
        entry_id="AUTH-VULN-04",
        evidence_dir=workspace / "deliverables" / "verification" / "auth",
        auth_credentials=[],
        research_headers={"User-Agent": "test"},
    )

    async def fake_quick_probe(url, headers=None, follow_redirects=False, timeout=15.0):
        # Reflect the input: maxAge=99999999 → max_auth_age=99999999
        if "maxAge=99999999" in url and "maxAuthAge=" not in url.split("?", 1)[1].split("&")[0]:
            return {
                "status_code": 302,
                "location": ("https://www.amazon.com/ap/signin?"
                             "openid.pape.max_auth_age=99999999"
                             "&openid.return_to=https%3A%2F%2Fwww.ExampleStore.com%2F"),
                "body_snippet": "",
                "headers": {},
            }
        return {
            "status_code": 302,
            "location": ("https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0"
                         "&openid.return_to=https%3A%2F%2Fwww.ExampleStore.com%2F"),
            "body_snippet": "",
            "headers": {},
        }

    monkeypatch.setattr(auth_verifier, "quick_probe", fake_quick_probe)

    result = asyncio.run(auth_verifier._verify_max_auth_age(ctx))
    assert result.state is EvidenceState.LIVE_CONFIRMED
    assert "winning_param" in result.evidence
    assert result.evidence["winning_param"] == "maxAge"


# --------------------------------------------------------------------------
# Pipeline config wiring
# --------------------------------------------------------------------------


def test_pipeline_config_default_verify_before_exploit_is_true(tmp_path):
    from sentinel.agent.pentest.pipeline import PipelineConfig
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        "client: t\nengagement_id: t-1\nauthorized_by: t@t\n"
        "valid_from: 2026-01-01\nvalid_until: 2026-12-31\n"
        "targets:\n  domains: [example.com]\n",
    )
    cfg = PipelineConfig(target="https://example.com",
                          scope_path=scope_path)
    assert cfg.verify_before_exploit is True
