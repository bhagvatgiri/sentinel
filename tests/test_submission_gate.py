"""Pre-submission gate — keep weak findings from reaching a bounty program."""
from __future__ import annotations

import json
from unittest.mock import MagicMock
import pytest

from sentinel.agent.pentest import submission_gate as sg


# ---- HOLD cases (the embarrassment-savers) --------------------------------


def test_disproven_is_hard_hold():
    v = sg.assess_finding({"title": "x", "evidence_state": "live_disproven"})
    assert v.decision == "hold"
    assert v.score == 0


def test_unproven_finding_holds():
    v = sg.assess_finding({"title": "IDOR maybe", "evidence_state": "recon_inferred",
                           "impact": "account takeover"})
    assert v.decision == "hold"
    assert any("not proven" in r for r in v.reasons)


def test_best_practice_should_framing_holds():
    """The ExampleChat OAuth lesson — SHOULD/best-practice framing = Informative."""
    v = sg.assess_finding({
        "title": "OAuth refresh token rotation",
        "description": "Per RFC 6749 §10.4 the server should rotate; this is a "
                       "best-practice hardening recommendation.",
        "evidence_state": "live_confirmed",
    })
    assert v.decision == "hold"
    assert any("best-practice" in r.lower() or "should" in r.lower() for r in v.reasons)


def test_missing_headers_no_impact_holds():
    v = sg.assess_finding({
        "title": "Missing security headers",
        "description": "The response is missing Content-Security-Policy and HSTS.",
        "evidence_state": "live_confirmed",
    })
    assert v.decision == "hold"
    assert any("never pays alone" in r for r in v.reasons)


def test_clickjacking_no_impact_holds():
    v = sg.assess_finding({"title": "Clickjacking on dashboard",
                           "evidence_state": "live_confirmed"})
    assert v.decision == "hold"


def test_login_csrf_holds():
    v = sg.assess_finding({"title": "Login CSRF", "evidence_state": "confirmed"})
    assert v.decision == "hold"


# ---- GO cases (the payers) ------------------------------------------------


def test_idor_cross_tenant_confirmed_is_go():
    v = sg.assess_finding({
        "title": "IDOR in /api/orders",
        "description": "Swapping the order id returns another user's order with PII "
                       "(cross-tenant unauthorized access).",
        "evidence_state": "live_confirmed",
        "severity": "high",
    })
    assert v.decision == "go"
    assert v.score >= 65


def test_auth_bypass_ato_is_go():
    v = sg.assess_finding({
        "title": "Auth bypass leads to account takeover",
        "description": "Forging the session cookie grants access to any victim "
                       "account (account takeover).",
        "evidence_state": "verified",
    })
    assert v.decision == "go"


# ---- REVIEW cases ---------------------------------------------------------


def test_confirmed_impact_but_low_score_is_review():
    """Proven + impact but in a touchy class → review, not auto-go."""
    v = sg.assess_finding({
        "title": "Open redirect chained to token theft",
        "description": "Open redirect that leaks the oauth token to attacker "
                       "(unauthorized access to victim session).",
        "evidence_state": "live_confirmed",
    })
    assert v.decision in ("go", "review")  # has impact; not a hard hold


def test_proven_but_no_impact_is_review():
    v = sg.assess_finding({
        "title": "GraphQL introspection enabled",
        "description": "Introspection query returns the full schema.",
        "evidence_state": "live_confirmed",
    })
    assert v.decision == "review"
    assert any("no concrete impact" in r for r in v.reasons)


# ---- program maturity -----------------------------------------------------


def test_clickjacking_with_impact_words_still_holds():
    """Regression for #604497 — clickjacking that ASSERTS 'steal user info'
    must HOLD, not REVIEW/GO off the impact-flavored keyword."""
    v = sg.assess_finding({
        "title": "Clickjacking (UI redress)",
        "description": ("Site lacks X-Frame-Options. An attacker can iframe it; "
                        "it could lead to steal user information and account access."),
        "evidence_state": "live_confirmed",
    })
    assert v.decision == "hold"
    assert any("never pays alone" in r for r in v.reasons)


def test_internal_hostname_disclosure_holds():
    """Regression for #3720501 — WAF bypass exposing only an internal hostname
    is not account/data/funds impact; must not GO."""
    v = sg.assess_finding({
        "title": "Null-byte WAF bypass leaks internal origin hostname",
        "description": ("Null byte bypasses the WAF and leaks the internal origin "
                        "hostname ccg11-origin-www-1.example.com."),
        "evidence_state": "live_confirmed",
    }, program_maturity="high")
    assert v.decision == "hold"


def test_mature_program_real_idor_is_review_dupcheck():
    """Regression for #3718233 — a real high-impact IDOR on a mature program is
    REVIEW (dup-check first), not an auto-GO."""
    v = sg.assess_finding({
        "title": "Unauthenticated IDOR leaks docs + API credentials",
        "description": ("GET /doc?id=N returns any document unauthenticated, "
                        "leaking api_key and api_secret plus another user's data."),
        "evidence_state": "live_confirmed", "severity": "high",
    }, program_maturity="high")
    assert v.decision == "review"
    assert any("duplicate" in r.lower() or "dup-check" in r.lower() for r in v.reasons)


def test_fresh_program_real_idor_is_go():
    """Counter-check: the SAME finding on a fresh program (low maturity) GOes —
    we didn't over-block legitimate submissions."""
    v = sg.assess_finding({
        "title": "Unauthenticated IDOR leaks another user's data + API credentials",
        "description": ("GET /doc?id=N returns any document unauthenticated, "
                        "exposing another user's data and leaked api_key."),
        "evidence_state": "live_confirmed", "severity": "high",
    }, program_maturity="low")
    assert v.decision == "go"


def test_high_maturity_lowers_score():
    f = {"title": "Open redirect", "evidence_state": "live_confirmed",
         "description": "open redirect on /go"}
    low = sg.assess_finding(f, program_maturity="low")
    high = sg.assess_finding(f, program_maturity="high")
    assert high.score <= low.score


# ---- assess_run -----------------------------------------------------------


def test_assess_run_counts():
    findings = [
        {"title": "IDOR cross-tenant PII", "evidence_state": "live_confirmed",
         "description": "another user's data, unauthorized access"},
        {"title": "Missing security headers", "evidence_state": "live_confirmed"},
        {"title": "x", "evidence_state": "live_disproven"},
    ]
    out = sg.assess_run(findings)
    assert out["counts"]["go"] >= 1
    assert out["counts"]["hold"] >= 2
    assert len(out["verdicts"]) == 3


# ---- tool -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_json_finding(monkeypatch):
    ctx = MagicMock()
    ctx.scope.engagement_mode.value = "bbp"
    monkeypatch.setattr(sg, "_require_ctx", lambda: ctx)
    out = await sg.assess_submission.handler({
        "finding": json.dumps({"title": "Missing HSTS header",
                               "evidence_state": "live_confirmed"}),
    })
    assert out.get("is_error") is not True
    assert "HOLD" in out["content"][0]["text"]


@pytest.mark.asyncio
async def test_tool_plaintext_finding(monkeypatch):
    """Plaintext (no evidence_state) is handled and correctly held as unproven —
    the gate refuses to green-light something not reproduced live."""
    ctx = MagicMock()
    ctx.scope.engagement_mode.value = "bbp"
    monkeypatch.setattr(sg, "_require_ctx", lambda: ctx)
    out = await sg.assess_submission.handler({
        "finding": "IDOR: swapping id returns another user's PII",
        "program_maturity": "low",
    })
    text = out["content"][0]["text"]
    assert out.get("is_error") is not True
    assert "HOLD" in text and "reproduce it live" in text


@pytest.mark.asyncio
async def test_tool_proven_json_idor_is_go(monkeypatch):
    ctx = MagicMock()
    ctx.scope.engagement_mode.value = "bbp"
    monkeypatch.setattr(sg, "_require_ctx", lambda: ctx)
    out = await sg.assess_submission.handler({
        "finding": json.dumps({
            "title": "IDOR cross-tenant",
            "description": "another user's PII via unauthorized access",
            "evidence_state": "live_confirmed", "severity": "high"}),
        "program_maturity": "low",
    })
    text = out["content"][0]["text"]
    assert "GO" in text


@pytest.mark.asyncio
async def test_tool_empty_errors(monkeypatch):
    out = await sg.assess_submission.handler({"finding": ""})
    assert out.get("is_error") is True
