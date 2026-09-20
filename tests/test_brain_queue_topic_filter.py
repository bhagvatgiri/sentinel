"""BrainQueue low-signal topic filter — Phase 96 fix."""

from __future__ import annotations

from sentinel.agent.brain_queue import BrainQueue


def test_rejects_pre_warm_header_only_topic():
    # The exact topic that crashed in the rgs-us.com run.
    assert BrainQueue._is_low_signal(
        "web application security: stack signals server=LiteSpeed, x-powered-by=PHP/8.3.30",
        "pre-warm:pre-warm: header-only signals (no body marker)",
    )


def test_rejects_when_requested_by_marks_header_only():
    assert BrainQueue._is_low_signal(
        "anything goes here that should still be rejected",
        "pre-warm: header-only signals (no body marker)",
    )


def test_rejects_short_topics():
    assert BrainQueue._is_low_signal("xss", "operator")
    assert BrainQueue._is_low_signal("auth", "pentest")
    assert BrainQueue._is_low_signal("", "anyone")
    assert BrainQueue._is_low_signal("    ", "anyone")


def test_rejects_too_short_topics():
    assert BrainQueue._is_low_signal("nginx ssrf", "operator")  # 10 chars, < 12 trigger
    assert BrainQueue._is_low_signal("xss", "operator")
    # Single word longer than 12 chars is fine (e.g. "authentication") —
    # it's a real OWASP category worth researching.
    assert not BrainQueue._is_low_signal("authentication vulnerabilities", "operator")


def test_accepts_well_formed_topics():
    # These are the kinds of topics the agent SHOULD be researching.
    assert not BrainQueue._is_low_signal(
        "WordPress LiteSpeed Cache plugin RCE CVE-2024-28000 exploitation",
        "pentest:auth",
    )
    assert not BrainQueue._is_low_signal(
        "OAuth2 redirect_uri bypass against Okta-hosted SaaS apps",
        "operator",
    )
    assert not BrainQueue._is_low_signal(
        "Spring Boot actuator endpoint exposure recent vulnerabilities",
        "auto-extracted",
    )
