"""Shared event-kind styling — both UIs render the same icons/chips."""

from __future__ import annotations

from sentinel.web.event_styles import (
    DEFAULT_STYLE, EVENT_STYLES, all_kinds, kinds_in_group, style_for,
)


# Every event kind the pipeline can emit. If the pipeline starts emitting a
# new kind, the test forces us to add it to EVENT_STYLES so both UIs render
# it consistently instead of silently falling through to DEFAULT_STYLE.
_REQUIRED_KINDS_FROM_PIPELINE = [
    # Standard KIND_* constants from sentinel/agent/event_log.py
    "pipeline_started", "pipeline_completed",
    "phase_started", "phase_completed", "phase_failed",
    "tool_called", "tool_result", "agent_text",
    "brain_enqueued", "brain_skipped", "brain_started",
    "brain_completed", "brain_failed",
    "brain_search", "brain_fetch", "brain_ingest", "brain_dedup_skip",
    # String literals emitted by pipeline.py (Phase 5/6/10)
    "phase_retry", "phase_skipped_resume", "brain_prewarm",
    # Audit/event kinds emitted by bypass_tool.py (Phase 9)
    "bypass_probe_ok", "bypass_probe_refused",
    "bypass_probe_skipped", "bypass_probe_http_error",
    "waf_bypass_attempt", "waf_bypass_refused",
    "origin_ip_crtsh", "origin_ip_probe_hit",
    "origin_ip_probe_refused", "origin_ip_probe_http_error",
    # Phase 99 — intel-brief
    "intel_brief_started", "intel_brief_corpus_query",
    "intel_brief_brain_enqueued", "intel_brief_completed",
    # Phase 01 Plan 02 — STATE-01 CURRENT_STATE auto-roll hook
    "state_update", "state_update_failed",
]


def test_state_update_event_styles_registered():
    """STATE-01 — both event kinds emitted by the phase-end hook are styled."""
    assert "state_update" in EVENT_STYLES
    assert "state_update_failed" in EVENT_STYLES
    assert EVENT_STYLES["state_update"]["chip"] == "ok"
    assert EVENT_STYLES["state_update"]["group"] == "pipeline"
    assert EVENT_STYLES["state_update_failed"]["chip"] == "low"
    assert EVENT_STYLES["state_update_failed"]["group"] == "pipeline"


def test_every_pipeline_kind_has_a_style_entry():
    """Forces us to register new kinds — silent fallthrough is the bug we're avoiding."""
    missing = [k for k in _REQUIRED_KINDS_FROM_PIPELINE if k not in EVENT_STYLES]
    assert not missing, f"missing styling for: {missing}"


def test_unknown_kind_falls_through_to_default_style():
    s = style_for("totally-made-up-kind-xyz")
    assert s == DEFAULT_STYLE


def test_known_kind_returns_specific_style():
    s = style_for("phase_completed")
    assert s["chip"] == "ok"
    assert s["icon"] == "✓"
    assert s["group"] == "phase"


def test_every_style_has_required_fields():
    for kind, style in EVENT_STYLES.items():
        for field in ("chip", "icon", "label", "group"):
            assert style.get(field), f"{kind}.{field} missing"
        assert style["chip"] in (
            "info", "low", "medium", "high", "critical", "ok"
        ), f"{kind}.chip is not a recognized chip class"
        assert style["group"] in (
            "phase", "brain", "tool", "bypass", "pipeline", "chain",
            "trace", "ctf", "attack", "teacher", "other"
        ), f"{kind}.group is not a recognized group"


def test_kinds_in_group_returns_only_that_group():
    bypass_kinds = kinds_in_group("bypass")
    assert "waf_bypass_attempt" in bypass_kinds
    assert "phase_started" not in bypass_kinds


def test_all_kinds_returns_every_registered_kind():
    kinds = all_kinds()
    assert len(kinds) >= len(_REQUIRED_KINDS_FROM_PIPELINE)
    for k in _REQUIRED_KINDS_FROM_PIPELINE:
        assert k in kinds
