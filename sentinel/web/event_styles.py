"""Shared event-kind styling for both UIs.

The FastAPI/HTMX agent-runs dashboard and the Streamlit Audit page both render
the structured event stream from `runs/events-<job_id>.jsonl`. Without a shared
map, every kind would need bespoke styling in each UI — and new kinds added in
the pipeline (Phase 5/6/9 added a half-dozen) would silently render as the
generic fallback chip.

This module is the single source of truth. When a new event kind is emitted by
the pipeline (or any tool), add a row here once and both UIs pick it up.

Each style entry:
    chip   : "info" | "low" | "medium" | "high" | "critical" | "ok"
             — drives the colored badge background
    icon   : single character or short emoji shown before the label
    label  : human-readable short label for the event
    group  : which panel this kind belongs to ("phase", "brain", "tool",
             "bypass", "pipeline", "other") — agent-runs uses this to bucket
             events into the right side panel
"""

from __future__ import annotations

from typing import TypedDict


class EventStyle(TypedDict):
    chip: str
    icon: str
    label: str
    group: str


# Fallback for unknown kinds — never raises; just renders generically.
DEFAULT_STYLE: EventStyle = {
    "chip": "info",
    "icon": "·",
    "label": "event",
    "group": "other",
}


EVENT_STYLES: dict[str, EventStyle] = {
    # ---- pipeline lifecycle ------------------------------------------------
    "pipeline_started":   {"chip": "low",      "icon": "▶", "label": "pipeline started",   "group": "pipeline"},
    "pipeline_completed": {"chip": "ok",       "icon": "", "label": "pipeline completed", "group": "pipeline"},
    # Run-level abort marker. Written either by the pipeline itself (clean
    # shutdown after SIGTERM, cost-cap, etc.) or appended retroactively by
    # an audit-honesty pass when a run was killed externally without ever
    # writing a completion event. Both UIs (agent-runs list + detail) treat
    # this as a terminal kind in compute_run_status() → 'aborted'.
    "pipeline_aborted":   {"chip": "critical", "icon": "", "label": "pipeline aborted",   "group": "pipeline"},

    # ---- Phase 01 Plan 02 — CURRENT_STATE auto-roll hook (STATE-01) -------
    # Phase-end hook in sentinel/agent/pentest/pipeline.py emits one of
    # these after every phase: `state_update` on success, `state_update_failed`
    # on swallowed exception. Both render in the agent-runs dashboard's
    # pipeline panel via the same EVENT_STYLES machinery.
    "state_update":        {"chip": "ok",       "icon": "", "label": "CURRENT_STATE refreshed",     "group": "pipeline"},
    "state_update_failed": {"chip": "low",      "icon": "", "label": "CURRENT_STATE refresh failed", "group": "pipeline"},

    # ---- phases ------------------------------------------------------------
    "phase_started":         {"chip": "low",      "icon": "▶", "label": "phase started",   "group": "phase"},
    "phase_completed":       {"chip": "ok",       "icon": "", "label": "phase completed", "group": "phase"},
    "phase_failed":          {"chip": "critical", "icon": "", "label": "phase failed",    "group": "phase"},
    # C1 (2026-XX-XX): a parallel vuln/exploit class agent raised an exception;
    # the wave now isolates it (return_exceptions=True) so siblings survive,
    # and emits this so the crash stays visible on the run timeline.
    "phase_crashed":         {"chip": "critical", "icon": "", "label": "phase crashed (wave-isolated)", "group": "phase"},
    "phase_retry":           {"chip": "medium",   "icon": "↻", "label": "phase retry",     "group": "phase"},
    "phase_skipped_resume":  {"chip": "info",     "icon": "", "label": "skipped (resume)","group": "phase"},
    "phase_skipped_budget_exhausted": {"chip": "high", "icon": "", "label": "skipped (scan budget exhausted)", "group": "phase"},
    # 2026-XX-XX: recon produced no deliverable (e.g. SDK streaming hang) → the
    # pipeline skips vuln/exploit/verify rather than run context-less agents.
    "recon_failed_abort":    {"chip": "critical", "icon": "", "label": "recon failed — agentic phases skipped", "group": "phase"},
    # 2026-XX-XX: recon agent finished without writing recon_deliverable.md →
    # we synthesize it from the raw scanner artifacts (crawl.txt/nuclei.json/
    # nmap.txt) so downstream phases don't stall at the handoff.
    "recon_deliverable_auto_synthesized": {"chip": "info", "icon": "", "label": "recon deliverable auto-synthesized", "group": "phase"},

    # ---- B1 JS bundle harvester (Phase B1, 2026-XX-XX) ---------------------
    "js_bundle_fetched":      {"chip": "info", "icon": "", "label": "JS bundle fetched",     "group": "tool"},
    "js_bundle_refused":      {"chip": "low",  "icon": "⊘", "label": "JS bundle out-of-scope", "group": "tool"},
    "js_sourcemap_fetched":   {"chip": "info", "icon": "", "label": "JS sourcemap fetched",  "group": "tool"},
    "js_endpoint_extracted":  {"chip": "info", "icon": "", "label": "JS extractors run",     "group": "tool"},

    # ---- B7 JWT analyzer (Phase B7, 2026-XX-XX) ---------------------------
    "jwt_analyzed":           {"chip": "info",     "icon": "", "label": "JWT analyzed",         "group": "tool"},
    "jwt_weak_secret_found":  {"chip": "critical", "icon": "", "label": "JWT weak HMAC secret", "group": "tool"},

    # ---- B6/B14 takeover probe (Phase B6, 2026-XX-XX) ---------------------
    "takeover_checked":       {"chip": "info",     "icon": "", "label": "takeover probe",       "group": "tool"},
    "takeover_candidate":     {"chip": "critical", "icon": "", "label": "takeover candidate",   "group": "tool"},

    # ---- B10 trufflehog verified-secret (Phase B10, 2026-XX-XX) -----------
    "secret_verify_run":      {"chip": "info",     "icon": "", "label": "secret verify run",    "group": "tool"},
    "secret_text_scanned":    {"chip": "info",     "icon": "", "label": "secret text scanned",  "group": "tool"},
    "secret_verified_live":   {"chip": "critical", "icon": "", "label": "VERIFIED LIVE secret", "group": "tool"},

    # ---- B12 SSTImap (Phase B12, 2026-XX-XX) -------------------------------
    "ssti_probed":            {"chip": "info",     "icon": "", "label": "SSTI probed",          "group": "tool"},
    "ssti_confirmed":         {"chip": "critical", "icon": "", "label": "SSTI CONFIRMED",        "group": "tool"},

    # ---- B11 Corsy CORS misconfig (Phase B11, 2026-XX-XX) ------------------
    "cors_probed":            {"chip": "info",     "icon": "", "label": "CORS probed",          "group": "tool"},
    "cors_full_scan":         {"chip": "info",     "icon": "", "label": "CORS full scan",       "group": "tool"},
    "cors_misconfig_found":   {"chip": "high",     "icon": "", "label": "CORS misconfig",       "group": "tool"},

    # ---- B5 hidden-param discovery (Phase B5, 2026-XX-XX) -----------------
    "hidden_params_scan":     {"chip": "info",     "icon": "", "label": "param scan",           "group": "tool"},
    "hidden_param_found":     {"chip": "medium",   "icon": "", "label": "hidden param",         "group": "tool"},

    # ---- B9 OpenAPI/spec discovery (Phase B9, 2026-XX-XX) -----------------
    "api_spec_scan":          {"chip": "info",     "icon": "", "label": "API spec scan",        "group": "tool"},
    "api_spec_found":         {"chip": "high",     "icon": "", "label": "API SPEC FOUND",       "group": "tool"},

    # ---- B2 GraphQL introspect + auth diff (Phase B2, 2026-XX-XX) ---------
    "graphql_introspect_run":     {"chip": "info",     "icon": "", "label": "GraphQL introspect",    "group": "tool"},
    "graphql_introspection_open": {"chip": "high",     "icon": "", "label": "GraphQL introspection OPEN", "group": "tool"},
    "graphql_field_auth_scan":    {"chip": "info",     "icon": "", "label": "GraphQL field auth scan", "group": "tool"},
    "graphql_field_no_authz":     {"chip": "critical", "icon": "", "label": "GraphQL field NO authz",  "group": "tool"},

    # ---- B3 OAST callback receiver (Phase B3, 2026-XX-XX) -----------------
    "oast_token_issued":      {"chip": "info",     "icon": "", "label": "OAST token issued",     "group": "tool"},
    "oast_poll":              {"chip": "info",     "icon": "", "label": "OAST poll",             "group": "tool"},
    "oast_callback_observed": {"chip": "critical", "icon": "", "label": "OAST callback received", "group": "tool"},

    # ---- B4 race-condition tester (Phase B4, 2026-XX-XX) ------------------
    "race_request_run":       {"chip": "info",     "icon": "", "label": "race probe",            "group": "tool"},
    "race_state_diverged":    {"chip": "high",     "icon": "", "label": "race divergence!",      "group": "tool"},

    # ---- B8 HTTP smuggling probe (Phase B8, 2026-XX-XX) -------------------
    "smuggling_probe":          {"chip": "info",     "icon": "", "label": "smuggling probe",       "group": "tool"},
    "smuggling_signal_detected":{"chip": "high",     "icon": "", "label": "smuggling DESYNC!",     "group": "tool"},

    # ---- response-hint extraction (2026-XX-XX) — agent hint-following -----
    # http_get/http_post extract server hints ("use X instead", "deprecated,
    # migrate to /api/v2", "param required", ...) and surface them in the tool
    # result. This event fires when >=1 hint is detected on a response, so the
    # operator can see which endpoints gave hints the agent should have followed.
    "response_hint_surfaced": {"chip": "info", "icon": "", "label": "server hint surfaced", "group": "tool"},

    # ---- cross-endpoint pivot ledger (Tier 3 #6, 2026-XX-XX) -------------
    # http_get records "use X instead" / redirect pivots; pending_pivots()
    # nudges the agent to probe them. recorded = a new pivot the server
    # pointed at; resolved = the agent followed the hint and probed it.
    "endpoint_pivot_recorded": {"chip": "medium", "icon": "↪", "label": "pivot hint recorded", "group": "tool"},
    "endpoint_pivot_resolved": {"chip": "ok",     "icon": "↩", "label": "pivot followed",       "group": "tool"},

    # ---- pre-submission gate (2026-XX-XX) — "will this get nulled?" -------
    # assess_submission scores a finding GO/REVIEW/HOLD before it reaches a
    # bug-bounty program, so weak findings don't get submitted + closed
    # Informative. Stops reputation/embarrassment damage.
    "submission_assessed": {"chip": "info", "icon": "", "label": "submission gate", "group": "tool"},

    # ---- agent / tool stream ----------------------------------------------
    "tool_called": {"chip": "info", "icon": "→", "label": "tool called", "group": "tool"},
    "tool_result": {"chip": "info", "icon": "←", "label": "tool result", "group": "tool"},
    "agent_text":  {"chip": "low",  "icon": "", "label": "agent text",  "group": "tool"},

    # ---- brain queue ------------------------------------------------------
    "brain_enqueued":   {"chip": "medium",   "icon": "⊕", "label": "brain enqueued",   "group": "brain"},
    "brain_started":    {"chip": "medium",   "icon": "▶", "label": "brain started",    "group": "brain"},
    "brain_completed":  {"chip": "ok",       "icon": "", "label": "brain completed",  "group": "brain"},
    "brain_stalled":    {"chip": "medium",   "icon": "⊘", "label": "brain stalled",    "group": "brain"},
    "brain_skipped":    {"chip": "info",     "icon": "∅", "label": "brain skipped",    "group": "brain"},
    "brain_failed":     {"chip": "critical", "icon": "", "label": "brain failed",     "group": "brain"},
    "brain_search":     {"chip": "low",      "icon": "", "label": "brain search",    "group": "brain"},
    "brain_fetch":      {"chip": "low",      "icon": "⤓", "label": "brain fetch",      "group": "brain"},
    "brain_ingest":     {"chip": "low",      "icon": "⊙", "label": "brain ingest",     "group": "brain"},
    "brain_dedup_skip": {"chip": "info",     "icon": "⇄", "label": "brain dedup",      "group": "brain"},
    "brain_topic_saturated": {"chip": "medium", "icon": "", "label": "brain topic saturated", "group": "brain"},
    "ingest_skip_dedup": {"chip": "info",     "icon": "⇄", "label": "ingest dedup-skip",  "group": "brain"},
    "ingest_ok":         {"chip": "ok",       "icon": "⊙", "label": "ingest ok",          "group": "brain"},
    "ingest_url_novelty_override": {"chip": "low", "icon": "↻", "label": "ingest URL-novelty override", "group": "brain"},
    "brain_prewarm":    {"chip": "medium",   "icon": "", "label": "brain pre-warmed", "group": "brain"},

    # ---- chain-attack executor (Phase 3.5) -------------------------------
    "chain_started":    {"chip": "medium",   "icon": "",  "label": "chain started",   "group": "chain"},
    "chain_step_ok":    {"chip": "ok",       "icon": "", "label": "chain step ok",   "group": "chain"},
    "chain_step_fail":  {"chip": "low",      "icon": "", "label": "chain step fail", "group": "chain"},
    "chain_completed":  {"chip": "ok",       "icon": "", "label": "chain completed", "group": "chain"},
    "chain_abandoned":  {"chip": "info",     "icon": "⊘", "label": "chain abandoned", "group": "chain"},

    # ---- WAF / origin-IP / auth bypass intelligence (Phase 9) -------------
    "bypass_probe_ok":         {"chip": "info",     "icon": "", "label": "bypass probe",        "group": "bypass"},
    "bypass_probe_refused":    {"chip": "low",      "icon": "", "label": "bypass probe refused","group": "bypass"},
    "bypass_probe_skipped":    {"chip": "info",     "icon": "·",  "label": "bypass probe skipped","group": "bypass"},
    "bypass_probe_http_error": {"chip": "low",      "icon": "", "label": "bypass probe error",  "group": "bypass"},
    "waf_bypass_attempt":      {"chip": "medium",   "icon": "", "label": "WAF bypass attempt",  "group": "bypass"},
    "waf_bypass_refused":      {"chip": "low",      "icon": "", "label": "WAF bypass refused",  "group": "bypass"},
    "origin_ip_crtsh":         {"chip": "info",     "icon": "", "label": "crt.sh lookup",      "group": "bypass"},
    "origin_ip_probe_hit":     {"chip": "high",     "icon": "", "label": "origin IP found",    "group": "bypass"},
    "origin_ip_probe_refused": {"chip": "low",      "icon": "", "label": "origin probe refused","group": "bypass"},
    "origin_ip_probe_http_error": {"chip": "low",   "icon": "", "label": "origin probe error",  "group": "bypass"},

    # ---- Phase 99 — intelligence-brief phase (pipeline pre-fetches corpus + brain per tech) ----
    "intel_brief_started":         {"chip": "low",      "icon": "", "label": "intel brief started",   "group": "phase"},
    "intel_brief_corpus_query":    {"chip": "info",     "icon": "", "label": "intel: corpus query",  "group": "phase"},
    "intel_brief_brain_enqueued":  {"chip": "medium",   "icon": "", "label": "intel: brain enqueued","group": "phase"},
    "intel_brief_completed":       {"chip": "ok",       "icon": "", "label": "intel brief written",   "group": "phase"},

    # ---- Wave 1 / A1 — prompt-injection defense (2026-XX-XX) --------------
    "injection_defense_triggered": {"chip": "critical", "icon": "", "label": "injection defense fired", "group": "pipeline"},

    # ---- Wave 1 / A2 — handoff primitive (2026-XX-XX) ---------------------
    "phase_handoff":               {"chip": "medium",   "icon": "↪", "label": "phase handoff",          "group": "phase"},

    # ---- Wave 2 / A3 — retester swarm (2026-XX-XX) ------------------------
    "retester_verdict":            {"chip": "ok",       "icon": "", "label": "retester verdict",      "group": "phase"},

    # ---- Wave 2 / A7 — Ctrl+C reconcile (2026-XX-XX) ----------------------
    "ctrlc_reconcile":             {"chip": "high",     "icon": "", "label": "Ctrl+C reconciled",     "group": "pipeline"},

    # ---- Wave 2 / A4 — tracing spans (2026-XX-XX) -------------------------
    # Generic span events render with the colored chip matching the span_kind
    # (tool_call, phase, agent, handoff, etc.). New kinds beyond the 8
    # documented ones still render via DEFAULT_STYLE.
    "span_started":                {"chip": "info",     "icon": "▷", "label": "span started",          "group": "trace"},
    "span_ended":                  {"chip": "ok",       "icon": "◁", "label": "span ended",            "group": "trace"},

    # ---- Wave 9 — Opus 4.7 teacher events (2026-XX-XX) -------------------
    # Teacher fires once-per-phase (review-only mode) or up to 3x-per-phase
    # (full mode). Verdict chip color encoded by the route, not here.
    "teacher_plan":                {"chip": "info",     "icon": "", "label": "teacher plan",          "group": "teacher"},
    "teacher_critique":            {"chip": "medium",   "icon": "", "label": "teacher critique",      "group": "teacher"},
    "teacher_verdict":             {"chip": "ok",       "icon": "",  "label": "teacher verdict",       "group": "teacher"},
    "teacher_rework":              {"chip": "medium",   "icon": "↻",  "label": "teacher rework",        "group": "teacher"},
    "teacher_rejected":            {"chip": "critical", "icon": "",  "label": "teacher rejected",      "group": "teacher"},
    "teacher_budget_exhausted":    {"chip": "medium",   "icon": "",  "label": "teacher budget out",    "group": "teacher"},

    # ---- Phase 2.6 / Fix 4 — per-finding common-sense validator (2026-XX-XX) -----
    # Each `live_confirmed` queue entry gets an Opus per-entry review.
    # Downgrades are flagged so the dashboard surfaces "this would have
    # been a false positive" prominently.
    "common_sense_validated":      {"chip": "info",     "icon": "", "label": "common-sense validated", "group": "teacher"},
    "common_sense_downgraded":     {"chip": "medium",   "icon": "↓",  "label": "downgraded",            "group": "teacher"},
    "common_sense_class_done":     {"chip": "ok",       "icon": "",  "label": "validator done",        "group": "teacher"},

    # ---- Fix 1 — auto-login at phase entry (2026-XX-XX) ------------------
    "auto_login_attempted":        {"chip": "info",     "icon": "", "label": "auto-login attempted",  "group": "phase"},
    "auto_login_failed":           {"chip": "medium",   "icon": "", "label": "auto-login failed",     "group": "phase"},
    "auto_login_skipped":          {"chip": "info",     "icon": "—",  "label": "auto-login skipped",   "group": "phase"},

    # ---- Real-Chrome-via-CDP DataDome bypass (2026-XX-XX) ----------------
    "chrome_bootstrap_started":    {"chip": "low",      "icon": "", "label": "Chrome bootstrap",      "group": "tool"},
    "chrome_attached":             {"chip": "ok",       "icon": "",  "label": "Chrome attached",       "group": "tool"},
    "chrome_session_verified":     {"chip": "ok",       "icon": "", "label": "Chrome session warm",   "group": "tool"},
    "chrome_attach_failed":        {"chip": "critical", "icon": "",  "label": "Chrome attach failed", "group": "tool"},
    "chrome_cookies_snapshotted":  {"chip": "ok",       "icon": "", "label": "Chrome cookies refreshed","group": "tool"},

    # ---- Token-thrifty reports (2026-XX-XX) ------------------------------
    "report_phase_skipped_no_exploits": {"chip": "info", "icon": "⊘",  "label": "report skipped (0 exploits)", "group": "phase"},

    # ---- Cost-cut audit (2026-XX-XX): pre-flight + chain/correlation gates
    "preflight_refused":                                   {"chip": "critical", "icon": "", "label": "pre-flight refused — 0 tokens spent", "group": "pipeline"},
    "chain_phase_skipped_no_confirmed_primitives":         {"chip": "info",     "icon": "⊘",  "label": "chain skipped (0 confirmed primitives)", "group": "phase"},
    "correlation_phase_skipped_no_confirmed_primitives":   {"chip": "info",     "icon": "⊘",  "label": "correlation skipped (0 confirmed primitives)", "group": "phase"},

    # ---- Plan 03-04 (VERIFY-06): PoC verification sandbox events (2026-XX-XX)
    # The Phase 3 verify-phase wraps each non-destructive finding with paired
    # poc_run_started + poc_run_completed events emitted by execute_poc
    # (sentinel/agent/poc/sandbox.py). Both events bucket into the `phase`
    # panel so the dashboard renders them next to phase_started/completed.
    # The completed-event chip is `ok` here as a default — Plan 03-06's
    # dashboard route overrides the chip dynamically based on the
    # `evidence_state` field in the payload (verified -> ok,
    # unreproducible -> low, manual-required -> high), the same dynamic-chip
    # pattern phase_completed uses for its `outcome` field. New event kinds
    # registered here so both the agent-runs panel AND the legal-artifact
    # audit-event renderer pick them up automatically.
    "poc_run_started":   {"chip": "info", "icon": "", "label": "PoC verify started",   "group": "phase"},
    "poc_run_completed": {"chip": "ok",   "icon": "", "label": "PoC verify completed", "group": "phase"},

    # ---- Plan 03-05 (VERIFY-08): correlation input filter applied (2026-XX-XX)
    # Emitted by the pipeline pre-correlation call site when the configured
    # `scope.correlation_input_filter` mode trims findings before they reach
    # the correlation agent. Payload carries `filter_mode`, `findings_before`,
    # `findings_after`, `dropped_states`. group=phase so the event renders
    # next to phase_started/phase_completed in the dashboard's phase panel.
    "correlation_input_filter_applied": {"chip": "info", "icon": "", "label": "correlation filter applied", "group": "phase"},

    # ---- Plan 03-02 (COST-01): operator-explicit cost-cap abort (2026-XX-XX)
    # Distinct from `phase_skipped_budget_exhausted` (line 62) which is the
    # soft default-cap signal. `scan_aborted_cost_cap` fires only when the
    # operator passed --max-cost-usd N AND the strict-mode between-phase
    # guard crossed the threshold. Audit-log entry is hash-chained
    # (CLAUDE.md safety-boundary #2); the chip=critical surface matches
    # `preflight_refused` (both are graceful-refusal pipeline signals).
    # Motivated by the 2026-XX-XX cost finding (.planning/phases/
    # 02-siliconflow-qwen-235b-parity-benchmark/post-mortem/
    # 2026-XX-XX-cost-finding.md): the wrong Qwen alias burned $19.94 on
    # half a Juice Shop bench scan; with --max-cost-usd 5 it would have
    # aborted at ~$5-7.
    "scan_aborted_cost_cap":                               {"chip": "critical", "icon": "", "label": "scan aborted: cost cap (--max-cost-usd)", "group": "pipeline"},

    # ---- Human-in-the-loop login (2026-XX-XX) ----------------------------
    "human_login_requested":  {"chip": "medium",   "icon": "", "label": "human login requested",  "group": "tool"},
    "human_login_completed":  {"chip": "ok",       "icon": "", "label": "human login completed",  "group": "tool"},
    "human_login_skipped":    {"chip": "info",     "icon": "⊘", "label": "human login skipped",    "group": "tool"},
    "human_login_timed_out":  {"chip": "critical", "icon": "","label": "human login timed out",  "group": "tool"},

    # ---- NopeCHA captcha-solver auto-emit (Quick 260517-f7a, 2026-XX-XX) --
    # Fires from _browser_get_impl when a vendor detected pre-wait disappears
    # post-wait — the NopeCHA extension solved the challenge inline.
    "captcha_solved":         {"chip": "ok",       "icon": "","label": "captcha solved",         "group": "tool"},

    # ---- Human-in-the-loop signup (Quick 260517-f7a, 2026-XX-XX) ----------
    # Pause-for-operator account creation. Mirrors human_login_* lifecycle:
    # one event per terminal state (needed/completed/skipped/timeout).
    "human_signup_needed":    {"chip": "medium",   "icon": "","label": "human signup needed",    "group": "tool"},
    "human_signup_completed": {"chip": "ok",       "icon": "", "label": "human signup completed", "group": "tool"},
    "human_signup_skipped":   {"chip": "info",     "icon": "⊘", "label": "human signup skipped",   "group": "tool"},
    "human_signup_timeout":   {"chip": "critical", "icon": "","label": "human signup timed out", "group": "tool"},

    # ---- OOB callback infrastructure (2026-XX-XX) — blind-vuln oracle ----
    # register_oob_token mints a token, agent embeds <token>.oast.fun into
    # the payload, check_oob_callback waits for DNS/HTTP/SMTP callback.
    # Both events show in the agent-runs activity stream + the dedicated
    # /agent-runs/<job_id>/oob panel.
    "oob_token_registered":  {"chip": "info",    "icon": "", "label": "OOB token registered",  "group": "tool"},
    "oob_callback_received": {"chip": "ok",      "icon": "", "label": "OOB callback received", "group": "tool"},

    # ---- OAuth install tool (2026-XX-XX) — token-lifecycle capability -----
    # oauth_install_app walks an operator-registered OAuth app's consent flow
    # in headless Chromium, captures the code, exchanges for refresh+access
    # tokens. Feeds the Phase 2.5 oauth_refresh_replay verifier (RFC 6749
    # §10.4). Render in the activity stream + /agent-runs/<job>/oauth-installs.
    "oauth_install_started":   {"chip": "info", "icon": "", "label": "OAuth install started",   "group": "tool"},
    "oauth_install_completed": {"chip": "ok",   "icon": "",  "label": "OAuth install completed", "group": "tool"},
    "oauth_install_failed":    {"chip": "low",  "icon": "",  "label": "OAuth install failed",    "group": "tool"},
    "oauth_token_captured":    {"chip": "info", "icon": "", "label": "OAuth token captured",    "group": "tool"},

    # ---- Multi-step probe sequencer (Tier 2, 2026-XX-XX) ------------------
    # probe_sequence runs a stateful chain of HTTP steps with named bindings
    # (rotate→extract→replay, CSRF fetch→submit, IDOR id-substitution, ...).
    "probe_sequence_started":   {"chip": "info", "icon": "", "label": "probe sequence started",   "group": "tool"},
    "probe_sequence_step":      {"chip": "info", "icon": "→", "label": "probe sequence step",      "group": "tool"},
    "probe_sequence_completed": {"chip": "ok",   "icon": "", "label": "probe sequence completed", "group": "tool"},

    # ---- OAuth RFC checklist (Tier 2, 2026-XX-XX) ------------------------
    # oauth_rfc_audit runs §6/§10.4/§10.12/§9700 checks against an installed
    # app. oauth_rfc_check fires per clause; completed carries the fail count.
    "oauth_rfc_check":           {"chip": "info",     "icon": "", "label": "OAuth RFC check",          "group": "tool"},
    "oauth_rfc_audit_completed": {"chip": "ok",       "icon": "",  "label": "OAuth RFC audit completed", "group": "tool"},

    # ---- bbot recon orchestrator (2026-XX-XX) — 60+ OSINT modules in one run ----
    # Emitted by sentinel/agent/pentest/bbot_tool.py:run_bbot when a bbot
    # subprocess completes. Renders in agent-runs activity stream + the
    # dedicated /agent-runs/<job_id>/bbot panel.
    "bbot_run_completed":    {"chip": "info",    "icon": "", "label": "bbot recon run",       "group": "tool"},

    # ---- Visual triage pipeline (2026-XX-XX) — gowitness + llava:13b ------
    # visual_recon_captured fires per scope-authorized URL the gowitness
    # subprocess wrote a screenshot for. visual_triage_completed fires per
    # screenshot the local llava:13b vision model returned a description
    # for. Both render in the activity stream + the dedicated
    # /agent-runs/<job_id>/visual panel (screenshot grid + descriptions).
    "visual_recon_captured":   {"chip": "info", "icon": "", "label": "screenshot captured",         "group": "tool"},
    "visual_triage_completed": {"chip": "ok",   "icon": "", "label": "screenshot triaged (LLaVA)",  "group": "tool"},

    # ---- Wave 4 / A5 — constraint gradation (2026-XX-XX) -----------------
    "constraint_lab_only":         {"chip": "low",      "icon": "", "label": "Lab-only",          "group": "phase"},
    "constraint_operational":      {"chip": "medium",   "icon": "", "label": "Operational",       "group": "phase"},
    "constraint_complete":         {"chip": "ok",       "icon": "", "label": "Complete",          "group": "phase"},

    # ---- Wave 4 / A6 — ATT&CK tactic badges (2026-XX-XX) -----------------
    # Each tactic gets its own chip/icon so finding cards in the dashboard
    # can flag which kill-chain stage(s) a finding exercises. The slug is
    # produced by sentinel.web.routes.attack_heatmap from the canonical
    # tactic name.
    "attack_tactic_initial_access":      {"chip": "high",     "icon": "", "label": "Initial Access",      "group": "attack"},
    "attack_tactic_execution":           {"chip": "high",     "icon": "▶", "label": "Execution",            "group": "attack"},
    "attack_tactic_persistence":         {"chip": "high",     "icon": "", "label": "Persistence",          "group": "attack"},
    "attack_tactic_privilege_escalation":{"chip": "critical", "icon": "▲", "label": "Privilege Escalation", "group": "attack"},
    "attack_tactic_defense_evasion":     {"chip": "medium",   "icon": "", "label": "Defense Evasion",      "group": "attack"},
    "attack_tactic_credential_access":   {"chip": "high",     "icon": "", "label": "Credential Access",   "group": "attack"},
    "attack_tactic_discovery":           {"chip": "info",     "icon": "", "label": "Discovery",            "group": "attack"},
    "attack_tactic_lateral_movement":    {"chip": "high",     "icon": "↔", "label": "Lateral Movement",     "group": "attack"},
    "attack_tactic_collection":          {"chip": "medium",   "icon": "", "label": "Collection",           "group": "attack"},
    "attack_tactic_command_and_control": {"chip": "high",     "icon": "", "label": "Command and Control",  "group": "attack"},
    "attack_tactic_exfiltration":        {"chip": "critical", "icon": "", "label": "Exfiltration",         "group": "attack"},
    "attack_tactic_impact":              {"chip": "critical", "icon": "", "label": "Impact",               "group": "attack"},

    # ---- Wave 3 / CTF-only tools (2026-XX-XX) -----------------------------
    "webshell_dropped":            {"chip": "high",     "icon": "", "label": "webshell dropped",      "group": "ctf"},
    "c2_listener_opened":          {"chip": "high",     "icon": "", "label": "C2 listener opened",   "group": "ctf"},
    "c2_command_sent":             {"chip": "medium",   "icon": "", "label": "C2 command sent",       "group": "ctf"},
    "ssh_command_run":             {"chip": "medium",   "icon": "", "label": "SSH cmd run",          "group": "ctf"},
    "ctf_code_executed":           {"chip": "high",     "icon": "", "label": "CTF code executed",    "group": "ctf"},
    "ctf_flag_search":             {"chip": "info",     "icon": "", "label": "CTF flag search",      "group": "ctf"},
    "ctf_flag_found":              {"chip": "critical", "icon": "", "label": "CTF FLAG FOUND",       "group": "ctf"},
    "netcat_probe":                {"chip": "info",     "icon": "", "label": "netcat probe",         "group": "ctf"},
    "ctf_exfil_staged":            {"chip": "high",     "icon": "", "label": "CTF exfil staged",     "group": "ctf"},
    "ctf_writeup_saved":           {"chip": "ok",       "icon": "", "label": "CTF writeup saved",    "group": "ctf"},

    # ---- Wave 5 / CTF-only specialist agents (2026-XX-XX) -----------------
    "codeact_execution":           {"chip": "info",     "icon": "", "label": "CodeAct exec",         "group": "ctf"},
    "sandbox_violation":           {"chip": "critical", "icon": "", "label": "sandbox violation",     "group": "ctf"},
    "replay_attack_step":          {"chip": "medium",   "icon": "↺", "label": "replay step",           "group": "ctf"},
    "redteam_killchain_step":      {"chip": "high",     "icon": "", "label": "kill-chain step",       "group": "ctf"},
    "persistence_dropped":         {"chip": "critical", "icon": "", "label": "persistence dropped",   "group": "ctf"},
    "subghz_decode":               {"chip": "info",     "icon": "", "label": "sub-GHz decoded",       "group": "ctf"},
    "wifi_handshake":              {"chip": "high",     "icon": "", "label": "WiFi handshake crack",  "group": "ctf"},

    # ---- Phase 02 / SiliconFlow Qwen 235B parity benchmark (2026-XX-XX) ---
    # BENCH-05/06/07/08 (Plans 02-01..02-03) emit started/completed pairs
    # per suite. BENCH-09 (Plan 02-04) emits bench_default_profile_flipped
    # into the first suite's audit log when verdict_overall='pass'.
    "bench_parity_eval_started":   {"chip": "low",      "icon": "▶", "label": "parity-eval started",   "group": "pipeline"},
    "bench_parity_eval_completed": {"chip": "ok",       "icon": "", "label": "parity-eval completed", "group": "pipeline"},
    "bench_default_profile_flipped": {"chip": "high",   "icon": "⤿", "label": "default profile flipped", "group": "pipeline"},

    # ---- Wave 7 / Blue-team + DFIR + RE + memory analysis (2026-XX-XX) ----
    "pcap_parsed":                 {"chip": "info",     "icon": "", "label": "pcap parsed",          "group": "tool"},
    "ioc_extracted":               {"chip": "medium",   "icon": "", "label": "IOC extracted",        "group": "tool"},
    "sigma_rule_emitted":          {"chip": "ok",       "icon": "", "label": "Sigma rule emitted",   "group": "tool"},
    "binary_analyzed":             {"chip": "info",     "icon": "", "label": "binary analyzed",      "group": "tool"},
    "memdump_processed":           {"chip": "info",     "icon": "", "label": "memdump processed",    "group": "tool"},

    # ---- Phase 4.5 / STREAM-01 — event-subscription registry (2026-XX-XX) ---
    # Registered here so Plans 04.5-02/03/04/05/06 don't need a second
    # event_styles edit when they consume the registry. subscriber_fired
    # fires once per dispatched callback (success OR error — outcome on
    # payload). streaming_phase_started is emitted by Plans 04.5-02/03/04
    # from inside their callbacks when a downstream phase begins absorbing
    # an upstream phase_completed event. subscribers_halted fires once
    # when Plan 04.5-05's cost-cap watchdog flips the kill switch.
    "subscriber_fired":            {"chip": "info",     "icon": "", "label": "subscriber fired",     "group": "phase"},
    "streaming_phase_started":     {"chip": "info",     "icon": "", "label": "streaming phase started", "group": "phase"},
    "subscribers_halted":          {"chip": "high",     "icon": "", "label": "subscribers halted",    "group": "pipeline"},

    # ---- Phase 5 / NOVEL-06 — Zero-day discovery harness audit events (2026-XX-XX) ----
    # Three event kinds emitted by _run_novelty_sweep in pipeline.py. All
    # bucket into group=phase so the dashboard renders them next to
    # phase_started / phase_completed. The chip vocabulary scales with
    # signal weight: score_computed=info (low signal — every finding gets
    # one), escalated=medium (LLM call about to fire or was declined),
    # evidence_captured=high (validated exploit chain landed — the 0-day
    # candidate the operator actually wants to triage).
    "novelty_score_computed":          {"chip": "info",   "icon": "", "label": "novelty scored",          "group": "phase"},
    "novel_finding_escalated":         {"chip": "medium", "icon": "", "label": "novel finding escalated", "group": "phase"},
    "novel_finding_evidence_captured": {"chip": "high",   "icon": "", "label": "0-day candidate captured","group": "phase"},

    # ---- Phase 2.5 — non-destructive test-workspace mode (2026-XX-XX) ----
    # Verifiers that use scope.auth_credentials test accounts to auto-reproduce
    # vulnerabilities non-destructively (previously stuck waiting for manual
    # operator review). Each per-class verifier emits these three kinds:
    # attempted at the start of the probe, confirmed/disproven at the end.
    "verifier_ndtest_attempted": {"chip": "info",   "icon": "", "label": "verifier ND-test attempted", "group": "phase"},
    "verifier_ndtest_confirmed": {"chip": "high",   "icon": "", "label": "verifier ND-test confirmed", "group": "phase"},
    "verifier_ndtest_disproven": {"chip": "ok",     "icon": "",  "label": "verifier ND-test disproven", "group": "phase"},
    # D3/D4 — weak-evidence downgrade: a single rate-limit probe or a truncated
    # brute-force run is not deterministic proof; verifier defers to the operator
    # rather than auto-confirming.
    "verifier_ndtest_manual":   {"chip": "medium", "icon": "", "label": "verifier ND-test → manual (weak evidence)", "group": "phase"},

    # ---- OAuth refresh-replay verifier (2026-XX-XX) — RFC 6749 §10.4 ------
    # The oauth_refresh_replay auth sub-type runs a 5-step rotation/replay
    # probe against an operator-registered OAuth app. verified = the prior
    # refresh token still works after rotation (Critical bug); disproven =
    # rotation correctly invalidates it (RFC compliant).
    "oauth_refresh_replay_started":   {"chip": "info",     "icon": "", "label": "OAuth refresh-replay probe", "group": "phase"},
    "oauth_refresh_replay_verified":  {"chip": "critical", "icon": "", "label": "OAuth refresh-replay CONFIRMED", "group": "phase"},
    "oauth_refresh_replay_disproven": {"chip": "ok",       "icon": "",  "label": "OAuth refresh-replay disproven (RFC compliant)", "group": "phase"},

    # ---- Evidence-Grade Adversarial Validation gate (2026-XX-XX) ----------
    # The adversarial_validation.gate_finding() pure-Python gate runs over every
    # live_confirmed queue entry BEFORE the Opus common-sense pass. It enforces
    # the 7-rule doctrine (signal!=finding, full-chain/realized-impact,
    # alternative-hypothesis enumeration, documented-by-design, defense-in-depth,
    # variant-vs-control + mechanism, honest evidence_state). All three kinds are
    # emitted from gate_finding via the injected event_emit callable.
    "adversarial_contract_checked": {"chip": "info",     "icon": "", "label": "adversarial contract checked", "group": "phase"},
    "adversarial_downgraded":       {"chip": "medium",   "icon": "", "label": "adversarial gate downgraded",   "group": "phase"},
    "documented_by_design_match":   {"chip": "ok",       "icon": "", "label": "documented-by-design (not a finding)", "group": "phase"},
    # D1 + D7 durable pure-Python evidence gates (2026-XX-XX audit).
    # Emitted by _enforce_pre_exploit_evidence_gates before Phase 3 exploit.
    "fp_gate_recon_inferred_downgraded": {"chip": "medium", "icon": "", "label": "D1: recon_inferred downgraded before exploit", "group": "phase"},
    "fp_gate_weak_evidence_rejected":    {"chip": "medium", "icon": "", "label": "D7: weak evidence rejected before exploit",    "group": "phase"},
}


# ---- Wave 3 — engagement mode badges -----------------------------------

# Per-mode chip / icon / label. The dashboard renders this on every run
# card so CTF / LAB / BBP runs are visually distinct from production
# (which is the only mode that produces client-deliverable PDFs).
MODE_BADGE_STYLES: dict[str, dict] = {
    "production": {"chip": "info",     "icon": "", "label": "production"},
    "bbp":        {"chip": "low",      "icon": "", "label": "bug bounty"},
    "ctf":        {"chip": "medium",   "icon": "", "label": "CTF"},
    "lab":        {"chip": "high",     "icon": "", "label": "lab"},
}


def style_for_mode(mode: str) -> dict:
    """Return the badge styling for an engagement mode. Unknown values
    fall back to a neutral chip so the dashboard never raises."""
    return MODE_BADGE_STYLES.get(
        (mode or "").strip().lower(),
        {"chip": "info", "icon": "·", "label": mode or "unknown"},
    )


# ---- Span-kind styling (Wave 2 / A4) -----------------------------------

# Per-span_kind chip+icon. The flame graph view uses this to color each
# row; adding a new kind requires a row here so the dashboard renders it.
SPAN_KIND_STYLES: dict[str, dict] = {
    "phase":      {"chip": "medium",   "icon": "▣", "label": "phase"},
    "agent":      {"chip": "info",     "icon": "", "label": "agent"},
    "tool_call":  {"chip": "low",      "icon": "", "label": "tool"},
    "handoff":    {"chip": "medium",   "icon": "↪", "label": "handoff"},
    "mcp_list":   {"chip": "info",     "icon": "", "label": "mcp list"},
    "generation": {"chip": "info",     "icon": "", "label": "generation"},
    "guardrail":  {"chip": "high",     "icon": "", "label": "guardrail"},
    "verifier":   {"chip": "ok",       "icon": "", "label": "verifier"},
}


def style_for_span_kind(kind: str) -> dict:
    """Return the chip/icon/label for a span_kind. Unknown kinds get a
    safe default so the renderer never raises."""
    return SPAN_KIND_STYLES.get(kind, {"chip": "info", "icon": "·", "label": kind or "span"})


def attack_tactic_slug(tactic: str) -> str:
    """Wave 4 / A6 — slugify an ATT&CK tactic name into the event-styles key.
    Example: "Initial Access" -> "attack_tactic_initial_access". Stable
    against future tactic additions (returns a key whose lookup falls back
    to DEFAULT_STYLE if no row was added)."""
    slug = (tactic or "").lower().replace(" ", "_").replace("-", "_")
    return f"attack_tactic_{slug}"


def style_for(kind: str) -> EventStyle:
    """Return the styling row for `kind`, falling back to DEFAULT_STYLE."""
    return EVENT_STYLES.get(kind, DEFAULT_STYLE)


def all_kinds() -> list[str]:
    return list(EVENT_STYLES.keys())


def kinds_in_group(group: str) -> list[str]:
    return [k for k, v in EVENT_STYLES.items() if v["group"] == group]
