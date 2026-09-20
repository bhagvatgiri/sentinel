"""STREAM-03 — hermetic tests for the streaming ReportContext accumulator.

The accumulator (`sentinel.agent.pentest.report_prompt.ReportContext`) subscribes
ONCE to `'phase_completed'` (the exact-match kind the pipeline emits — see
``KIND_PHASE_COMPLETED='phase_completed'`` at ``sentinel/agent/event_log.py:50``)
and filters internally on ``event['phase'] == 'recon'``. When the recon phase
lands, the callback reads ``workspace/deliverables/recon_deliverable.md`` into
``context.recon_body`` so the eventual Phase 5 report-agent prompt can be
pre-drafted with engagement-context / methodology / scope sections that don't
depend on exploit findings.

Load-bearing invariants pinned here:

  - ONE subscription registered on exact-match ``'phase_completed'`` with
    ``callback_name='report.absorb'``.
  - Internal filter: non-recon phases (``vuln:xss``, ``correlation``, etc.) do
    NOT trigger any body capture.
  - ``install()`` threads ``event_log=event_log`` into
    ``event_subscribers.subscribe(...)`` so Plan 04.5-05's cost-cap watchdog
    can capture the EventLog reference (BLOCKER 1 wiring owned by this plan).
  - Defensive: a missing ``recon_deliverable.md`` is NOT a crash — the
    accumulator stays at ``recon_body=None`` and the subscriber survives.
  - Pathological recon bodies (>8000 chars) are truncated inside
    ``render_report_prompt`` with a ``... (truncated)`` marker.
  - Back-compat: ``render_report_prompt(...)`` with no ``recon_prewarmed=``
    kwarg (or ``recon_prewarmed=None``) emits a byte-identical prompt to the
    pre-Plan-04.5-04 baseline (the inline snapshot below pins this).
  - ``drain_report_streaming_to_prompt(context, ...)`` byte-equals
    ``render_report_prompt(..., recon_prewarmed=context.recon_body)``.
  - Pipeline integration smoke (Test 13 — Task 2 territory): both
    CorrelationContext + ReportContext install/uninstall lifecycle works
    end-to-end through ``pipeline.run()``.

Runs offline. No network. No Claude SDK. No Ollama. No Chroma.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentinel.agent import event_log as elog
from sentinel.agent.pentest import event_subscribers as subs


# ---- Autouse reset fixture (same pattern as test_event_subscribers.py /
#      test_correlation_streaming.py / test_verify_streaming.py) -----------


@pytest.fixture(autouse=True)
def _reset_subs():
    subs.clear_subscribers()
    subs.reset_halt()
    yield
    subs.clear_subscribers()
    subs.reset_halt()


@pytest.fixture
def tmp_log(tmp_path: Path) -> elog.EventLog:
    return elog.EventLog(tmp_path / "events.jsonl")


# ---- Fixed kwargs used by the back-compat snapshot test ------------------


_BASELINE_KWARGS = dict(
    client="acme-corp",
    engagement_id="2026-Q1-test-001",
    target="https://staging.acme-corp.example",
    workspace="/tmp/ws",
    max_turns=40,
    max_budget_usd=10.0,
    env_context_block=None,
    style="full",
    exploit_summary=None,
    n_exploits=0,
)


# ---- Inline snapshot — pre-Plan-04.5-04 render_report_prompt output ------
# Captured 2026-XX-XX at plan execution time by running the existing
# render_report_prompt(**_BASELINE_KWARGS) BEFORE the recon_prewarmed=
# kwarg was added. Pinned here as a triple-quoted multi-line string so any
# future drift in render_report_prompt (style="full" + env_context_block=None
# path) fails Test 7 loudly.
#
# The snapshot lives INLINE in this file — NO separate fixture file under
# tests/fixtures/. (Per plan revision iter 2 WARNING 2.)


_RENDER_REPORT_PROMPT_BASELINE = """You are Sentinel's final-report agent. The pentest pipeline has completed
all phases on this engagement and you have on-disk:

- `recon_deliverable.md`
- 6 × `<class>_analysis_deliverable.md`
- 6 × `<class>_exploitation_evidence.md`
- 6 × `<class>_exploitation_queue.json`
- `chain_analysis_deliverable.md`

Plus optionally a SAST cache (`sast_findings.json`).

## Engagement context

- **Client:** acme-corp
- **Engagement ID:** 2026-Q1-test-001
- **Target:** https://staging.acme-corp.example
- **Workspace:** /tmp/ws

## CRITICAL — Evidence-state gating (Phase 2.5 ground truth)

For EVERY entry across the `<class>_exploitation_queue.json` files, read the
`evidence_state` field BEFORE deciding where it goes in the report:

- `live_confirmed`        → eligible for the Findings By Severity table with
                            full claimed severity. Phase 2.5 reproduced the
                            bug end-to-end — this is a real finding.
- `live_disproven`        → DO NOT include in Findings table. Move to an
                            "Unverified Hypotheses (verifier-disproven)"
                            appendix with the verifier's note explaining why
                            the bug did not reproduce.
- `requires_test_credentials` / `requires_two_accounts` →
                            DO NOT include in Findings table. Move to a
                            "Blocked on Operator Credentials" appendix.
- `manual_verification_required` →
                            DO NOT include in Findings table. Move to an
                            "Operator Manual Verification Required" appendix
                            with the reason (e.g., destructive policy).
- `verification_error`    → DO NOT include in Findings table. Move to a
                            "Verifier Errored — Unknown State" appendix
                            so the operator knows to re-run.

Recon-inferred severity in queue entries is a HYPOTHESIS, not a finding.
Phase 2.5's verdict supersedes the recon-inferred severity. Headline
findings, Executive Summary, and CVSS scores must reflect ONLY
`live_confirmed` evidence. The deliverable's credibility — and the
operator's bug-bounty reputation — depends on this discipline.

If after gating ZERO entries remain `live_confirmed`, the report MUST say so
explicitly in the Executive Summary: "Phase 2.5 live verification disproved
or could not test all queue entries. No live-confirmed findings in this
engagement; see appendices for hypothesis-state breakdown."

The chain analysis (`chain_analysis_deliverable.md` + `chain_execution_
evidence.md`) follows the same rule: only chains whose terminal step succeeded
AND whose composing primitives were `live_confirmed` belong in the Findings
table. Chains that abandoned because primitives were not verifier-confirmed
go in the disproven-hypotheses appendix.

## Your job

Write `deliverables/comprehensive_security_assessment_report.md` — a
single-document client deliverable. Concise. Action-oriented. No filler.

Required sections (in this order):

1. **Executive summary** (4-6 sentences). Plain language for a non-technical
   exec. State the engagement scope, the headline finding, the most
   important mitigation.

2. **Findings by severity** — table:
   ```
   | Severity | Count |
   |----------|-------|
   | critical | N     |
   | high     | N     |
   | medium   | N     |
   | low      | N     |
   | info     | N     |
   ```
   Counts include ONLY `live_confirmed` entries from the per-class queues
   plus chains whose primitives were all live_confirmed.

   IMMEDIATELY AFTER the severity table, render the **Findings constraint
   gradation** table (Wave 4 / A5 — paper 2510.17521). For every
   `live_confirmed` entry, render one row with these columns:

   ```
   | ID | Severity | Lab | Operational | Complete | Title |
   |----|----------|-----|-------------|----------|-------|
   | CSRF-VULN-04 | High | ✓ | ✓ | ✗ | Missing CSRF token |
   ```

   - `Lab` (`reproduces_in_lab`)            — bug reproduces given any state.
   - `Operational` (`reproduces_under_operational`) — bug reproduces while
       service uptime is maintained AND the probe stays under a 5% error rate
       (no destructive testing).
   - `Complete` (`reproduces_complete`)     — bug reproduces operationally
       AND a Sentinel-synthesised remediation patch blocks the same probe
       on a fixture. Wave 4 leaves Complete almost always ✗ — that is honest.

   These flags live on the queue entry's `verification` block. Read them
   verbatim — DO NOT infer from severity. A finding can be `live_confirmed`
   yet fail Operational (verifier had to flap the endpoint), and the report
   must show that ✗ honestly.

   If zero entries remain after gating, render the table as:
   ```
   ## Findings by Severity
   _No live-confirmed findings._ See appendices for verifier-disproven
   hypotheses, blocked-on-credentials entries, and manual-verification-
   required items.
   ```

   After the severity table, render these appendix sub-sections (omit any
   that have zero entries):
   - **Appendix A — Unverified Hypotheses (verifier-disproven):** every
     `live_disproven` entry with the verifier's reason
   - **Appendix B — Blocked on Operator Credentials:** every
     `requires_test_credentials` / `requires_two_accounts` entry
   - **Appendix C — Operator Manual Verification Required:** every
     `manual_verification_required` entry
   - **Appendix D — Verifier Errored:** every `verification_error` entry,
     so the operator knows to re-run after the underlying tooling is fixed

3. **Top 5 priority remediations** — ranked. Each one names the ID(s) it
   addresses, the engineering effort to implement (S/M/L), and the impact
   reduction.

4. **Detailed findings** — for each `<ID>` (across all classes + chains):
   - One-line title
   - Severity
   - **ATT&CK techniques** (e.g. `T1190, T1078`) and **CAPEC patterns**
     (e.g. `CAPEC-66`) — Wave 4 / A6. Read these from the entry's
     `attack_technique_ids` / `capec_ids` fields if present; otherwise
     leave a single line "ATT&CK / CAPEC: untagged".
   - **Constraint gradation:** `Lab=✓/✗  Operational=✓/✗  Complete=✓/✗`
     Match the row in the gradation table.
   - Affected surface (URL/endpoint/component)
   - One-paragraph technical detail
   - Reproduction (concrete commands)
   - Recommended fix

5. **ATT&CK Coverage Heatmap** (Wave 4 / A6) — render a one-row-per-tactic
   table showing which ATT&CK kill-chain stages this engagement exercised:

   ```
   | Tactic                | Findings exercising | Technique IDs |
   |-----------------------|---------------------|---------------|
   | Initial Access        | 4                   | T1190, T1133  |
   | Execution             | 1                   | T1059.007     |
   | Persistence           | 0                   | —             |
   | Privilege Escalation  | 0                   | —             |
   | Defense Evasion       | 2                   | T1078         |
   | Credential Access     | 1                   | T1556         |
   | Discovery             | 0                   | —             |
   | Lateral Movement      | 0                   | —             |
   | Collection            | 0                   | —             |
   | Command and Control   | 0                   | —             |
   | Exfiltration          | 0                   | —             |
   | Impact                | 0                   | —             |
   ```

   Use the canonical ATT&CK enterprise tactic ordering above. A finding
   with multiple techniques shows up in each tactic it touches.

6. **Confirmed safe** — bullet list of components/controls observed to be
   correctly implemented. Sized to give the operator confidence in what
   they've already done right.

7. **Engagement methodology** — 1 short paragraph. What phases ran
   (recon, vuln-analysis, exploitation, correlation), what tools, what
   constraints (rate limit, scope, time budget).

8. **Scope and audit trail** — note the engagement scope file, the audit
   log path, and that every URL touched is recorded there.

## Tools available

- **read_file(path)** — read every input.
- **write_deliverable(filename, content)** — write the final report.
- **corpus_search(query, source_filter, top_k)** — useful for compliance
  framework references in the remediation suggestions.
- **Task(subagent_type='deliverable_summarizer', ...)** — Use this to read
  EACH deliverable in a fresh sub-context. The subagent returns a ~200-word
  structured summary per file. PREFER THIS over read_file for the per-class
  deliverables — it keeps your own context window slim so you can hold
  every summary at once during synthesis. Only fall back to direct
  read_file when you need a specific quote/payload verbatim for the
  Detailed Findings section.

## Recommended flow

1. List the deliverables you expect (recon + 6 analysis + 6 evidence +
   chain_analysis). For each, spawn a `deliverable_summarizer` Task in
   parallel where possible. Tolerate missing files (some classes produce
   empty queues → no evidence file).
2. Once all summaries return, synthesize the executive summary, severity
   table, top-5 remediations, and confirmed-safe sections directly from
   the summaries — no further reads needed.
3. For the Detailed Findings section ONLY, use read_file on the specific
   evidence files to grab exact reproduction commands and payloads.
4. Write the final report once, in one write_deliverable call.

## Constraints

- Maximum **40 agent turns**.
- Maximum **$10.00** in LLM spend.
- One output file. Don't write notes / scratchpad files.

Begin by listing the deliverables/ dir contents (via read_file on each
expected name; tolerate missing files for vuln classes that produced
empty queues).
"""


# ==========================================================================
# Task 1 tests — ReportContext accumulator + render_report_prompt extension
# ==========================================================================


# ---- Test 1 — empty accumulator ------------------------------------------


def test_empty_accumulator_recon_body_is_none(tmp_path: Path):
    from sentinel.agent.pentest.report_prompt import ReportContext

    ctx = ReportContext(workspace=tmp_path)
    assert ctx.recon_body is None
    assert ctx.recon_received_ts is None


# ---- Test 2 — install registers ONE subscription on 'phase_completed' ----


def test_install_registers_one_phase_completed_subscription(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.report_prompt import ReportContext

    ctx = ReportContext(workspace=tmp_path)
    mock_audit = MagicMock()

    before = subs.subscriptions()
    ctx.install(event_log=tmp_log, audit_log=mock_audit)
    after = subs.subscriptions()

    # At least one new subscription registered (cost-cap watchdog from
    # Plan 04.5-05 may also auto-install — filter by callback_name to be
    # precise about WHICH subscription belongs to ReportContext).
    report_subs = [h for h in after if h.callback_name == "report.absorb"]
    assert len(report_subs) == 1
    handle = report_subs[0]
    assert handle.event_kind_pattern == "phase_completed"
    assert handle.callback_name == "report.absorb"
    # And no pre-existing subscription was removed.
    assert len(after) >= len(before) + 1


# ---- Test 3 — install emits streaming_phase_started ----------------------


def test_install_emits_streaming_phase_started_event(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.report_prompt import ReportContext

    ctx = ReportContext(workspace=tmp_path)
    ctx.install(event_log=tmp_log, audit_log=None)

    started = [
        e for e in tmp_log.all_events()
        if e["kind"] == "streaming_phase_started" and e.get("phase") == "report"
    ]
    assert len(started) == 1
    assert started[0]["phase"] == "report"
    assert started[0]["trigger_phase"] == "pipeline_startup"


# ---- Test 4 — absorb on recon phase_completed reads the deliverable ------


def test_absorb_on_recon_phase_completed_reads_deliverable(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.report_prompt import ReportContext

    workspace = tmp_path / "ws"
    deliv_dir = workspace / "deliverables"
    deliv_dir.mkdir(parents=True)
    (deliv_dir / "recon_deliverable.md").write_text(
        "# Recon\n\nFound 3 endpoints", encoding="utf-8",
    )

    ctx = ReportContext(workspace=workspace)
    ctx.install(event_log=tmp_log, audit_log=None)

    tmp_log.emit("phase_completed", phase="recon")

    assert ctx.recon_body == "# Recon\n\nFound 3 endpoints"
    assert ctx.recon_received_ts is not None
    assert ctx.recon_received_ts > 0


# ---- Test 5 — non-recon phase_completed is a no-op -----------------------


def test_absorb_ignores_non_recon_phase_completed(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.report_prompt import ReportContext

    workspace = tmp_path / "ws"
    deliv_dir = workspace / "deliverables"
    deliv_dir.mkdir(parents=True)
    # Drop a recon deliverable so we can prove the callback IGNORED it.
    (deliv_dir / "recon_deliverable.md").write_text("# Recon\n", encoding="utf-8")

    ctx = ReportContext(workspace=workspace)
    ctx.install(event_log=tmp_log, audit_log=None)

    for phase in ("vuln:xss", "exploit:sqli", "correlation", "report",
                  "verify-phase-03", "chain_execute"):
        tmp_log.emit("phase_completed", phase=phase)

    assert ctx.recon_body is None
    assert ctx.recon_received_ts is None


# ---- Test 6 — defensive truncation at 8000 chars -------------------------


def test_render_report_prompt_truncates_recon_prewarmed_at_8000_chars(
    tmp_path: Path,
):
    """Pathological recon body (20000 chars) must be truncated to 8000 chars +
    an explicit ``... (truncated)`` marker so the report prompt can't balloon.
    """
    from sentinel.agent.pentest.report_prompt import render_report_prompt

    huge_body = "X" * 20000
    out = render_report_prompt(
        client="c", engagement_id="e", target="t", workspace="w",
        max_turns=1, max_budget_usd=1.0,
        env_context_block=None,
        style="full", exploit_summary=None, n_exploits=0,
        recon_prewarmed=huge_body,
    )

    # The body's X-run must be bounded by 8000 chars in the rendered output.
    assert "X" * 20000 not in out
    # The truncation marker must be present.
    assert "... (truncated)" in out
    # And the section header is still present (we didn't skip the block).
    assert "## Pre-drafted engagement context (from recon)" in out
    # Sanity — the rendered output must contain SOME X's (the prefix made it in).
    assert "X" * 100 in out


# ---- Test 7 — back-compat snapshot (recon_prewarmed=None) -----------------


def test_render_report_prompt_back_compat_snapshot_when_recon_prewarmed_none():
    """LOAD-BEARING. The pre-Plan-04.5-04 render_report_prompt output for a
    fixed kwargs set is pinned as ``_RENDER_REPORT_PROMPT_BASELINE`` above.
    Calling render_report_prompt(**same_kwargs, recon_prewarmed=None) MUST
    produce byte-identical output.

    If this test fails after a future edit to REPORT_PROMPT or
    render_report_prompt, the snapshot must be re-captured INTENTIONALLY
    (audit-log style — the change to the constant is the legal artifact).
    """
    from sentinel.agent.pentest.report_prompt import render_report_prompt

    out = render_report_prompt(**_BASELINE_KWARGS, recon_prewarmed=None)
    assert out == _RENDER_REPORT_PROMPT_BASELINE


# ---- Test 8 — recon_prewarmed populated injects the section --------------


def test_render_report_prompt_injects_section_when_recon_prewarmed_populated():
    from sentinel.agent.pentest.report_prompt import render_report_prompt

    out = render_report_prompt(
        client="c", engagement_id="e", target="t", workspace="w",
        max_turns=1, max_budget_usd=1.0,
        env_context_block=None,
        style="full", exploit_summary=None, n_exploits=0,
        recon_prewarmed="# canned recon body",
    )

    assert "## Pre-drafted engagement context (from recon)" in out
    assert "# canned recon body" in out
    assert "<recon_deliverable>" in out


# ---- Test 9 — defensive: missing recon_deliverable.md is not a crash -----


def test_absorb_on_missing_recon_deliverable_does_not_crash(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.report_prompt import ReportContext

    workspace = tmp_path / "ws"
    deliv_dir = workspace / "deliverables"
    deliv_dir.mkdir(parents=True)
    # NOTE: no recon_deliverable.md written.

    ctx = ReportContext(workspace=workspace)
    ctx.install(event_log=tmp_log, audit_log=None)

    # Must not raise.
    tmp_log.emit("phase_completed", phase="recon")

    assert ctx.recon_body is None


# ---- Test 10 — uninstall removes the subscription -----------------------


def test_uninstall_removes_subscription(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    from sentinel.agent.pentest.report_prompt import ReportContext

    def _count_report_absorb() -> int:
        return len([h for h in subs.subscriptions()
                    if h.callback_name == "report.absorb"])

    before_count = _count_report_absorb()
    assert before_count == 0

    ctx = ReportContext(workspace=tmp_path)
    ctx.install(event_log=tmp_log, audit_log=None)
    assert _count_report_absorb() == 1

    ctx.uninstall()
    assert _count_report_absorb() == 0


# ---- Test 11 — drain_report_streaming_to_prompt byte-identity ------------


def test_drain_report_streaming_to_prompt_matches_direct_render_with_recon(
    tmp_path: Path, tmp_log: elog.EventLog,
):
    """drain_report_streaming_to_prompt(ctx, **kw) MUST byte-equal
    render_report_prompt(**kw, recon_prewarmed=ctx.recon_body) when the
    context has absorbed a recon body.
    """
    from sentinel.agent.pentest.report_prompt import (
        ReportContext, drain_report_streaming_to_prompt, render_report_prompt,
    )

    workspace = tmp_path / "ws"
    deliv_dir = workspace / "deliverables"
    deliv_dir.mkdir(parents=True)
    (deliv_dir / "recon_deliverable.md").write_text(
        "# Recon\n\nSome findings", encoding="utf-8",
    )

    ctx = ReportContext(workspace=workspace)
    ctx.install(event_log=tmp_log, audit_log=None)
    tmp_log.emit("phase_completed", phase="recon")
    assert ctx.recon_body == "# Recon\n\nSome findings"

    kwargs = dict(
        client="c", engagement_id="e", target="t", workspace="w",
        max_turns=1, max_budget_usd=1.0,
        env_context_block=None, style="full",
        exploit_summary=None, n_exploits=0,
    )
    output_drain = drain_report_streaming_to_prompt(ctx, **kwargs)
    output_direct = render_report_prompt(
        **kwargs, recon_prewarmed=ctx.recon_body,
    )
    assert output_drain == output_direct


# ---- Test 12 — drain with no recon == baseline ---------------------------


def test_drain_report_streaming_to_prompt_with_no_recon_matches_baseline(
    tmp_path: Path,
):
    """Empty ReportContext (no absorb) must drain to byte-identical baseline
    output as render_report_prompt(**kw) (no recon_prewarmed= kwarg).
    Transitively asserts Test 7 via the drain path.
    """
    from sentinel.agent.pentest.report_prompt import (
        ReportContext, drain_report_streaming_to_prompt, render_report_prompt,
    )

    ctx = ReportContext(workspace=tmp_path)
    # NO install / absorb — ctx.recon_body stays None.

    kwargs = dict(
        client="c", engagement_id="e", target="t", workspace="w",
        max_turns=1, max_budget_usd=1.0,
        env_context_block=None, style="full",
        exploit_summary=None, n_exploits=0,
    )
    output_drain = drain_report_streaming_to_prompt(ctx, **kwargs)
    output_baseline = render_report_prompt(**kwargs)
    assert output_drain == output_baseline


# ==========================================================================
# Task 2 — pipeline-integration smoke test
# ==========================================================================


# ---- Test 13 — pipeline integration smoke: both contexts wired -----------


def test_pipeline_integration_smoke(tmp_path: Path):
    """End-to-end-ish smoke: build a PentestPipeline-like surface that mocks
    out the real agent calls and asserts that at the moment the report
    phase would run, both _correlation_ctx.all_findings() AND
    _report_ctx.recon_body reflect what the upstream emits delivered. After
    pipeline_completed emit, both contexts are uninstalled (subscriptions()
    no longer contains correlation.absorb / report.absorb).

    This is a sanity check — the byte-identity tests in
    test_streaming_batch_equivalence.py + the back-compat snapshot in this
    file's Test 7 cover the prompt-shape proofs.
    """
    from sentinel.agent.pentest.correlation import CorrelationContext
    from sentinel.agent.pentest.report_prompt import ReportContext

    workspace = tmp_path / "ws"
    deliv_dir = workspace / "deliverables"
    deliv_dir.mkdir(parents=True)
    (deliv_dir / "recon_deliverable.md").write_text(
        "# Recon\n\nFound endpoints", encoding="utf-8",
    )

    event_log = elog.EventLog(tmp_path / "events.jsonl")

    correlation_ctx = CorrelationContext(workspace=workspace)
    report_ctx = ReportContext(workspace=workspace)

    correlation_ctx.install(event_log=event_log, audit_log=None)
    report_ctx.install(event_log=event_log, audit_log=None)

    # Simulate the pipeline's phase_completed events in order.
    event_log.emit("phase_completed", phase="recon")
    # Vuln phases would normally have queue files; for this smoke we just emit
    # them and expect the correlation accumulator to walk empty entries
    # gracefully (no crash, empty findings).
    event_log.emit("phase_completed", phase="vuln:xss")
    event_log.emit("phase_completed", phase="exploit:xss")

    # By the time the correlation phase would render, both contexts are
    # live with their absorbed state.
    assert report_ctx.recon_body == "# Recon\n\nFound endpoints"
    # CorrelationContext entries may include empty findings (no queue files)
    # but the accumulator absorbed both events.
    assert len(correlation_ctx.entries) == 2

    # Simulate pipeline_completed handler tearing down both contexts.
    correlation_ctx.uninstall()
    report_ctx.uninstall()

    remaining = {h.callback_name for h in subs.subscriptions()}
    assert "correlation.absorb" not in remaining
    assert "report.absorb" not in remaining
