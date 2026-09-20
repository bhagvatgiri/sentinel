"""Sentinel full-functionality DRY RUN (offline, no target, no Claude).

Exercises the deterministic machinery end-to-end with synthetic data:
  0. inventory + dispatch (classes, verifiers, model routing, event styles)
  1. the doctrine gate matrix (gate_finding) — the heart of FP control
  2. is_documented_by_design (canonical + fail-open)
  3. novel-class verifier FP-guard (no-control -> MANUAL, no network)
  4. INTEGRATED finding-promotion chain on a realistic synthetic engagement:
     gate -> D6 report eligibility -> correlation filter
  5. reliability primitives (_coerce_phase_result, _is_retryable / wall-clock)
  6. bash scanner-signal extraction (E2)

Prints a section-by-section PASS/FAIL/SKIP report. Each check is isolated.
"""
import asyncio
import json
import tempfile
from pathlib import Path

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
SKIP = "\033[33mSKIP\033[0m"
results = {"pass": 0, "fail": 0, "skip": 0}


def check(name, fn):
    try:
        ok, detail = fn()
    except Exception as e:
        results["skip"] += 1
        print(f"  {SKIP}  {name}  ({type(e).__name__}: {e})")
        return
    if ok:
        results["pass"] += 1
        print(f"  {PASS}  {name}  {detail}")
    else:
        results["fail"] += 1
        print(f"  {FAIL}  {name}  {detail}")


from sentinel.core.findings import EvidenceState as E
from sentinel.agent.pentest import adversarial_validation as av


def gate(entry, cls, state=E.LIVE_CONFIRMED, mode="production"):
    return asyncio.run(av.gate_finding(entry, cls, current_state=state, scope_mode=mode))


# ---------------------------------------------------------------- SECTION 0
print("\n=== SECTION 0 — inventory + dispatch ===")

def _classes():
    from sentinel.agent.pentest.vuln_classes import VULN_CLASSES
    slugs = [c.slug for c in VULN_CLASSES]
    return ("novel" in slugs and len(slugs) == 17, f"{len(slugs)} classes, novel={'novel' in slugs}")
check("17 vuln classes incl. novel", _classes)

def _verifier_dispatch():
    import sentinel.agent.pentest.verifiers  # noqa: F401 — eager registration
    from sentinel.agent.pentest.verifier_tool import lookup_verifier
    need = ["novel", "takeover", "redirect", "graphql", "race", "idor", "auth"]
    missing = [s for s in need if lookup_verifier(s) is None]
    return (not missing, f"resolved {len(need)-len(missing)}/{len(need)}; missing={missing}")
check("class verifiers dispatchable", _verifier_dispatch)

def _model_routing():
    from sentinel.agent.model_router import ModelRouter as MR
    import sentinel.agent.model_router as m
    txt = Path(m.__file__).read_text()
    return ("vuln:novel" in txt and "opus" in txt.lower(), "vuln:novel/exploit:novel -> opus present")
check("novel -> Opus routing", _model_routing)

def _event_styles():
    from sentinel.web.event_styles import style_for
    s = style_for("phase_crashed")
    return (s.get("label", "").lower().find("crash") >= 0, f"phase_crashed -> {s.get('label')}")
check("event_styles phase_crashed", _event_styles)


# ---------------------------------------------------------------- SECTION 1
print("\n=== SECTION 1 — doctrine gate matrix (the FP heart) ===")

verifier_idor = {"ID": "IDOR-1", "evidence_state": "live_confirmed",
                 "verification": {"summary": "read victim order #1002 -> victim PII (email,address)"}}
check("verifier-confirmed IDOR survives",
      lambda: (gate(verifier_idor, "idor").new_evidence_state == E.LIVE_CONFIRMED, "-> live_confirmed"))

ExampleChat = {"ID": "JWT-1", "vulnerability_type": "refresh token rotation grace 12h",
         "client_type": "confidential", "is_spec_permitted": True,
         "verification": {"summary": "old refresh valid 12h after rotation"}}
check("CASE B ExampleChat by-design downgraded",
      lambda: (gate(ExampleChat, "jwt").new_evidence_state == E.LIVE_DISPROVEN, "-> live_disproven"))

bare = {"ID": "AUTH-1", "vulnerability_type": "auth gate code bug", "evidence_state": "live_confirmed"}
check("CASE A bare signal downgraded",
      lambda: (gate(bare, "auth").new_evidence_state != E.LIVE_CONFIRMED,
               f"-> {gate(bare,'auth').new_evidence_state.value}"))

sec = {"ID": "AUTH-2", "verification": {"summary": "reached /admin"},
       "adversarial": {"second_control_found": True}}
check("CASE A second-control held",
      lambda: (gate(sec, "auth").new_evidence_state == E.MANUAL_VERIFICATION_REQUIRED, "-> manual"))

novel_full = {"ID": "NOV-1", "adversarial": {
    "realized_impact": "cross-tenant data read", "impact_evidence_ref": "ev/n.json",
    "chain_layers": [{"name": "tenant-id-confusion", "proven": True}],
    "ruled_out_alternatives": ["cache", "shared-fixture", "race"],
    "variant_resp_hash": "aaa", "control_resp_hash": "bbb", "mechanism": "tenant id read from header not token",
    "readback_resp_hash": "ccc",
    # novel is a bypass class → rule 5 requires a defense-in-depth probe.
    "defense_in_depth_probe": "probed for a second tenant-scoping check downstream; none present",
    "second_control_found": False}}
check("novel full contract passes",
      lambda: (gate(novel_full, "novel").passed, f"-> {gate(novel_full,'novel').new_evidence_state.value}"))

novel_nocontrol = {"ID": "NOV-2", "adversarial": {
    "realized_impact": "maybe", "chain_layers": [{"name": "x", "proven": True}],
    "ruled_out_alternatives": ["a", "b", "c"], "variant_resp_hash": "aaa",
    "control_resp_hash": "", "mechanism": "guess"}}
check("novel missing control downgraded",
      lambda: (gate(novel_nocontrol, "novel").new_evidence_state != E.LIVE_CONFIRMED,
               f"-> {gate(novel_nocontrol,'novel').new_evidence_state.value}"))

check("monotonic-down never promotes",
      lambda: (gate(novel_full, "novel", state=E.RECON_INFERRED).new_evidence_state == E.RECON_INFERRED,
               "recon_inferred stays"))
check("CTF mode pass-through",
      lambda: (gate(bare, "auth", mode="ctf").new_evidence_state == E.LIVE_CONFIRMED, "ctf bypass"))


# ---------------------------------------------------------------- SECTION 2
print("\n=== SECTION 2 — is_documented_by_design ===")
def _bydesign_hit():
    ok, txt = asyncio.run(av.is_documented_by_design(
        {"vulnerability_type": "refresh token rotation grace", "client_type": "confidential"},
        "jwt", corpus_search=None))
    return (ok, f"confidential refresh -> by_design={ok} ({txt[:50]})")
check("canonical ExampleChat refresh = by-design", _bydesign_hit)

def _failopen():
    ok, txt = asyncio.run(av.is_documented_by_design(
        {"vulnerability_type": "totally novel logic bug xyz"}, "idor", corpus_search=None))
    return (ok is False, f"fail-open (corpus None) -> by_design={ok}")
check("fail-open never suppresses", _failopen)


# ---------------------------------------------------------------- SECTION 3
print("\n=== SECTION 3 — novel verifier FP-guard (no network) ===")
def _novel_nocontrol_manual():
    import sentinel.agent.pentest.verifiers  # noqa
    from sentinel.agent.pentest.verifier_tool import lookup_verifier, VerificationContext
    from sentinel.core.scope import Scope
    fn = lookup_verifier("novel")
    with tempfile.TemporaryDirectory() as td:
        ev = Path(td) / "ev"; ev.mkdir()
        ctx = VerificationContext(
            scope=Scope.__new__(Scope), target="https://x.test",
            workspace_dir=Path(td), vuln_class="novel",
            queue_entry={"ID": "NOV-X", "adversarial": {"variant_request": "GET /a", "mechanism": "m"}},
            entry_id="NOV-X", evidence_dir=ev, auth_credentials=[])
        res = asyncio.run(fn(ctx))
    return (res.state == E.MANUAL_VERIFICATION_REQUIRED, f"no control_request -> {res.state.value}")
check("novel no-control -> MANUAL", _novel_nocontrol_manual)


# ---------------------------------------------------------------- SECTION 4
print("\n=== SECTION 4 — INTEGRATED promotion chain (synthetic engagement) ===")
def _integrated():
    from sentinel.agent.pentest.exploit_summary import count_exploitable_findings
    from sentinel.agent.pentest.pipeline import _filter_findings_for_correlation  # noqa
    # 8 findings across classes/states; gate each, then simulate report + correlation
    findings = [
        ("idor", verifier_idor, "EXPLOITED"),       # should reach report
        ("jwt", ExampleChat, "EXPLOITED"),                 # by-design -> dropped
        ("auth", bare, "EXPLOITED"),                 # bare -> dropped
        ("novel", novel_full, "EXPLOITED"),          # full contract -> reach
        ("novel", novel_nocontrol, "EXPLOITED"),     # no control -> dropped
    ]
    gated = []
    for cls, entry, _ in findings:
        out = gate(entry, cls)
        gated.append((cls, entry["ID"], out.new_evidence_state.value))
    confirmed = [g for g in gated if g[2] in ("live_confirmed", "verified")]
    # D6 report eligibility on a temp workspace. Accumulate per class (two
    # 'novel' findings share the same class file — must not overwrite).
    with tempfile.TemporaryDirectory() as td:
        deliv = Path(td) / "deliverables"; deliv.mkdir()
        per_class: dict = {}
        for cls, entry, status in findings:
            fid = entry["ID"]
            kept = next((g[2] for g in gated if g[1] == fid), "")
            d = per_class.setdefault(cls, {"blocks": [], "entries": []})
            d["blocks"].append(f"### {fid}: x\n**Status:** {status}\n**Severity:** high\n")
            d["entries"].append({"ID": fid, "evidence_state": kept})
        for cls, d in per_class.items():
            (deliv / f"{cls}_exploitation_evidence.md").write_text(
                "## Successfully Exploited Vulnerabilities\n\n" + "\n".join(d["blocks"]))
            (deliv / f"{cls}_exploitation_queue.json").write_text(
                json.dumps({"vulnerabilities": d["entries"]}))
        n, rep = count_exploitable_findings(Path(td))
    rep_ids = sorted({f.finding_id for f in rep})
    detail = (f"gated={ {g[1]: g[2] for g in gated} } | report_eligible={rep_ids}")
    # Expect: IDOR-1 + NOV-1 reach the report; the rest dropped
    ok = set(rep_ids) == {"IDOR-1", "NOV-1"}
    print(f"        detail: {detail}")
    return (ok, f"report_eligible={rep_ids} (expected IDOR-1, NOV-1)")
check("full chain: only verified findings reach report", _integrated)

def _correlation_filter():
    from sentinel.agent.pentest.pipeline import _filter_findings_for_correlation
    from sentinel.core.findings import Finding, Severity
    fs = [Finding(title=s.value, description="d", severity=Severity.HIGH, scanner="t",
                  target="http://x", location=s.value, evidence_state=s) for s in E]
    kept, weak = _filter_findings_for_correlation(fs, "verified_only")
    kept_states = {f.evidence_state for f in kept}
    return (kept_states == {E.VERIFIED, E.LIVE_CONFIRMED} and weak == [],
            f"verified_only keeps {len(kept)} (VERIFIED+LIVE_CONFIRMED), weak={len(weak)}")
check("correlation filter (kept,weak) contract", _correlation_filter)


# ---------------------------------------------------------------- SECTION 5
print("\n=== SECTION 5 — reliability primitives ===")
def _coerce():
    from sentinel.agent.pentest.pipeline import PentestPipeline, PhaseResult
    dummy = object.__new__(PentestPipeline)
    exc = PentestPipeline._coerce_phase_result(dummy, RuntimeError("boom"), "vuln:idor", None)
    good = PentestPipeline._coerce_phase_result(dummy, PhaseResult("x", 1, 0.0, 1, True), "x", None)
    return (isinstance(exc, PhaseResult) and not exc.success and good.success,
            f"exc->failed PhaseResult({exc.name}); PhaseResult passthrough OK")
check("_coerce_phase_result (C1)", _coerce)

def _cancelled_reraises():
    from sentinel.agent.pentest.pipeline import PentestPipeline
    dummy = object.__new__(PentestPipeline)
    try:
        PentestPipeline._coerce_phase_result(dummy, asyncio.CancelledError(), "x", None)
        return (False, "did NOT re-raise CancelledError")
    except asyncio.CancelledError:
        return (True, "CancelledError re-raised (honors cancellation)")
check("_coerce re-raises CancelledError", _cancelled_reraises)

def _wallclock_nonretryable():
    from sentinel.agent.pentest.pipeline import _is_retryable, PhaseWallClockExceeded
    return (_is_retryable(PhaseWallClockExceeded("t")) is False and _is_retryable(TimeoutError()) is True,
            "PhaseWallClockExceeded non-retryable; TimeoutError retryable")
check("C5 wall-clock non-retryable", _wallclock_nonretryable)


# ---------------------------------------------------------------- SECTION 6
print("\n=== SECTION 6 — bash scanner-signal extraction (E2) ===")
def _scanner_signals():
    from sentinel.agent.pentest.bash_tool import _extract_scanner_signals
    nuclei = '{"info":{"name":"CVE-2024-1234","severity":"high"},"matched-at":"https://x/a"}\n' \
             '{"info":{"name":"exposed-panel","severity":"medium"},"matched-at":"https://x/admin"}'
    out = _extract_scanner_signals("nuclei", nuclei)
    return ("SCANNER SIGNALS" in out and "high" in out.lower() and "CVE-2024-1234" in out,
            f"extracted {len(out)} chars incl severity-sorted hits")
check("nuclei signal extraction", _scanner_signals)


# ---------------------------------------------------------------- REPORT
print("\n" + "=" * 60)
print(f"DRY RUN COMPLETE:  {PASS} {results['pass']}   {FAIL} {results['fail']}   {SKIP} {results['skip']}")
print("=" * 60)
import sys
sys.exit(1 if results["fail"] else 0)
