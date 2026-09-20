"""STREAM-01 — hermetic tests for the event-subscription registry.

The registry (`sentinel/agent/pentest/event_subscribers.py`) turns the existing
one-way `event_log.emit(kind, **payload)` machinery into a subscription bus
that downstream Phase 4.5 plans (correlation streaming, verify streaming,
report pre-warm, cost-cap halt, dashboard tab) consume.

Load-bearing invariants pinned here:
  - registration order is preserved (list, not dict)
  - dispatch fires synchronously in registration order (NEVER parallel)
  - every callback invocation writes a `subscriber_fired` audit-log entry
    through the EXISTING `AuditLog.write` API (hash-chained, append-only)
  - subscriber exceptions NEVER propagate up into `event_log.emit`
  - dispatch fires AFTER the on-disk JSONL write so a subscriber crash
    cannot corrupt the legal artifact
  - halt-on-event short-circuits dispatch (STREAM-05 hook lands here)

Runs offline. No network. No Claude SDK. No Ollama. No Chroma.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentinel.agent import event_log as elog
from sentinel.agent.pentest import event_subscribers as subs


# ---- Autouse reset fixture -----------------------------------------------


@pytest.fixture(autouse=True)
def _reset_registry():
    """Reset the module-level registry between every test so state never leaks."""
    subs.clear_subscribers()
    yield
    subs.clear_subscribers()


@pytest.fixture
def tmp_log(tmp_path: Path) -> elog.EventLog:
    return elog.EventLog(tmp_path / "events.jsonl")


# ---- Test 1 — registration -----------------------------------------------


def test_subscribe_returns_handle_with_monotonic_id():
    """`subscribe()` returns a SubscriptionHandle with id / event_kind_pattern /
    callback_name; `subscriptions()` returns it in registration order.

    NOTE: this test uses a glob pattern to exercise the fnmatch SEMANTICS of
    subscribe(); the production pipeline does not emit this kind shape —
    see Test 3 docstring + the interfaces "Production emit-shape note".
    """
    def cb(_event):  # noqa: D401
        return None

    handle = subs.subscribe("vuln:*:phase_completed", cb)
    assert isinstance(handle, subs.SubscriptionHandle)
    assert handle.event_kind_pattern == "vuln:*:phase_completed"
    assert handle.callback_name == cb.__qualname__
    # id is monotonic — second registration must be strictly greater.
    handle2 = subs.subscribe("recon:phase_completed", cb)
    assert handle2.id > handle.id

    listed = subs.subscriptions()
    # Filter out the STREAM-05 cost-cap watchdog (auto-installed on first
    # subscribe per Plan 04.5-05); the assertion below is about USER
    # subscriptions and their registration order.
    user_listed = [
        h for h in listed
        if h.callback_name != "event_subscribers.cost_cap_watchdog"
    ]
    assert [h.event_kind_pattern for h in user_listed] == [
        "vuln:*:phase_completed",
        "recon:phase_completed",
    ]


# ---- Test 2 — exact match -------------------------------------------------


def test_exact_match_dispatches_callback(tmp_log: elog.EventLog):
    """subscribe('recon:phase_completed', cb) + emit('recon:phase_completed', phase='recon')
    invokes cb exactly once with the full event dict.
    """
    seen: list[dict] = []
    subs.subscribe("recon:phase_completed", lambda e: seen.append(e))
    tmp_log.emit("recon:phase_completed", phase="recon")

    # cb must have fired exactly once with the event dict.
    matched = [e for e in seen if e["kind"] == "recon:phase_completed"]
    assert len(matched) == 1
    assert matched[0]["phase"] == "recon"
    assert "ts" in matched[0]


# ---- Test 3 — glob match (fnmatch SEMANTICS, not production emit shape) --


def test_glob_match_uses_fnmatch_semantics(tmp_log: elog.EventLog):
    """Tests fnmatch.fnmatchcase semantics on subscriber patterns using
    SYNTHETIC event kinds. The production pipeline emits
    `kind='phase_completed'` uniformly (constant
    `KIND_PHASE_COMPLETED='phase_completed'`); production subscribers in
    Plans 04.5-02/03/04 use the exact-match pattern `'phase_completed'`
    plus an internal `event['phase']` filter, NOT glob patterns like
    `'vuln:*:phase_completed'`. This test pins the fnmatch contract for
    future event-kind families.
    """
    seen: list[str] = []
    subs.subscribe("vuln:*:phase_completed", lambda e: seen.append(e["kind"]))

    tmp_log.emit("vuln:xss:phase_completed", phase="vuln:xss")
    tmp_log.emit("vuln:xss:phase_started", phase="vuln:xss")
    tmp_log.emit("exploit:xss:phase_completed", phase="exploit:xss")

    # Only the first kind matches the glob.
    assert seen == ["vuln:xss:phase_completed"]


# ---- Test 4 — in-order dispatch ------------------------------------------


def test_dispatch_invokes_callbacks_in_registration_order(tmp_log: elog.EventLog):
    """Three callbacks on the same pattern fire in registration order
    (assert via list-of-call-order, NOT timestamps).
    """
    order: list[str] = []

    subs.subscribe("x", lambda _e: order.append("a"))
    subs.subscribe("x", lambda _e: order.append("b"))
    subs.subscribe("x", lambda _e: order.append("c"))

    tmp_log.emit("x")
    assert order == ["a", "b", "c"]


# ---- Test 5 — exception isolation ----------------------------------------


def test_callback_exception_does_not_propagate(tmp_log: elog.EventLog):
    """A raising callback's exception is caught and logged; ok_cb still fires;
    emit() returns normally; the raising_cb's subscriber_fired event has
    outcome='error' and error field set to repr(exc).
    """
    ok_calls: list[dict] = []

    def raising_cb(_event):
        raise RuntimeError("boom")

    def ok_cb(event):
        ok_calls.append(event)

    subs.subscribe("x", raising_cb)
    subs.subscribe("x", ok_cb)

    # Must return normally despite the raising callback.
    result = tmp_log.emit("x")
    assert result["kind"] == "x"
    # Downstream callback still fired.
    assert len(ok_calls) == 1

    # Inspect the subscriber_fired events appended to the EventLog.
    all_events = tmp_log.all_events()
    fired = [e for e in all_events if e["kind"] == "subscriber_fired"]
    # One per registered subscriber.
    assert len(fired) == 2
    # The raising one carries outcome=error + a non-empty error field.
    error_fired = [e for e in fired if e["outcome"] == "error"]
    assert len(error_fired) == 1
    assert "boom" in error_fired[0]["error"]
    assert error_fired[0]["callback_name"] == raising_cb.__qualname__
    # The ok one carries outcome=ok with no error field (or empty).
    ok_fired = [e for e in fired if e["outcome"] == "ok"]
    assert len(ok_fired) == 1


# ---- Test 6 — audit_log threading ----------------------------------------


def test_audit_log_threaded_through_dispatch(tmp_log: elog.EventLog):
    """Passing audit_log=MagicMock(...) to subscribe() makes the dispatcher
    write 'subscriber_fired' through that AuditLog. Payload carries
    subscription_id, callback_name, trigger_kind, outcome.
    """
    mock_audit = MagicMock()
    subs.subscribe("x", lambda _e: None, audit_log=mock_audit, callback_name="my_cb")

    tmp_log.emit("x", phase="x")

    # Mock was invoked with event='subscriber_fired' and the documented payload.
    assert mock_audit.write.call_count == 1
    call = mock_audit.write.call_args
    # First positional arg is the event name; second is the payload dict.
    args = call.args
    assert args[0] == "subscriber_fired"
    payload = args[1]
    assert payload["callback_name"] == "my_cb"
    assert payload["trigger_kind"] == "x"
    assert payload["outcome"] == "ok"
    assert "subscription_id" in payload
    assert "trigger_ts" in payload


# ---- Test 7 — deterministic ordering under parallel emit ----------------


def test_deterministic_subscriber_fired_sequence_under_parallel_emit(tmp_log: elog.EventLog):
    """Two coroutines awaited via asyncio.gather each emit one event. A
    subscriber callback records the order of trigger_kind values; with an
    asyncio.Event handoff pinning the order, the same input sequence
    produces the same subscriber_fired sequence.

    Proves determinism is preserved WHEN the test fixture pins the emission
    order — NOT that asyncio guarantees ordering for arbitrary parallel
    emissions. The load-bearing invariant: same input sequence ⇒ same
    subscriber_fired sequence.
    """
    captured: list[str] = []

    subs.subscribe("phase_completed", lambda e: captured.append(e["phase"]))

    a_done = asyncio.Event()

    async def emit_a():
        tmp_log.emit("phase_completed", phase="recon")
        a_done.set()

    async def emit_b():
        await a_done.wait()
        tmp_log.emit("phase_completed", phase="vuln:xss")

    async def run():
        await asyncio.gather(emit_a(), emit_b())

    asyncio.run(run())

    assert captured == ["recon", "vuln:xss"]


# ---- Test 8 — dispatch fires AFTER file write ----------------------------


def test_dispatch_fires_after_jsonl_write(tmp_log: elog.EventLog):
    """When the callback runs, the triggering event line must already be on
    disk in the JSONL file. Pins the "JSONL is the truth, subscribers are
    derived" ordering — a subscriber crash must NOT corrupt the on-disk
    legal artifact.
    """
    snapshots: list[list[str]] = []

    def cb(event):
        # Read the on-disk file at callback time.
        lines = tmp_log.path.read_text().splitlines()
        # Capture only the trigger event kinds (skip subscriber_fired etc.).
        snapshots.append([
            json.loads(ln)["kind"]
            for ln in lines
        ])

    subs.subscribe("x", cb)
    tmp_log.emit("x", payload_marker="alpha")

    # When cb fired, the 'x' event was ALREADY on disk.
    assert len(snapshots) == 1
    assert "x" in snapshots[0]


# ---- Test 9 — halt-on-event ----------------------------------------------


def test_halt_short_circuits_dispatch(tmp_log: elog.EventLog):
    """halt_all_subscribers('test') sets the kill switch; subsequent emit()
    calls do NOT invoke any callback. One `subscribers_halted` event has
    been written. reset_halt() re-arms the registry.
    """
    seen: list[dict] = []
    subs.subscribe("x", lambda e: seen.append(e))

    subs.halt_all_subscribers("test", event_log=tmp_log)
    tmp_log.emit("x")
    assert seen == []

    # subscribers_halted event was emitted exactly once.
    halted_events = [e for e in tmp_log.all_events() if e["kind"] == "subscribers_halted"]
    assert len(halted_events) == 1
    assert halted_events[0]["reason"] == "test"

    # Reset re-enables dispatch.
    subs.reset_halt()
    tmp_log.emit("x")
    assert len(seen) == 1


# ---- Test 10 — no audit_log path -----------------------------------------


def test_no_audit_log_kwarg_skips_audit_write(tmp_log: elog.EventLog):
    """subscribe('x', cb) WITHOUT audit_log kwarg: cb invoked AND a
    subscriber_fired event lands in the EventLog tail, but no
    AuditLog.write call (mock asserted not called).
    """
    mock_audit = MagicMock()
    seen: list[dict] = []

    # IMPORTANT: do NOT pass audit_log here.
    subs.subscribe("x", lambda e: seen.append(e))

    tmp_log.emit("x")

    assert len(seen) == 1
    # subscriber_fired DID land on the EventLog.
    fired = [e for e in tmp_log.all_events() if e["kind"] == "subscriber_fired"]
    assert len(fired) == 1
    # But the unrelated mock_audit was never touched (we never passed it in).
    assert mock_audit.write.call_count == 0


# ---- Test 11 — event_styles registrations --------------------------------


def test_event_styles_registers_three_new_kinds():
    """sentinel.web.event_styles.EVENT_STYLES must contain entries for
    subscriber_fired, streaming_phase_started, and subscribers_halted with
    the documented chip/icon/label/group shapes."""
    from sentinel.web.event_styles import EVENT_STYLES

    assert "subscriber_fired" in EVENT_STYLES
    sf = EVENT_STYLES["subscriber_fired"]
    assert sf["chip"] == "info"
    assert sf["group"] == "phase"
    assert sf["label"] == "subscriber fired"
    assert sf["icon"]  # non-empty

    assert "streaming_phase_started" in EVENT_STYLES
    sps = EVENT_STYLES["streaming_phase_started"]
    assert sps["chip"] == "info"
    assert sps["group"] == "phase"
    assert sps["label"] == "streaming phase started"
    assert sps["icon"]

    assert "subscribers_halted" in EVENT_STYLES
    sh = EVENT_STYLES["subscribers_halted"]
    assert sh["chip"] == "high"
    assert sh["group"] == "pipeline"
    assert sh["label"] == "subscribers halted"
    assert sh["icon"]


# ---- Test 12 — subscription introspection --------------------------------


def test_subscriptions_returns_handles_in_registration_order():
    """subscribe two patterns; subscriptions() returns both handles in
    registration order with the right patterns and callback_names.
    """
    def cb_one(_e):
        return None

    def cb_two(_e):
        return None

    h1 = subs.subscribe("a", cb_one, callback_name="alpha")
    h2 = subs.subscribe("b:*", cb_two, callback_name="bravo")

    listed = subs.subscriptions()
    # Filter out the STREAM-05 cost-cap watchdog (auto-installed on first
    # subscribe per Plan 04.5-05); the assertion below is about USER
    # subscriptions and their registration order.
    user_listed = [
        h for h in listed
        if h.callback_name != "event_subscribers.cost_cap_watchdog"
    ]
    assert len(user_listed) == 2
    assert user_listed[0].id == h1.id
    assert user_listed[0].event_kind_pattern == "a"
    assert user_listed[0].callback_name == "alpha"
    assert user_listed[1].id == h2.id
    assert user_listed[1].event_kind_pattern == "b:*"
    assert user_listed[1].callback_name == "bravo"
