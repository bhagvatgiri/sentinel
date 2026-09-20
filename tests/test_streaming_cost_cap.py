"""STREAM-05 — hermetic tests for the cost-cap watchdog.

Pins the load-bearing invariants:
  - The watchdog auto-installs on the FIRST `subscribe()` call (idempotent).
  - When ``scan_aborted_cost_cap`` fires, ``halt_all_subscribers`` fires
    within ONE event-tick — no NEW ``subscriber_fired`` audit-log entries
    appear AFTER the ``subscribers_halted`` entry.
  - A SECOND ``scan_aborted_cost_cap`` emit short-circuits on the
    ``_HALTED`` check BEFORE the watchdog callback runs; the
    ``subscribers_halted`` entry lands EXACTLY ONCE regardless of how many
    cost-cap events fire (idempotency).
  - ``subscribers_halted`` writes through the EXISTING hash-chained
    ``AuditLog.write`` API. ``AuditLog.verify`` returns ``True`` across the
    full halt sequence.
  - Halt does NOT cancel in-flight ``asyncio`` tasks. Plan 03-02's
    ``CostCapAbort`` propagation handles in-flight subprocess cleanup.

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
from sentinel.core.scope import AuditLog


# ---- Autouse reset fixture -----------------------------------------------


@pytest.fixture(autouse=True)
def _reset_registry_and_watchdog():
    """Reset BOTH the subscriber registry AND the cost-cap watchdog state
    between every test so module-level state never leaks across the suite.
    """
    subs.clear_subscribers()
    subs._reset_cost_cap_watchdog()
    yield
    subs.clear_subscribers()
    subs._reset_cost_cap_watchdog()


@pytest.fixture
def tmp_log(tmp_path: Path) -> elog.EventLog:
    return elog.EventLog(tmp_path / "events.jsonl")


@pytest.fixture
def tmp_audit(tmp_path: Path) -> AuditLog:
    """Real AuditLog at tmp_path/.audit.jsonl for hash-chain assertions."""
    return AuditLog(tmp_path / ".audit.jsonl")


# ---- Test 1 — watchdog auto-installs on first subscribe ------------------


def test_watchdog_auto_installs_on_first_subscribe():
    """Calling subscribe() for the first time auto-installs the cost-cap
    watchdog. subscriptions() returns 2 handles — the user's subscription
    AND the watchdog's 'scan_aborted_cost_cap' subscription.
    """
    def cb(_event):
        return None

    subs.subscribe("x", cb)

    listed = subs.subscriptions()
    assert len(listed) == 2

    # First handle is the user's 'x' subscription (registered before
    # the watchdog inside subscribe() — but the watchdog's install
    # call happens at the top of subscribe() so it registers FIRST).
    # The order is: watchdog first (it auto-installs at the top of
    # subscribe() before the new handle is appended), then the user's.
    watchdog_handles = [
        h for h in listed
        if h.callback_name == "event_subscribers.cost_cap_watchdog"
    ]
    assert len(watchdog_handles) == 1
    assert watchdog_handles[0].event_kind_pattern == "scan_aborted_cost_cap"

    user_handles = [
        h for h in listed
        if h.callback_name != "event_subscribers.cost_cap_watchdog"
    ]
    assert len(user_handles) == 1
    assert user_handles[0].event_kind_pattern == "x"

    assert subs._COST_CAP_WATCHDOG_INSTALLED is True


# ---- Test 2 — watchdog idempotent on subsequent subscribe ---------------


def test_watchdog_install_is_idempotent_across_subscribe_calls():
    """Multiple subscribe() calls only install the watchdog once.
    subscriptions() returns N+1 handles where N is the number of user
    subscriptions and 1 is the singleton watchdog.
    """
    def cb1(_e):
        return None

    def cb2(_e):
        return None

    subs.subscribe("x", cb1)
    subs.subscribe("y", cb2)

    listed = subs.subscriptions()
    assert len(listed) == 3, (
        f"expected exactly 3 subscriptions (2 user + 1 watchdog); got "
        f"{[h.callback_name for h in listed]}"
    )

    watchdog_handles = [
        h for h in listed
        if h.callback_name == "event_subscribers.cost_cap_watchdog"
    ]
    assert len(watchdog_handles) == 1
    assert subs._COST_CAP_WATCHDOG_INSTALLED is True


# ---- Test 3 — no subscribe call → no watchdog ---------------------------


def test_no_subscribe_call_means_no_watchdog():
    """If subscribe() was never called, _COST_CAP_WATCHDOG_INSTALLED stays
    False — the watchdog is installed lazily, never eagerly.
    """
    # autouse fixture has cleared state — no subscribe call has fired yet.
    assert subs._COST_CAP_WATCHDOG_INSTALLED is False
    assert len(subs.subscriptions()) == 0


# ---- Test 4 — scan_aborted_cost_cap triggers halt -----------------------


def test_scan_aborted_cost_cap_triggers_halt(tmp_log: elog.EventLog):
    """When the watchdog is installed and 'scan_aborted_cost_cap' fires, the
    watchdog calls halt_all_subscribers — _HALTED is True after the emit,
    and exactly one 'subscribers_halted' event lands in the EventLog tail.
    """
    seen: list[dict] = []
    subs.subscribe("phase_completed", lambda e: seen.append(e), event_log=tmp_log)

    # Pre-condition: halt is off.
    assert subs._HALTED is False

    # Fire the cap-trip event.
    tmp_log.emit(
        "scan_aborted_cost_cap",
        engagement_id="e1",
        scan_spend_usd=5.5,
        cap_usd=5.0,
        phase_at_trip="exploit:xss",
    )

    # Post-condition: halt is on, exactly ONE subscribers_halted event was emitted.
    assert subs._HALTED is True
    halted = [e for e in tmp_log.all_events() if e["kind"] == "subscribers_halted"]
    assert len(halted) == 1
    assert halted[0]["reason"] == "cost_cap_tripped"
    assert halted[0]["triggered_by"] == "scan_aborted_cost_cap"


# ---- Test 5 — load-bearing topological ordering -------------------------


def test_no_subscriber_fired_after_halt_audit_chain_intact(
    tmp_log: elog.EventLog, tmp_audit: AuditLog, tmp_path: Path,
):
    """LOAD-BEARING TOPOLOGICAL-ORDERING TEST.

    After 'subscribers_halted' lands in the audit log, ZERO 'subscriber_fired'
    entries appear AFTER it in the audit log. AuditLog.verify() returns True
    across the full halt sequence — the hash chain is intact.
    """
    cb_calls: list[dict] = []

    def cb(event):
        cb_calls.append(event)

    # Register a user subscription with the real AuditLog AND EventLog —
    # registers user subscription + auto-installs watchdog with both captures.
    subs.subscribe(
        "phase_completed", cb,
        audit_log=tmp_audit, event_log=tmp_log,
        callback_name="user.phase_completed",
    )

    # 1. Fire a normal phase_completed — cb fires; subscriber_fired lands.
    tmp_log.emit("phase_completed", phase="vuln:xss")
    assert len(cb_calls) == 1

    # 2. Fire the cap-trip event — watchdog fires + subscribers_halted lands.
    tmp_log.emit(
        "scan_aborted_cost_cap",
        engagement_id="e",
        scan_spend_usd=5.5,
        cap_usd=5.0,
        phase_at_trip="exploit:xss",
        phases_completed=4,
        phases_total=8,
    )
    assert subs._HALTED is True

    # 3. Fire a second phase_completed — dispatch short-circuits; cb does NOT fire.
    tmp_log.emit("phase_completed", phase="exploit:sqli")
    # cb was NOT invoked a second time.
    assert len(cb_calls) == 1

    # 4. Walk the audit log and assert topological ordering.
    audit_path = tmp_audit.path
    entries: list[dict] = []
    with audit_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    events_in_order = [(i, e["event"]) for i, e in enumerate(entries)]

    # Find the index of subscribers_halted.
    halted_indices = [i for i, ev in events_in_order if ev == "subscribers_halted"]
    assert len(halted_indices) == 1, (
        f"expected exactly one subscribers_halted entry in audit log; got "
        f"{halted_indices} in {events_in_order}"
    )
    halted_idx = halted_indices[0]

    # ZERO subscriber_fired entries appear AFTER subscribers_halted.
    after = [ev for i, ev in events_in_order if i > halted_idx]
    assert "subscriber_fired" not in after, (
        f"FOUND subscriber_fired AFTER subscribers_halted! events_after={after}"
    )

    # 5. AuditLog.verify returns (True, None) — hash chain intact.
    ok, err = AuditLog.verify(audit_path)
    assert ok is True, f"audit chain integrity check failed: {err}"
    assert err is None


# ---- Test 6 — halt idempotent: exactly-once subscribers_halted ----------


def test_second_cost_cap_emit_short_circuits_on_halted_check(
    tmp_log: elog.EventLog, tmp_audit: AuditLog,
):
    """Asserts that a second `scan_aborted_cost_cap` emit's dispatch
    short-circuits on the `_HALTED` check BEFORE the watchdog callback
    runs; `subscribers_halted` lands EXACTLY ONCE in the audit log
    regardless of how many cost-cap events fire.

    Sequence:
      - emit('scan_aborted_cost_cap', ...) → watchdog fires, _HALTED
        set, subscribers_halted lands once.
      - emit('scan_aborted_cost_cap', ...) AGAIN → dispatch sees _HALTED
        is True, short-circuits before invoking the watchdog callback;
        no second subscribers_halted entry.

    Assert _HALTED stays True; exactly ONE subscribers_halted in the
    audit log; exactly ONE subscribers_halted in the EventLog tail.
    """
    subs.subscribe(
        "phase_completed", lambda _e: None,
        audit_log=tmp_audit, event_log=tmp_log,
    )

    # First emit — watchdog fires.
    tmp_log.emit(
        "scan_aborted_cost_cap",
        engagement_id="e",
        scan_spend_usd=5.5,
        cap_usd=5.0,
    )
    assert subs._HALTED is True

    # Second emit — should short-circuit on the _HALTED check.
    tmp_log.emit(
        "scan_aborted_cost_cap",
        engagement_id="e",
        scan_spend_usd=7.0,
        cap_usd=5.0,
    )
    assert subs._HALTED is True

    # EventLog: exactly ONE subscribers_halted event.
    halted_event = [e for e in tmp_log.all_events() if e["kind"] == "subscribers_halted"]
    assert len(halted_event) == 1, (
        f"expected exactly one subscribers_halted in event_log; got "
        f"{len(halted_event)}"
    )

    # AuditLog: exactly ONE subscribers_halted entry.
    entries: list[dict] = []
    with tmp_audit.path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    halted_audit = [e for e in entries if e["event"] == "subscribers_halted"]
    assert len(halted_audit) == 1, (
        f"expected exactly one subscribers_halted in audit_log; got "
        f"{len(halted_audit)}"
    )


# ---- Test 7 — reset_halt + fresh subscribe re-arms watchdog -------------


def test_reset_halt_and_fresh_subscribe_re_arms_watchdog(tmp_log: elog.EventLog):
    """After a cap-trip + reset_halt + _reset_cost_cap_watchdog +
    clear_subscribers, a fresh subscribe re-installs the watchdog and the
    pipeline can run again — _HALTED is False, subsequent emits dispatch
    normally.
    """
    seen_first: list[dict] = []
    subs.subscribe("x", lambda e: seen_first.append(e), event_log=tmp_log)

    tmp_log.emit("scan_aborted_cost_cap", scan_spend_usd=5.5, cap_usd=5.0)
    assert subs._HALTED is True

    # Fresh process — full reset.
    subs.reset_halt()
    subs._reset_cost_cap_watchdog()
    subs.clear_subscribers()

    assert subs._HALTED is False
    assert subs._COST_CAP_WATCHDOG_INSTALLED is False

    # Subscribe again — watchdog re-installs lazily.
    seen_second: list[dict] = []
    subs.subscribe("x", lambda e: seen_second.append(e), event_log=tmp_log)
    assert subs._COST_CAP_WATCHDOG_INSTALLED is True

    tmp_log.emit("x", phase="x")
    assert len(seen_second) == 1


# ---- Test 8 — in-flight async tasks NOT cancelled by halt ---------------


def test_halt_does_not_cancel_in_flight_async_tasks(tmp_log: elog.EventLog):
    """Halt only stops NEW dispatch fan-out — it does NOT cancel already-
    scheduled asyncio tasks. Documents the invariant: in-flight subprocess
    work from Plan 04.5-03's verify-phase-03 streaming continues to run
    after halt; Plan 03-02's CostCapAbort propagation is what handles the
    in-flight cleanup (between-finding `_check_cost_cap` raises).
    """
    async def run_test():
        slow_done = asyncio.Event()

        async def slow_task():
            # Simulate a longer-running async unit of work that was
            # scheduled BEFORE the halt fired.
            await asyncio.sleep(0.05)
            slow_done.set()

        scheduled_tasks: list[asyncio.Task] = []

        def cb(_event):
            # Subscriber schedules an in-flight task.
            task = asyncio.get_running_loop().create_task(slow_task())
            scheduled_tasks.append(task)

        subs.subscribe("phase_completed", cb, event_log=tmp_log)

        # Fire a normal phase_completed — cb schedules the slow_task.
        tmp_log.emit("phase_completed", phase="vuln:xss")
        assert len(scheduled_tasks) == 1

        # Now trip the cap.
        tmp_log.emit("scan_aborted_cost_cap", scan_spend_usd=5.5, cap_usd=5.0)
        assert subs._HALTED is True

        # The slow task is STILL pending immediately after halt — halt does
        # NOT cancel it. (The done flag is False; the task is not done.)
        assert scheduled_tasks[0].done() is False
        assert slow_done.is_set() is False

        # Await the task — it must complete normally.
        await scheduled_tasks[0]
        assert slow_done.is_set() is True
        assert scheduled_tasks[0].done() is True
        # Task did not raise.
        assert scheduled_tasks[0].exception() is None

    asyncio.run(run_test())


# ---- Test 9 — subscribers_halted style registered -----------------------


def test_event_styles_subscribers_halted_registered():
    """Regression guard for Plan 04.5-01's event_styles registration of
    subscribers_halted. The dashboard's halted-banner UI (Plan 04.5-06)
    depends on chip='high' and group='pipeline'.
    """
    from sentinel.web.event_styles import EVENT_STYLES

    assert "subscribers_halted" in EVENT_STYLES
    style = EVENT_STYLES["subscribers_halted"]
    assert style["chip"] == "high"
    assert style["group"] == "pipeline"


# ---- Test 10 — audit write defensive: no audit_log path ------------------


def test_audit_write_skipped_when_no_audit_log_captured(tmp_log: elog.EventLog):
    """When the first subscribe call provides NO audit_log, the watchdog's
    _COST_CAP_AUDIT_LOG stays None and the watchdog does NOT call any
    AuditLog.write. The subscribers_halted event still lands in the
    EventLog tail.
    """
    mock_audit = MagicMock()

    # NB: do NOT pass audit_log here — captures None into watchdog.
    subs.subscribe("phase_completed", lambda _e: None, event_log=tmp_log)

    # Sanity: the watchdog captured None for the audit log.
    assert subs._COST_CAP_AUDIT_LOG is None
    # And the captured event_log is our tmp_log.
    assert subs._COST_CAP_EVENT_LOG is tmp_log

    tmp_log.emit("scan_aborted_cost_cap", scan_spend_usd=5.5, cap_usd=5.0)

    # The unrelated mock_audit was never touched (we never threaded it in).
    assert mock_audit.write.call_count == 0

    # subscribers_halted DID land on the EventLog.
    halted = [e for e in tmp_log.all_events() if e["kind"] == "subscribers_halted"]
    assert len(halted) == 1
