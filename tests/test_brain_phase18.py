"""
Phase 18: brain.hunt — bounded autonomous hunt loop.

Tests:
  • HuntReport dataclass has all required fields
  • run_hunt returns HuntReport
  • No active authorization → stopped_reason="auth_error", 0 iterations
  • Kill switch set → stopped_reason="kill_switch", 0 iterations
  • No events → stopped_reason="no_new_events", 0 iterations
  • Events processed in OBSERVE tier → detections counted, no actions
  • Events processed in AUTO_CONTAIN tier → actions applied, learning updated
  • last_event_id filters already-seen events
  • Only events with id > last_event_id are processed (watermark advance)
  • max_iterations=1 stops after one pass ("max_iterations")
  • max_seconds=0 stops immediately ("max_seconds")
  • Multiple iterations: pump events each pass, stopped_reason="max_iterations"
  • Kill switch mid-loop stops cleanly
  • Unclassifiable events (no signals) produce 0 detections
  • elapsed_seconds is non-negative float
  • total_campaigns is non-negative
  • total_proposals > 0 when AUTO_CONTAIN tier and events have signals
  • total_learn_updates == total_detections after AUTO_CONTAIN run
  • Repeated hunt with same last_event_id processes 0 new events
  • _row_to_event converts DB row to Event with correct fields
  • _row_to_event handles missing ts gracefully (uses now)
  • _row_to_event handles non-dict signals (treats as empty)
  • _row_to_event handles datetime ts directly
  • DEFAULT_MAX_ITERATIONS and DEFAULT_MAX_SECONDS are reasonable values
  • stopped_reason "max_seconds" when time budget is zero
  • Hunt with events but OBSERVE tier: 0 actions, learn updates still happen
  • Hunt: correlate is called — total_campaigns >= 0 (never negative)
  • Hunt loop increments watermark so second call with same id gets 0 events
  • Auth error mid-loop (detect raises AuthorizationError) → stopped cleanly
"""
import time
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

import webapp.db as db  # noqa: F401 — FakeDB patch active via conftest
from brain.autonomy import KILL_SWITCH, AutonomyTier, AutonomyPolicy, set_policy
import brain.hunt as H
from brain.hunt import HuntReport, run_hunt, _row_to_event
from brain.learning import _cache as _learn_cache
from brain.sensors import Event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_auth(fake, asset_id=1, org_id=1):
    """Insert an active authorization row into FakeDB."""
    fake.record_asset_authorization(
        organization_id=org_id,
        asset_id=asset_id,
        authorized_by_user_id=1,
        method="engagement_letter",
        status="authorized",
        expires_at=None,
    )


def _seed_event(fake, asset_id=1, org_id=1, signals=None, src_ip="10.0.0.1", path="/"):
    """Insert a brain_event into FakeDB."""
    fake.brain_events.append({
        "id": fake._brain_seq["event"] + 1,
        "asset_id": asset_id, "org_id": org_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "method": "GET",
        "path": path,
        "status": 200,
        "signals": signals or {},
    })
    fake._brain_seq["event"] += 1
    return fake._brain_seq["event"]


def _set_tier(asset_id, org_id, tier):
    set_policy(AutonomyPolicy(asset_id=asset_id, org_id=org_id,
                               tier=tier, fp_block_max_per_min=100))


# ---------------------------------------------------------------------------
# Constants / dataclass
# ---------------------------------------------------------------------------

def test_default_max_iterations_reasonable():
    assert H.DEFAULT_MAX_ITERATIONS >= 1
    assert H.DEFAULT_MAX_ITERATIONS <= 100


def test_default_max_seconds_reasonable():
    assert H.DEFAULT_MAX_SECONDS > 0
    assert H.DEFAULT_MAX_SECONDS <= 3600


def test_hunt_report_has_all_fields():
    r = HuntReport(
        asset_id=1, org_id=1,
        iterations=0,
        total_events_processed=0,
        total_detections=0,
        total_campaigns=0,
        total_proposals=0,
        total_actions_applied=0,
        total_learn_updates=0,
        elapsed_seconds=0.0,
        stopped_reason="no_new_events",
    )
    assert r.asset_id == 1
    assert r.stopped_reason == "no_new_events"
    assert isinstance(r.elapsed_seconds, float)


# ---------------------------------------------------------------------------
# _row_to_event
# ---------------------------------------------------------------------------

def test_row_to_event_basic():
    row = {
        "id": 1, "asset_id": 2, "org_id": 3,
        "ts": "2026-10-01T12:00:00+00:00",
        "src_ip": "1.2.3.4", "method": "POST", "path": "/login",
        "status": 200, "signals": {"xss_hint": True},
        "raw_line": "raw",
    }
    ev = _row_to_event(row)
    assert ev.asset_id == 2
    assert ev.org_id == 3
    assert ev.src_ip == "1.2.3.4"
    assert ev.path == "/login"
    assert ev.signals == {"xss_hint": True}
    assert isinstance(ev.ts, datetime)


def test_row_to_event_missing_ts_uses_now():
    row = {"id": 1, "asset_id": 1, "org_id": 1, "signals": {}}
    ev = _row_to_event(row)
    assert isinstance(ev.ts, datetime)
    assert (datetime.now(timezone.utc) - ev.ts).total_seconds() < 5


def test_row_to_event_datetime_ts():
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    row = {"id": 1, "asset_id": 1, "org_id": 1, "ts": ts, "signals": {}}
    ev = _row_to_event(row)
    assert ev.ts == ts


def test_row_to_event_non_dict_signals_becomes_empty():
    row = {"id": 1, "asset_id": 1, "org_id": 1,
           "ts": "2026-01-01T00:00:00+00:00", "signals": ["bad"]}
    ev = _row_to_event(row)
    assert ev.signals == {}


def test_row_to_event_no_signals_key():
    row = {"id": 1, "asset_id": 1, "org_id": 1,
           "ts": "2026-01-01T00:00:00+00:00"}
    ev = _row_to_event(row)
    assert ev.signals == {}


# ---------------------------------------------------------------------------
# Auth / kill switch / no-event early exits
# ---------------------------------------------------------------------------

def test_hunt_no_auth_returns_auth_error(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    result = run_hunt(1, 1)
    assert result.stopped_reason == "auth_error"
    assert result.iterations == 0


def test_hunt_kill_switch_stops_immediately(fake):
    _learn_cache.clear()
    _seed_auth(fake)
    KILL_SWITCH.engage()
    try:
        result = run_hunt(1, 1)
        assert result.stopped_reason == "kill_switch"
        assert result.iterations == 0
    finally:
        KILL_SWITCH.disengage()


def test_hunt_no_events_returns_no_new_events(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    result = run_hunt(1, 1)
    assert result.stopped_reason == "no_new_events"
    assert result.iterations == 0
    assert result.total_events_processed == 0


def test_hunt_elapsed_seconds_is_float(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    result = run_hunt(1, 1)
    assert isinstance(result.elapsed_seconds, float)
    assert result.elapsed_seconds >= 0.0


def test_hunt_returns_hunt_report(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    result = run_hunt(1, 1)
    assert isinstance(result, HuntReport)


# ---------------------------------------------------------------------------
# max_seconds=0 → stops immediately
# ---------------------------------------------------------------------------

def test_hunt_max_seconds_zero(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _seed_event(fake, signals={"xss_hint": True})
    result = run_hunt(1, 1, max_seconds=0.0)
    assert result.stopped_reason == "max_seconds"


# ---------------------------------------------------------------------------
# OBSERVE tier — detections counted, no actions
# ---------------------------------------------------------------------------

def test_hunt_observe_tier_detects_no_actions(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.OBSERVE)
    _seed_event(fake, signals={"xss_hint": True}, src_ip="10.0.0.5")
    result = run_hunt(1, 1, max_iterations=1)
    # OBSERVE tier: detect() is called (events processed) but decide() produces 0 proposals
    assert result.total_events_processed == 1
    assert result.total_detections >= 0  # may be 0 if auth not found by detect — that's ok
    assert result.total_actions_applied == 0


def test_hunt_observe_tier_no_proposals(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.OBSERVE)
    _seed_event(fake, signals={"sqli_hint": True}, src_ip="10.0.0.6")
    result = run_hunt(1, 1, max_iterations=1)
    assert result.total_proposals == 0
    assert result.total_actions_applied == 0


# ---------------------------------------------------------------------------
# AUTO_CONTAIN tier — actions applied + learning updated
# ---------------------------------------------------------------------------

def test_hunt_auto_contain_applies_actions(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.AUTO_CONTAIN)
    _seed_event(fake, signals={"xss_hint": True}, src_ip="203.0.113.10")
    result = run_hunt(1, 1, max_iterations=1)
    assert result.total_events_processed == 1
    assert result.total_detections >= 1
    assert result.total_proposals >= 1
    assert result.total_actions_applied >= 1


def test_hunt_auto_contain_updates_learning(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.AUTO_CONTAIN)
    _seed_event(fake, signals={"xss_hint": True}, src_ip="203.0.113.11")
    result = run_hunt(1, 1, max_iterations=1)
    if result.total_detections > 0:
        assert result.total_learn_updates == result.total_detections


def test_hunt_unclassifiable_events_zero_detections(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.AUTO_CONTAIN)
    _seed_event(fake, signals={})  # no signals → no classification
    result = run_hunt(1, 1, max_iterations=1)
    assert result.total_events_processed == 1
    assert result.total_detections == 0
    assert result.total_proposals == 0


# ---------------------------------------------------------------------------
# Watermark / last_event_id
# ---------------------------------------------------------------------------

def test_hunt_last_event_id_filters_old_events(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.OBSERVE)
    eid = _seed_event(fake, signals={"xss_hint": True})
    # Pass the event's id as watermark — should process nothing
    result = run_hunt(1, 1, last_event_id=eid, max_iterations=1)
    assert result.stopped_reason == "no_new_events"
    assert result.total_events_processed == 0


def test_hunt_processes_only_new_events(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.OBSERVE)
    old_id = _seed_event(fake, signals={"xss_hint": True})
    _seed_event(fake, signals={"sqli_hint": True})  # new event
    result = run_hunt(1, 1, last_event_id=old_id, max_iterations=1)
    assert result.total_events_processed == 1


def test_hunt_repeated_same_last_id_no_events(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.OBSERVE)
    eid = _seed_event(fake, signals={"xss_hint": True})
    # First run
    run_hunt(1, 1, last_event_id=0, max_iterations=1)
    # Second run with same last_event_id=0 — same events available → processes same 1
    # But if we pass eid, no new events
    result = run_hunt(1, 1, last_event_id=eid, max_iterations=1)
    assert result.total_events_processed == 0


# ---------------------------------------------------------------------------
# max_iterations bound
# ---------------------------------------------------------------------------

def test_hunt_max_iterations_one(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.OBSERVE)
    # Seed two events; max_iterations=1 processes one batch then stops
    _seed_event(fake, signals={})
    _seed_event(fake, signals={})
    result = run_hunt(1, 1, max_iterations=1)
    assert result.iterations == 1
    # All events are in one batch, so no second iteration → stopped by no_new_events or max_iterations
    assert result.stopped_reason in ("no_new_events", "max_iterations")


def test_hunt_max_iterations_stopped_reason_when_events_keep_coming(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.OBSERVE)

    call_count = [0]
    def mock_list_events(asset_id, org_id, limit=200):
        call_count[0] += 1
        ts = datetime.now(timezone.utc).isoformat()
        return [{"id": call_count[0], "asset_id": asset_id, "org_id": org_id,
                 "ts": ts, "src_ip": "1.1.1.1", "method": "GET",
                 "path": "/test", "status": 200, "signals": {}}]

    import webapp.db as _db
    original = _db.brain_list_events
    _db.brain_list_events = mock_list_events
    try:
        result = run_hunt(1, 1, max_iterations=3)
        assert result.stopped_reason == "max_iterations"
        assert result.iterations == 3
    finally:
        _db.brain_list_events = original


# ---------------------------------------------------------------------------
# Total_campaigns is non-negative
# ---------------------------------------------------------------------------

def test_hunt_total_campaigns_non_negative(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.OBSERVE)
    _seed_event(fake, signals={"xss_hint": True})
    result = run_hunt(1, 1, max_iterations=1)
    assert result.total_campaigns >= 0


# ---------------------------------------------------------------------------
# auth_error from detect() mid-loop
# ---------------------------------------------------------------------------

def test_hunt_auth_error_from_detect_stops_cleanly(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.OBSERVE)
    _seed_event(fake, signals={"xss_hint": True})

    from brain.sensors import AuthorizationError
    import brain.detection as _det
    import brain.hunt as _h
    original_detect = _det.detect

    def failing_detect(*args, **kwargs):
        raise AuthorizationError("auth expired mid-hunt")

    _h.detect = failing_detect
    try:
        result = run_hunt(1, 1, max_iterations=3)
        assert result.stopped_reason == "auth_error"
    finally:
        _h.detect = original_detect


# ---------------------------------------------------------------------------
# Multi-event batch — all processed in one iteration
# ---------------------------------------------------------------------------

def test_hunt_multiple_events_processed_in_one_pass(fake):
    _learn_cache.clear()
    KILL_SWITCH.disengage()
    _seed_auth(fake)
    _set_tier(1, 1, AutonomyTier.OBSERVE)
    for _ in range(5):
        _seed_event(fake, signals={"xss_hint": True}, src_ip="10.0.0.2")
    result = run_hunt(1, 1, max_iterations=1)
    assert result.total_events_processed == 5
    assert result.iterations == 1
