"""
HydraBrain bounded autonomous hunt loop — Phase 18+.

run_hunt(asset_id, org_id, ...) polls brain_events, runs the full
detect → correlate → cve_match → decide → apply → auto_fix → observe pipeline
in a loop bounded by max_iterations and max_seconds.

Stopped reasons:
  "no_new_events"   — poll returned nothing new; loop is idle
  "max_iterations"  — hard iteration cap reached
  "max_seconds"     — wall-clock budget exhausted
  "kill_switch"     — global kill switch is set
  "auth_error"      — active authorization row is missing

Safety invariants (all inherited from sub-modules):
  * Kill switch checked on every iteration — stops loop immediately.
  * Self-lockout guard in decide() prevents blocking control-channel IPs.
  * FP rate brake in decide() downgrades auto-actions to recommend when
    the per-asset rate is exceeded.
  * Authorization verified at start and on each detect() call.
  * Every applied action carries a TTL and rollback_token.
  * observe() updates brain_knowledge so future iterations improve.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List

from brain.autonomy import KILL_SWITCH
from brain.correlation import correlate
from brain.decision import decide
from brain.detection import detect
from brain.learning import (
    OUTCOME_BLOCKED, OUTCOME_DETECTED,
    observe,
)
from brain.response import apply_action
from brain.sensors import AuthorizationError, Event

DEFAULT_MAX_ITERATIONS: int  = 10
DEFAULT_MAX_SECONDS:    float = 60.0


# ---------------------------------------------------------------------------
# Report dataclass
# ---------------------------------------------------------------------------

@dataclass
class HuntReport:
    asset_id:              int
    org_id:                int
    iterations:            int
    total_events_processed: int
    total_detections:      int
    total_campaigns:       int
    total_proposals:       int
    total_actions_applied: int
    total_auto_fixes:      int
    total_learn_updates:   int
    elapsed_seconds:       float
    stopped_reason:        str   # see module docstring for valid values


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _row_to_event(row: dict) -> Event:
    """Reconstruct an Event from a brain_events DB row dict."""
    ts_raw = row.get("ts") or row.get("created_at") or row.get("timestamp")
    if isinstance(ts_raw, str):
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    elif isinstance(ts_raw, datetime):
        ts = ts_raw
    else:
        ts = datetime.now(timezone.utc)

    signals = row.get("signals")
    if not isinstance(signals, dict):
        signals = {}

    return Event(
        asset_id=int(row.get("asset_id", 0)),
        org_id=int(row.get("org_id", 0)),
        ts=ts,
        src_ip=row.get("src_ip"),
        method=row.get("method"),
        path=row.get("path"),
        status=row.get("status"),
        signals=signals,
        raw_line=row.get("raw_line") or row.get("raw") or "",
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_hunt(
    asset_id: int,
    org_id: int,
    *,
    max_iterations: int   = DEFAULT_MAX_ITERATIONS,
    max_seconds:    float = DEFAULT_MAX_SECONDS,
    last_event_id:  int   = 0,
) -> HuntReport:
    """Run the bounded hunt loop for one asset/org pair.

    Returns a HuntReport summarising what happened. Never raises on
    AuthorizationError or kill switch — captures both as stopped_reason.

    last_event_id: start watermark; only events with id > last_event_id
    are processed. Callers that want an incremental poll across multiple
    calls should persist report-returned last_event_id themselves.
    """
    import webapp.db as db
    from brain.learning import _cache as _lc  # noqa: F401  — for invalidation side-effects

    start = time.monotonic()

    report = HuntReport(
        asset_id=asset_id, org_id=org_id,
        iterations=0,
        total_events_processed=0,
        total_detections=0,
        total_campaigns=0,
        total_proposals=0,
        total_actions_applied=0,
        total_auto_fixes=0,
        total_learn_updates=0,
        elapsed_seconds=0.0,
        stopped_reason="no_new_events",
    )

    # --- authorization pre-check (belt + suspenders on top of detect()) ---
    try:
        auth = db.get_active_authorization(asset_id, org_id)
        if auth is None:
            report.stopped_reason = "auth_error"
            report.elapsed_seconds = time.monotonic() - start
            return report
    except Exception:
        report.stopped_reason = "auth_error"
        report.elapsed_seconds = time.monotonic() - start
        return report

    current_watermark = last_event_id

    for _i in range(max_iterations):
        # Wall-clock budget check
        if time.monotonic() - start >= max_seconds:
            report.stopped_reason = "max_seconds"
            break

        # Kill switch check
        if KILL_SWITCH.engaged:
            report.stopped_reason = "kill_switch"
            break

        # --- poll new events since watermark ---
        try:
            all_rows = db.brain_list_events(asset_id, org_id)
        except Exception:
            break

        new_rows = [r for r in all_rows if (r.get("id") or 0) > current_watermark]
        if not new_rows:
            report.stopped_reason = "no_new_events"
            break

        events: List[Event] = [_row_to_event(r) for r in new_rows]
        report.total_events_processed += len(events)
        report.iterations += 1

        # --- detect (includes CVE matching) ---
        try:
            detections = detect(asset_id, org_id, events)
        except AuthorizationError:
            report.stopped_reason = "auth_error"
            break
        report.total_detections += len(detections)

        # --- correlate (informational; logged in report) ---
        campaigns = correlate(detections)
        report.total_campaigns += len(campaigns)

        # --- cve_match & auto_fix ---
        # For detections with high-confidence CVE matches, apply known fixes
        auto_fixes_applied = 0
        for det in detections:
            if det.cve_confidence >= 0.85 and det.cve_matches:
                # Try to apply autonomous fix
                try:
                    from brain.autonomous_fixer import apply_fixes_for_detection
                    applied = apply_fixes_for_detection(
                        asset_id, org_id, det,
                        [{"cve_id": cve_id, "fix_recommendation": {}} for cve_id in det.cve_matches],
                        max_fixes=1
                    )
                    auto_fixes_applied += len(applied)
                except Exception as e:
                    # Log but don't fail the hunt
                    import logging
                    logging.getLogger(__name__).warning(f"Auto-fix failed: {e}")

        report.total_auto_fixes += auto_fixes_applied

        # --- decide ---
        proposals = decide(asset_id, org_id, detections)
        report.total_proposals += len(proposals)

        # --- apply + track outcomes ---
        action_ids: List[int] = []
        for prop in proposals:
            action_id = apply_action(asset_id, org_id, prop)
            action_ids.append(action_id)
            report.total_actions_applied += 1

        # --- observe (learning feedback) ---
        # Determine best outcome: 'applied' on any action → BLOCKED
        best_outcome = OUTCOME_DETECTED
        if action_ids or auto_fixes_applied > 0:
            for aid in action_ids:
                try:
                    row = db.brain_get_action(aid, org_id) or {}
                    if row.get("status") == "applied":
                        best_outcome = OUTCOME_BLOCKED
                        break
                except Exception:
                    pass

        for det in detections:
            observe(asset_id, org_id, det.fingerprint, det.attack_class, best_outcome)
            report.total_learn_updates += 1

        # Advance watermark
        current_watermark = max((r.get("id") or 0) for r in new_rows)

        # Post-work time check
        if time.monotonic() - start >= max_seconds:
            report.stopped_reason = "max_seconds"
            break
    else:
        # Loop ran to completion without any break
        report.stopped_reason = "max_iterations"

    report.elapsed_seconds = time.monotonic() - start
    return report
