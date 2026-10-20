"""Celery tasks for continuous monitoring (Phase 5).

Each task is a thin wrapper around a plain, synchronously-callable function
so the scheduling logic itself can be unit-tested without a running
broker — see tests/test_phase5_scheduler.py, which calls these functions
directly rather than through Celery's .delay()/.apply_async().
"""
import logging

from webapp.celery_app import celery_app
from webapp import db
from webapp.services import remediation_service, web_scan_service

logger = logging.getLogger("hydrax.scheduler")


def _check_due_scans(enqueue=None) -> int:
    """Find every asset whose scheduled scan is due and enqueue a job for
    each. Returns the number enqueued.

    `enqueue` defaults to the real Celery `.delay()` call (requires a live
    broker); tests inject a plain recording callable instead so this
    function's actual logic — which assets are due, advancing the schedule —
    is verifiable without Redis running at all.
    """
    if enqueue is None:
        enqueue = lambda asset_id, org_id: run_scheduled_web_scan.delay(asset_id, org_id)  # noqa: E731
    due = db.list_due_assets()
    for asset in due:
        # Advance the schedule immediately, before the job even runs, so a
        # slow scan or a worker outage can't cause the same asset to be
        # re-enqueued by the next beat tick before this one finishes.
        db.mark_asset_scanned(asset["id"])
        enqueue(asset["id"], asset["organization_id"])
    return len(due)


@celery_app.task(name="webapp.tasks.check_due_scans")
def check_due_scans() -> int:
    return _check_due_scans()


def _run_scheduled_web_scan(asset_id: int, organization_id: int) -> None:
    """Runs an authorized, already-verified web asset's scheduled scan using
    the same web_scan_service every manually-triggered scan uses — no
    separate/duplicate scanning logic for the scheduled path.

    Re-checks authorization immediately before running (spec's threat model:
    an asset can be de-authorized after being scheduled but before the job
    executes) rather than trusting the state at schedule time.
    """
    asset = db.get_asset(asset_id, organization_id)
    if not asset:
        logger.warning("scheduled scan skipped: asset %s not found in org %s", asset_id, organization_id)
        return
    if asset["verification_status"] != "verified" or asset["authorization_status"] != "authorized":
        logger.info("scheduled scan skipped: asset %s is not currently authorized", asset_id)
        return
    active_auth = db.get_active_authorization(asset_id, organization_id)
    if not db.check_authorization_scope(asset["url"], active_auth):
        logger.info("scheduled scan skipped: asset %s has no active in-scope authorization record", asset_id)
        return
    if asset["added_by_user_id"] is None:
        logger.info("scheduled scan skipped: asset %s has no owning user to attribute the scan to", asset_id)
        return

    from config.settings import DEFAULT_SCANNER_KEYS
    try:
        web_scan_service.start_web_scan(asset["added_by_user_id"], asset["url"], DEFAULT_SCANNER_KEYS)
    except ValueError as e:
        logger.warning("scheduled scan for asset %s could not start: %s", asset_id, e)


@celery_app.task(name="webapp.tasks.run_scheduled_web_scan")
def run_scheduled_web_scan(asset_id: int, organization_id: int) -> None:
    _run_scheduled_web_scan(asset_id, organization_id)


@celery_app.task(name="webapp.tasks.check_verifications")
def check_verifications() -> int:
    """Periodic sweep (spec §15): finalizes every remediation task whose
    verification scan has finished, deciding FIXED vs REOPENED from that
    scan's real result. Plain-function logic lives in
    remediation_service.check_and_finalize_verifications so it's testable
    without a broker, same pattern as check_due_scans."""
    return remediation_service.check_and_finalize_verifications()


def _run_brain_hunt(
    asset_id: int,
    org_id: int,
    max_iterations: int = 5,
    max_seconds: float = 30.0,
) -> dict:
    """Run one bounded hunt for an asset and return the serialised HuntReport.

    Imports brain.hunt lazily so the module is only loaded in workers that
    have the brain package available (same pattern as web_scan_service).
    """
    import dataclasses
    from brain.hunt import run_hunt
    report = run_hunt(asset_id, org_id,
                      max_iterations=max_iterations,
                      max_seconds=max_seconds)
    return dataclasses.asdict(report)


@celery_app.task(name="webapp.tasks.run_brain_hunt")
def run_brain_hunt(
    asset_id: int,
    org_id: int,
    max_iterations: int = 5,
    max_seconds: float = 30.0,
) -> dict:
    return _run_brain_hunt(asset_id, org_id, max_iterations, max_seconds)


def _check_due_brain_hunts(enqueue=None) -> int:
    """Find every asset that currently has an active authorization and enqueue
    a brain hunt for each. Returns the count of hunts enqueued.

    `enqueue` defaults to the real Celery delay call; tests inject a plain
    recording callable to verify the logic without a running broker.
    """
    if enqueue is None:
        enqueue = lambda asset_id, org_id: run_brain_hunt.delay(asset_id, org_id)  # noqa: E731
    authorized = db.brain_list_authorized_assets()
    for row in authorized:
        enqueue(row["asset_id"], row["organization_id"])
    return len(authorized)


@celery_app.task(name="webapp.tasks.check_due_brain_hunts")
def check_due_brain_hunts() -> int:
    return _check_due_brain_hunts()
