"""Celery application: the job queue + scheduler backing continuous
monitoring (spec §7).

Architecture (see docs/ARCHITECTURE.md §2):

    Celery beat --check_due_scans (every 60s)--> enqueues one job per due
    asset onto a queue named for its job type --> a worker consuming that
    queue runs it --> Finding Processor (webapp.db.add_finding's own
    fingerprint dedup, Phase 4) --> Risk Engine / Alert Engine (later phases).

Queue names match the spec's architecture diagram. Only `web_scan` has a
real task behind it right now (Phase 5) — `connector_assessment` (Phase 8),
`asset_discovery`/`config_assessment` (Phase 7), and `vuln_correlation`
(already happening inline in add_finding, Phase 4) are reserved queue names
for when their respective phases land, not fake/stub tasks.

Run a worker:   celery -A webapp.celery_app worker --loglevel=info
Run the beat:   celery -A webapp.celery_app beat --loglevel=info

No Redis is available in the development sandbox this was built in — the
Celery app object, task registration, and routing config are all verified by
import and by calling task functions directly (bypassing the broker, see
tests/test_phase5_scheduler.py), but the actual broker round-trip has not
been exercised against a live Redis. Verify that before first real use.
"""
from celery import Celery

from webapp import config
from webapp.logging_config import configure_logging

# Structured (JSON) logs for worker events too (spec §22), not just the API
# process — same formatter/request-id-correlation machinery as webapp/main.py.
configure_logging()

celery_app = Celery("hydrax", broker=config.REDIS_URL, backend=config.REDIS_URL)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "webapp.tasks.check_due_scans": {"queue": "scheduler"},
        "webapp.tasks.run_scheduled_web_scan": {"queue": "web_scan"},
        "webapp.tasks.check_verifications": {"queue": "scheduler"},
    },
    beat_schedule={
        "check-due-scans": {
            "task": "webapp.tasks.check_due_scans",
            "schedule": config.SCHEDULER_CHECK_INTERVAL_SECONDS,
        },
        "check-remediation-verifications": {
            "task": "webapp.tasks.check_verifications",
            "schedule": config.SCHEDULER_CHECK_INTERVAL_SECONDS,
        },
    },
)

# Importing this registers the @celery_app.task-decorated functions below.
from webapp import tasks  # noqa: E402,F401
