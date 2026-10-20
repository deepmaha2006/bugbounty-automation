"""
HydraBrain dispatcher — bridge brain_actions → connector_jobs.

Bug fix: brain/response.py's apply_action() docstring has always said
"Connector dispatch is a stub (Phase 16+)". This module is that Phase 16
fix: when the brain applies a containment action it creates a real signed
connector_job so the connector agent can actually execute it.

Supported action_type → connector job_type mapping:
  block_source    → block_source   (iptables DROP)
  unblock_source  → unblock_source (iptables -D)
  apply_waf_rule  → apply_waf_rule (nginx snippet write)
  remove_waf_rule → remove_waf_rule (nginx snippet delete)
  kill_session    → kill_session   (conntrack / iptables state flush)

Actions that are NOT dispatched (only recorded as proposals):
  recommend, alert, escalate — require human interaction, no connector job.

Safety: if no active/online connector exists for the org the action remains
in brain_actions with status='applied' but no connector_job is created. This
is logged but does NOT raise so the hunt loop continues. The connector will
pick up the job on its next poll when it comes online.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Brain action types that should be dispatched as connector jobs.
_DISPATCHABLE: frozenset = frozenset({
    "block_source",
    "unblock_source",
    "apply_waf_rule",
    "remove_waf_rule",
    "kill_session",
})

# Default job TTL in minutes when the action carries no explicit expiry.
_DEFAULT_JOB_TTL_MINUTES = 60


def _build_job_scope(action_type: str, params: dict) -> dict:
    """Build the job scope dict from a brain_action's params."""
    if action_type in ("block_source", "unblock_source"):
        return {
            "src_ip": params.get("src_ip") or params.get("target_ip", ""),
            "reason": params.get("reason", "brain auto-contain"),
        }
    if action_type in ("apply_waf_rule", "remove_waf_rule"):
        return {
            "rule_id":    params.get("rule_id", ""),
            "rule_body":  params.get("rule_body", ""),
            "src_ip":     params.get("src_ip", ""),
            "reason":     params.get("reason", "brain waf"),
        }
    if action_type == "kill_session":
        return {
            "src_ip": params.get("src_ip", ""),
            "reason": params.get("reason", "brain kill_session"),
        }
    return dict(params)


def _pick_connector(org_id: int) -> Optional[dict]:
    """Return the first non-revoked connector for the org, or None."""
    import webapp.db as db
    from webapp.db import connector_state
    connectors = db.list_connectors(org_id)
    for c in connectors:
        if connector_state(c) not in ("REVOKED", "OFFLINE"):
            return c
    # Fall back to any non-revoked connector even if degraded/offline.
    for c in connectors:
        if not c.get("revoked_at"):
            return c
    return None


def dispatch_action(action_id: int, org_id: int, asset_id: int,
                    action_type: str, params: dict) -> Optional[int]:
    """Create a connector_job for a brain_action.

    Returns the connector_job id on success, None if skipped/no connector.
    Never raises — failures are logged so the hunt loop keeps running.
    """
    if action_type not in _DISPATCHABLE:
        return None

    try:
        import webapp.db as db
        from webapp.services import connector_crypto

        connector = _pick_connector(org_id)
        if connector is None:
            logger.warning(
                "brain.dispatcher: no connector available for org_id=%d "
                "action_id=%d action_type=%s — job NOT dispatched",
                org_id, action_id, action_type,
            )
            return None

        scope = _build_job_scope(action_type, params)

        # Use explicit expiry from params if present, else default TTL.
        expires_at_str = params.get("expires_at")
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(
                    str(expires_at_str).replace("Z", "+00:00")
                )
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except (ValueError, AttributeError):
                expires_at = datetime.now(timezone.utc) + timedelta(minutes=_DEFAULT_JOB_TTL_MINUTES)
        else:
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=_DEFAULT_JOB_TTL_MINUTES)

        job = db.create_connector_job(
            organization_id=org_id,
            connector_id=connector["id"],
            job_type=action_type,
            scope=scope,
            authorized_by_user_id=None,   # brain-initiated; no user session
            expires_at=expires_at,
        )

        # Sign the job so the connector can verify it came from the platform.
        priv_pem, _ = connector_crypto.get_platform_signing_keys()
        payload = connector_crypto.job_signing_payload(job)
        signature = connector_crypto.sign(priv_pem, payload)
        db.set_connector_job_signature(job["id"], signature)

        logger.info(
            "brain.dispatcher: dispatched connector_job id=%d "
            "type=%s connector=%d org=%d action=%d",
            job["id"], action_type, connector["id"], org_id, action_id,
        )
        return job["id"]

    except Exception:
        logger.exception(
            "brain.dispatcher: failed to dispatch action_id=%d type=%s org=%d",
            action_id, action_type, org_id,
        )
        return None
