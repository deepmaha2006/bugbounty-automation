"""
HydraBrain response — apply, rollback, and TTL-expire containment actions.

Phase 15: persists ProposedActions to brain_actions, rolls back on kill switch
or TTL expiry. Connector dispatch is a stub (Phase 16+ wires it to real jobs).

Safety invariants:
  * Every applied action gets a unique rollback_token stored in brain_actions.
  * rollback_action() flips status → 'rolled_back' and appends to INCIDENT_LOG.
  * rollback_all() is the kill-switch handler — rolls back every applied/proposed
    action for the asset.
  * expire_ttl_actions() rolls back anything whose params.expires_at has passed.
  * "recommend" actions land as status='proposed' and never auto-execute.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from brain.decision import ProposedAction
from brain.incident_log import INCIDENT_LOG


def apply_action(asset_id: int, org_id: int, proposed: ProposedAction) -> int:
    """Persist a proposed action to brain_actions. Returns the new action id.

    Actions of type 'recommend' land with status='proposed' (no auto-execute).
    All others land with status='applied'.
    """
    import webapp.db as db

    expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=proposed.ttl_seconds)
    ).isoformat()

    from brain.virtual_patch import APPROVAL_GATED_ACTION_TYPES
    if proposed.action_type in APPROVAL_GATED_ACTION_TYPES or proposed.action_type == "recommend":
        status = "proposed"
    else:
        status = "applied"

    action_id = db.brain_insert_action(
        asset_id=asset_id,
        org_id=org_id,
        incident_id=proposed.incident_id,
        action_type=proposed.action_type,
        params={**proposed.params,
                "ttl_seconds": proposed.ttl_seconds,
                "expires_at": expires_at},
        tier_at_time=str(proposed.tier),
        status=status,
        rollback_token=proposed.rollback_token,
    )

    INCIDENT_LOG.append(
        entry_type="action",
        asset_id=asset_id,
        org_id=org_id,
        payload={
            "action_id": action_id,
            "action_type": proposed.action_type,
            "status": status,
            "params": proposed.params,
            "rollback_token": proposed.rollback_token,
            "tier": str(proposed.tier),
        },
        actor="brain.response",
    )

    # Dispatch to connector only for applied (not proposed) actions.
    if status == "applied":
        from brain.dispatcher import dispatch_action
        dispatch_action(
            action_id=action_id,
            org_id=org_id,
            asset_id=asset_id,
            action_type=proposed.action_type,
            params={**proposed.params,
                    "ttl_seconds": proposed.ttl_seconds,
                    "expires_at": expires_at},
        )

    return action_id


def rollback_action(
    action_id: int, org_id: int, actor: str = "brain.response"
) -> bool:
    """Roll back one action. Returns True if status changed, False otherwise."""
    import webapp.db as db

    action = db.brain_get_action(action_id, org_id)
    if action is None:
        return False
    if action.get("status") not in ("applied", "proposed"):
        return False  # already terminal

    db.brain_update_action_status(action_id, org_id, "rolled_back")

    INCIDENT_LOG.append(
        entry_type="rollback",
        asset_id=action["asset_id"],
        org_id=org_id,
        payload={
            "action_id": action_id,
            "rollback_token": action.get("rollback_token"),
            "original_type": action.get("type"),
        },
        actor=actor,
    )
    return True


def rollback_all(
    asset_id: int, org_id: int, actor: str = "brain.response"
) -> int:
    """Roll back every applied/proposed action for asset. Kill-switch handler.

    Returns the count of actions rolled back.
    """
    import webapp.db as db

    actions = db.brain_list_actions(
        asset_id=asset_id, org_id=org_id,
        status_filter=["applied", "proposed"],
    )
    count = 0
    for action in actions:
        if rollback_action(action["id"], org_id, actor=actor):
            count += 1
    return count


def approve_action(
    action_id: int, org_id: int, approver: str
) -> bool:
    """Approve a proposed action (human gate). Returns True if status changed."""
    import webapp.db as db

    action = db.brain_get_action(action_id, org_id)
    if action is None:
        return False
    if action.get("status") != "proposed":
        return False

    db.brain_update_action_status(action_id, org_id, "approved", approver=approver)

    INCIDENT_LOG.append(
        entry_type="approval",
        asset_id=action["asset_id"],
        org_id=org_id,
        payload={
            "action_id": action_id,
            "approver": approver,
            "original_type": action.get("type"),
        },
        actor=approver,
    )
    return True


def reject_action(
    action_id: int, org_id: int, approver: str, reason: str = ""
) -> bool:
    """Reject a proposed action. Returns True if status changed."""
    import webapp.db as db

    action = db.brain_get_action(action_id, org_id)
    if action is None:
        return False
    if action.get("status") != "proposed":
        return False

    db.brain_update_action_status(action_id, org_id, "failed", approver=approver)

    INCIDENT_LOG.append(
        entry_type="rejection",
        asset_id=action["asset_id"],
        org_id=org_id,
        payload={
            "action_id": action_id,
            "approver": approver,
            "reason": reason,
            "original_type": action.get("type"),
        },
        actor=approver,
    )
    return True


def expire_ttl_actions(asset_id: int, org_id: int) -> int:
    """Roll back applied actions past their TTL. Returns count rolled back."""
    import webapp.db as db

    now = datetime.now(timezone.utc)
    actions = db.brain_list_actions(
        asset_id=asset_id, org_id=org_id,
        status_filter=["applied"],
    )
    count = 0
    for action in actions:
        expires_at_str = (action.get("params") or {}).get("expires_at")
        if not expires_at_str:
            continue
        try:
            expires_at = datetime.fromisoformat(
                str(expires_at_str).replace("Z", "+00:00")
            )
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if now >= expires_at:
                if rollback_action(action["id"], org_id, actor="ttl_expiry"):
                    count += 1
        except (ValueError, AttributeError):
            pass
    return count
