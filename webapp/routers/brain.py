"""Brain API — resolve, incidents, events, actions, knowledge, policy, hunt.

POST /api/brain/resolve   — deterministic KB resolver (analyst report)
GET  /api/brain/incidents — list brain_incidents for an asset
GET  /api/brain/events    — list brain_events for an asset
GET  /api/brain/actions   — list brain_actions for an asset
GET  /api/brain/knowledge — list brain_knowledge for an asset
GET  /api/brain/policy    — read in-memory autonomy policy
POST /api/brain/policy    — write in-memory autonomy policy
POST /api/brain/hunt      — synchronous mini-hunt (small iteration/time caps)
"""
import dataclasses
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from webapp import db as _db
from webapp.routers.auth import require_operator
from webapp.schemas import (BrainAssetOrgRequest, BrainHuntRequest,
                            BrainPolicyRequest, BrainResolveRequest)
from webapp.services import remediation_service
from webapp.services.api_rate_limiter import FixedWindowLimiter

router = APIRouter(prefix="/api/brain", tags=["brain"])

# Per-user bound on a cheap, CPU-only endpoint that also writes to the
# unresolved store: generous for interactive/feed use, bounded for abuse.
brain_resolve_limiter = FixedWindowLimiter(max_requests=60, window_seconds=60)


@router.post("/resolve")
def brain_resolve(body: BrainResolveRequest, user: dict = Depends(require_operator)):
    if not brain_resolve_limiter.allow(user["id"]):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many resolve requests. Please wait and try again.")
    finding = {
        # A free-text signal is matched like a finding title when no type is given.
        "type": body.type or body.signal or "",
        "category": body.category or "",
        "cwe": body.cwe or "",
        "confidence": body.confidence or "",
    }
    context = {}
    if body.context:
        if body.context.exposure:
            context["exposure"] = body.context.exposure
        if body.context.asset:
            context["asset"] = body.context.asset
    report = remediation_service.resolve(finding, context)
    if body.signal and body.type:
        report["signal"] = body.signal
    return report


@router.get("/incidents")
def brain_list_incidents(
    asset_id: int = Query(...),
    org_id: int = Query(...),
    state: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    user: dict = Depends(require_operator),
):
    """List brain_incidents for an asset, optionally filtered by state."""
    if org_id != user.get("organization_id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Cross-org access not permitted.")
    return _db.brain_list_incidents(asset_id=asset_id, org_id=org_id,
                                    state=state, limit=limit)


@router.get("/events")
def brain_list_events(
    asset_id: int = Query(...),
    org_id: int = Query(...),
    limit: int = Query(200, le=1000),
    user: dict = Depends(require_operator),
):
    """List recent brain_events for an asset."""
    if org_id != user.get("organization_id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Cross-org access not permitted.")
    return _db.brain_list_events(asset_id=asset_id, org_id=org_id, limit=limit)


@router.get("/actions")
def brain_list_actions(
    asset_id: int = Query(...),
    org_id: int = Query(...),
    action_status: Optional[str] = Query(None, alias="status"),
    limit: int = Query(100, le=500),
    user: dict = Depends(require_operator),
):
    """List brain_actions for an asset, optionally filtered by status."""
    if org_id != user.get("organization_id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Cross-org access not permitted.")
    status_filter = [action_status] if action_status else None
    return _db.brain_list_actions(asset_id=asset_id, org_id=org_id,
                                  status_filter=status_filter, limit=limit)


@router.get("/knowledge")
def brain_list_knowledge(
    asset_id: int = Query(...),
    org_id: int = Query(...),
    limit: int = Query(100, le=500),
    user: dict = Depends(require_operator),
):
    """List brain_knowledge records for an asset, sorted by confidence descending."""
    if org_id != user.get("organization_id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Cross-org access not permitted.")
    return _db.brain_list_knowledge(asset_id=asset_id, org_id=org_id, limit=limit)


@router.get("/policy")
def brain_get_policy(
    asset_id: int = Query(...),
    org_id: int = Query(...),
    user: dict = Depends(require_operator),
):
    """Return the current in-memory autonomy policy for an asset."""
    if org_id != user.get("organization_id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Cross-org access not permitted.")
    from brain.autonomy import get_policy
    p = get_policy(asset_id, org_id)
    return {
        "asset_id": p.asset_id,
        "org_id": p.org_id,
        "tier": p.tier.value,
        "fp_block_max_per_min": p.fp_block_max_per_min,
    }


@router.post("/policy")
def brain_set_policy(
    body: BrainPolicyRequest,
    user: dict = Depends(require_operator),
):
    """Set the in-memory autonomy policy for an asset."""
    if body.org_id != user.get("organization_id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Cross-org access not permitted.")
    from brain.autonomy import AutonomyPolicy, AutonomyTier, set_policy
    set_policy(AutonomyPolicy(
        asset_id=body.asset_id,
        org_id=body.org_id,
        tier=AutonomyTier(body.tier),
    ))
    return {"ok": True, "tier": body.tier}


@router.post("/hunt")
def brain_hunt(
    body: BrainHuntRequest,
    user: dict = Depends(require_operator),
):
    """Trigger a synchronous bounded hunt for an asset. Returns HuntReport."""
    if body.org_id != user.get("organization_id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Cross-org access not permitted.")
    from brain.hunt import run_hunt
    report = run_hunt(
        body.asset_id, body.org_id,
        max_iterations=body.max_iterations,
        max_seconds=body.max_seconds,
        last_event_id=body.last_event_id,
    )
    return dataclasses.asdict(report)


# ---------------------------------------------------------------------------
# Kill-switch endpoints (Phase 21 completion)
# ---------------------------------------------------------------------------

@router.post("/kill-switch/engage")
def brain_kill_switch_engage(user: dict = Depends(require_operator)):
    """Engage the global kill switch — all autonomous actions stop immediately."""
    from brain.autonomy import KILL_SWITCH
    KILL_SWITCH.engage()
    return {"ok": True, "engaged": True}


@router.post("/kill-switch/disengage")
def brain_kill_switch_disengage(user: dict = Depends(require_operator)):
    """Disengage the global kill switch."""
    from brain.autonomy import KILL_SWITCH
    KILL_SWITCH.disengage()
    return {"ok": True, "engaged": False}


@router.get("/kill-switch")
def brain_kill_switch_status(user: dict = Depends(require_operator)):
    """Return current kill-switch state."""
    from brain.autonomy import KILL_SWITCH
    return {"engaged": KILL_SWITCH.engaged}


# ---------------------------------------------------------------------------
# Rollback / TTL expiry endpoints
# ---------------------------------------------------------------------------

@router.post("/rollback-all")
def brain_rollback_all(
    body: BrainAssetOrgRequest,
    user: dict = Depends(require_operator),
):
    """Roll back every applied/proposed action for an asset."""
    if body.org_id != user.get("organization_id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Cross-org access not permitted.")
    from brain.response import rollback_all
    count = rollback_all(body.asset_id, body.org_id, actor=f"user:{user['id']}")
    return {"ok": True, "rolled_back": count}


@router.post("/expire-actions")
def brain_expire_actions(
    body: BrainAssetOrgRequest,
    user: dict = Depends(require_operator),
):
    """Expire TTL-past actions and roll them back."""
    if body.org_id != user.get("organization_id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Cross-org access not permitted.")
    from brain.response import expire_ttl_actions
    count = expire_ttl_actions(body.asset_id, body.org_id)
    return {"ok": True, "expired": count}
