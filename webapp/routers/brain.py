"""Remediation engine live input: POST /api/brain/resolve.

Accepts a *described* detected event from the operator's own monitored
systems and returns the same analyst report the scan pipeline produces.
It runs the deterministic KB resolver only — no outbound calls, no agents,
nothing executed. Unmatched input falls back to generic guidance and is
recorded in the unresolved store so the knowledge base can grow.
"""
from fastapi import APIRouter, Depends, HTTPException, status

from webapp.routers.auth import require_operator
from webapp.schemas import BrainResolveRequest
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
