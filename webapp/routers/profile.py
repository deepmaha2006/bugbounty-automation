"""Profile routes: get/update user profile, change password."""
import logging

from fastapi import APIRouter, Depends, HTTPException

from webapp import db, security
from webapp.routers.auth import require_user
from webapp.schemas import ProfileUpdate, PasswordChange

router = APIRouter(prefix="/api/profile", tags=["profile"])
logger = logging.getLogger("hydrax.profile")


@router.get("")
def get_profile(user: dict = Depends(require_user)):
    p = db.get_profile(user["id"])
    p["username"] = user["username"]
    # Same source as the login response's UserOut.role: the users row that
    # authenticated this request.
    p["role"] = user["role"]
    # Once a profiles row exists, get_profile returns `SELECT * FROM profiles`,
    # which has no email column — so email used to vanish after the first
    # save. The users row always has it.
    if not p.get("email"):
        p["email"] = user.get("email", "")

    # Additive hero stats. member_since comes from users.created_at.
    created = user.get("created_at")
    if created:
        p["member_since"] = created.isoformat() if hasattr(created, "isoformat") else str(created)
    # Scan/finding totals reuse the dashboard's existing org-scoped query (no
    # new SQL); they are organization-wide, flagged by stats_scope. A failure
    # here must never break the profile page.
    try:
        stats = db.dashboard_stats(user["organization_id"])
        p["total_scans"] = int(stats.get("total_scans") or 0)
        p["total_findings"] = int(stats.get("total_findings") or 0)
        p["stats_scope"] = "organization"
    except Exception:  # noqa: BLE001
        logger.exception("profile stats unavailable for user %s", user.get("id"))
    return p


@router.put("")
def update_profile(body: ProfileUpdate, user: dict = Depends(require_user)):
    db.upsert_profile(user["id"], body.model_dump(exclude_unset=True))
    return db.get_profile(user["id"])


@router.post("/password")
def change_password(body: PasswordChange, user: dict = Depends(require_user)):
    if not security.verify_password(body.current_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    db.update_password_hash(user["id"], security.hash_password(body.new_password))
    return {"ok": True}