"""Settings routes: get/update platform + scan settings, admin user
management, and API key management (HydraX)."""
from fastapi import APIRouter, Depends, HTTPException

from webapp import config as wcfg
from webapp import db, security
from webapp.routers.auth import require_admin, require_operator
from webapp.schemas import (AdminInfoOut, ApiKeyCreate, ApiKeyCreatedOut, ApiKeyOut,
                            AuditLogEntry, RoleChangeRequest, SettingsUpdate)
from webapp.services import kali_tools

router = APIRouter(prefix="/api/settings", tags=["settings"])

_KEYS = {
    "default_threads": int, "default_timeout": int, "verify_ssl": bool,
    "accent": str,
}

_TRUE_STRINGS = {"true", "1", "yes", "on"}


def _parse_bool(v) -> bool:
    """Settings are stored as strings ("true"/"false", see update_settings).
    Plain bool() would read the string "false" as True, so parse explicitly;
    anything not recognizably true (incl. "false"/"0"/"no"/""/None) is False."""
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in _TRUE_STRINGS


@router.get("")
def get_settings(user: dict = Depends(require_operator)):
    raw = db.get_all_settings()
    cast = {}
    for k, t in _KEYS.items():
        v = raw.get(k, "")
        if v == "" or v is None:
            # Unset: unchanged behavior — "" for strings, None otherwise, so
            # the UI can still apply its own defaults.
            cast[k] = "" if t is str else None
            continue
        try:
            cast[k] = _parse_bool(v) if t is bool else t(v)
        except (ValueError, TypeError):
            cast[k] = None
    cast["app_name"] = wcfg.APP_TITLE
    cast["version"] = wcfg.APP_VERSION
    return cast


@router.put("")
def update_settings(body: SettingsUpdate, user: dict = Depends(require_admin)):
    changes = body.model_dump(exclude_unset=True)
    applied = {}
    for k, v in changes.items():
        if k in _KEYS:
            db.set_setting(k, str(v).lower() if isinstance(v, bool) else str(v))
            applied[k] = v
    if applied:
        db.add_audit_log(user["id"], "settings_changed", details=applied)
    return {"ok": True, "updated": list(changes.keys())}


@router.get("/tools")
def tool_status(user: dict = Depends(require_operator)):
    """Report the availability of every Kali tool integrated into HydraX."""
    return {
        "platform": "Kali Linux",
        "tools": kali_tools.tool_status(),
        "available": sum(1 for v in kali_tools.tool_status().values() if v),
        "total": len(kali_tools.tool_status()),
    }


@router.get("/admin", response_model=AdminInfoOut)
def admin_info(user: dict = Depends(require_admin)):
    """Admin-only platform info: bootstrap, users, security posture."""
    return {
        "admin": user["username"],
        "role": user["role"],
        "users": db.list_users(user["organization_id"]),
        "jwt_ephemeral": bool(getattr(wcfg, "JWT_DEV_MODE", False)),
        "jwt_configured": bool(getattr(wcfg, "AUTH_CONFIGURED", False)),
        "registration_open": False,
    }


@router.get("/audit-log", response_model=list)
def audit_log(limit: int = 100, offset: int = 0, user: dict = Depends(require_admin)):
    """Read-only, org-scoped audit trail (spec §18) — admin-only, since it
    can reveal other users' actions within the same organization."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    rows = db.get_audit_log(user["organization_id"], limit=limit, offset=offset)
    return [AuditLogEntry(**r).model_dump() for r in rows]


@router.post("/admin/users/{user_id}/unlock")
def unlock_user(user_id: int, user: dict = Depends(require_admin)):
    """Clear a persistent account lockout early (spec §17's "admin-visible
    unlock" requirement) — org-scoped, so an admin can't unlock a user
    outside their own organization."""
    if not db.admin_unlock_user(user_id, user["organization_id"]):
        raise HTTPException(status_code=404, detail="User not found")
    db.add_audit_log(user["id"], "user_unlocked", details={"target_user_id": user_id})
    return {"ok": True}


@router.post("/admin/users/{user_id}/role")
def change_user_role(user_id: int, body: RoleChangeRequest, user: dict = Depends(require_admin)):
    """Role changes are an explicitly audited action (spec §18)."""
    org_users = db.list_users(user["organization_id"])
    target = next((u for u in org_users if u["id"] == user_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    # WSTG-BUSL (business-logic safeguard, Phase 20 audit): demoting the
    # organization's last admin is unrecoverable without direct DB access —
    # nobody left could call this very endpoint to undo it. Not an access-
    # control bypass (only an admin can reach this at all), but a real
    # self-inflicted-lockout / insider-containment gap worth closing cheaply.
    if target["role"] == "admin" and body.role != "admin":
        remaining_admins = sum(1 for u in org_users if u["role"] == "admin" and u["id"] != user_id)
        if remaining_admins == 0:
            raise HTTPException(status_code=400,
                                detail="Cannot demote the organization's last admin")
    db.set_user_role(user_id, body.role)
    db.add_audit_log(user["id"], "role_changed",
                     details={"target_user_id": user_id, "old_role": target["role"], "new_role": body.role})
    return {"ok": True}


# --- API keys (Phase 3, spec §17: "API authentication", §18: "API key
# creation/revocation" must be audited) -------------------------------------
def _api_key_out(row: dict) -> ApiKeyOut:
    return ApiKeyOut(
        id=row["id"], name=row["name"], key_prefix=row["key_prefix"],
        created_at=row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else row["created_at"],
        last_used_at=(row["last_used_at"].isoformat()
                     if hasattr(row.get("last_used_at"), "isoformat") else row.get("last_used_at")),
        revoked_at=(row["revoked_at"].isoformat()
                   if hasattr(row.get("revoked_at"), "isoformat") else row.get("revoked_at")),
    )


@router.get("/api-keys", response_model=list)
def list_api_keys(user: dict = Depends(require_admin)):
    return [_api_key_out(r).model_dump() for r in db.list_api_keys(user["organization_id"])]


@router.post("/api-keys", response_model=ApiKeyCreatedOut)
def create_api_key(body: ApiKeyCreate, user: dict = Depends(require_admin)):
    raw_key, prefix = security.generate_api_key()
    key_id = db.create_api_key(user["organization_id"], user["id"], body.name,
                               prefix, security.hash_opaque_token(raw_key))
    db.add_audit_log(user["id"], "api_key_created", details={"name": body.name, "key_id": key_id})
    row = db.list_api_keys(user["organization_id"])
    row = next(r for r in row if r["id"] == key_id)
    out = _api_key_out(row)
    return ApiKeyCreatedOut(**out.model_dump(), api_key=raw_key)


@router.delete("/api-keys/{key_id}")
def revoke_api_key(key_id: int, user: dict = Depends(require_admin)):
    if not db.revoke_api_key(key_id, user["organization_id"]):
        raise HTTPException(status_code=404, detail="API key not found")
    db.add_audit_log(user["id"], "api_key_revoked", details={"key_id": key_id})
    return {"ok": True}
