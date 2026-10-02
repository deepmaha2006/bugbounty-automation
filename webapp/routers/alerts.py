"""Alert + notification-channel routes (spec §9).

Channel management (create/list/delete) is admin-only — a webhook/Slack/
Teams URL or an email address is effectively a secret-adjacent destination
for sensitive finding data, so only an org admin configures where alerts go.
Viewing and acknowledging alerts is available to every role that can see
findings at all.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from webapp import db
from webapp.routers.auth import require_admin, require_operator, require_viewer
from webapp.schemas import (AlertOut, NotificationChannelCreate, NotificationChannelOut,
                            NotificationOut)
from utils.ssrf_guard import UnsafeScanTargetError, assert_safe_scan_target

router = APIRouter(tags=["alerts"])
channels_router = APIRouter(prefix="/api/notification-channels", tags=["alerts"])

# webhook/slack/teams channels are just "POST this finding payload to a
# URL an org admin supplied" — with zero validation, that URL could be
# http://169.254.169.254/... (cloud metadata) or the platform's own
# internal services, and the platform's own alert-delivery job would
# dutifully make that request the next time a Critical/High finding fires
# (CWE-918 SSRF, WSTG-INPV-19, ASVS V5.2.5). "email" needs no URL check.
_URL_CHANNEL_TYPES = ("webhook", "slack", "teams")


def _reject_unsafe_channel_url(channel_type: str, config_: dict) -> None:
    if channel_type not in _URL_CHANNEL_TYPES:
        return
    url = (config_ or {}).get("url")
    if not url:
        raise HTTPException(status_code=422, detail="config.url is required for this channel type")
    try:
        assert_safe_scan_target(url)
    except UnsafeScanTargetError as e:
        raise HTTPException(status_code=422, detail=f"Unsafe destination URL: {e}") from e


def _channel_out(row: dict) -> NotificationChannelOut:
    return NotificationChannelOut(
        id=row["id"], channel_type=row["channel_type"], name=row["name"],
        config=row["config"], enabled=row["enabled"],
        created_at=row["created_at"] if isinstance(row["created_at"], str) else row["created_at"].isoformat(),
    )


@channels_router.get("", response_model=list)
def list_channels(user: dict = Depends(require_admin)):
    return [_channel_out(c).model_dump() for c in db.list_notification_channels(user["organization_id"])]


@channels_router.post("", response_model=NotificationChannelOut)
def create_channel(body: NotificationChannelCreate, user: dict = Depends(require_admin)):
    _reject_unsafe_channel_url(body.channel_type, body.config)
    cid = db.create_notification_channel(user["organization_id"], body.channel_type,
                                         body.name, body.config)
    db.add_audit_log(user["id"], "notification_channel_created",
                     details={"channel_id": cid, "channel_type": body.channel_type})
    return _channel_out(db.get_notification_channel(cid, user["organization_id"]))


@channels_router.delete("/{channel_id}")
def delete_channel(channel_id: int, user: dict = Depends(require_admin)):
    if not db.delete_notification_channel(channel_id, user["organization_id"]):
        raise HTTPException(status_code=404, detail="Notification channel not found")
    db.add_audit_log(user["id"], "notification_channel_deleted", details={"channel_id": channel_id})
    return {"ok": True}


def _alert_out(row: dict, notifications: list) -> AlertOut:
    def _iso(v):
        return v if v is None or isinstance(v, str) else v.isoformat()
    return AlertOut(
        id=row["id"], organization_id=row["organization_id"], finding_id=row["finding_id"],
        asset_id=row.get("asset_id"), severity=row["severity"], status=row["status"],
        created_at=_iso(row["created_at"]), last_notified_at=_iso(row.get("last_notified_at")),
        acknowledged_at=_iso(row.get("acknowledged_at")),
        acknowledged_by_user_id=row.get("acknowledged_by_user_id"),
        notifications=[NotificationOut(
            id=n["id"], channel_id=n.get("channel_id"), status=n["status"],
            error_message=n.get("error_message"), sent_at=_iso(n["sent_at"]),
        ) for n in notifications],
    )


@router.get("/api/alerts", response_model=list)
def list_alerts(status: Optional[str] = None, user: dict = Depends(require_viewer)):
    if status and status not in ("open", "acknowledged"):
        raise HTTPException(status_code=422, detail="status must be 'open' or 'acknowledged'")
    rows = db.list_alerts(user["organization_id"], status=status)
    return [_alert_out(r, db.list_alert_notifications(r["id"])).model_dump() for r in rows]


@router.get("/api/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, user: dict = Depends(require_viewer)):
    row = db.get_alert(alert_id, user["organization_id"])
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_out(row, db.list_alert_notifications(alert_id))


@router.post("/api/alerts/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge_alert(alert_id: int, user: dict = Depends(require_operator)):
    if not db.acknowledge_alert(alert_id, user["organization_id"], user["id"]):
        raise HTTPException(status_code=404, detail="Alert not found")
    db.add_audit_log(user["id"], "alert_acknowledged", details={"alert_id": alert_id})
    row = db.get_alert(alert_id, user["organization_id"])
    return _alert_out(row, db.list_alert_notifications(alert_id))
