"""Asset routes: register/list/update/delete authorized assets.

The two supported asset types per the platform spec are WEB_APPLICATION and
COMPANY_CONNECTOR. Every route here is scoped to the caller's organization —
an asset belonging to another organization is always a 404, never a 403 that
would confirm its existence.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from webapp import db
from webapp.routers.auth import require_operator, require_viewer
from webapp.schemas import AssetCreate, AssetMonitoringUpdate, AssetOut, AssetUpdate

router = APIRouter(prefix="/api/assets", tags=["assets"])


def _asset_out(row: dict) -> AssetOut:
    return AssetOut(
        id=row["id"], organization_id=row["organization_id"],
        asset_type=row["asset_type"], name=row["name"], url=row["url"],
        hostname=row.get("hostname") or "", environment=row["environment"],
        business_criticality=row["business_criticality"],
        authorization_status=row["authorization_status"],
        monitoring_status=row["monitoring_status"],
        monitoring_frequency=row.get("monitoring_frequency", "manual"),
        verification_status=row["verification_status"],
        added_by_user_id=row.get("added_by_user_id"),
        created_at=row["created_at"], updated_at=row["updated_at"],
        first_seen=row.get("first_seen"), last_seen=row.get("last_seen"),
        next_scan_at=row.get("next_scan_at"), last_scan_at=row.get("last_scan_at"),
    )


@router.get("", response_model=list)
def list_assets(asset_type: Optional[str] = None, user: dict = Depends(require_viewer)):
    if asset_type and asset_type not in ("WEB_APPLICATION", "COMPANY_CONNECTOR"):
        raise HTTPException(status_code=422, detail="asset_type must be WEB_APPLICATION or COMPANY_CONNECTOR")
    rows = db.list_assets(user["organization_id"], asset_type=asset_type)
    return [_asset_out(r).model_dump() for r in rows]


@router.post("", response_model=AssetOut)
def create_asset(body: AssetCreate, user: dict = Depends(require_operator)):
    if db.get_target_by_url(body.url, user["organization_id"]):
        raise HTTPException(status_code=400, detail="An asset with this URL already exists in your organization")
    asset_id = db.create_asset(
        user["organization_id"], body.name, body.asset_type, body.url,
        hostname=body.hostname, environment=body.environment,
        business_criticality=body.business_criticality,
        added_by_user_id=user["id"],
    )
    db.add_audit_log(user["id"], "asset_created", target_id=asset_id,
                     details={"name": body.name, "asset_type": body.asset_type, "url": body.url})
    return _asset_out(db.get_asset(asset_id, user["organization_id"]))


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, user: dict = Depends(require_viewer)):
    row = db.get_asset(asset_id, user["organization_id"])
    if not row:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_out(row)


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: int, body: AssetUpdate, user: dict = Depends(require_operator)):
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    if not db.update_asset(asset_id, user["organization_id"], **changes):
        raise HTTPException(status_code=404, detail="Asset not found")
    db.add_audit_log(user["id"], "asset_modified", target_id=asset_id, details=changes)
    return _asset_out(db.get_asset(asset_id, user["organization_id"]))


@router.patch("/{asset_id}/monitoring", response_model=AssetOut)
def update_monitoring(asset_id: int, body: AssetMonitoringUpdate,
                      user: dict = Depends(require_operator)):
    """Configure continuous monitoring for one asset (spec §7: admins
    configure per-asset scan frequency — 5m/15m/30m/hourly/daily/weekly, or
    'manual' to disable scheduling)."""
    if not db.set_asset_monitoring(asset_id, user["organization_id"],
                                   body.monitoring_status, body.monitoring_frequency):
        raise HTTPException(status_code=404, detail="Asset not found")
    db.add_audit_log(user["id"], "asset_monitoring_changed", target_id=asset_id,
                     details={"monitoring_status": body.monitoring_status,
                             "monitoring_frequency": body.monitoring_frequency})
    return _asset_out(db.get_asset(asset_id, user["organization_id"]))


@router.delete("/{asset_id}")
def delete_asset(asset_id: int, user: dict = Depends(require_operator)):
    row = db.get_asset(asset_id, user["organization_id"])
    if not row:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete_asset(asset_id, user["organization_id"])
    # target_id isn't set here: the row is already gone, and audit_log.target_id
    # is a real FK — pointing it at a nonexistent id would violate the
    # constraint. The identifying info lives in details instead.
    db.add_audit_log(user["id"], "asset_deleted",
                     details={"asset_id": asset_id, "name": row["name"], "url": row["url"]})
    return {"ok": True}
