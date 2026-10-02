"""Finding (vulnerability) routes: cross-scan listing, detail, and lifecycle
status transitions (spec §4, §8, §13).

Every finding here has already been deduplicated by fingerprint at insert
time (webapp/db.py::add_finding) — a repeat detection of the same
vulnerability on the same asset updates occurrence_count/last_seen on one
row rather than appearing again, so this API's listing is the vulnerability
list an analyst actually wants, not a raw per-scan findings dump.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from webapp import db
from webapp.routers.auth import require_operator, require_viewer
from webapp.schemas import FindingDetailOut, FindingStatusUpdate

router = APIRouter(prefix="/api/findings", tags=["findings"])

_VALID_STATUSES = {"NEW", "OPEN", "ACKNOWLEDGED", "IN_PROGRESS",
                   "FIX_PENDING_VERIFICATION", "FIXED", "REOPENED",
                   "FALSE_POSITIVE", "ACCEPTED_RISK"}
_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


def _detail_out(row: dict) -> FindingDetailOut:
    return FindingDetailOut(
        id=row["id"], scan_id=row["scan_id"], organization_id=row["organization_id"],
        title=row["type"], severity=row["severity"], status=row.get("status", "NEW"),
        confidence=row["confidence"], cve=row.get("cve"), cwe=row.get("cwe"),
        cvss_estimated=row.get("cvss"),
        affected_component=row.get("affected_component") or row.get("parameter") or row["type"],
        occurrence_count=row.get("occurrence_count", 1),
        first_seen=row.get("discovered_at") or "", last_seen=row.get("last_seen") or "",
        detection_method=row.get("tool", ""), evidence=row.get("evidence", ""),
        affected_endpoint=row.get("url", ""), parameter=row.get("parameter"),
        payload=row.get("payload"), remediation=row.get("remediation", ""),
        business_impact=row.get("business_impact"), technical_impact=row.get("technical_impact"),
        risk_score=row.get("risk_score"), risk_factors=row.get("risk_factors"),
    )


@router.get("", response_model=list)
def list_findings(status: Optional[str] = None, severity: Optional[str] = None,
                  user: dict = Depends(require_viewer)):
    if status and status not in _VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status. Must be one of: {sorted(_VALID_STATUSES)}")
    if severity and severity not in _VALID_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"Invalid severity. Must be one of: {sorted(_VALID_SEVERITIES)}")
    rows = db.list_findings(user["organization_id"], status=status, severity=severity)
    return [_detail_out(r).model_dump() for r in rows]


@router.get("/{finding_id}", response_model=FindingDetailOut)
def get_finding(finding_id: int, user: dict = Depends(require_viewer)):
    row = db.get_finding(finding_id, user["organization_id"])
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _detail_out(row)


@router.patch("/{finding_id}/status", response_model=FindingDetailOut)
def update_status(finding_id: int, body: FindingStatusUpdate, user: dict = Depends(require_operator)):
    existing = db.get_finding(finding_id, user["organization_id"])
    if not existing:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.update_finding_status(finding_id, user["organization_id"], body.status)
    db.add_audit_log(user["id"], "finding_status_changed",
                     details={"finding_id": finding_id, "old_status": existing["status"],
                             "new_status": body.status})
    return _detail_out(db.get_finding(finding_id, user["organization_id"]))
