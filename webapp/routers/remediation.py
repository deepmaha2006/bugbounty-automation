"""Remediation task routes (spec §14, §15).

Creating/editing tasks and submitting a fix is require_operator (the roles
that actually do remediation work per spec §17); viewing is require_viewer.
Status can only be moved through OPEN/ASSIGNED/IN_PROGRESS manually — the
rest of the lifecycle (FIX_SUBMITTED through FIXED/REOPENED) is exclusively
driven by POST .../submit-fix and the automatic verification sweep, per
spec §15's "do NOT simply change it to FIXED" rule (enforced in
webapp/db.py::update_remediation_task, not just at this layer).
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from webapp import db
from webapp.routers.auth import require_operator, require_viewer
from webapp.schemas import (RemediationCommentCreate, RemediationCommentOut,
                            RemediationTaskCreate, RemediationTaskOut, RemediationTaskUpdate)
from webapp.services import remediation_service

router = APIRouter(prefix="/api/remediation-tasks", tags=["remediation"])


def _iso(v):
    return v if v is None or isinstance(v, str) else v.isoformat()


def _task_out(row: dict, comments: list) -> RemediationTaskOut:
    return RemediationTaskOut(
        id=row["id"], organization_id=row["organization_id"], finding_id=row["finding_id"],
        assignee_user_id=row.get("assignee_user_id"), team=row.get("team"),
        priority=row["priority"], due_date=_iso(row.get("due_date")), status=row["status"],
        verification_scan_id=row.get("verification_scan_id"),
        verification_evidence=row.get("verification_evidence"),
        created_at=_iso(row["created_at"]), updated_at=_iso(row["updated_at"]),
        comments=[RemediationCommentOut(id=c["id"], user_id=c.get("user_id"),
                                        comment=c["comment"], created_at=_iso(c["created_at"]))
                 for c in comments],
    )


@router.get("", response_model=list)
def list_tasks(status: Optional[str] = None, assignee_user_id: Optional[int] = None,
              user: dict = Depends(require_viewer)):
    rows = db.list_remediation_tasks(user["organization_id"], status=status,
                                     assignee_user_id=assignee_user_id)
    return [_task_out(r, []).model_dump() for r in rows]


@router.post("", response_model=RemediationTaskOut)
def create_task(body: RemediationTaskCreate, user: dict = Depends(require_operator)):
    if not db.get_finding(body.finding_id, user["organization_id"]):
        raise HTTPException(status_code=404, detail="Finding not found")
    task_id = db.create_remediation_task(
        user["organization_id"], body.finding_id, body.assignee_user_id,
        body.team, body.priority, body.due_date,
    )
    db.add_audit_log(user["id"], "remediation_task_created", details={
        "task_id": task_id, "finding_id": body.finding_id, "assignee_user_id": body.assignee_user_id,
    })
    return _task_out(db.get_remediation_task(task_id, user["organization_id"]), [])


@router.get("/{task_id}", response_model=RemediationTaskOut)
def get_task(task_id: int, user: dict = Depends(require_viewer)):
    row = db.get_remediation_task(task_id, user["organization_id"])
    if not row:
        raise HTTPException(status_code=404, detail="Remediation task not found")
    return _task_out(row, db.list_remediation_comments(task_id))


@router.patch("/{task_id}", response_model=RemediationTaskOut)
def update_task(task_id: int, body: RemediationTaskUpdate, user: dict = Depends(require_operator)):
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    try:
        ok = db.update_remediation_task(task_id, user["organization_id"], **changes)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    if not ok:
        raise HTTPException(status_code=404, detail="Remediation task not found")
    db.add_audit_log(user["id"], "remediation_task_updated", details={"task_id": task_id, **changes})
    return _task_out(db.get_remediation_task(task_id, user["organization_id"]),
                     db.list_remediation_comments(task_id))


@router.post("/{task_id}/submit-fix", response_model=RemediationTaskOut)
def submit_fix(task_id: int, user: dict = Depends(require_operator)):
    """Never sets FIXED directly — schedules a real verification scan
    instead (spec §15)."""
    try:
        remediation_service.submit_fix(task_id, user["organization_id"], user["id"])
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    db.add_audit_log(user["id"], "remediation_fix_submitted", details={"task_id": task_id})
    return _task_out(db.get_remediation_task(task_id, user["organization_id"]),
                     db.list_remediation_comments(task_id))


@router.post("/{task_id}/comments", response_model=RemediationTaskOut)
def add_comment(task_id: int, body: RemediationCommentCreate, user: dict = Depends(require_operator)):
    if not db.get_remediation_task(task_id, user["organization_id"]):
        raise HTTPException(status_code=404, detail="Remediation task not found")
    db.add_remediation_comment(task_id, user["id"], body.comment)
    return _task_out(db.get_remediation_task(task_id, user["organization_id"]),
                     db.list_remediation_comments(task_id))
