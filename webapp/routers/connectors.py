"""Company Connector routes (spec §5, §6).

Two distinct audiences hit this router:
  - Human users (JWT/API-key auth via require_admin/operator/viewer) manage
    enrollment tokens, view connectors, create jobs, and revoke/pause.
  - The connector agent itself (webapp/services/connector_crypto.py-signed
    jobs; auth via a per-connector bearer secret, not a user session) polls
    for jobs and submits signed results.

The allowlisted job model is the platform's highest-stakes security control
(docs/SECURITY_MODEL.md §4): job_type is a closed enum (webapp/db.py::
JOB_TYPES) enforced by a DB CHECK constraint AND Pydantic's own field
validation before it ever reaches the database — there is no code path here
that accepts an arbitrary command string.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException

from webapp import config, db, security
from webapp.routers.auth import require_admin, require_operator, require_viewer
from webapp.schemas import (ConnectorEnrollOut, ConnectorEnrollRequest, ConnectorHeartbeatRequest,
                            ConnectorJobCreate, ConnectorJobOut, ConnectorJobResultSubmit,
                            ConnectorOut, EnrollmentTokenOut, SignedJobOut)
from webapp.services import connector_crypto

router = APIRouter(prefix="/api/connectors", tags=["connectors"])


# --- human-facing: enrollment token issuance --------------------------------
@router.post("/enrollment-tokens", response_model=EnrollmentTokenOut)
def create_enrollment_token(user: dict = Depends(require_admin)):
    raw_token = security.generate_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=config.CONNECTOR_ENROLLMENT_TOKEN_EXPIRE_MINUTES)
    db.create_enrollment_token(user["organization_id"], user["id"],
                               security.hash_opaque_token(raw_token), expires_at)
    db.add_audit_log(user["id"], "connector_enrollment_token_created")
    return EnrollmentTokenOut(enrollment_token=raw_token, expires_at=expires_at.isoformat())


# --- connector-facing: enrollment (no prior session — the token IS the credential) --
@router.post("/enroll", response_model=ConnectorEnrollOut)
def enroll(body: ConnectorEnrollRequest):
    row = db.get_enrollment_token(security.hash_opaque_token(body.enrollment_token))
    if not row:
        raise HTTPException(status_code=401, detail="Invalid enrollment token")
    if row["used_at"]:
        raise HTTPException(status_code=401, detail="Enrollment token has already been used")
    expires_at = row["expires_at"]
    expires_dt = datetime.fromisoformat(expires_at) if isinstance(expires_at, str) else expires_at
    if expires_dt.tzinfo is None:
        expires_dt = expires_dt.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) >= expires_dt:
        raise HTTPException(status_code=401, detail="Enrollment token has expired")

    # Validate the submitted public key is well-formed before trusting it.
    try:
        connector_crypto.load_public_key(body.public_key_pem)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid public key: {e}") from e

    raw_secret = security.generate_refresh_token()
    connector_id = db.create_connector(
        row["organization_id"], body.name, body.public_key_pem,
        security.hash_opaque_token(raw_secret), body.version, body.os,
    )
    db.mark_enrollment_token_used(row["id"])
    db.add_audit_log(row["created_by_user_id"], "connector_enrolled",
                     details={"connector_id": connector_id, "name": body.name})
    _, platform_public_pem = connector_crypto.get_platform_signing_keys()
    return ConnectorEnrollOut(connector_id=connector_id, connector_secret=raw_secret,
                              platform_public_key_pem=platform_public_pem)


# --- connector-facing auth: resolves the calling connector from its secret --
def require_connector(x_connector_secret: Optional[str] = Header(None)) -> dict:
    if not x_connector_secret:
        raise HTTPException(status_code=401, detail="Missing X-Connector-Secret")
    connector = db.get_connector_by_secret_hash(security.hash_opaque_token(x_connector_secret))
    if not connector:
        raise HTTPException(status_code=401, detail="Invalid connector secret")
    if connector.get("revoked_at"):
        raise HTTPException(status_code=403, detail="This connector has been revoked")
    return connector


def _connector_out(row: dict) -> ConnectorOut:
    def _iso(v):
        return v if v is None or isinstance(v, str) else v.isoformat()
    return ConnectorOut(
        id=row["id"], organization_id=row["organization_id"], name=row["name"],
        version=row.get("version"), os=row.get("os"), state=db.connector_state(row),
        paused=row["paused"], current_job_id=row.get("current_job_id"),
        last_heartbeat_at=_iso(row.get("last_heartbeat_at")), created_at=_iso(row["created_at"]),
    )


@router.post("/me/heartbeat", response_model=ConnectorOut)
def heartbeat(body: ConnectorHeartbeatRequest, connector: dict = Depends(require_connector)):
    db.record_connector_heartbeat(connector["id"], body.version, body.os)
    return _connector_out(db.get_connector(connector["id"], connector["organization_id"]))


@router.get("/me/jobs/next", response_model=Optional[SignedJobOut])
def get_next_job(connector: dict = Depends(require_connector)):
    job = db.get_next_pending_job(connector["id"])
    if not job:
        return None
    # Reuse the exact same canonical-payload builder used to sign the job at
    # creation time, so what's returned here always matches what the
    # connector needs to reconstruct and verify — no risk of the two
    # payload-construction call sites drifting apart.
    signed_payload = connector_crypto.job_signing_payload(job)
    return SignedJobOut(job_id=job["id"], organization_id=job["organization_id"],
                        connector_id=job["connector_id"], job_type=job["job_type"],
                        scope=job["scope"], authorization=signed_payload["authorization"],
                        created_at=signed_payload["created_at"], expires_at=signed_payload["expires_at"],
                        signature=job["signature"])


@router.post("/jobs/{job_id}/result")
def submit_job_result(job_id: int, body: ConnectorJobResultSubmit,
                      connector: dict = Depends(require_connector)):
    """Verifies the result signature against THIS connector's own registered
    public key before ever trusting it — a result that doesn't verify is
    recorded as rejected and audited, never silently accepted.

    There's no human user_id for this connector-initiated request — audit_log
    .user_id is nullable precisely for this case (Phase 12), with
    organization_id passed explicitly since there's no user row to derive it
    from."""
    ok = connector_crypto.verify(connector["public_key_pem"], body.result, body.signature)
    if not ok:
        db.reject_connector_job_result(job_id, connector["id"], "Result signature verification failed")
        db.add_audit_log(None, "connector_job_result_rejected", organization_id=connector["organization_id"],
                         details={"connector_id": connector["id"], "job_id": job_id,
                                  "reason": "signature verification failed"})
        raise HTTPException(status_code=400, detail="Result signature verification failed")

    if not db.submit_connector_job_result(job_id, connector["id"], body.result, body.signature):
        raise HTTPException(status_code=404, detail="Job not found or not in a state accepting a result")
    db.add_audit_log(None, "connector_job_result_submitted", organization_id=connector["organization_id"],
                     details={"connector_id": connector["id"], "job_id": job_id})
    return {"ok": True}


# --- human-facing: connector management -------------------------------------
@router.get("", response_model=list)
def list_connectors(user: dict = Depends(require_viewer)):
    return [_connector_out(c).model_dump() for c in db.list_connectors(user["organization_id"])]


@router.get("/{connector_id}", response_model=ConnectorOut)
def get_connector(connector_id: int, user: dict = Depends(require_viewer)):
    row = db.get_connector(connector_id, user["organization_id"])
    if not row:
        raise HTTPException(status_code=404, detail="Connector not found")
    return _connector_out(row)


@router.get("/{connector_id}/jobs", response_model=list)
def list_jobs(connector_id: int, user: dict = Depends(require_viewer)):
    if not db.get_connector(connector_id, user["organization_id"]):
        raise HTTPException(status_code=404, detail="Connector not found")
    rows = db.list_connector_jobs(connector_id, user["organization_id"])
    return [ConnectorJobOut(
        id=r["id"], connector_id=r["connector_id"], job_type=r["job_type"], scope=r["scope"],
        status=r["status"], result=r.get("result"), rejection_reason=r.get("rejection_reason"),
        created_at=r["created_at"] if isinstance(r["created_at"], str) else r["created_at"].isoformat(),
        expires_at=r["expires_at"] if isinstance(r["expires_at"], str) else r["expires_at"].isoformat(),
        sent_at=(r["sent_at"] if r.get("sent_at") is None or isinstance(r["sent_at"], str) else r["sent_at"].isoformat()),
        completed_at=(r["completed_at"] if r.get("completed_at") is None or isinstance(r["completed_at"], str)
                     else r["completed_at"].isoformat()),
    ).model_dump() for r in rows]


@router.post("/{connector_id}/jobs", response_model=ConnectorJobOut)
def create_job(connector_id: int, body: ConnectorJobCreate, user: dict = Depends(require_operator)):
    connector = db.get_connector(connector_id, user["organization_id"])
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    if connector.get("revoked_at"):
        raise HTTPException(status_code=422, detail="Cannot assign a job to a revoked connector")
    if connector["paused"]:
        raise HTTPException(status_code=422, detail="Cannot assign a job to a paused connector")

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=config.CONNECTOR_JOB_EXPIRE_MINUTES)
    job = db.create_connector_job(user["organization_id"], connector_id, body.job_type,
                                  body.scope, user["id"], expires_at)
    platform_private_pem, _ = connector_crypto.get_platform_signing_keys()
    signature = connector_crypto.sign(platform_private_pem, connector_crypto.job_signing_payload(job))
    db.set_connector_job_signature(job["id"], signature)

    db.add_audit_log(user["id"], "connector_job_created",
                     details={"connector_id": connector_id, "job_id": job["id"], "job_type": body.job_type})
    job["signature"] = signature
    return ConnectorJobOut(
        id=job["id"], connector_id=job["connector_id"], job_type=job["job_type"], scope=job["scope"],
        status="pending",
        created_at=job["created_at"] if isinstance(job["created_at"], str) else job["created_at"].isoformat(),
        expires_at=job["expires_at"] if isinstance(job["expires_at"], str) else job["expires_at"].isoformat(),
    )


@router.post("/{connector_id}/revoke", response_model=ConnectorOut)
def revoke_connector(connector_id: int, user: dict = Depends(require_admin)):
    if not db.revoke_connector(connector_id, user["organization_id"]):
        raise HTTPException(status_code=404, detail="Connector not found")
    db.add_audit_log(user["id"], "connector_revoked", details={"connector_id": connector_id})
    return _connector_out(db.get_connector(connector_id, user["organization_id"]))


@router.post("/{connector_id}/pause", response_model=ConnectorOut)
def pause_connector(connector_id: int, paused: bool = True, user: dict = Depends(require_operator)):
    if not db.set_connector_paused(connector_id, user["organization_id"], paused):
        raise HTTPException(status_code=404, detail="Connector not found")
    db.add_audit_log(user["id"], "connector_paused" if paused else "connector_resumed",
                     details={"connector_id": connector_id})
    return _connector_out(db.get_connector(connector_id, user["organization_id"]))
