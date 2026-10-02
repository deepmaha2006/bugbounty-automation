"""Verification endpoints: DNS TXT challenge and engagement letter upload."""

import logging
import os
import secrets
import string
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse

from webapp import config, db, security
from webapp.routers.auth import require_operator, require_viewer
from webapp.schemas import MessageOut

logger = logging.getLogger("hydrax.verification")

router = APIRouter(prefix="/api/verification", tags=["verification"])

# Magic-byte signatures for each allowed engagement-letter file type — the
# extension check alone only constrains the filename, not the actual bytes.
_MAGIC_BYTES = {
    ".pdf": (b"%PDF",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
}


def _validate_letter_content(file_ext: str, contents: bytes) -> None:
    """Reject content whose magic bytes don't match its claimed extension."""
    signatures = _MAGIC_BYTES.get(file_ext, ())
    if signatures and not any(contents.startswith(sig) for sig in signatures):
        raise ValueError(f"File content does not match the expected {file_ext} format")

# Directory for uploaded engagement letters — derived from config.UPLOAD_DIR
# (the single source of truth for storage paths) rather than recomputed here.
LETTERS_DIR = config.UPLOAD_DIR / "engagement_letters"
LETTERS_DIR.mkdir(parents=True, exist_ok=True)


def _generate_dns_token() -> str:
    """Generate a random DNS TXT token."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(32))


def _extract_domain(target_url: str) -> str:
    """Extract the host (domain or IP) from a target URL, dropping scheme/port.

    Shared by the DNS TXT generate and verify endpoints so both operate on
    exactly the same name.
    """
    from urllib.parse import urlparse
    parsed = urlparse(target_url or "")
    domain = parsed.netloc or parsed.path
    if ':' in domain:
        domain = domain.split(':')[0]
    return domain.strip().rstrip('/')


def _resolve_txt_records(domain: str) -> list:
    """Return the TXT record values for a domain via dnspython.

    Any DNS failure (NXDOMAIN, no answer of type TXT, timeout, missing
    resolver, unreachable server) results in an empty list — a failed lookup
    can never verify a target.
    """
    try:
        import dns.resolver  # declared in requirements.txt
        answers = dns.resolver.resolve(domain, "TXT")
    except Exception:  # noqa: BLE001 — any DNSException path returns []
        return []
    values = []
    for rdata in answers:
        for txt_string in rdata.strings:
            try:
                values.append(txt_string.decode("utf-8"))
            except (UnicodeDecodeError, AttributeError):
                values.append(str(txt_string))
    return values


@router.post("/dns-txt/generate", response_model=dict)
def generate_dns_txt_challenge(
    target_url: str = Form(...),
    user: dict = Depends(require_operator)
):
    """Generate a DNS TXT challenge token for domain verification."""
    domain = _extract_domain(target_url)
    if not domain:
        raise HTTPException(status_code=422, detail="Invalid URL")

    # Check if target exists in the requester's organization
    target = db.get_target_by_url(target_url, user["organization_id"])
    if not target:
        # Create target if it doesn't exist
        target_id = db.add_target(target_url, user["organization_id"],
                                  verification_method="dns_txt",
                                  added_by_user_id=user["id"])
    else:
        target_id = target["id"]

    # Generate token
    token = _generate_dns_token()

    # Store token in target record (target_id was just resolved within this
    # org, so no additional org filter is needed on the UPDATE itself)
    conn = db._get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE targets
                       SET dns_txt_token = %s,
                           verification_method = 'dns_txt',
                           verification_status = 'pending',
                           updated_at = NOW()
                       WHERE id = %s AND organization_id = %s""",
                    (token, target_id, user["organization_id"])
                )
    finally:
        db._put_conn(conn)

    # Also log to audit
    db.add_audit_log(
        user_id=user["id"],
        action="dns_txt_challenge_generated",
        target_id=target_id,
        details={"domain": domain, "token": token}
    )

    return {
        "target_id": target_id,
        "domain": domain,
        "dns_txt_token": token,
        "instruction": f"Add a TXT record to {domain} with value: hydrax-verification={token}"
    }


@router.post("/dns-txt/verify", response_model=MessageOut)
def verify_dns_txt_challenge(
    target_url: str = Form(...),
    user: dict = Depends(require_operator)
):
    """Verify DNS TXT challenge by performing a real TXT lookup for the target
    domain and confirming the per-target challenge token is present."""
    target = db.get_target_by_url(target_url, user["organization_id"])
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if target["verification_method"] != "dns_txt":
        raise HTTPException(status_code=400, detail="Target is not set up for DNS TXT verification")

    if target["verification_status"] == "verified":
        return MessageOut(message="Target already verified")

    token = target.get("dns_txt_token")
    if not token:
        raise HTTPException(status_code=400, detail="No DNS TXT challenge generated for this target")

    domain = _extract_domain(target["url"])
    expected = f"hydrax-verification={token}"

    if config.VERIFY_MODE == "simulated":
        # Development/lab-only branch: treat the stored challenge token as
        # present so local E2E (127.0.0.1 / lab domains) can complete the flow
        # without real DNS. Only active when HYDRAX_VERIFY_MODE=simulated is
        # explicitly set — it is never the default.
        txt_values = [expected]
    else:
        txt_values = _resolve_txt_records(domain)

    verified = any(v.strip() == expected for v in txt_values)

    if verified:
        db.update_target_verification(target["id"], "verified")
        db.record_asset_authorization(
            user["organization_id"], target["id"], user["id"], "dns_txt", "authorized",
            evidence={"domain": domain, "expected": expected})
        db.add_audit_log(
            user_id=user["id"],
            action="dns_txt_challenge_verified",
            target_id=target["id"],
            details={"domain": target["url"]}
        )
        return MessageOut(message="Target verified successfully via DNS TXT challenge")
    else:
        db.update_target_verification(target["id"], "failed")
        db.record_asset_authorization(
            user["organization_id"], target["id"], user["id"], "dns_txt", "failed",
            evidence={"domain": domain, "expected": expected, "found": txt_values})
        db.add_audit_log(
            user_id=user["id"],
            action="dns_txt_challenge_failed",
            target_id=target["id"],
            details={"domain": target["url"]}
        )
        raise HTTPException(status_code=400, detail="DNS TXT verification failed. Please check your TXT record.")


MAX_ENGAGEMENT_LETTER_SIZE = 10 * 1024 * 1024  # 10 MB — generous for a PDF/image, not unbounded


@router.post("/engagement-letter/upload", response_model=MessageOut)
def upload_engagement_letter(
    target_url: str = Form(...),
    file: UploadFile = File(...),
    user: dict = Depends(require_operator)
):
    """Upload and verify engagement letter for target authorization."""
    # Validate file type
    allowed_extensions = {'.pdf', '.jpg', '.jpeg', '.png'}
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
        )

    # Get or create target (scoped to the requester's organization)
    target = db.get_target_by_url(target_url, user["organization_id"])
    if not target:
        target_id = db.add_target(target_url, user["organization_id"],
                                  verification_method="engagement_letter",
                                  added_by_user_id=user["id"])
    else:
        target_id = target["id"]
        # Update verification method if not already set
        if target["verification_method"] != "engagement_letter":
            conn = db._get_conn()
            try:
                with conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """UPDATE targets
                               SET verification_method = 'engagement_letter',
                                   verification_status = 'pending',
                                   updated_at = NOW()
                               WHERE id = %s AND organization_id = %s""",
                            (target_id, user["organization_id"])
                        )
            finally:
                db._put_conn(conn)

    # Save file
    safe_filename = f"target_{target_id}_{secrets.token_hex(8)}{file_ext}"
    file_path = LETTERS_DIR / safe_filename

    try:
        # WSTG-BUSL-09 / CWE-400: read one byte past the cap so an oversized
        # upload is detected without ever buffering the whole thing.
        contents = file.file.read(MAX_ENGAGEMENT_LETTER_SIZE + 1)
    finally:
        file.file.close()

    if len(contents) > MAX_ENGAGEMENT_LETTER_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {MAX_ENGAGEMENT_LETTER_SIZE // (1024 * 1024)}MB"
        )

    try:
        _validate_letter_content(file_ext, contents)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    try:
        with open(file_path, "wb") as f:
            f.write(contents)
    except OSError as e:
        # WSTG-ERRH-01 / ASVS V7.4.1: str(e) on an OSError includes the full
        # filesystem path — logged for an operator to actually act on, never
        # returned to the client.
        logger.error("Failed to save engagement letter", extra={"error": str(e)})
        raise HTTPException(status_code=500, detail="Failed to save file") from e

    # Mark target as verified
    db.verify_target_with_letter(target_id, str(file_path))
    db.record_asset_authorization(
        user["organization_id"], target_id, user["id"], "engagement_letter", "authorized",
        evidence={"filename": file.filename, "size": len(contents)})

    # Log to audit
    db.add_audit_log(
        user_id=user["id"],
        action="engagement_letter_uploaded",
        target_id=target_id,
        details={
            "filename": file.filename,
            "size": len(contents),
            "path": str(file_path)
        }
    )

    return MessageOut(message="Engagement letter uploaded and target verified successfully")


@router.get("/target/{target_id}/status", response_model=dict)
def get_target_verification_status(
    target_id: int,
    user: dict = Depends(require_viewer)
):
    """Get verification status of a target."""
    target = db.get_target(target_id, user["organization_id"])
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    return {
        "target_id": target["id"],
        "url": target["url"],
        "verification_method": target["verification_method"],
        "verification_status": target["verification_status"],
        "verified_at": target.get("verified_at")
    }


@router.post("/target/{target_id}/reset", response_model=MessageOut)
def reset_target_verification(
    target_id: int,
    user: dict = Depends(require_operator)
):
    """Reset target verification status to pending."""
    target = db.get_target(target_id, user["organization_id"])
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    conn = db._get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE targets
                       SET verification_status = 'pending',
                           dns_txt_token = NULL,
                           engagement_letter_path = NULL,
                           verified_at = NULL,
                           updated_at = NOW()
                       WHERE id = %s AND organization_id = %s""",
                    (target_id, user["organization_id"])
                )
    finally:
        db._put_conn(conn)

    db.add_audit_log(
        user_id=user["id"],
        action="target_verification_reset",
        target_id=target_id,
        details={"url": target["url"]}
    )

    return MessageOut(message="Target verification reset to pending")


@router.get("/target/verify", response_model=dict)
def verify_target_by_url(
    url: str,
    user: dict = Depends(require_viewer)
):
    """Check if a target is verified by URL."""
    target = db.get_target_by_url(url, user["organization_id"])
    if not target:
        return {"verified": False, "message": "Target not found"}

    return {
        "verified": target["verification_status"] == "verified",
        "verification_status": target["verification_status"],
        "verification_method": target["verification_method"],
        "message": f"Target verification status: {target['verification_status']}"
    }