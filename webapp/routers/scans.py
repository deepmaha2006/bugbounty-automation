"""Scan routes: start web scans, list scans, get scan detail, catalog."""
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, status

from webapp import db
from webapp.routers.auth import require_operator, require_viewer
from webapp.schemas import (WebScanRequest, SystemScanRequest,
                            ScanOut, ScanListItem, ScannerCatalogOut)
from webapp.services import remediation_service
from webapp.services import web_scan_service
from webapp.services import scan_manager
from webapp.services.api_rate_limiter import FixedWindowLimiter
from webapp.services.system_scan_service import start_system_scan, _parse_target

router = APIRouter(prefix="/api", tags=["scans"])

# Scan creation is bounded in *concurrency* by scan_manager (MAX_CONCURRENT_
# SCANS, default 3 — excess requests queue rather than run) but not in
# *request rate*: nothing previously stopped a compromised account/API key
# from enqueuing an unbounded number of scans. 30 starts / 10 minutes per
# user is generous for real usage while bounding abuse (spec §21).
scan_start_limiter = FixedWindowLimiter(max_requests=30, window_seconds=600)


def _rate_limited() -> HTTPException:
    return HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                         detail="Too many scans started recently. Please wait and try again.")


def _scan_to_out(s: dict, with_findings: bool = True) -> ScanOut:
    """Convert a scan dict from DB to ScanOut, safely handling NULL values."""
    findings, summary = [], None
    if with_findings:
        findings = [_finding_out(f) for f in s.get("findings", [])][:200]
        # Web assets are internet-facing by construction (db.ASSET_TYPE_EXPOSURE).
        context = {"exposure": "internet_facing" if (s.get("scan_type") or "web") == "web"
                   else "unknown"}
        analysis = remediation_service.analyze_scan(findings, context)
        for f, report in zip(findings, analysis["reports"]):
            f["analyst"] = report
        summary = {"top_priorities": analysis["top_priorities"],
                   "issues": analysis["issues"]}
    # Use 'or' to convert None/NULL to defaults for fields that can be NULL in DB
    return ScanOut(
        id=s["id"],
        target=s.get("target") or "",
        scan_type=s.get("scan_type") or "web",
        status=s.get("status") or "queued",
        progress=s.get("progress") or 0.0,
        phase=s.get("phase") or "",
        message=s.get("message") or "",
        findings=findings,
        stats=s.get("stats") or {},
        created_at=s.get("created_at") or "",
        started_at=s.get("started_at"),
        finished_at=s.get("finished_at"),
        user_id=s.get("user_id"),
        analyst_summary=summary,
    )


def _finding_out(f: dict) -> dict:
    return {
        "severity": f["severity"], "type": f["type"], "description": f["description"],
        "evidence": f.get("evidence", ""), "url": f.get("url", ""),
        "remediation": f.get("remediation", ""), "tool": f.get("tool", ""),
        "parameter": f.get("parameter"), "payload": f.get("payload"),
        "tool_command": f.get("tool_command", ""),
        "raw_output": f.get("raw_output", ""),
        "confidence": f.get("confidence", "confirmed"),
        "verified": bool(f.get("verified", True))
    }


def _scan_list_item(s: dict) -> ScanListItem:
    import json as _json
    sev = db.severity_counts(s["id"])
    stats = s.get("stats") or {}
    if isinstance(stats, str):
        try:
            stats = _json.loads(stats)
        except (ValueError, TypeError):
            stats = {}
    return ScanListItem(
        id=s["id"], target=s["target"], scan_type=s["scan_type"], status=s["status"],
        severity_counts=sev, security_score=stats.get("security_score", 0),
        created_at=s["created_at"],
    )


@router.get("/settings/scanners", response_model=ScannerCatalogOut)
def scanner_catalog(user: dict = Depends(require_viewer)):
    import sys
    from pathlib import Path as _P
    root = _P(__file__).resolve().parent.parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from config.settings import SCANNER_CATEGORIES, ALL_SCANNER_KEYS, DEFAULT_SCANNER_KEYS
    from config.profiles import DEFAULT_PROFILES_DIR
    profiles = sorted(p.stem for p in DEFAULT_PROFILES_DIR.glob("*.yaml")) or ["web-full"]

    # Strip non-serializable scanner classes from the catalog.
    categories = []
    for cat in SCANNER_CATEGORIES:
        scanners = []
        for s in cat.get("scanners", []):
            scanners.append({k: v for k, v in s.items() if k != "cls"})
        categories.append({"name": cat["name"], "icon": cat.get("icon", ""),
                           "scanners": scanners})

    return ScannerCatalogOut(
        categories=categories, all_keys=ALL_SCANNER_KEYS,
        default_keys=DEFAULT_SCANNER_KEYS, profiles=profiles,
    )


@router.post("/scans/web", response_model=ScanOut)
def start_web_scan_api(body: WebScanRequest, user: dict = Depends(require_operator)):
    if not scan_start_limiter.allow(user["id"]):
        raise _rate_limited()
    if not body.target.strip():
        raise HTTPException(status_code=422, detail="Target URL is required")
    if not body.scope_authorized:
        raise HTTPException(status_code=403,
                            detail="Authorization required: you must confirm the target is in scope.")
    if not body.vuln_types:
        raise HTTPException(status_code=422, detail="Select at least one vulnerability type.")
    
    # Check if target is verified (scoped to the requester's organization —
    # another org's target of the same URL must not be visible or reusable).
    target = db.get_target_by_url(body.target, user["organization_id"])
    if not target:
        raise HTTPException(status_code=404, detail="Target not found. Please add target first.")
    if target["verification_status"] != "verified":
        raise HTTPException(
            status_code=403,
            detail=f"Target verification required. Current status: {target['verification_status']}. "
                   f"Please complete verification via DNS TXT challenge or engagement letter upload."
        )

    try:
        scan_id = web_scan_service.start_web_scan(
            user["id"], body.target, body.vuln_types)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    db.add_audit_log(user["id"], "scan_started", target_id=target["id"], scan_id=scan_id,
                     details={"scan_type": "web", "vuln_types": body.vuln_types})
    return _scan_to_out(db.get_scan(scan_id, user["organization_id"]), with_findings=False)


@router.post("/scans/system", response_model=ScanOut)
def start_system_scan_api(body: SystemScanRequest,
                          user: dict = Depends(require_operator)):
    if not scan_start_limiter.allow(user["id"]):
        raise _rate_limited()
    if not body.target.strip():
        raise HTTPException(status_code=422, detail="Target is required")
    if not body.scope_authorized:
        raise HTTPException(status_code=403,
                            detail="Authorization required: you must confirm the target is in scope.")
    if body.scan_mode not in ("fast", "full"):
        raise HTTPException(status_code=422, detail="scan_mode must be 'fast' or 'full'")

    # Parse and normalize the target (matches _parse_target in system_scan_service)
    try:
        parsed = _parse_target(body.target)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    # Normalize target URL for lookup
    normalized_target = parsed["raw"]

    # Look up the target in the database (scoped to the requester's org)
    target = db.get_target_by_url(normalized_target, user["organization_id"])
    if not target:
        raise HTTPException(status_code=404, detail="Target not found. Please add the target first and complete verification.")

    # Check verification status
    if target["verification_status"] != "verified":
        raise HTTPException(
            status_code=403,
            detail=f"Target verification required. Current status: {target['verification_status']}. "
                   f"Please complete verification via DNS TXT challenge or engagement letter upload."
        )

    # Check ownership - NULL owner (legacy) cannot be owned by anyone
    if target["added_by_user_id"] is None:
        raise HTTPException(
            status_code=403,
            detail="Target has no owner (legacy). Cannot start system scan."
        )

    # Verify the requesting user owns this target
    if target["added_by_user_id"] != user["id"]:
        # Do not leak information about other users' targets
        raise HTTPException(
            status_code=403,
            detail="Target not found. Please add the target first and complete verification."
        )

    try:
        scan_id = start_system_scan(user["id"], body.target, body.scan_mode,
                                    body.tools, body.threads)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    db.add_audit_log(user["id"], "scan_started", target_id=target["id"], scan_id=scan_id,
                     details={"scan_type": "system", "scan_mode": body.scan_mode})
    return _scan_to_out(db.get_scan(scan_id, user["organization_id"]), with_findings=False)


@router.get("/scans", response_model=list)
def list_scans_api(user: dict = Depends(require_viewer)):
    return [_scan_list_item(s).model_dump()
           for s in db.list_scans(user["organization_id"], user_id=user["id"])]


@router.get("/scans/all", response_model=list)
def list_all_scans_api(user: dict = Depends(require_viewer)):
    """Every scan in the caller's organization (not literally every scan on
    the platform — that would leak across tenants)."""
    return [_scan_list_item(s).model_dump() for s in db.list_scans(user["organization_id"])]


@router.get("/scans/{scan_id}", response_model=ScanOut)
def scan_detail(scan_id: int, user: dict = Depends(require_viewer)):
    s = db.get_scan(scan_id, user["organization_id"])
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_to_out(s)