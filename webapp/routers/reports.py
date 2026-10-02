"""Report routes: list reports, stream/download report files, and generate
org-wide executive/technical reports on demand (CVM platform spec §23)."""
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, Response

from webapp import config as wcfg
from webapp import db
from webapp.routers.auth import require_viewer
from webapp.services import report_generator
from webapp.services.api_rate_limiter import FixedWindowLimiter

router = APIRouter(prefix="/api/reports", tags=["reports"])

_FORMAT_MEDIA = {
    "json": "application/json",
    "csv": "text/csv",
    "pdf": "application/pdf",
}

# PDF rendering is the most CPU-intensive path a viewer-role request can
# trigger with no other bound on it (spec §21's "API abuse" review) — 10
# generations / minute per user across both report types.
report_generation_limiter = FixedWindowLimiter(max_requests=10, window_seconds=60)


def _rate_limited() -> HTTPException:
    return HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                         detail="Too many reports generated recently. Please wait and try again.")


@router.get("")
def list_reports(user: dict = Depends(require_viewer)):
    out = []
    for r in db.list_reports(user["organization_id"]):
        path = Path(r["path"])
        out.append({
            "id": r["id"], "scan_id": r["scan_id"], "target": r["target"],
            "scan_type": r["scan_type"], "format": r["format"],
            "name": path.name, "created_at": r["created_at"],
            "size": path.stat().st_size if path.exists() else 0,
        })
    return out


@router.get("/{report_id}/download")
def download_report(report_id: int, user: dict = Depends(require_viewer)):
    r = db.get_report(report_id, user["organization_id"])
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    path = Path(r["path"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file missing")
    return FileResponse(path, filename=path.name, media_type=_media(r["format"]))


def _media(fmt: str) -> str:
    return "application/json" if fmt == "json" else "text/html"


def _attachment(content: bytes, media_type: str, filename: str) -> Response:
    return Response(
        content=content, media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/executive")
def executive_report(fmt: str = Query("json", alias="format", pattern="^(json|csv|pdf)$"),
                     user: dict = Depends(require_viewer)):
    if not report_generation_limiter.allow(user["id"]):
        raise _rate_limited()
    data = report_generator.build_executive_summary(user["organization_id"])
    db.add_audit_log(user["id"], "report_generated",
                     details={"report_type": "executive", "format": fmt})
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if fmt == "json":
        body = report_generator.render_json(data)
    elif fmt == "csv":
        body = report_generator.render_csv_executive(data)
    else:
        body = report_generator.render_pdf_executive(data)
    return _attachment(body, _FORMAT_MEDIA[fmt], f"executive_report_{ts}.{fmt}")


@router.get("/technical")
def technical_report(fmt: str = Query("json", alias="format", pattern="^(json|csv|pdf)$"),
                     user: dict = Depends(require_viewer)):
    if not report_generation_limiter.allow(user["id"]):
        raise _rate_limited()
    rows = report_generator.build_technical_findings(user["organization_id"])
    db.add_audit_log(user["id"], "report_generated",
                     details={"report_type": "technical", "format": fmt})
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if fmt == "json":
        body = report_generator.render_json(rows)
    elif fmt == "csv":
        body = report_generator.render_csv_technical(rows)
    else:
        body = report_generator.render_pdf_technical(rows)
    return _attachment(body, _FORMAT_MEDIA[fmt], f"technical_report_{ts}.{fmt}")