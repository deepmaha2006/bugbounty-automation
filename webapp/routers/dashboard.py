"""Dashboard route: aggregate stats for the dashboard page (HydraX)."""
import json

from fastapi import APIRouter, Depends

from webapp import db
from webapp.routers.auth import require_admin, require_viewer
from webapp.schemas import DashboardStats, ScanListItem
from webapp.services import scan_manager

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _scan_item(s: dict) -> ScanListItem:
    """Convert a raw scan row into a ScanListItem with live severity counts."""
    stats = s.get("stats") or {}
    if isinstance(stats, str):
        try:
            stats = json.loads(stats)
        except (ValueError, TypeError):
            stats = {}
    sev = db.severity_counts(s["id"])
    return ScanListItem(
        id=s["id"], target=s["target"], scan_type=s["scan_type"],
        status=s["status"], severity_counts=sev,
        security_score=int(stats.get("security_score", 0) or 0),
        created_at=s["created_at"],
    )


@router.get("/stats")
def stats(user: dict = Depends(require_viewer)):
    d = db.dashboard_stats(user["organization_id"])
    d["recent_scans"] = [_scan_item(s) for s in d.get("recent_scans", [])]
    return DashboardStats(**d)


@router.get("/system-health")
def system_health(user: dict = Depends(require_admin)):
    """Admin-only 'system health' view (spec §22) — scan reliability + alert
    delivery metrics for this org over the last 7 days, plus the live
    process-wide scan-queue snapshot. Distinct from /health: this is
    org-scoped operational insight for admins, not a liveness probe."""
    metrics = db.system_health_metrics(user["organization_id"])
    metrics["scan_queue"] = scan_manager.stats()
    return metrics
