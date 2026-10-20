"""
HydraBrain telemetry bridge — Phase 20.

Converts scanner findings into brain events and seeds brain_knowledge.
Called by web_scan_service after a scan completes so the brain pipeline
automatically learns from every authorized scan without any manual wiring.

Safety: always verifies get_active_authorization before writing events.
AuthorizationError propagates to callers; web_scan_service swallows it so
a missing authorization row never breaks an in-progress scan.
"""
from __future__ import annotations

from typing import Any, Dict, List

from brain.learning import FINDING_TYPE_TO_ATTACK_CLASS, cross_feed_from_scan
from brain.sensors import AuthorizationError

# Maps attack_class → the signal key that brain.detection.classify_event uses.
_ATTACK_CLASS_TO_SIGNAL: Dict[str, str] = {
    "xss":            "xss_hint",
    "sql_injection":  "sqli_hint",
    "path_traversal": "path_traversal",
    "ssrf":           "ssrf_hint",
    "csrf":           "csrf_hint",
    "rce":            "rce_hint",
    "open_redirect":  "redirect_hint",
    "scanner_probe":  "scanner_signature",
}


def finding_to_signals(finding_type: str, category: str = "") -> Dict[str, Any]:
    """Map a scanner finding type/category to a brain signals dict.

    Tries the finding's own type first; falls back to category.
    Returns {} when neither maps to a known attack class.
    """
    raw_type = (finding_type or "").lower().strip()
    attack_class = FINDING_TYPE_TO_ATTACK_CLASS.get(raw_type)
    if not attack_class:
        raw_cat = (category or "").lower().strip()
        attack_class = FINDING_TYPE_TO_ATTACK_CLASS.get(raw_cat)
    if not attack_class:
        return {}
    signal_key = _ATTACK_CLASS_TO_SIGNAL.get(attack_class)
    if not signal_key:
        return {}
    return {signal_key: True}


def ingest_scan_findings(
    asset_id: int,
    org_id: int,
    findings: List[Dict],
) -> Dict[str, int]:
    """Feed scanner findings into the brain pipeline.

    Steps:
    1. Verifies an active authorization exists — raises AuthorizationError
       if none (caller is responsible for handling or swallowing this).
    2. Seeds brain_knowledge via cross_feed_from_scan (EWMA confidence).
    3. Inserts a brain_event per finding that maps to a known signal so
       the hunt loop can detect / correlate / decide on them.

    Returns {"knowledge_updates": N, "events_inserted": M}.
    Per-event insert errors are swallowed; one bad row never aborts the rest.
    """
    import webapp.db as db

    auth = db.get_active_authorization(asset_id, org_id)
    if auth is None:
        raise AuthorizationError(
            f"No active authorization for asset_id={asset_id} org_id={org_id}; "
            "skipping brain telemetry ingestion."
        )

    knowledge_count = cross_feed_from_scan(asset_id, org_id, findings)

    events_inserted = 0
    for f in findings:
        signals = finding_to_signals(
            f.get("type") or "",
            f.get("category") or "",
        )
        if not signals:
            continue
        try:
            db.brain_insert_event(
                asset_id=asset_id,
                org_id=org_id,
                src_ip=None,
                method="SCAN",
                path=f.get("url") or f.get("path") or f.get("affected_endpoint"),
                status=None,
                signals=signals,
            )
            events_inserted += 1
        except Exception:
            pass

    return {"knowledge_updates": knowledge_count, "events_inserted": events_inserted}
