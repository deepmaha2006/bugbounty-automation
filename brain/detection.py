"""
HydraBrain detection — classify Events into named attack classes and upsert brain_incidents.

Phase 14: observe mode only. Detection creates/updates incidents; no response is taken.

Safety: every call verifies a current get_active_authorization() row first.

Phase 18+: CVE matching and enhanced detection for autonomous brain.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

from brain.incident_log import INCIDENT_LOG
from brain.sensors import AuthorizationError, Event

# ---------------------------------------------------------------------------
# Attack classification
# ---------------------------------------------------------------------------

SIGNAL_TO_ATTACK_CLASS: Dict[str, str] = {
    "path_traversal": "path_traversal",
    "sqli_hint": "sql_injection",
    "xss_hint": "xss",
    "scanner_signature": "scanner_probe",
}

_SEVERITY_MAP: Dict[str, str] = {
    "sql_injection": "high",
    "path_traversal": "high",
    "xss": "medium",
    "ssrf": "medium",
    "csrf": "medium",
    "scanner_probe": "low",
}


def classify_event(event: Event) -> Optional[str]:
    """Return the highest-priority attack class for this event's signals, or None."""
    for signal_key, attack_class in SIGNAL_TO_ATTACK_CLASS.items():
        if event.signals.get(signal_key):
            return attack_class
    return None


def severity_for(attack_class: str) -> str:
    return _SEVERITY_MAP.get(attack_class, "low")


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

def event_fingerprint(
    asset_id: int, org_id: int, attack_class: str, src_ip: Optional[str]
) -> str:
    """Deterministic 32-char hex fingerprint for incident deduplication."""
    raw = f"{asset_id}:{org_id}:{attack_class}:{src_ip or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Detection result dataclass
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    asset_id: int
    org_id: int
    attack_class: str
    fingerprint: str
    event: Event
    incident_id: Optional[int] = None
    cve_matches: List[str] = None  # CVE IDs matched for this detection
    cve_confidence: float = 0.0    # Highest confidence among matched CVEs


# ---------------------------------------------------------------------------
# CVE Matching
# ---------------------------------------------------------------------------

_cve_cache: Dict[str, List[Dict[str, Any]]] = {}  # attack_class -> list of CVEs


def _load_cve_cache() -> None:
    """Load CVE database into memory for fast matching."""
    global _cve_cache
    if _cve_cache:
        return  # Already loaded

    try:
        import webapp.db as db
        conn = db.get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT cve_id, attack_class, cvss_score, fix_recommendation
                FROM brain_cve_db
                WHERE attack_class IS NOT NULL AND attack_class != 'unknown'
            """)
            rows = cur.fetchall()
            for row in rows:
                cve_id, attack_class, cvss_score, fix_rec = row
                if attack_class not in _cve_cache:
                    _cve_cache[attack_class] = []
                _cve_cache[attack_class].append({
                    "cve_id": cve_id,
                    "cvss_score": cvss_score or 0.0,
                    "fix_recommendation": fix_rec,
                })
        logger = __import__('logging').getLogger(__name__)
        logger.info(f"Loaded CVE cache: {sum(len(v) for v in _cve_cache.values())} CVEs across {len(_cve_cache)} attack classes")
    except Exception as e:
        logger = __import__('logging').getLogger(__name__)
        logger.warning(f"Failed to load CVE cache: {e}")


def match_cves(event: Event, attack_class: str) -> List[Dict[str, Any]]:
    """Match event against known CVEs for the attack class.

    Returns list of matched CVEs with confidence scores.
    """
    _load_cve_cache()

    if attack_class not in _cve_cache:
        return []

    matches = []
    path = (event.path or "").lower()
    query = (event.signals.get("query", "") or "").lower()
    body = (event.signals.get("body", "") or "").lower()
    ua = (event.signals.get("user_agent", "") or "").lower()

    # Simple pattern matching - in production use more sophisticated matching
    for cve in _cve_cache[attack_class]:
        confidence = 0.5  # Base confidence

        # Check for CVE-specific patterns in path/query/body
        # This is a simplified version - real implementation would use
        # CVE attack_vector patterns
        if attack_class == "sql_injection" and ("'" in query or "union" in query or "select" in query):
            confidence = 0.85
        elif attack_class == "xss" and ("<script" in query or "onerror" in query or "javascript:" in query):
            confidence = 0.85
        elif attack_class == "path_traversal" and ("../" in path or "..\\" in path):
            confidence = 0.9
        elif attack_class == "scanner_probe" and ("sqlmap" in ua or "nikto" in ua or "nmap" in ua):
            confidence = 0.95

        if confidence > 0.6:
            matches.append({
                "cve_id": cve["cve_id"],
                "confidence": confidence,
                "cvss_score": cve.get("cvss_score", 0.0),
                "fix_recommendation": cve.get("fix_recommendation", {}),
            })

    # Sort by confidence descending
    matches.sort(key=lambda x: x["confidence"], reverse=True)
    return matches


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def detect(asset_id: int, org_id: int, events: List[Event]) -> List[Detection]:
    """Classify events, upsert brain_incidents, append to INCIDENT_LOG.

    Requires an active authorization row for asset_id/org_id — raises
    AuthorizationError if none exists.

    Phase 14+: observe mode with CVE matching.
    """
    import webapp.db as db

    auth = db.get_active_authorization(asset_id, org_id)
    if auth is None:
        raise AuthorizationError(
            f"No active authorization for asset_id={asset_id} org_id={org_id}"
        )

    detections: List[Detection] = []
    for event in events:
        attack_class = classify_event(event)
        if attack_class is None:
            continue

        # Match against known CVEs
        cve_matches = match_cves(event, attack_class)
        cve_ids = [m["cve_id"] for m in cve_matches]
        max_cve_conf = max([m["confidence"] for m in cve_matches], default=0.0)

        fp = event_fingerprint(asset_id, org_id, attack_class, event.src_ip)
        summary = (
            f"{attack_class} from {event.src_ip or 'unknown'} "
            f"on {event.path or '/'}"
        )
        if cve_ids:
            summary += f" (CVEs: {', '.join(cve_ids[:3])})"

        incident_id = db.brain_upsert_incident(
            asset_id=asset_id,
            org_id=org_id,
            fingerprint=fp,
            severity=severity_for(attack_class),
            summary=summary,
        )

        INCIDENT_LOG.append(
            entry_type="detection",
            asset_id=asset_id,
            org_id=org_id,
            payload={
                "attack_class": attack_class,
                "fingerprint": fp,
                "src_ip": event.src_ip,
                "path": event.path,
                "signals": event.signals,
                "cve_matches": cve_matches[:5],  # Store top 5 matches
            },
            actor="brain.detection",
        )

        detections.append(Detection(
            asset_id=asset_id,
            org_id=org_id,
            attack_class=attack_class,
            fingerprint=fp,
            event=event,
            incident_id=incident_id,
            cve_matches=cve_ids,
            cve_confidence=max_cve_conf,
        ))

    return detections
