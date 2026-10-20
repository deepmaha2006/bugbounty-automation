"""
HydraBrain detection — classify Events into named attack classes and upsert brain_incidents.

Phase 14: observe mode only. Detection creates/updates incidents; no response is taken.

Safety: every call verifies a current get_active_authorization() row first.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional

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


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def detect(asset_id: int, org_id: int, events: List[Event]) -> List[Detection]:
    """Classify events, upsert brain_incidents, append to INCIDENT_LOG.

    Requires an active authorization row for asset_id/org_id — raises
    AuthorizationError if none exists.

    Phase 14: observe mode only — no brain_actions created, no containment
    or remediation triggered.
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

        fp = event_fingerprint(asset_id, org_id, attack_class, event.src_ip)
        summary = (
            f"{attack_class} from {event.src_ip or 'unknown'} "
            f"on {event.path or '/'}"
        )

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
        ))

    return detections
