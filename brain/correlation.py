"""
HydraBrain correlation — group related detections into attack campaigns.

Phase 14: observe mode only. Campaigns are in-memory summaries suitable for
streaming to the Live Defense view; they are not persisted separately (the
underlying brain_incidents table already deduplicates by fingerprint).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from brain.detection import Detection

DEFAULT_WINDOW_SECONDS = 600  # 10-minute campaign window


@dataclass
class Campaign:
    asset_id: int
    org_id: int
    src_ip: Optional[str]
    attack_class: str
    count: int
    first_seen: datetime
    last_seen: datetime
    fingerprints: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)


def correlate(
    detections: List[Detection],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> List[Campaign]:
    """Group detections into campaigns by (asset_id, org_id, src_ip, attack_class).

    Events within window_seconds of each other from the same source and
    attack class are merged into one campaign. Returns campaigns sorted
    most-recent-first.
    """
    CampaignKey = Tuple[int, int, Optional[str], str]
    groups: Dict[CampaignKey, Campaign] = {}
    closed: List[Campaign] = []

    for det in sorted(detections, key=lambda d: d.event.ts):
        key: CampaignKey = (
            det.asset_id, det.org_id, det.event.src_ip, det.attack_class
        )
        if key in groups:
            camp = groups[key]
            gap = (det.event.ts - camp.last_seen).total_seconds()
            if gap <= window_seconds:
                camp.count += 1
                camp.last_seen = det.event.ts
                if det.fingerprint not in camp.fingerprints:
                    camp.fingerprints.append(det.fingerprint)
                if det.event.path and det.event.path not in camp.paths:
                    camp.paths.append(det.event.path)
                continue
            # Gap too large: close the old campaign and open a fresh one
            closed.append(groups.pop(key))

        groups[key] = Campaign(
            asset_id=det.asset_id,
            org_id=det.org_id,
            src_ip=det.event.src_ip,
            attack_class=det.attack_class,
            count=1,
            first_seen=det.event.ts,
            last_seen=det.event.ts,
            fingerprints=[det.fingerprint],
            paths=[det.event.path] if det.event.path else [],
        )

    all_campaigns = closed + list(groups.values())
    return sorted(all_campaigns, key=lambda c: c.last_seen, reverse=True)
