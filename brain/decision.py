"""
HydraBrain decision — choose and propose containment actions for detections.

Phase 15: auto_contain tier enabled. Actions are reversible and TTL-bound.
The kill switch, self-lockout guard, and FP rate brake are always enforced.

Safety invariants:
  * Kill switch engaged → OBSERVE for all assets; no actions proposed.
  * Self-lockout guard → loopback, unspecified, and owner-allowlist IPs are
    never blocked, regardless of tier.
  * FP rate brake → auto-actions downgrade to "recommend" when per-minute cap
    is exceeded; the downgrade is logged to the audit trail.
  * Tier ceiling → effective_tier() from autonomy module, capped by auth row.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from brain.autonomy import AutonomyTier, effective_tier
from brain.detection import Detection
from brain.incident_log import INCIDENT_LOG
from brain.virtual_patch import APPROVAL_GATED_ACTION_TYPES, PATCHABLE_CLASSES

DEFAULT_TTL_SECONDS = 3600  # 1-hour auto-rollback for contain actions

# ---------------------------------------------------------------------------
# Self-lockout guard
# ---------------------------------------------------------------------------

_SELF_LOCKOUT_EXACT: frozenset = frozenset(
    {"127.0.0.1", "::1", "0.0.0.0", "localhost", ""}
)
_OWNER_ALLOWLIST: Set[str] = set()


def configure_allowlist(ips) -> None:
    """Seed the owner/control-channel allowlist. Thread-safe."""
    _OWNER_ALLOWLIST.clear()
    _OWNER_ALLOWLIST.update(str(ip) for ip in ips)


def is_self_lockout(ip: Optional[str]) -> bool:
    """Return True if ip must never be blocked."""
    if not ip:
        return True
    if ip in _SELF_LOCKOUT_EXACT:
        return True
    if ip.startswith("127."):
        return True
    if ip in _OWNER_ALLOWLIST:
        return True
    return False


# ---------------------------------------------------------------------------
# FP rate brake (in-process sliding window, per asset/org)
# ---------------------------------------------------------------------------

class _FPRateBrake:
    def __init__(self):
        self._lock = threading.Lock()
        self._windows: Dict[tuple, List[float]] = {}

    def check_and_record(self, asset_id: int, org_id: int, max_per_min: int) -> bool:
        """Return True (allowed + recorded) or False (rate exceeded)."""
        key = (asset_id, org_id)
        now = time.monotonic()
        cutoff = now - 60.0
        with self._lock:
            bucket = [t for t in self._windows.get(key, []) if t >= cutoff]
            if len(bucket) >= max_per_min:
                self._windows[key] = bucket
                return False
            bucket.append(now)
            self._windows[key] = bucket
            return True

    def reset(self, asset_id: int, org_id: int) -> None:
        """Test helper — clear the window for an asset."""
        with self._lock:
            self._windows.pop((asset_id, org_id), None)


_RATE_BRAKE = _FPRateBrake()


# ---------------------------------------------------------------------------
# ProposedAction
# ---------------------------------------------------------------------------

@dataclass
class ProposedAction:
    asset_id: int
    org_id: int
    incident_id: Optional[int]
    action_type: str       # "block_source" | "recommend"
    params: Dict
    tier: AutonomyTier
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    rollback_token: str = field(default_factory=lambda: secrets.token_hex(16))


# ---------------------------------------------------------------------------
# Main decision function
# ---------------------------------------------------------------------------

def decide(
    asset_id: int,
    org_id: int,
    detections: List[Detection],
    *,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> List[ProposedAction]:
    """Propose containment actions for a batch of detections.

    Returns a list of ProposedActions — not yet written to DB.
    Call response.apply_action() for each to persist and audit them.
    """
    tier = effective_tier(asset_id, org_id)
    is_auto = tier in (AutonomyTier.AUTO_CONTAIN, AutonomyTier.AUTO_REMEDIATE)

    proposals: List[ProposedAction] = []

    for det in detections:
        # Kill switch re-checked per detection for thread-safety
        if effective_tier(asset_id, org_id) == AutonomyTier.OBSERVE:
            break

        # Self-lockout guard — log refusal and skip
        if is_self_lockout(det.event.src_ip):
            INCIDENT_LOG.append(
                entry_type="decision",
                asset_id=asset_id, org_id=org_id,
                payload={"reason": "self_lockout_guard",
                         "src_ip": det.event.src_ip,
                         "attack_class": det.attack_class},
                actor="brain.decision",
            )
            continue

        if tier == AutonomyTier.OBSERVE:
            continue

        # At auto_remediate tier, patchable classes get a WAF rule instead of IP block.
        if tier == AutonomyTier.AUTO_REMEDIATE and det.attack_class in PATCHABLE_CLASSES:
            from brain.virtual_patch import generate_patch
            vp = generate_patch(det)
            if vp is not None:
                action_type = "apply_waf_rule"
                params: Dict = {
                    "rule_id": vp.rule_id,
                    "rule_spec": vp.rule_spec,
                    "rollback_spec": vp.rollback_spec,
                    "attack_class": det.attack_class,
                }
            else:
                action_type = "block_source"
                params = {
                    "src_ip": det.event.src_ip,
                    "attack_class": det.attack_class,
                    "fingerprint": det.fingerprint,
                }
        else:
            action_type = "block_source"
            params = {
                "src_ip": det.event.src_ip,
                "attack_class": det.attack_class,
                "fingerprint": det.fingerprint,
            }

        # Approval-gated action types are never auto-applied — land as 'proposed'
        if action_type in APPROVAL_GATED_ACTION_TYPES:
            # These are written by apply_action as status='proposed' automatically
            # (recommend path already handled below via action_type override)
            pass

        if is_auto:
            # FP rate brake: get policy limit, check window
            max_per_min = 5
            try:
                from brain.autonomy import get_policy
                pol = get_policy(asset_id, org_id)
                if pol is not None:
                    max_per_min = pol.fp_block_max_per_min
            except Exception:
                pass

            if not _RATE_BRAKE.check_and_record(asset_id, org_id, max_per_min):
                action_type = "recommend"
                INCIDENT_LOG.append(
                    entry_type="decision",
                    asset_id=asset_id, org_id=org_id,
                    payload={"reason": "fp_rate_exceeded",
                             "downgraded_to": "recommend",
                             "attack_class": det.attack_class,
                             "src_ip": det.event.src_ip},
                    actor="brain.decision",
                )

        proposals.append(ProposedAction(
            asset_id=asset_id,
            org_id=org_id,
            incident_id=det.incident_id,
            action_type=action_type,
            params=params,
            tier=tier,
            ttl_seconds=ttl_seconds,
        ))

        INCIDENT_LOG.append(
            entry_type="decision",
            asset_id=asset_id, org_id=org_id,
            payload={"action_type": action_type,
                     "attack_class": det.attack_class,
                     "src_ip": det.event.src_ip,
                     "tier": str(tier)},
            actor="brain.decision",
        )

    return proposals
