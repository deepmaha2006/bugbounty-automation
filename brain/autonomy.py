"""
HydraBrain autonomy tiers, per-asset policy, and kill switch.

Four tiers (default: observe):
  observe         — detect + log + alert only. Zero action.
  recommend       — detect + produce a proposed action for human approval.
  auto_contain    — may take reversible containment on its own (IP block/TTL,
                    session kill, rate clamp). Everything else stays recommend.
  auto_remediate  — may additionally apply reversible virtual patches (WAF rules).
                    Editing app source/config is ALWAYS an approval gate.

The KILL_SWITCH forces every asset to observe and must be honoured before any
action is dispatched.  All tier comparisons go through effective_tier() or
can_act_autonomously(), which check the switch.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from enum import Enum
from typing import Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Tier definition
# ---------------------------------------------------------------------------

class AutonomyTier(str, Enum):
    OBSERVE = "observe"
    RECOMMEND = "recommend"
    AUTO_CONTAIN = "auto_contain"
    AUTO_REMEDIATE = "auto_remediate"


# Numeric rank — higher means more autonomous.
_TIER_RANK: Dict[AutonomyTier, int] = {
    AutonomyTier.OBSERVE: 0,
    AutonomyTier.RECOMMEND: 1,
    AutonomyTier.AUTO_CONTAIN: 2,
    AutonomyTier.AUTO_REMEDIATE: 3,
}


def tier_rank(tier: AutonomyTier) -> int:
    return _TIER_RANK[tier]


# ---------------------------------------------------------------------------
# Per-asset policy
# ---------------------------------------------------------------------------

@dataclass
class AutonomyPolicy:
    asset_id: int
    org_id: int
    tier: AutonomyTier = AutonomyTier.OBSERVE
    # False-positive brake: max auto-block actions allowed per minute.
    # Exceeding this escalates to recommend instead of acting.
    fp_block_max_per_min: int = 5


# ---------------------------------------------------------------------------
# Kill switch — global, forces every asset to observe instantly.
# ---------------------------------------------------------------------------

class _KillSwitch:
    """Thread-safe global kill switch.  engage() forces all assets to observe."""

    def __init__(self) -> None:
        self._engaged = False
        self._lock = threading.Lock()

    @property
    def engaged(self) -> bool:
        with self._lock:
            return self._engaged

    def engage(self) -> None:
        with self._lock:
            self._engaged = True

    def disengage(self) -> None:
        with self._lock:
            self._engaged = False


# Module-level singleton — import and call brain.autonomy.KILL_SWITCH.engage()
KILL_SWITCH = _KillSwitch()


# ---------------------------------------------------------------------------
# Policy store
# ---------------------------------------------------------------------------

class PolicyStore:
    """Thread-safe in-memory store for per-asset autonomy policies."""

    def __init__(self) -> None:
        self._policies: Dict[Tuple[int, int], AutonomyPolicy] = {}
        self._lock = threading.Lock()

    def set(self, policy: AutonomyPolicy) -> None:
        key = (policy.asset_id, policy.org_id)
        with self._lock:
            self._policies[key] = policy

    def get(self, asset_id: int, org_id: int) -> AutonomyPolicy:
        """Return stored policy, or a default observe policy if none is set."""
        with self._lock:
            return self._policies.get(
                (asset_id, org_id),
                AutonomyPolicy(asset_id=asset_id, org_id=org_id),
            )

    def remove(self, asset_id: int, org_id: int) -> None:
        with self._lock:
            self._policies.pop((asset_id, org_id), None)

    def all_policies(self) -> list:
        with self._lock:
            return list(self._policies.values())


# Module-level singleton policy store.
_POLICY_STORE = PolicyStore()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def set_policy(policy: AutonomyPolicy) -> None:
    _POLICY_STORE.set(policy)


def get_policy(asset_id: int, org_id: int) -> AutonomyPolicy:
    """Return the stored policy (kill switch does NOT alter the stored value)."""
    return _POLICY_STORE.get(asset_id, org_id)


def remove_policy(asset_id: int, org_id: int) -> None:
    _POLICY_STORE.remove(asset_id, org_id)


def effective_tier(
    asset_id: int,
    org_id: int,
    auth: Optional[dict] = None,
) -> AutonomyTier:
    """Effective autonomy tier for an asset.

    Rules applied in order:
    1. If kill switch is engaged → OBSERVE (overrides everything).
    2. If an authorization record caps the tier, apply the cap.
       (auth dict may carry a ``max_autonomy_tier`` field added in Phase 15+)
    3. Return the stored policy tier.
    """
    if KILL_SWITCH.engaged:
        return AutonomyTier.OBSERVE

    policy = _POLICY_STORE.get(asset_id, org_id)
    tier = policy.tier

    # Optional authorization ceiling (Phase 15+ will populate this field).
    if auth is not None:
        cap_str = auth.get("max_autonomy_tier")
        if cap_str and cap_str in AutonomyTier.__members__.values():
            cap = AutonomyTier(cap_str)
            if tier_rank(tier) > tier_rank(cap):
                tier = cap

    return tier


def can_act_autonomously(
    asset_id: int,
    org_id: int,
    required_tier: AutonomyTier,
    auth: Optional[dict] = None,
) -> bool:
    """True iff the asset's effective tier is >= required_tier."""
    eff = effective_tier(asset_id, org_id, auth)
    return tier_rank(eff) >= tier_rank(required_tier)
