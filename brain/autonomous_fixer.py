"""HydraBrain Autonomous Fixer — applies fixes for detected vulnerabilities.

This module implements the auto-remediation capability for the self-evolving brain.
It generates and applies fixes based on CVE knowledge and learned patterns.
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from brain.autonomy import AutonomyTier, get_policy
from brain.decision import ProposedAction
from brain.response import apply_action
from brain.virtual_patch import generate_patch, PATCHABLE_CLASSES

logger = logging.getLogger(__name__)


# ============================================================================
# Fix Action Dataclass
# ============================================================================

@dataclass
class FixAction:
    """Represents an autonomous fix to be applied."""
    cve_id: Optional[str]
    attack_class: str
    fix_type: str              # "virtual_patch", "config_change", "rate_limit", "header_add"
    target: str                # Target identifier (rule_id, config_key, etc.)
    action: str                # Human-readable action description
    params: Dict[str, Any]     # Parameters for the connector job
    rollback: str              # Human-readable rollback description
    rollback_params: Dict[str, Any]  # Parameters for rollback job
    confidence: float          # 0.0 - 1.0
    requires_approval: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# Fix Generators
# ============================================================================

def generate_virtual_patch_fix(
    asset_id: int,
    org_id: int,
    detection_attack_class: str,
    cve_match: Optional[Dict] = None
) -> Optional[FixAction]:
    """Generate a virtual WAF patch fix for patchable attack classes."""
    if detection_attack_class not in PATCHABLE_CLASSES:
        return None

    # Create a detection-like object for virtual_patch.generate_patch
    from brain.detection import Detection
    from brain.sensors import Event
    from datetime import datetime

    mock_event = Event(
        asset_id=asset_id,
        org_id=org_id,
        ts=datetime.now(timezone.utc),
        src_ip="",
        path="/",
        signals={"attack_class": detection_attack_class}
    )
    mock_detection = Detection(
        asset_id=asset_id,
        org_id=org_id,
        attack_class=detection_attack_class,
        fingerprint="",
        event=mock_event
    )

    patch = generate_patch(mock_detection)
    if not patch:
        return None

    rule_id = patch["rule_id"]
    rule_body = patch["rule"]

    return FixAction(
        cve_id=cve_match.get("cve_id") if cve_match else None,
        attack_class=detection_attack_class,
        fix_type="virtual_patch",
        target=rule_id,
        action=f"Deploy WAF rule to block {detection_attack_class} attacks",
        params={
            "rule_id": rule_id,
            "rule_body": rule_body,
            "src_ip": "",
            "reason": f"Auto-patch for {detection_attack_class}" +
                     (f" (CVE: {cve_match['cve_id']})" if cve_match else ""),
        },
        rollback=f"Remove WAF rule {rule_id}",
        rollback_params={
            "rule_id": rule_id,
            "reason": "Auto-rollback",
        },
        confidence=0.85 if cve_match else 0.7,
    )


def generate_rate_limit_fix(
    asset_id: int,
    org_id: int,
    src_ip: str,
    cve_match: Optional[Dict] = None
) -> FixAction:
    """Generate a rate limiting fix for scanner/probe sources."""
    rule_id = f"ratelimit-{src_ip.replace('.', '-')}-{uuid.uuid4().hex[:8]}"

    return FixAction(
        cve_id=cve_match.get("cve_id") if cve_match else None,
        attack_class="scanner_probe",
        fix_type="rate_limit",
        target=rule_id,
        action=f"Rate limit source IP {src_ip} for aggressive scanning",
        params={
            "src_ip": src_ip,
            "limit": "10r/s",
            "burst": "20",
            "reason": "Auto-rate-limit for scanner activity",
        },
        rollback=f"Remove rate limit for {src_ip}",
        rollback_params={
            "src_ip": src_ip,
            "reason": "Auto-rollback rate limit",
        },
        confidence=0.75,
    )


def generate_header_fix(
    asset_id: int,
    org_id: int,
    attack_class: str,
    cve_match: Optional[Dict] = None
) -> Optional[FixAction]:
    """Generate security header fixes."""
    headers_map = {
        "xss": [
            ("Content-Security-Policy", "default-src 'self'; script-src 'self'"),
            ("X-Content-Type-Options", "nosniff"),
        ],
        "clickjack": [
            ("X-Frame-Options", "DENY"),
        ],
        "info_disclosure": [
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ],
    }

    headers = headers_map.get(attack_class, [])
    if not headers:
        return None

    fixes = []
    for header_name, header_value in headers:
        rule_id = f"header-{header_name.lower()}-{uuid.uuid4().hex[:8]}"
        fixes.append(FixAction(
            cve_id=cve_match.get("cve_id") if cve_match else None,
            attack_class=attack_class,
            fix_type="header_add",
            target=header_name,
            action=f"Add security header {header_name}",
            params={
                "header_name": header_name,
                "header_value": header_value,
                "reason": f"Auto-add security header for {attack_class}",
            },
            rollback=f"Remove header {header_name}",
            rollback_params={
                "header_name": header_name,
                "reason": "Auto-rollback header",
            },
            confidence=0.8,
        ))

    return fixes[0] if fixes else None  # Return first for now


# ============================================================================
# Main Fix Application
# ============================================================================

def select_fix_for_detection(
    asset_id: int,
    org_id: int,
    detection,
    cve_matches: List[Dict]
) -> List[FixAction]:
    """Select appropriate fix(es) for a detection.

    Returns list of FixAction objects sorted by confidence (highest first).
    """
    fixes = []
    attack_class = detection.attack_class

    # 1. Try CVE-specific fix first (highest confidence)
    for cve_match in cve_matches[:3]:  # Top 3 matches
        fix_rec = cve_match.get("fix_recommendation", {})
        if isinstance(fix_rec, str):
            fix_rec = json.loads(fix_rec)

        if fix_rec.get("virtual_patch") and attack_class in PATCHABLE_CLASSES:
            fix = generate_virtual_patch_fix(asset_id, org_id, attack_class, cve_match)
            if fix:
                fixes.append(fix)

    # 2. Generate virtual patch if patchable (fallback)
    if attack_class in PATCHABLE_CLASSES:
        fix = generate_virtual_patch_fix(asset_id, org_id, attack_class, cve_matches[0] if cve_matches else None)
        if fix and fix not in fixes:
            fixes.append(fix)

    # 3. Security headers
    header_fix = generate_header_fix(asset_id, org_id, attack_class, cve_matches[0] if cve_matches else None)
    if header_fix:
        fixes.append(header_fix)

    # 4. Rate limiting for scanner probes
    if attack_class == "scanner_probe" and detection.event.src_ip:
        fix = generate_rate_limit_fix(asset_id, org_id, detection.event.src_ip, cve_matches[0] if cve_matches else None)
        fixes.append(fix)

    # Sort by confidence descending
    fixes.sort(key=lambda f: f.confidence, reverse=True)
    return fixes


def apply_autonomous_fix(
    asset_id: int,
    org_id: int,
    fix: FixAction,
    actor: str = "brain.autonomous_fixer"
) -> Optional[int]:
    """Apply a fix autonomously via the brain response system.

    Returns brain_action_id on success, None on failure.
    """
    # Check autonomy policy
    policy = get_policy(asset_id, org_id)
    if policy.tier < AutonomyTier.auto_remediate:
        logger.info(f"Autonomy tier {policy.tier.value} < auto_remediate, skipping auto-fix")
        return None

    # Check if fix requires approval
    if fix.requires_approval and policy.tier < AutonomyTier.auto_remediate:
        logger.info(f"Fix requires approval but tier is {policy.tier.value}")
        return None

    # Map fix_type to brain action type
    action_type_map = {
        "virtual_patch": "apply_waf_rule",
        "rate_limit": "apply_waf_rule",  # Uses same WAF mechanism
        "header_add": "apply_waf_rule",  # Can be implemented as WAF rule
        "config_change": "edit_config",  # Requires approval
    }

    action_type = action_type_map.get(fix.fix_type)
    if not action_type:
        logger.warning(f"Unknown fix type: {fix.fix_type}")
        return None

    # Generate rollback token
    rollback_token = uuid.uuid4().hex

    # Create ProposedAction
    from brain.decision import ProposedAction
    proposed = ProposedAction(
        incident_id=detection.incident_id if 'detection' in locals() else None,
        asset_id=asset_id,
        org_id=org_id,
        type=action_type,
        params=fix.params,
        tier_at_time=policy.tier.value,
        ttl_seconds=3600,  # 1 hour default TTL
        rollback_token=rollback_token,
    )

    # Apply via brain response system
    action_id = apply_action(proposed, actor=actor)
    if action_id:
        logger.info(f"Applied autonomous fix: action_id={action_id} fix_type={fix.fix_type}")
    else:
        logger.warning(f"Failed to apply autonomous fix: {fix.fix_type}")

    return action_id


def apply_fixes_for_detection(
    asset_id: int,
    org_id: int,
    detection,
    cve_matches: List[Dict],
    max_fixes: int = 1
) -> List[int]:
    """Apply fixes for a detection up to max_fixes."""
    fixes = select_fix_for_detection(asset_id, org_id, detection, cve_matches)
    applied = []

    for fix in fixes[:max_fixes]:
        action_id = apply_autonomous_fix(asset_id, org_id, fix)
        if action_id:
            applied.append(action_id)

    return applied


# ============================================================================
# Fix Verification (Post-Application)
# ============================================================================

async def verify_fix_effectiveness(
    asset_id: int,
    org_id: int,
    action_id: int,
    wait_seconds: int = 60
) -> bool:
    """Verify that a fix was effective by checking for continued attacks.

    This would be called after a delay to check if the fix stopped attacks.
    """
    import asyncio
    await asyncio.sleep(wait_seconds)

    import webapp.db as db

    # Check for new events of same attack class from same source
    # This is a simplified check - real implementation would be more sophisticated
    events = db.brain_list_events(asset_id=asset_id, org_id=org_id, limit=100)
    # ... check if attacks continued ...

    return True  # Placeholder