"""
HydraBrain virtual_patch — generate WAF rule specifications from detections.

Phase 16: auto_remediate tier. Virtual patches are WAF rules that block or
rate-limit attack patterns without modifying application source code or config
files. Only patchable attack classes can be auto-applied; anything that touches
source/config is always approval-gated.

Patchable (auto_remediate): xss, sql_injection, path_traversal, scanner_probe
Approval-gated (always):    edit_source, edit_config, and any unknown class
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from brain.detection import Detection

# Attack classes for which a virtual WAF rule can be auto-generated and applied.
PATCHABLE_CLASSES = frozenset(
    {"xss", "sql_injection", "path_traversal", "scanner_probe"}
)

# Action types that always require human approval — never auto-applied.
APPROVAL_GATED_ACTION_TYPES = frozenset({"edit_source", "edit_config"})


@dataclass
class VirtualPatch:
    asset_id: int
    org_id: int
    attack_class: str
    path: Optional[str]
    src_ip: Optional[str]
    rule_id: str
    rule_spec: Dict[str, Any]    # payload for apply_waf_rule connector job
    rollback_spec: Dict[str, Any]  # payload for remove_waf_rule connector job
    severity: str


def rule_id_for(
    asset_id: int, org_id: int, attack_class: str, path: Optional[str]
) -> str:
    """Deterministic, stable rule identifier (32-char hex, prefixed)."""
    raw = f"{asset_id}:{org_id}:{attack_class}:{path or ''}"
    return "hydrax-" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def generate_patch(detection: Detection) -> Optional[VirtualPatch]:
    """Generate a WAF rule spec for a detection.

    Returns None for attack classes that have no virtual patch mapping, or
    when the attack class is not in PATCHABLE_CLASSES.
    """
    cls = detection.attack_class
    if cls not in PATCHABLE_CLASSES:
        return None

    path = detection.event.path
    src_ip = detection.event.src_ip
    rid = rule_id_for(detection.asset_id, detection.org_id, cls, path)

    if cls == "xss":
        rule_spec = {
            "type": "block_pattern",
            "pattern": r"<script|javascript:|onerror\s*=|onload\s*=",
            "location": "query",
            "path": path,
            "rule_id": rid,
        }
    elif cls == "sql_injection":
        rule_spec = {
            "type": "block_pattern",
            "pattern": r"(?i)(UNION\s+SELECT|SELECT\s+.*FROM|'--|OR\s+['\d]+=)",
            "location": "query",
            "path": path,
            "rule_id": rid,
        }
    elif cls == "path_traversal":
        rule_spec = {
            "type": "block_pattern",
            "pattern": r"\.\.[/\\]|%2e%2e|%252e",
            "location": "path",
            "path": path,
            "rule_id": rid,
        }
    elif cls == "scanner_probe":
        rule_spec = {
            "type": "rate_limit",
            "src_ip": src_ip,
            "max_req_per_min": 10,
            "rule_id": rid,
        }
    else:
        return None

    rollback_spec = {"rule_id": rid, "attack_class": cls}

    # Use detection severity as WAF rule severity
    from brain.detection import severity_for
    severity = severity_for(cls)

    return VirtualPatch(
        asset_id=detection.asset_id,
        org_id=detection.org_id,
        attack_class=cls,
        path=path,
        src_ip=src_ip,
        rule_id=rid,
        rule_spec=rule_spec,
        rollback_spec=rollback_spec,
        severity=severity,
    )


def patches_for(detections: List[Detection]) -> List[VirtualPatch]:
    """Generate VirtualPatch objects for all patchable detections."""
    seen_rule_ids: set = set()
    patches = []
    for det in detections:
        patch = generate_patch(det)
        if patch is None:
            continue
        if patch.rule_id in seen_rule_ids:
            continue  # deduplicate same rule
        seen_rule_ids.add(patch.rule_id)
        patches.append(patch)
    return patches
