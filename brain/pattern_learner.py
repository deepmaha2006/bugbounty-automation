"""HydraBrain Pattern Learner — learns attack patterns from detections and outcomes.

This module implements the continuous learning loop for the self-evolving brain.
It updates brain_knowledge based on detection outcomes and feeds improvements
back into the detection/correlation pipeline.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ============================================================================
# Outcome Constants (from learning.py)
# ============================================================================

OUTCOME_DETECTED = "detected"
OUTCOME_BLOCKED = "blocked"
OUTCOME_FALSE_POSITIVE = "false_positive"
OUTCOME_ROLLBACK = "rollback"


# ============================================================================
# Learning Configuration
# ============================================================================

# EWMA alpha (same as learning.py)
ALPHA = 0.2

# Confidence thresholds
MIN_CONFIDENCE_FOR_AUTO_ACTION = 0.7
HIGH_CONFIDENCE_THRESHOLD = 0.85
LOW_CONFIDENCE_THRESHOLD = 0.3

# FP rate brake (from decision.py)
FP_BLOCK_MAX_PER_MIN = 5


# ============================================================================
# Pattern Dataclasses
# ============================================================================

@dataclass
class AttackPattern:
    """Represents a learned attack pattern."""
    signature_fingerprint: str
    attack_class: str
    pattern_features: Dict[str, Any]  # Path patterns, query patterns, headers, etc.
    confidence: float
    times_seen: int
    success_rate: float
    last_seen: datetime
    first_seen: datetime
    recommended_fix: Dict[str, Any] = None


# ============================================================================
# Pattern Learner
# ============================================================================

class AttackPatternLearner:
    """Learns new attack patterns from detected events and outcomes."""

    def __init__(self):
        self._pattern_cache: Dict[str, AttackPattern] = {}

    def learn_from_detection(
        self,
        asset_id: int,
        org_id: int,
        detection,
        outcome: str,
        fix_applied: Optional[Dict] = None
    ) -> None:
        """Update pattern knowledge based on detection outcome.

        Args:
            asset_id: Asset identifier
            org_id: Organization identifier
            detection: Detection object from brain.detection
            outcome: One of OUTCOME_DETECTED, OUTCOME_BLOCKED, OUTCOME_FALSE_POSITIVE, OUTCOME_ROLLBACK
            fix_applied: Optional fix that was applied
        """
        import webapp.db as db

        # Extract pattern features from event
        event = detection.event
        features = self._extract_features(event)

        # Create or update signature fingerprint
        sig_fp = self._signature_fingerprint(
            asset_id, org_id, detection.attack_class, features
        )

        # Get existing knowledge
        knowledge = self._get_knowledge(asset_id, org_id, sig_fp)

        # Update based on outcome
        if outcome == OUTCOME_BLOCKED:
            # Fix worked - increase confidence
            self._update_knowledge(
                asset_id, org_id, sig_fp, detection.attack_class,
                features, success=True, fix_applied=fix_applied
            )
        elif outcome == OUTCOME_FALSE_POSITIVE:
            # False positive - decrease confidence
            self._update_knowledge(
                asset_id, org_id, sig_fp, detection.attack_class,
                features, success=False
            )
        elif outcome == OUTCOME_ROLLBACK:
            # Fix was rolled back - may indicate issue
            self._update_knowledge(
                asset_id, org_id, sig_fp, detection.attack_class,
                features, success=False, fix_applied=fix_applied
            )
        else:  # OUTCOME_DETECTED
            # Just detected - update times_seen
            self._update_knowledge(
                asset_id, org_id, sig_fp, detection.attack_class,
                features, success=None
            )

        # Check if we should flag for analyst review
        self._check_review_threshold(asset_id, org_id, sig_fp)

    def _extract_features(self, event) -> Dict[str, Any]:
        """Extract discriminative features from an event."""
        features = {
            "method": event.method,
            "path_pattern": self._normalize_path(event.path),
            "query_params": list(event.signals.get("query", {}).keys()) if isinstance(event.signals.get("query"), dict) else [],
            "status": event.status,
            "user_agent_prefix": self._ua_prefix(event.signals.get("user_agent", "")),
            "attack_class": event.signals.get("attack_class", ""),
        }
        return features

    def _normalize_path(self, path: Optional[str]) -> str:
        """Normalize path for pattern matching."""
        if not path:
            return "/"
        # Replace IDs/numbers with placeholder
        import re
        path = re.sub(r'/\d+', '/{id}', path)
        path = re.sub(r'/[a-f0-9]{8,}', '/{hash}', path)
        return path

    def _ua_prefix(self, ua: str) -> str:
        """Extract tool signature from user agent."""
        if not ua:
            return ""
        ua_lower = ua.lower()
        for tool in ["sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirb", "burp", "zap", "wfuzz", "ffuf"]:
            if tool in ua_lower:
                return tool
        return "browser" if "mozilla" in ua_lower else "unknown"

    def _signature_fingerprint(
        self,
        asset_id: int,
        org_id: int,
        attack_class: str,
        features: Dict
    ) -> str:
        """Create deterministic fingerprint for pattern."""
        # Use path pattern + attack class + method as base
        raw = f"{asset_id}:{org_id}:{attack_class}:{features.get('path_pattern', '')}:{features.get('method', '')}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _get_knowledge(self, asset_id: int, org_id: int, sig_fp: str) -> Optional[Dict]:
        """Get existing knowledge from database."""
        import webapp.db as db
        return db.brain_get_knowledge(asset_id, org_id, sig_fp)

    def _update_knowledge(
        self,
        asset_id: int,
        org_id: int,
        sig_fp: str,
        attack_class: str,
        features: Dict,
        success: Optional[bool],
        fix_applied: Optional[Dict] = None
    ) -> None:
        """Update brain_knowledge with EWMA confidence model."""
        import webapp.db as db

        knowledge = self._get_knowledge(asset_id, org_id, sig_fp)

        if knowledge:
            old_confidence = float(knowledge.get("confidence", 0.5))
            times_seen = knowledge.get("times_seen", 1)
            success_rate = float(knowledge.get("success_rate", 0.0))

            # Update EWMA confidence
            if success is True:
                new_confidence = old_confidence + ALPHA * (1.0 - old_confidence)
                new_success_rate = (success_rate * times_seen + 1.0) / (times_seen + 1)
            elif success is False:
                new_confidence = old_confidence - ALPHA * old_confidence
                new_success_rate = (success_rate * times_seen + 0.0) / (times_seen + 1)
            else:
                new_confidence = old_confidence
                new_success_rate = success_rate

            new_times_seen = times_seen + 1

            # Update recommended fix if provided
            recommended_fix = knowledge.get("recommended_action", {})
            if fix_applied:
                recommended_fix = fix_applied

            db.brain_upsert_knowledge(
                asset_id=asset_id,
                org_id=org_id,
                signature_fingerprint=sig_fp,
                attack_class=attack_class,
                recommended_action=recommended_fix,
                remediation=knowledge.get("remediation", {}),
                confidence=new_confidence,
                times_seen=new_times_seen,
                success_rate=new_success_rate,
            )
        else:
            # New pattern
            initial_confidence = 0.6 if success is True else 0.4
            if success is None:
                initial_confidence = 0.5

            db.brain_upsert_knowledge(
                asset_id=asset_id,
                org_id=org_id,
                signature_fingerprint=sig_fp,
                attack_class=attack_class,
                recommended_action=fix_applied or {},
                remediation={},
                confidence=initial_confidence,
                times_seen=1,
                success_rate=1.0 if success is True else 0.0,
            )

        # Clear cache
        self._pattern_cache.pop(sig_fp, None)

    def _check_review_threshold(self, asset_id: int, org_id: int, sig_fp: str) -> None:
        """Flag patterns with low confidence for analyst review."""
        knowledge = self._get_knowledge(asset_id, org_id, sig_fp)
        if knowledge:
            conf = float(knowledge.get("confidence", 0.5))
            if conf < LOW_CONFIDENCE_THRESHOLD and knowledge.get("times_seen", 0) > 5:
                # Flag for review
                import webapp.db as db
                db.brain_flag_for_review(asset_id, org_id, sig_fp, "low_confidence")
                logger.warning(f"Pattern {sig_fp} flagged for review: confidence={conf}")


# ============================================================================
# CVE Knowledge Feeder
# ============================================================================

class CVEKnowledgeFeeder:
    """Feeds CVE knowledge into brain_knowledge for proactive detection."""

    @staticmethod
    def sync_cves_to_knowledge(asset_id: int, org_id: int, limit: int = 1000) -> int:
        """Sync relevant CVEs from brain_cve_db to brain_knowledge.

        Returns number of knowledge records created/updated.
        """
        import webapp.db as db

        conn = db.get_conn()
        synced = 0

        try:
            with conn.cursor() as cur:
                # Get CVEs with fix recommendations
                cur.execute("""
                    SELECT cve_id, attack_class, fix_recommendation, cvss_score
                    FROM brain_cve_db
                    WHERE attack_class IS NOT NULL
                    AND attack_class != 'unknown'
                    AND fix_recommendation IS NOT NULL
                    AND fix_recommendation != '{}'
                    ORDER BY cvss_score DESC NULLS LAST
                    LIMIT %s
                """, (limit,))

                for row in cur.fetchall():
                    cve_id, attack_class, fix_rec, cvss_score = row

                    # Create signature fingerprint from CVE
                    sig_fp = hashlib.sha256(
                        f"cve:{cve_id}:{attack_class}".encode()
                    ).hexdigest()[:32]

                    # Upsert knowledge
                    db.brain_upsert_knowledge(
                        asset_id=asset_id,
                        org_id=org_id,
                        signature_fingerprint=sig_fp,
                        attack_class=attack_class,
                        recommended_action=fix_rec,
                        remediation={
                            "source": "cve_database",
                            "cve_id": cve_id,
                            "cvss_score": float(cvss_score) if cvss_score else 0.0
                        },
                        confidence=0.95,  # High confidence from known CVE
                        times_seen=1,
                        success_rate=0.0,
                    )
                    synced += 1

        finally:
            conn.close()

        logger.info(f"Synced {synced} CVE records to brain_knowledge for asset {asset_id}")
        return synced


# ============================================================================
# Knowledge Exporter (for sharing across assets)
# ============================================================================

class KnowledgeExporter:
    """Exports learned patterns for sharing across assets/organizations."""

    @staticmethod
    def export_knowledge(org_id: int) -> List[Dict]:
        """Export high-confidence knowledge for sharing."""
        import webapp.db as db

        conn = db.get_conn()
        exported = []

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT signature_fingerprint, attack_class, recommended_action,
                           remediation, confidence, times_seen, success_rate
                    FROM brain_knowledge
                    WHERE org_id = %s
                    AND confidence >= %s
                    AND times_seen >= 3
                    AND success_rate >= 0.7
                """, (org_id, HIGH_CONFIDENCE_THRESHOLD))

                for row in cur.fetchall():
                    sig_fp, attack_class, rec_action, remediation, conf, times, sr = row
                    exported.append({
                        "signature_fingerprint": sig_fp,
                        "attack_class": attack_class,
                        "recommended_action": rec_action,
                        "remediation": remediation,
                        "confidence": float(conf),
                        "times_seen": times,
                        "success_rate": float(sr),
                        "exported_at": datetime.now(timezone.utc).isoformat(),
                    })

        finally:
            conn.close()

        return exported

    @staticmethod
    def import_knowledge(org_id: int, knowledge_list: List[Dict]) -> int:
        """Import shared knowledge into organization."""
        import webapp.db as db

        imported = 0
        for k in knowledge_list:
            try:
                db.brain_upsert_knowledge(
                    asset_id=0,  # Global/org-level
                    org_id=org_id,
                    signature_fingerprint=k["signature_fingerprint"],
                    attack_class=k["attack_class"],
                    recommended_action=k["recommended_action"],
                    remediation=k["remediation"],
                    confidence=k["confidence"] * 0.9,  # Slight discount for imported
                    times_seen=k["times_seen"],
                    success_rate=k["success_rate"],
                )
                imported += 1
            except Exception as e:
                logger.warning(f"Failed to import knowledge {k['signature_fingerprint']}: {e}")

        return imported