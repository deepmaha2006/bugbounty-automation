"""
Phase 17: brain.learning — fast-path cache + scanner cross-feed + observe().

Tests:
  • Outcome constants exist and _VALID_OUTCOMES is correctly populated
  • _update_confidence: delta arithmetic + clamping at both ends
  • _update_success_rate: EWMA formula for blocked vs other outcomes
  • FINDING_TYPE_TO_ATTACK_CLASS: known keys map correctly
  • _SEVERITY_TO_CONFIDENCE: ordering (critical > high > medium > low > info)
  • _default_recommended_action / _default_remediation: per class + unknown fallback
  • Cache internals: put/get/invalidate; TTL expiry (monkeypatch time.monotonic)
  • observe() — new record created with correct confidence + success_rate
  • observe() — existing record updated (EWMA applied correctly)
  • observe() — unknown outcome is silently ignored (no DB write)
  • observe() — blocked outcome nudges success_rate up; false_positive nudges down
  • observe() — multiple outcomes, confidence stays in [0.10, 0.99]
  • observe() — cache is invalidated after write
  • cross_feed_from_scan() — unknown type is skipped
  • cross_feed_from_scan() — known type → upsert + confidence from severity
  • cross_feed_from_scan() — count returned equals valid findings only
  • cross_feed_from_scan() — explicit fingerprint in finding is used as-is
  • cross_feed_from_scan() — fingerprint derived from type+path when absent
  • cross_feed_from_scan() — case-insensitive type matching (upper, mixed)
  • cross_feed_from_scan() — url key used as path if path absent
  • cross_feed_from_scan() — empty findings list returns 0
  • cross_feed_from_scan() — all known attack classes produce correct rec + rem
  • get_recommendation() — miss (no record) returns None
  • get_recommendation() — DB hit → correct shape returned
  • get_recommendation() — cache hit: second call uses cache (DB not hit again)
  • get_recommendation() — invalidate clears cache, next call hits DB
  • Full pipeline: cross_feed → observe(blocked) → get_recommendation consistency
  • Full pipeline: observe(false_positive) × N → confidence approaches minimum
  • Full pipeline: mixed outcomes stay clamped inside [0.10, 0.99]
  • cross_feed_from_scan() — sql injection (with space) maps to sql_injection class
  • observe() ensures recommended_action / remediation are preserved from existing record
  • observe() on brand-new record sets reasonable initial confidence (0.5 ± delta)
  • _cache_get on expired entry returns None and removes from _cache
  • cross_feed_from_scan() — missing severity defaults to medium (0.65)
"""
import importlib
import time
import types
from unittest.mock import MagicMock, patch

import pytest

import webapp.db as db  # noqa: F401 — ensures FakeDB patch is active via conftest
import brain.learning as L


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _kb(fake, asset_id=1, org_id=1, fingerprint="fp1", attack_class="xss",
        confidence=0.5, times_seen=1, success_rate=0.0):
    """Insert a brain_knowledge row directly into FakeDB for test setup."""
    fake.brain_knowledge.append({
        "id": 99, "asset_id": asset_id, "org_id": org_id,
        "signature_fingerprint": fingerprint,
        "attack_class": attack_class,
        "recommended_action": {"action": "apply_waf_rule"},
        "remediation": {"summary": "existing"},
        "confidence": confidence, "times_seen": times_seen, "success_rate": success_rate,
    })


# ---------------------------------------------------------------------------
# Constants / pure-function tests
# ---------------------------------------------------------------------------

def test_outcome_constants_defined():
    assert L.OUTCOME_DETECTED      == "detected"
    assert L.OUTCOME_BLOCKED       == "blocked"
    assert L.OUTCOME_FALSE_POSITIVE == "false_positive"
    assert L.OUTCOME_ROLLBACK      == "rollback"


def test_valid_outcomes_set():
    assert L._VALID_OUTCOMES == {"detected", "blocked", "false_positive", "rollback"}


def test_update_confidence_detected():
    c = L._update_confidence(0.5, L.OUTCOME_DETECTED)
    assert abs(c - 0.55) < 1e-9


def test_update_confidence_blocked():
    c = L._update_confidence(0.5, L.OUTCOME_BLOCKED)
    assert abs(c - 0.60) < 1e-9


def test_update_confidence_false_positive():
    c = L._update_confidence(0.5, L.OUTCOME_FALSE_POSITIVE)
    assert abs(c - 0.30) < 1e-9


def test_update_confidence_rollback():
    c = L._update_confidence(0.5, L.OUTCOME_ROLLBACK)
    assert abs(c - 0.35) < 1e-9


def test_update_confidence_clamp_max():
    c = L._update_confidence(0.96, L.OUTCOME_BLOCKED)   # 0.96 + 0.10 = 1.06 → 0.99
    assert c == 0.99


def test_update_confidence_clamp_min():
    c = L._update_confidence(0.12, L.OUTCOME_FALSE_POSITIVE)  # 0.12 - 0.20 = -0.08 → 0.10
    assert c == 0.10


def test_update_success_rate_blocked():
    sr = L._update_success_rate(0.0, L.OUTCOME_BLOCKED)
    expected = 0.2 * 1.0 + 0.8 * 0.0
    assert abs(sr - expected) < 1e-9


def test_update_success_rate_detected():
    sr = L._update_success_rate(0.5, L.OUTCOME_DETECTED)
    expected = 0.2 * 0.0 + 0.8 * 0.5
    assert abs(sr - expected) < 1e-9


def test_update_success_rate_false_positive():
    sr = L._update_success_rate(0.8, L.OUTCOME_FALSE_POSITIVE)
    expected = 0.2 * 0.0 + 0.8 * 0.8
    assert abs(sr - expected) < 1e-9


def test_finding_type_to_attack_class_xss():
    assert L.FINDING_TYPE_TO_ATTACK_CLASS["xss"] == "xss"
    assert L.FINDING_TYPE_TO_ATTACK_CLASS["reflected_xss"] == "xss"
    assert L.FINDING_TYPE_TO_ATTACK_CLASS["stored_xss"] == "xss"


def test_finding_type_to_attack_class_sqli():
    assert L.FINDING_TYPE_TO_ATTACK_CLASS["sql injection"] == "sql_injection"
    assert L.FINDING_TYPE_TO_ATTACK_CLASS["sqli"] == "sql_injection"
    assert L.FINDING_TYPE_TO_ATTACK_CLASS["sql_injection"] == "sql_injection"


def test_finding_type_to_attack_class_path_traversal():
    assert L.FINDING_TYPE_TO_ATTACK_CLASS["path traversal"] == "path_traversal"
    assert L.FINDING_TYPE_TO_ATTACK_CLASS["directory traversal"] == "path_traversal"


def test_severity_ordering():
    sev = L._SEVERITY_TO_CONFIDENCE
    assert sev["critical"] > sev["high"] > sev["medium"] > sev["low"] > sev["info"]


def test_default_recommended_action_known():
    ra = L._default_recommended_action("xss")
    assert ra["action"] == "apply_waf_rule"
    ra = L._default_recommended_action("sql_injection")
    assert ra["action"] == "apply_waf_rule"
    ra = L._default_recommended_action("scanner_probe")
    assert ra["action"] == "block_source"


def test_default_recommended_action_unknown():
    ra = L._default_recommended_action("unknown_class")
    assert ra["action"] == "recommend"


def test_default_remediation_known():
    rem = L._default_remediation("xss")
    assert "summary" in rem and "steps" in rem


def test_default_remediation_unknown():
    rem = L._default_remediation("weird_class")
    assert "summary" in rem


# ---------------------------------------------------------------------------
# Cache internals
# ---------------------------------------------------------------------------

def test_cache_put_get():
    L._cache.clear()
    L._cache_put(1, 1, "fp_cache", {"attack_class": "xss"})
    result = L._cache_get(1, 1, "fp_cache")
    assert result is not None
    assert result["attack_class"] == "xss"


def test_cache_miss_returns_none():
    L._cache.clear()
    assert L._cache_get(99, 99, "no_such_fp") is None


def test_cache_invalidate():
    L._cache.clear()
    L._cache_put(1, 1, "fp_inv", {"attack_class": "xss"})
    L._cache_invalidate(1, 1, "fp_inv")
    assert L._cache_get(1, 1, "fp_inv") is None


def test_cache_ttl_expiry():
    L._cache.clear()
    key = L._cache_key(1, 1, "fp_ttl")
    # Insert an already-expired entry
    with L._cache_lock:
        L._cache[key] = ({"attack_class": "xss"}, time.monotonic() - 1.0)
    result = L._cache_get(1, 1, "fp_ttl")
    assert result is None
    # Expired key should have been removed
    with L._cache_lock:
        assert key not in L._cache


# ---------------------------------------------------------------------------
# observe()
# ---------------------------------------------------------------------------

def test_observe_creates_new_record(fake):
    L._cache.clear()
    L.observe(1, 1, "fp_new", "xss", L.OUTCOME_DETECTED)
    rec = fake.brain_get_knowledge(1, 1, "fp_new")
    assert rec is not None
    assert rec["attack_class"] == "xss"
    # New record: 0.5 + 0.05 = 0.55
    assert abs(float(rec["confidence"]) - 0.55) < 1e-6


def test_observe_updates_existing_record(fake):
    L._cache.clear()
    _kb(fake, fingerprint="fp_upd", confidence=0.7, success_rate=0.3)
    L.observe(1, 1, "fp_upd", "xss", L.OUTCOME_BLOCKED)
    rec = fake.brain_get_knowledge(1, 1, "fp_upd")
    expected_conf = L._update_confidence(0.7, L.OUTCOME_BLOCKED)
    assert abs(float(rec["confidence"]) - expected_conf) < 1e-6


def test_observe_unknown_outcome_no_write(fake):
    L._cache.clear()
    L.observe(1, 1, "fp_bad", "xss", "not_a_real_outcome")
    assert fake.brain_get_knowledge(1, 1, "fp_bad") is None


def test_observe_blocked_updates_confidence_up(fake):
    L._cache.clear()
    L.observe(1, 1, "fp_blk", "sql_injection", L.OUTCOME_BLOCKED)
    rec = fake.brain_get_knowledge(1, 1, "fp_blk")
    # Fresh record starts at 0.5, OUTCOME_BLOCKED → +0.10
    assert float(rec["confidence"]) > 0.5


def test_observe_false_positive_reduces_confidence(fake):
    L._cache.clear()
    _kb(fake, fingerprint="fp_fp", confidence=0.7)
    L.observe(1, 1, "fp_fp", "xss", L.OUTCOME_FALSE_POSITIVE)
    rec = fake.brain_get_knowledge(1, 1, "fp_fp")
    assert float(rec["confidence"]) < 0.7


def test_observe_clamps_confidence_at_min(fake):
    L._cache.clear()
    _kb(fake, fingerprint="fp_low", confidence=0.12)
    L.observe(1, 1, "fp_low", "xss", L.OUTCOME_FALSE_POSITIVE)
    rec = fake.brain_get_knowledge(1, 1, "fp_low")
    assert float(rec["confidence"]) >= 0.10


def test_observe_clamps_confidence_at_max(fake):
    L._cache.clear()
    _kb(fake, fingerprint="fp_high", confidence=0.96)
    L.observe(1, 1, "fp_high", "xss", L.OUTCOME_BLOCKED)
    rec = fake.brain_get_knowledge(1, 1, "fp_high")
    assert float(rec["confidence"]) <= 0.99


def test_observe_invalidates_cache(fake):
    L._cache.clear()
    L._cache_put(1, 1, "fp_cache_obs", {"attack_class": "xss"})
    _kb(fake, fingerprint="fp_cache_obs")
    L.observe(1, 1, "fp_cache_obs", "xss", L.OUTCOME_DETECTED)
    assert L._cache_get(1, 1, "fp_cache_obs") is None


def test_observe_preserves_recommended_action_from_existing(fake):
    L._cache.clear()
    # Insert existing record with custom recommended_action
    fake.brain_knowledge.append({
        "id": 50, "asset_id": 1, "org_id": 1,
        "signature_fingerprint": "fp_pres",
        "attack_class": "xss",
        "recommended_action": {"action": "custom_action"},
        "remediation": {"summary": "custom_rem"},
        "confidence": 0.5, "times_seen": 2, "success_rate": 0.0,
    })
    L.observe(1, 1, "fp_pres", "xss", L.OUTCOME_DETECTED)
    rec = fake.brain_get_knowledge(1, 1, "fp_pres")
    assert rec["recommended_action"]["action"] == "custom_action"


def test_observe_new_record_initial_confidence_reasonable(fake):
    L._cache.clear()
    L.observe(1, 1, "fp_init", "path_traversal", L.OUTCOME_DETECTED)
    rec = fake.brain_get_knowledge(1, 1, "fp_init")
    assert 0.10 <= float(rec["confidence"]) <= 0.99


# ---------------------------------------------------------------------------
# cross_feed_from_scan()
# ---------------------------------------------------------------------------

def test_cross_feed_unknown_type_skipped(fake):
    L._cache.clear()
    count = L.cross_feed_from_scan(1, 1, [{"type": "unknown_vuln_type"}])
    assert count == 0
    assert fake.brain_knowledge == []


def test_cross_feed_known_type_creates_record(fake):
    L._cache.clear()
    count = L.cross_feed_from_scan(1, 1, [{"type": "xss", "severity": "high", "path": "/test"}])
    assert count == 1
    assert len(fake.brain_knowledge) == 1
    assert fake.brain_knowledge[0]["attack_class"] == "xss"


def test_cross_feed_confidence_from_severity(fake):
    L._cache.clear()
    L.cross_feed_from_scan(1, 1, [{"type": "xss", "severity": "critical", "path": "/a"}])
    rec = fake.brain_knowledge[0]
    assert abs(float(rec["confidence"]) - 0.90) < 1e-6


def test_cross_feed_medium_severity_default(fake):
    L._cache.clear()
    # no severity key → defaults to "medium" → 0.65
    L.cross_feed_from_scan(1, 1, [{"type": "xss", "path": "/b"}])
    rec = fake.brain_knowledge[0]
    assert abs(float(rec["confidence"]) - 0.65) < 1e-6


def test_cross_feed_count_only_valid(fake):
    L._cache.clear()
    findings = [
        {"type": "xss", "severity": "high"},
        {"type": "unknown_xyz"},
        {"type": "sqli", "severity": "low"},
    ]
    count = L.cross_feed_from_scan(1, 1, findings)
    assert count == 2


def test_cross_feed_explicit_fingerprint_used(fake):
    L._cache.clear()
    L.cross_feed_from_scan(1, 1, [{"type": "xss", "fingerprint": "my_custom_fp"}])
    assert fake.brain_knowledge[0]["signature_fingerprint"] == "my_custom_fp"


def test_cross_feed_fingerprint_derived_from_type_path(fake):
    import hashlib
    L._cache.clear()
    findings = [{"type": "xss", "path": "/login"}]
    L.cross_feed_from_scan(1, 1, findings)
    fp_raw = "1:1:xss:/login"
    expected = hashlib.sha256(fp_raw.encode()).hexdigest()[:32]
    assert fake.brain_knowledge[0]["signature_fingerprint"] == expected


def test_cross_feed_case_insensitive_type(fake):
    L._cache.clear()
    count = L.cross_feed_from_scan(1, 1, [{"type": "XSS", "severity": "medium"}])
    assert count == 1
    assert fake.brain_knowledge[0]["attack_class"] == "xss"


def test_cross_feed_url_key_used_as_path(fake):
    import hashlib
    L._cache.clear()
    L.cross_feed_from_scan(1, 1, [{"type": "xss", "url": "/via_url"}])
    fp_raw = "1:1:xss:/via_url"
    expected = hashlib.sha256(fp_raw.encode()).hexdigest()[:32]
    assert fake.brain_knowledge[0]["signature_fingerprint"] == expected


def test_cross_feed_empty_findings_returns_zero(fake):
    L._cache.clear()
    count = L.cross_feed_from_scan(1, 1, [])
    assert count == 0


def test_cross_feed_sql_injection_with_space(fake):
    L._cache.clear()
    count = L.cross_feed_from_scan(1, 1, [{"type": "sql injection", "severity": "high"}])
    assert count == 1
    assert fake.brain_knowledge[0]["attack_class"] == "sql_injection"


def test_cross_feed_all_known_classes_have_rec_and_rem(fake):
    L._cache.clear()
    for cls in ["xss", "sql_injection", "path_traversal", "scanner_probe",
                "ssrf", "csrf", "rce", "open_redirect"]:
        ra = L._default_recommended_action(cls)
        rem = L._default_remediation(cls)
        assert "action" in ra
        assert "summary" in rem


# ---------------------------------------------------------------------------
# get_recommendation()
# ---------------------------------------------------------------------------

def test_get_recommendation_miss_returns_none(fake):
    L._cache.clear()
    assert L.get_recommendation(1, 1, "no_fp") is None


def test_get_recommendation_db_hit(fake):
    L._cache.clear()
    _kb(fake, fingerprint="fp_gr", attack_class="path_traversal",
        confidence=0.7, times_seen=3, success_rate=0.4)
    rec = L.get_recommendation(1, 1, "fp_gr")
    assert rec is not None
    assert rec["attack_class"] == "path_traversal"
    assert abs(rec["confidence"] - 0.7) < 1e-6
    assert rec["times_seen"] == 3
    assert abs(rec["success_rate"] - 0.4) < 1e-6
    assert "recommended_action" in rec
    assert "remediation" in rec


def test_get_recommendation_cache_hit(fake):
    L._cache.clear()
    _kb(fake, fingerprint="fp_ch", attack_class="xss")
    # First call — DB hit, populates cache
    L.get_recommendation(1, 1, "fp_ch")
    # Second call — should come from cache (we verify by removing DB entry)
    fake.brain_knowledge.clear()
    rec = L.get_recommendation(1, 1, "fp_ch")
    assert rec is not None and rec["attack_class"] == "xss"


def test_get_recommendation_after_invalidate_hits_db(fake):
    L._cache.clear()
    _kb(fake, fingerprint="fp_ci", attack_class="xss")
    L.get_recommendation(1, 1, "fp_ci")      # populate cache
    L._cache_invalidate(1, 1, "fp_ci")        # clear it
    # Update DB entry
    fake.brain_knowledge[0]["attack_class"] = "sql_injection"
    rec = L.get_recommendation(1, 1, "fp_ci")
    assert rec["attack_class"] == "sql_injection"


# ---------------------------------------------------------------------------
# Full pipeline tests
# ---------------------------------------------------------------------------

def test_pipeline_cross_feed_then_observe_blocked(fake):
    L._cache.clear()
    L.cross_feed_from_scan(1, 1, [{"type": "xss", "severity": "medium", "fingerprint": "fp_pipe"}])
    rec0 = fake.brain_get_knowledge(1, 1, "fp_pipe")
    assert abs(float(rec0["confidence"]) - 0.65) < 1e-6

    L.observe(1, 1, "fp_pipe", "xss", L.OUTCOME_BLOCKED)
    rec1 = fake.brain_get_knowledge(1, 1, "fp_pipe")
    assert float(rec1["confidence"]) > float(rec0["confidence"])


def test_pipeline_repeated_false_positive_approaches_minimum(fake):
    L._cache.clear()
    _kb(fake, fingerprint="fp_fp_rep", confidence=0.8)
    for _ in range(20):
        L.observe(1, 1, "fp_fp_rep", "xss", L.OUTCOME_FALSE_POSITIVE)
    rec = fake.brain_get_knowledge(1, 1, "fp_fp_rep")
    assert float(rec["confidence"]) == 0.10  # clamped at minimum


def test_pipeline_mixed_outcomes_stays_clamped(fake):
    L._cache.clear()
    _kb(fake, fingerprint="fp_mix", confidence=0.5)
    for outcome in [L.OUTCOME_BLOCKED] * 5 + [L.OUTCOME_FALSE_POSITIVE] * 3:
        L.observe(1, 1, "fp_mix", "xss", outcome)
    rec = fake.brain_get_knowledge(1, 1, "fp_mix")
    assert 0.10 <= float(rec["confidence"]) <= 0.99


def test_pipeline_get_recommendation_after_cross_feed(fake):
    L._cache.clear()
    L.cross_feed_from_scan(1, 1, [{"type": "path traversal", "severity": "high",
                                    "fingerprint": "fp_full"}])
    rec = L.get_recommendation(1, 1, "fp_full")
    assert rec is not None
    assert rec["attack_class"] == "path_traversal"
    assert rec["confidence"] == 0.80
    assert rec["recommended_action"]["action"] == "apply_waf_rule"
