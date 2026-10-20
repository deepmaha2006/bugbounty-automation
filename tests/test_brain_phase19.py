"""
Phase 19: Brain API + Celery integration.

Tests:
  DB layer
  • brain_list_knowledge returns empty list when no records
  • brain_list_knowledge returns records for correct asset/org only
  • brain_list_knowledge orders by confidence descending
  • brain_list_knowledge respects limit
  • brain_list_authorized_assets returns empty list when no authorizations
  • brain_list_authorized_assets returns asset/org pairs for authorized assets
  • brain_list_authorized_assets deduplicates same asset
  • brain_list_authorized_assets ignores non-authorized rows

  Schema
  • BrainPolicyRequest accepts valid tiers
  • BrainPolicyRequest rejects invalid tier
  • BrainHuntRequest uses defaults
  • BrainHuntRequest rejects out-of-range max_iterations
  • BrainHuntRequest rejects out-of-range max_seconds

  Celery tasks
  • _run_brain_hunt returns dict with stopped_reason key
  • _run_brain_hunt returns dict with asset_id
  • _check_due_brain_hunts with no authorized assets enqueues 0
  • _check_due_brain_hunts enqueues one call per authorized asset
  • _check_due_brain_hunts passes correct asset_id and org_id to enqueue

  HTTP endpoints (via TestClient)
  • GET /api/brain/actions requires auth
  • GET /api/brain/actions returns list for authorized user
  • GET /api/brain/actions cross-org returns 403
  • GET /api/brain/knowledge requires auth
  • GET /api/brain/knowledge returns list
  • GET /api/brain/knowledge cross-org returns 403
  • GET /api/brain/policy requires auth
  • GET /api/brain/policy returns tier field
  • GET /api/brain/policy cross-org returns 403
  • POST /api/brain/policy requires auth
  • POST /api/brain/policy sets tier and GET reflects it
  • POST /api/brain/policy invalid tier returns 422
  • POST /api/brain/policy cross-org returns 403
  • POST /api/brain/hunt requires auth
  • POST /api/brain/hunt returns stopped_reason
  • POST /api/brain/hunt cross-org returns 403
  • POST /api/brain/hunt invalid max_iterations returns 422
"""
import dataclasses

import pytest

import webapp.db as db  # noqa: F401 — FakeDB patch active via conftest
from brain.autonomy import AutonomyPolicy, AutonomyTier, set_policy
from brain.learning import _cache as _learn_cache
from conftest import auth_headers, register_user
from webapp.schemas import BrainHuntRequest, BrainPolicyRequest
from webapp.tasks import _check_due_brain_hunts, _run_brain_hunt


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_auth(fake, asset_id=1, org_id=1):
    fake.record_asset_authorization(
        organization_id=org_id,
        asset_id=asset_id,
        authorized_by_user_id=1,
        method="engagement_letter",
        status="authorized",
        expires_at=None,
    )


def _seed_knowledge(fake, asset_id=1, org_id=1, fingerprint="fp1",
                    attack_class="xss", confidence=0.7):
    fake.brain_upsert_knowledge(
        asset_id=asset_id, org_id=org_id,
        signature_fingerprint=fingerprint,
        attack_class=attack_class,
        recommended_action={"action": "apply_waf_rule"},
        remediation={"summary": "Encode output"},
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# DB layer: brain_list_knowledge
# ---------------------------------------------------------------------------

def test_brain_list_knowledge_empty(fake):
    assert fake.brain_list_knowledge(1, 1) == []


def test_brain_list_knowledge_returns_matching_records(fake):
    _seed_knowledge(fake, asset_id=1, org_id=1, fingerprint="fp1")
    _seed_knowledge(fake, asset_id=1, org_id=1, fingerprint="fp2")
    rows = fake.brain_list_knowledge(1, 1)
    assert len(rows) == 2


def test_brain_list_knowledge_filters_by_asset_org(fake):
    _seed_knowledge(fake, asset_id=1, org_id=1, fingerprint="fp1")
    _seed_knowledge(fake, asset_id=2, org_id=1, fingerprint="fp2")
    rows = fake.brain_list_knowledge(1, 1)
    assert len(rows) == 1
    assert rows[0]["signature_fingerprint"] == "fp1"


def test_brain_list_knowledge_orders_by_confidence_desc(fake):
    _seed_knowledge(fake, fingerprint="low", confidence=0.3)
    _seed_knowledge(fake, fingerprint="high", confidence=0.9)
    _seed_knowledge(fake, fingerprint="mid", confidence=0.6)
    rows = fake.brain_list_knowledge(1, 1)
    confidences = [r["confidence"] for r in rows]
    assert confidences == sorted(confidences, reverse=True)


def test_brain_list_knowledge_respects_limit(fake):
    for i in range(5):
        _seed_knowledge(fake, fingerprint=f"fp{i}", confidence=float(i) / 10)
    rows = fake.brain_list_knowledge(1, 1, limit=3)
    assert len(rows) == 3


# ---------------------------------------------------------------------------
# DB layer: brain_list_authorized_assets
# ---------------------------------------------------------------------------

def test_brain_list_authorized_assets_empty(fake):
    assert fake.brain_list_authorized_assets() == []


def test_brain_list_authorized_assets_returns_authorized(fake):
    _seed_auth(fake, asset_id=1, org_id=1)
    result = fake.brain_list_authorized_assets()
    assert len(result) == 1
    assert result[0]["asset_id"] == 1
    assert result[0]["organization_id"] == 1


def test_brain_list_authorized_assets_deduplicates(fake):
    _seed_auth(fake, asset_id=1, org_id=1)
    _seed_auth(fake, asset_id=1, org_id=1)
    result = fake.brain_list_authorized_assets()
    assert len(result) == 1


def test_brain_list_authorized_assets_ignores_non_authorized(fake):
    fake.record_asset_authorization(
        organization_id=1, asset_id=1, authorized_by_user_id=1,
        method="engagement_letter", status="pending", expires_at=None,
    )
    result = fake.brain_list_authorized_assets()
    assert result == []


# ---------------------------------------------------------------------------
# Schema: BrainPolicyRequest
# ---------------------------------------------------------------------------

def test_brain_policy_request_valid_tiers():
    for tier in ("observe", "recommend", "auto_contain", "auto_remediate"):
        m = BrainPolicyRequest(asset_id=1, org_id=1, tier=tier)
        assert m.tier == tier


def test_brain_policy_request_invalid_tier():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        BrainPolicyRequest(asset_id=1, org_id=1, tier="destroy")


# ---------------------------------------------------------------------------
# Schema: BrainHuntRequest
# ---------------------------------------------------------------------------

def test_brain_hunt_request_defaults():
    m = BrainHuntRequest(asset_id=1, org_id=1)
    assert m.max_iterations == 5
    assert m.max_seconds == 30.0
    assert m.last_event_id == 0


def test_brain_hunt_request_invalid_max_iterations():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        BrainHuntRequest(asset_id=1, org_id=1, max_iterations=0)


def test_brain_hunt_request_invalid_max_seconds():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        BrainHuntRequest(asset_id=1, org_id=1, max_seconds=0.5)


# ---------------------------------------------------------------------------
# Celery tasks
# ---------------------------------------------------------------------------

def test_run_brain_hunt_returns_dict_with_stopped_reason(fake):
    _learn_cache.clear()
    _seed_auth(fake)
    result = _run_brain_hunt(1, 1, max_iterations=1, max_seconds=30.0)
    assert isinstance(result, dict)
    assert "stopped_reason" in result


def test_run_brain_hunt_returns_asset_id(fake):
    _learn_cache.clear()
    _seed_auth(fake)
    result = _run_brain_hunt(1, 1, max_iterations=1, max_seconds=30.0)
    assert result["asset_id"] == 1


def test_check_due_brain_hunts_no_assets_enqueues_zero(fake):
    calls = []
    count = _check_due_brain_hunts(enqueue=lambda a, o: calls.append((a, o)))
    assert count == 0
    assert calls == []


def test_check_due_brain_hunts_enqueues_authorized_assets(fake):
    _seed_auth(fake, asset_id=1, org_id=1)
    _seed_auth(fake, asset_id=2, org_id=1)
    calls = []
    count = _check_due_brain_hunts(enqueue=lambda a, o: calls.append((a, o)))
    assert count == 2
    assert len(calls) == 2


def test_check_due_brain_hunts_passes_correct_ids(fake):
    _seed_auth(fake, asset_id=42, org_id=7)
    calls = []
    _check_due_brain_hunts(enqueue=lambda a, o: calls.append((a, o)))
    assert (42, 7) in calls


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------

@pytest.fixture()
def op_headers(client):
    """Operator-level user, registered as first user (auto-admin)."""
    return auth_headers(register_user(client, "brainop")["access_token"])


def test_brain_actions_requires_auth(client):
    r = client.get("/api/brain/actions", params={"asset_id": 1, "org_id": 1})
    assert r.status_code == 401


def test_brain_actions_returns_list(client, op_headers):
    r = client.get("/api/brain/actions",
                   headers=op_headers,
                   params={"asset_id": 1, "org_id": 1})
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_brain_actions_cross_org_403(client, op_headers):
    r = client.get("/api/brain/actions",
                   headers=op_headers,
                   params={"asset_id": 1, "org_id": 999})
    assert r.status_code == 403


def test_brain_knowledge_requires_auth(client):
    r = client.get("/api/brain/knowledge", params={"asset_id": 1, "org_id": 1})
    assert r.status_code == 401


def test_brain_knowledge_returns_list(client, op_headers):
    r = client.get("/api/brain/knowledge",
                   headers=op_headers,
                   params={"asset_id": 1, "org_id": 1})
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_brain_knowledge_cross_org_403(client, op_headers):
    r = client.get("/api/brain/knowledge",
                   headers=op_headers,
                   params={"asset_id": 1, "org_id": 999})
    assert r.status_code == 403


def test_brain_policy_get_requires_auth(client):
    r = client.get("/api/brain/policy", params={"asset_id": 1, "org_id": 1})
    assert r.status_code == 401


def test_brain_policy_get_returns_tier(client, op_headers):
    r = client.get("/api/brain/policy",
                   headers=op_headers,
                   params={"asset_id": 1, "org_id": 1})
    assert r.status_code == 200
    body = r.json()
    assert "tier" in body
    assert body["tier"] in ("observe", "recommend", "auto_contain", "auto_remediate")


def test_brain_policy_get_cross_org_403(client, op_headers):
    r = client.get("/api/brain/policy",
                   headers=op_headers,
                   params={"asset_id": 1, "org_id": 999})
    assert r.status_code == 403


def test_brain_policy_post_requires_auth(client):
    r = client.post("/api/brain/policy",
                    json={"asset_id": 1, "org_id": 1, "tier": "observe"})
    assert r.status_code == 401


def test_brain_policy_post_and_get_roundtrip(client, op_headers):
    r = client.post("/api/brain/policy",
                    headers=op_headers,
                    json={"asset_id": 1, "org_id": 1, "tier": "recommend"})
    assert r.status_code == 200
    assert r.json()["tier"] == "recommend"
    r2 = client.get("/api/brain/policy",
                    headers=op_headers,
                    params={"asset_id": 1, "org_id": 1})
    assert r2.json()["tier"] == "recommend"


def test_brain_policy_post_invalid_tier_422(client, op_headers):
    r = client.post("/api/brain/policy",
                    headers=op_headers,
                    json={"asset_id": 1, "org_id": 1, "tier": "nuke"})
    assert r.status_code == 422


def test_brain_policy_post_cross_org_403(client, op_headers):
    r = client.post("/api/brain/policy",
                    headers=op_headers,
                    json={"asset_id": 1, "org_id": 999, "tier": "observe"})
    assert r.status_code == 403


def test_brain_hunt_requires_auth(client):
    r = client.post("/api/brain/hunt",
                    json={"asset_id": 1, "org_id": 1})
    assert r.status_code == 401


def test_brain_hunt_returns_stopped_reason(client, op_headers, fake):
    _learn_cache.clear()
    _seed_auth(fake)
    r = client.post("/api/brain/hunt",
                    headers=op_headers,
                    json={"asset_id": 1, "org_id": 1,
                          "max_iterations": 1, "max_seconds": 10.0})
    assert r.status_code == 200
    body = r.json()
    assert "stopped_reason" in body
    assert body["asset_id"] == 1


def test_brain_hunt_cross_org_403(client, op_headers):
    r = client.post("/api/brain/hunt",
                    headers=op_headers,
                    json={"asset_id": 1, "org_id": 999,
                          "max_iterations": 1, "max_seconds": 10.0})
    assert r.status_code == 403


def test_brain_hunt_invalid_max_iterations_422(client, op_headers):
    r = client.post("/api/brain/hunt",
                    headers=op_headers,
                    json={"asset_id": 1, "org_id": 1,
                          "max_iterations": 0, "max_seconds": 10.0})
    assert r.status_code == 422
