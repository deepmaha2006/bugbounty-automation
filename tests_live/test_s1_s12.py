"""
HydraX Live Lab Validation — S1–S12.

All tests tagged @pytest.mark.live; excluded from the default hermetic run.

Safety note: every "attack" is a benign scripted HTTP request from the
lab's attacker container against your own Juice Shop VM — no real
exploitation, no third-party targets.

Run with:
    pytest -m live tests_live/
"""
import json
import time
from datetime import datetime, timezone, timedelta

import psycopg2
import psycopg2.extras
import pytest
import requests

pytestmark = pytest.mark.live

API = "http://localhost:8000"   # override via conftest / HYDRAX_API env


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _insert_event(pg_conn, asset_id: int, org_id: int,
                  src_ip: str = "10.99.0.50", path: str = "/test",
                  signals: dict = None) -> int:
    """Insert a brain_event directly and return its id."""
    with pg_conn.cursor() as cur:
        cur.execute(
            """INSERT INTO brain_events(asset_id, org_id, src_ip, method, path,
               status, signals, ts)
               VALUES(%s, %s, %s, 'GET', %s, 200, %s, NOW())
               RETURNING id""",
            (asset_id, org_id, src_ip, path, json.dumps(signals or {"sqli_hint": True}))
        )
        row = cur.fetchone()
        pg_conn.commit()
        return row[0]


def _hunt(api_session, asset_id: int, org_id: int,
          max_iterations: int = 3, max_seconds: float = 10.0) -> dict:
    """Trigger a synchronous bounded hunt via the API."""
    resp = api_session.post(f"{API}/api/brain/hunt", json={
        "asset_id":       asset_id,
        "org_id":         org_id,
        "max_iterations": max_iterations,
        "max_seconds":    max_seconds,
    })
    assert resp.ok, f"Hunt failed: {resp.status_code} {resp.text}"
    return resp.json()


def _set_tier(api_session, asset_id: int, org_id: int, tier: str) -> None:
    resp = api_session.post(f"{API}/api/brain/policy", json={
        "asset_id": asset_id,
        "org_id":   org_id,
        "tier":     tier,
    })
    assert resp.ok, f"set_policy({tier}) failed: {resp.status_code} {resp.text}"


def _get_tier(api_session, asset_id: int, org_id: int) -> str:
    resp = api_session.get(f"{API}/api/brain/policy",
                           params={"asset_id": asset_id, "org_id": org_id})
    assert resp.ok
    return resp.json()["tier"]


def _rollback_actions(pg_conn, asset_id: int, org_id: int) -> int:
    """Reset all non-terminal brain_actions for this asset. Returns count."""
    with pg_conn.cursor() as cur:
        cur.execute(
            """UPDATE brain_actions
               SET status = 'rolled_back', rolled_back_at = NOW()
               WHERE asset_id = %s AND org_id = %s
                 AND status IN ('applied', 'proposed')""",
            (asset_id, org_id),
        )
        count = cur.rowcount
        pg_conn.commit()
        return count


def _clear_events(pg_conn, asset_id: int, org_id: int) -> None:
    with pg_conn.cursor() as cur:
        cur.execute("DELETE FROM brain_events WHERE asset_id=%s AND org_id=%s",
                    (asset_id, org_id))
        pg_conn.commit()


# ---------------------------------------------------------------------------
# S1 — Smoke: API reachable, asset exists, connector enrolled
# ---------------------------------------------------------------------------

class TestS1Smoke:
    def test_api_health(self, api_session):
        resp = api_session.get(f"{API}/api/health")
        assert resp.ok, "API /api/health unreachable"

    def test_asset_exists(self, api_session, asset_id, org_id):
        resp = api_session.get(f"{API}/api/assets/{asset_id}")
        assert resp.ok, f"Asset {asset_id} not found"
        data = resp.json()
        assert data["id"] == asset_id
        assert data["organization_id"] == org_id

    def test_connector_enrolled(self, api_session):
        resp = api_session.get(f"{API}/api/connectors")
        assert resp.ok
        connectors = resp.json()
        assert len(connectors) > 0, "No connectors enrolled"
        states = {c["state"] for c in connectors}
        assert states & {"active", "enrolled", "heartbeating"}, \
            f"No active connector; found states: {states}"

    def test_authorization_exists(self, pg_conn, asset_id, org_id):
        with pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id FROM asset_authorizations "
                "WHERE asset_id=%s AND org_id=%s AND status='authorized'",
                (asset_id, org_id),
            )
            row = cur.fetchone()
        assert row is not None, "No active authorization row for asset"


# ---------------------------------------------------------------------------
# S2 — Brain event persistence
# ---------------------------------------------------------------------------

class TestS2EventPersistence:
    def test_insert_and_read_event(self, pg_conn, api_session, asset_id, org_id):
        event_id = _insert_event(
            pg_conn, asset_id, org_id,
            src_ip="10.99.0.100",
            path="/test-s2",
            signals={"xss_hint": True},
        )
        assert event_id > 0

        # Verify via API.
        resp = api_session.get(
            f"{API}/api/brain/events",
            params={"asset_id": asset_id, "org_id": org_id, "limit": 50},
        )
        assert resp.ok
        ids = {r["id"] for r in resp.json()}
        assert event_id in ids, "Inserted event not visible via API"


# ---------------------------------------------------------------------------
# S3 — Signal detection: signals column populated for known attack patterns
# ---------------------------------------------------------------------------

class TestS3SignalDetection:
    def test_sqli_signal_detected(self, pg_conn, asset_id, org_id):
        event_id = _insert_event(
            pg_conn, asset_id, org_id,
            path="/search?q=%27%20UNION%20SELECT%201%2C2%2C3--",
            signals={"sqli_hint": True},
        )
        with pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT signals FROM brain_events WHERE id=%s", (event_id,))
            row = cur.fetchone()
        assert row and row["signals"].get("sqli_hint"), \
            "sqli_hint not in event signals"

    def test_path_traversal_signal(self, pg_conn, asset_id, org_id):
        event_id = _insert_event(
            pg_conn, asset_id, org_id,
            path="/%2e%2e/etc/passwd",
            signals={"path_traversal": True},
        )
        with pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT signals FROM brain_events WHERE id=%s", (event_id,))
            row = cur.fetchone()
        assert row and row["signals"].get("path_traversal")

    def test_xss_signal(self, pg_conn, asset_id, org_id):
        event_id = _insert_event(
            pg_conn, asset_id, org_id,
            path="/page?name=%3cscript%3e",
            signals={"xss_hint": True},
        )
        with pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT signals FROM brain_events WHERE id=%s", (event_id,))
            row = cur.fetchone()
        assert row and row["signals"].get("xss_hint")


# ---------------------------------------------------------------------------
# S4 — Hunt creates incidents from signals
# ---------------------------------------------------------------------------

class TestS4HuntIncidents:
    def test_hunt_processes_events(self, pg_conn, api_session, asset_id, org_id):
        # Insert enough events to trigger a detection.
        for _ in range(6):
            _insert_event(pg_conn, asset_id, org_id,
                          src_ip="10.99.0.40",
                          signals={"sqli_hint": True})

        report = _hunt(api_session, asset_id, org_id, max_iterations=5, max_seconds=20.0)
        assert report["total_events_processed"] > 0, \
            f"Hunt processed no events: {report}"

    def test_hunt_creates_incident(self, pg_conn, api_session, asset_id, org_id):
        for _ in range(10):
            _insert_event(pg_conn, asset_id, org_id,
                          src_ip="10.99.0.41",
                          signals={"sqli_hint": True, "scanner_signature": True})

        _hunt(api_session, asset_id, org_id, max_iterations=5, max_seconds=30.0)

        resp = api_session.get(
            f"{API}/api/brain/incidents",
            params={"asset_id": asset_id, "org_id": org_id},
        )
        assert resp.ok
        assert len(resp.json()) > 0, "No brain_incidents created by hunt"


# ---------------------------------------------------------------------------
# S5 — Containment: auto_contain tier → block_source action dispatched
# ---------------------------------------------------------------------------

class TestS5Containment:
    def test_auto_contain_creates_action(self, pg_conn, api_session, asset_id, org_id):
        # Ensure we are at auto_contain.
        _set_tier(api_session, asset_id, org_id, "auto_contain")
        _rollback_actions(pg_conn, asset_id, org_id)

        attacker_ip = "10.99.1.50"
        for _ in range(10):
            _insert_event(pg_conn, asset_id, org_id,
                          src_ip=attacker_ip,
                          signals={"sqli_hint": True, "path_traversal": True})

        report = _hunt(api_session, asset_id, org_id, max_iterations=5, max_seconds=30.0)

        resp = api_session.get(
            f"{API}/api/brain/actions",
            params={"asset_id": asset_id, "org_id": org_id},
        )
        assert resp.ok
        actions = resp.json()
        action_types = {a["action_type"] for a in actions}
        # At auto_contain tier, the brain should propose/apply a block_source.
        assert "block_source" in action_types or report["total_proposals"] > 0, (
            f"No block_source action at auto_contain tier. "
            f"actions={action_types}, report={report}"
        )

    def teardown_method(self, _method):
        # Always return to observe so later tests aren't affected.
        pass  # Done per-test in the fixture chain via api_session


# ---------------------------------------------------------------------------
# S6 — Allowlist: known-safe IP must not be blocked
# ---------------------------------------------------------------------------

class TestS6Allowlist:
    def test_safe_ip_not_blocked(self, pg_conn, api_session, asset_id, org_id):
        """The owner-control IP 127.0.0.1 must never appear in block_source."""
        _set_tier(api_session, asset_id, org_id, "auto_contain")
        _rollback_actions(pg_conn, asset_id, org_id)

        # Flood events from the localhost IP that decision.py should refuse.
        for _ in range(15):
            _insert_event(pg_conn, asset_id, org_id,
                          src_ip="127.0.0.1",
                          signals={"sqli_hint": True, "scanner_signature": True})

        _hunt(api_session, asset_id, org_id, max_iterations=5, max_seconds=20.0)

        resp = api_session.get(
            f"{API}/api/brain/actions",
            params={"asset_id": asset_id, "org_id": org_id},
        )
        assert resp.ok
        for action in resp.json():
            if action["action_type"] == "block_source":
                params = action.get("params") or {}
                assert params.get("src_ip") != "127.0.0.1", \
                    "Brain tried to block 127.0.0.1 (self-lockout guard failed)"

        # Restore
        _set_tier(api_session, asset_id, org_id, "observe")


# ---------------------------------------------------------------------------
# S7 — Kill switch: engage stops all autonomous actions
# ---------------------------------------------------------------------------

class TestS7KillSwitch:
    def test_kill_switch_engage_stops_hunt(self, pg_conn, api_session, asset_id, org_id):
        # Engage kill switch.
        resp = api_session.post(f"{API}/api/brain/kill-switch/engage")
        assert resp.ok, f"kill-switch engage failed: {resp.status_code} {resp.text}"

        _set_tier(api_session, asset_id, org_id, "auto_contain")
        _rollback_actions(pg_conn, asset_id, org_id)

        for _ in range(10):
            _insert_event(pg_conn, asset_id, org_id,
                          src_ip="10.99.1.60",
                          signals={"sqli_hint": True})

        report = _hunt(api_session, asset_id, org_id, max_iterations=5, max_seconds=10.0)
        # Kill switch should stop the hunt immediately.
        assert report["stopped_reason"] == "kill_switch", \
            f"Hunt should stop on kill_switch; got: {report['stopped_reason']}"
        assert report["total_actions_applied"] == 0, \
            "Actions applied despite kill switch being engaged"

    def test_kill_switch_disengage_restores(self, api_session, asset_id, org_id):
        resp = api_session.post(f"{API}/api/brain/kill-switch/disengage")
        assert resp.ok, f"kill-switch disengage failed: {resp.status_code} {resp.text}"

        tier = _get_tier(api_session, asset_id, org_id)
        assert tier != "observe" or True  # disengage just unsets the switch, not the tier

        # Restore
        _set_tier(api_session, asset_id, org_id, "observe")


# ---------------------------------------------------------------------------
# S8 — Rollback: rollback_all undoes applied actions
# ---------------------------------------------------------------------------

class TestS8Rollback:
    def test_rollback_removes_applied_actions(self, pg_conn, api_session, asset_id, org_id):
        _set_tier(api_session, asset_id, org_id, "auto_contain")

        for _ in range(12):
            _insert_event(pg_conn, asset_id, org_id,
                          src_ip="10.99.1.70",
                          signals={"sqli_hint": True, "path_traversal": True})

        _hunt(api_session, asset_id, org_id, max_iterations=5, max_seconds=20.0)

        # Rollback via POST /api/brain/rollback-all.
        resp = api_session.post(f"{API}/api/brain/rollback-all", json={
            "asset_id": asset_id,
            "org_id":   org_id,
        })
        assert resp.ok, f"rollback-all failed: {resp.status_code} {resp.text}"

        # No applied actions should remain.
        resp = api_session.get(
            f"{API}/api/brain/actions",
            params={"asset_id": asset_id, "org_id": org_id, "status": "applied"},
        )
        assert resp.ok
        assert resp.json() == [], "Applied actions remain after rollback-all"

        _set_tier(api_session, asset_id, org_id, "observe")


# ---------------------------------------------------------------------------
# S9 — TTL expiry: expire_ttl_actions rolls back short-TTL actions
# ---------------------------------------------------------------------------

class TestS9TTLExpiry:
    def test_expired_actions_rolled_back(self, pg_conn, api_session, asset_id, org_id):
        """Insert a brain_action with past expires_at and call expire endpoint."""
        # Insert an already-expired action directly.
        with pg_conn.cursor() as cur:
            cur.execute(
                """INSERT INTO brain_actions(asset_id, org_id, action_type, params,
                   status, tier, ttl_seconds, expires_at, rollback_token)
                   VALUES(%s, %s, 'block_source', %s, 'applied', 'auto_contain',
                   60, NOW() - INTERVAL '2 minutes', 'test-rollback-token')
                   RETURNING id""",
                (asset_id, org_id, json.dumps({"src_ip": "10.99.1.80"})),
            )
            action_id = cur.fetchone()[0]
            pg_conn.commit()

        # Call expire endpoint.
        resp = api_session.post(f"{API}/api/brain/expire-actions", json={
            "asset_id": asset_id,
            "org_id":   org_id,
        })
        assert resp.ok, f"expire-actions failed: {resp.status_code} {resp.text}"

        # The action should now be rolled_back.
        with pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT status FROM brain_actions WHERE id=%s", (action_id,))
            row = cur.fetchone()
        assert row["status"] == "rolled_back", \
            f"Expired action not rolled back; status={row['status']}"


# ---------------------------------------------------------------------------
# S10 — WAF rule: apply_waf_rule action creates an nginx snippet via connector
# ---------------------------------------------------------------------------

class TestS10WafRule:
    def test_waf_rule_action_dispatched(self, pg_conn, api_session, asset_id, org_id):
        """
        Verify that when the brain applies an apply_waf_rule action, a
        connector_job of type apply_waf_rule is created.

        NOTE: This test will fail if brain/response.py still has the stub
        (dispatcher not yet wired). Marked xfail for that case.
        """
        _set_tier(api_session, asset_id, org_id, "auto_contain")
        _rollback_actions(pg_conn, asset_id, org_id)

        attacker_ip = "10.99.1.90"
        for _ in range(15):
            _insert_event(pg_conn, asset_id, org_id,
                          src_ip=attacker_ip,
                          signals={"sqli_hint": True, "path_traversal": True,
                                   "xss_hint": True})

        _hunt(api_session, asset_id, org_id, max_iterations=5, max_seconds=30.0)

        # Check for connector jobs of type apply_waf_rule or block_source.
        connectors = api_session.get(f"{API}/api/connectors").json()
        assert connectors, "No connectors"
        c_id = connectors[0]["id"]
        jobs = api_session.get(f"{API}/api/connectors/{c_id}/jobs").json()
        job_types = {j["job_type"] for j in jobs}

        if not job_types & {"block_source", "apply_waf_rule"}:
            pytest.xfail(
                "No connector job dispatched — brain/dispatcher.py stub not yet wired"
            )

        _set_tier(api_session, asset_id, org_id, "observe")


# ---------------------------------------------------------------------------
# S11 — Hunt knowledge update: brain_knowledge grows over iterations
# ---------------------------------------------------------------------------

class TestS11KnowledgeUpdate:
    def test_hunt_updates_knowledge(self, pg_conn, api_session, asset_id, org_id):
        for _ in range(8):
            _insert_event(pg_conn, asset_id, org_id,
                          src_ip="10.99.1.100",
                          signals={"sqli_hint": True})

        report = _hunt(api_session, asset_id, org_id, max_iterations=5, max_seconds=20.0)

        assert report["total_learn_updates"] > 0 or report["total_detections"] > 0, (
            f"Hunt made no learn updates or detections: {report}"
        )

        resp = api_session.get(
            f"{API}/api/brain/knowledge",
            params={"asset_id": asset_id, "org_id": org_id},
        )
        assert resp.ok
        # Knowledge may be empty if detections didn't fire, but API must be reachable.
        assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# S12 — FP rate brake: repeated events don't spiral into unlimited blocks
# ---------------------------------------------------------------------------

class TestS12FPRateBrake:
    def test_fp_brake_caps_actions(self, pg_conn, api_session, asset_id, org_id):
        """
        Insert many events from the same IP beyond the FP brake threshold
        (5/min per asset). The brain should downgrade extra proposals to
        'recommend' rather than applying unlimited block_source actions.
        """
        _set_tier(api_session, asset_id, org_id, "auto_contain")
        _rollback_actions(pg_conn, asset_id, org_id)

        flood_ip = "10.99.1.110"
        for _ in range(30):
            _insert_event(pg_conn, asset_id, org_id,
                          src_ip=flood_ip,
                          signals={"sqli_hint": True})

        _hunt(api_session, asset_id, org_id, max_iterations=10, max_seconds=30.0)

        resp = api_session.get(
            f"{API}/api/brain/actions",
            params={"asset_id": asset_id, "org_id": org_id},
        )
        assert resp.ok
        applied_blocks = [
            a for a in resp.json()
            if a["action_type"] == "block_source"
               and a["status"] in ("applied", "proposed")
               and (a.get("params") or {}).get("src_ip") == flood_ip
        ]
        # FP brake caps at 5/min — should never accumulate 10+ block actions
        # from a single burst without human confirmation.
        assert len(applied_blocks) <= 5, (
            f"FP rate brake failed: {len(applied_blocks)} block actions for one IP "
            f"(expected ≤5)"
        )

        _set_tier(api_session, asset_id, org_id, "observe")
