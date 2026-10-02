"""Phase 20 regression tests: independent post-Phase-19 security
verification (docs/SECURITY_VERIFICATION_REPORT.md).

These lock in findings this pass discovered that Phase 19's own audit
missed — several were pure logic-level bugs (race conditions, a test-double
contract mismatch) that no amount of "tests pass" would have caught without
specifically targeting them, which is exactly the point of this file.
"""
import ipaddress

import pytest

from webapp import db, security
from webapp.routers import auth as auth_router
from webapp.services import connector_crypto
from conftest import register_user, auth_headers


# --- V1: rate-limiter client-IP trust boundary (CWE-290/348) ---------------
class TestClientIpTrustBoundary:
    def test_untrusted_peer_headers_are_ignored(self):
        # No HYDRAX_TRUSTED_PROXY_IPS configured (this suite's default) —
        # an attacker-supplied X-Forwarded-For must never override the real
        # TCP peer, or they could pick their own rate-limit key at will.
        class _FakeClient:
            host = "203.0.113.9"

        class _FakeRequest:
            client = _FakeClient()
            headers = {"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8"}

        assert auth_router._client_ip(_FakeRequest()) == "203.0.113.9"

    def test_trusted_proxy_peer_uses_forwarded_for(self, monkeypatch):
        monkeypatch.setattr(auth_router.config, "TRUSTED_PROXY_IPS", ["10.0.0.5"])

        class _FakeClient:
            host = "10.0.0.5"

        class _FakeRequest:
            client = _FakeClient()
            headers = {"X-Forwarded-For": "198.51.100.7, 10.0.0.5"}

        assert auth_router._client_ip(_FakeRequest()) == "198.51.100.7"

    def test_trusted_proxy_supports_cidr_ranges(self, monkeypatch):
        monkeypatch.setattr(auth_router.config, "TRUSTED_PROXY_IPS", ["10.0.0.0/8"])
        assert auth_router._is_trusted_proxy("10.1.2.3") is True
        assert auth_router._is_trusted_proxy("192.168.1.1") is False

    def test_malformed_peer_or_config_never_crashes(self, monkeypatch):
        monkeypatch.setattr(auth_router.config, "TRUSTED_PROXY_IPS", ["not-an-ip", "10.0.0.0/8"])
        assert auth_router._is_trusted_proxy("10.1.1.1") is True
        assert auth_router._is_trusted_proxy("not-an-ip-either") is False


# --- V2: refresh-token rotation race condition (CWE-362) --------------------
class TestRefreshTokenRotationRace:
    def test_rotating_an_already_rotated_token_is_rejected_not_silently_reissued(self, fake, client):
        a = register_user(client, "raceuser")
        refresh1 = a["refresh_token"]
        r1 = client.post("/api/auth/refresh", json={"refresh_token": refresh1})
        assert r1.status_code == 200
        # Simulates the race directly at the db layer: a second "concurrent"
        # rotation attempt against the SAME already-revoked row must return
        # None (lost the race), never mint a second valid token pair from
        # the same original refresh token.
        row = fake.get_refresh_token(security.hash_opaque_token(refresh1))
        assert row["revoked_at"] is not None
        new_id = fake.rotate_refresh_token(row["id"], "some-new-hash", "2099-01-01T00:00:00+00:00")
        assert new_id is None

    def test_concurrent_refresh_attempt_via_api_is_rejected_and_revokes_family(self, fake, client):
        a = register_user(client, "raceuser2")
        refresh1 = a["refresh_token"]
        r1 = client.post("/api/auth/refresh", json={"refresh_token": refresh1})
        assert r1.status_code == 200
        # Replaying the original (now-rotated) token — whether from a real
        # attacker or a lost race — must be rejected and revoke the family.
        r2 = client.post("/api/auth/refresh", json={"refresh_token": refresh1})
        assert r2.status_code == 401
        assert "revoked" in r2.json()["detail"].lower()
        # The token issued by the first (legitimate) refresh is now also dead.
        new_refresh = r1.json()["refresh_token"]
        r3 = client.post("/api/auth/refresh", json={"refresh_token": new_refresh})
        assert r3.status_code == 401

    def test_rotate_refresh_token_returns_new_id_on_success(self, fake):
        uid = fake.create_user("rotok", "rotok@hydrax.local", "hash")
        rid = fake.create_refresh_token(uid, "hash-a", "2099-01-01T00:00:00+00:00")
        new_id = fake.rotate_refresh_token(rid, "hash-b", "2099-01-01T00:00:00+00:00")
        assert new_id is not None
        assert fake.refresh_tokens[rid]["revoked_at"] is not None
        assert fake.refresh_tokens[rid]["replaced_by_id"] == new_id


# --- V3: connector job-claim race condition (CWE-362) -----------------------
class TestConnectorJobClaimRace:
    def test_get_next_pending_job_only_hands_out_a_job_once(self, fake):
        uid = fake.create_user("connowner", "connowner@hydrax.local", "hash")
        cid = fake.create_connector(1, "race-connector", "pem", "sechash", "1.0", "linux")
        job = fake.create_connector_job(1, cid, "inventory_check", {}, uid, "2099-01-01T00:00:00+00:00")
        first = fake.get_next_pending_job(cid)
        assert first is not None
        assert first["id"] == job["id"]
        second = fake.get_next_pending_job(cid)
        assert second is None  # already claimed — must not be handed out twice


# --- V4: SSRF via notification-channel URLs (CWE-918) -----------------------
class TestNotificationChannelSSRF:
    @pytest.mark.parametrize("channel_type", ["webhook", "slack", "teams"])
    def test_loopback_and_metadata_urls_are_rejected_at_creation(self, monkeypatch, fake, client, channel_type):
        # Bypass this suite's own hermetic-fixture SSRF bypass for exactly
        # this test — we want to exercise the REAL guard here, using a
        # literal IP so no actual DNS/network access occurs.
        from webapp.routers import alerts as alerts_router
        from utils.ssrf_guard import assert_safe_scan_target
        monkeypatch.setattr(alerts_router, "assert_safe_scan_target", assert_safe_scan_target)

        a = register_user(client, f"ssrf_admin_{channel_type}", organization_name=f"SSRF {channel_type} Co")
        headers = auth_headers(a["access_token"])
        for evil_url in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:6379/"):
            r = client.post("/api/notification-channels", headers=headers, json={
                "channel_type": channel_type, "name": "evil", "config": {"url": evil_url},
            })
            assert r.status_code == 422, f"{evil_url} should have been rejected"

    def test_missing_url_is_rejected(self, fake, client):
        a = register_user(client, "ssrf_nourl_admin", organization_name="SSRF NoURL Co")
        headers = auth_headers(a["access_token"])
        r = client.post("/api/notification-channels", headers=headers, json={
            "channel_type": "webhook", "name": "no-url", "config": {},
        })
        assert r.status_code == 422

    def test_email_channel_type_needs_no_url_check(self, fake, client):
        a = register_user(client, "ssrf_email_admin", organization_name="SSRF Email Co")
        headers = auth_headers(a["access_token"])
        r = client.post("/api/notification-channels", headers=headers, json={
            "channel_type": "email", "name": "email-channel", "config": {"to": "ops@example.com"},
        })
        assert r.status_code == 200, r.text

    def test_delivery_time_recheck_exists_on_all_three_url_channels(self):
        import inspect
        from webapp.services import alert_engine
        for fn in (alert_engine._deliver_webhook, alert_engine._deliver_slack, alert_engine._deliver_teams):
            src = inspect.getsource(fn)
            assert "assert_safe_scan_target" in src


# --- V5: admin_info() output allowlisting (defense in depth) ----------------
class TestAdminInfoNoSensitiveLeak:
    def test_admin_info_never_includes_password_hash_or_mfa_secret(self, fake, client):
        a = register_user(client, "admininfo_admin", organization_name="AdminInfo Co")
        headers = auth_headers(a["access_token"])
        r = client.get("/api/settings/admin", headers=headers)
        assert r.status_code == 200
        body_text = r.text
        assert "password_hash" not in body_text
        assert "mfa_secret" not in body_text
        assert a["access_token"] not in body_text

    def test_list_users_selects_only_the_safe_column_set(self, fake):
        uid = fake.create_user("safecols", "safecols@hydrax.local", "supersecrethash")
        fake.users[uid]["mfa_secret"] = "TOTP-SECRET-VALUE"
        rows = fake.list_users(1)
        row = next(r for r in rows if r["id"] == uid)
        assert "password_hash" not in row
        assert "mfa_secret" not in row
        assert "failed_login_count" not in row
        assert set(row.keys()) == set(fake._LIST_USERS_SAFE_FIELDS)


# --- V6: last-admin demotion lockout (business logic) -----------------------
class TestLastAdminLockoutPrevention:
    def test_cannot_demote_the_only_admin(self, fake, client):
        a = register_user(client, "onlyadmin", organization_name="OnlyAdmin Co")
        headers = auth_headers(a["access_token"])
        r = client.post(f"/api/settings/admin/users/{a['user']['id']}/role",
                        headers=headers, json={"role": "viewer"})
        assert r.status_code == 400
        assert "last admin" in r.json()["detail"].lower()

    def test_can_demote_an_admin_when_another_remains(self, fake, client):
        a = register_user(client, "admin1", organization_name="TwoAdmins Co")
        headers = auth_headers(a["access_token"])
        b = register_user(client, "admin2", signup_email=True)
        # role_member joins the Default Org by default, not admin1's own
        # org — put them in the same org directly, matching the established
        # pattern in test_phase3_auth_hardening.py for this exact scenario.
        fake.users[b["user"]["id"]]["organization_id"] = a["user"]["organization_id"]
        client.post(f"/api/settings/admin/users/{b['user']['id']}/role",
                   headers=headers, json={"role": "admin"})
        r = client.post(f"/api/settings/admin/users/{b['user']['id']}/role",
                        headers=headers, json={"role": "viewer"})
        assert r.status_code == 200

    def test_promoting_or_lateral_role_changes_are_unaffected(self, fake, client):
        a = register_user(client, "onlyadmin2", organization_name="OnlyAdmin2 Co")
        headers = auth_headers(a["access_token"])
        # Same role -> same role is a no-op, not a demotion, must not 400.
        r = client.post(f"/api/settings/admin/users/{a['user']['id']}/role",
                        headers=headers, json={"role": "admin"})
        assert r.status_code == 200


# --- V7: connector enrollment key-type validation ---------------------------
class TestConnectorKeyTypeValidation:
    def test_non_ed25519_public_key_is_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        with pytest.raises(ValueError, match="Ed25519"):
            connector_crypto.load_public_key(pem)

    def test_genuine_ed25519_key_still_loads(self):
        _, pub_pem = connector_crypto.generate_keypair_pem()
        key = connector_crypto.load_public_key(pub_pem)
        assert key is not None


# --- V8: FakeDB test-double fidelity (created_at) ---------------------------
class TestFakeDbUserCreatedAt:
    def test_created_at_is_present_and_usable(self, fake):
        uid = fake.create_user("hasdate", "hasdate@hydrax.local", "hash")
        assert fake.users[uid]["created_at"]
        rows = fake.list_users(1)
        row = next(r for r in rows if r["id"] == uid)
        assert row["created_at"]


# --- V9: findings dedup race condition (CWE-362) ----------------------------
class TestFindingDedupRace:
    def test_add_finding_returns_the_real_db_contract_shape(self, fake):
        uid = fake.create_user("finduser", "finduser@hydrax.local", "hash")
        tid = fake.add_target("https://race.example.com", 1)
        sid = fake.create_scan(uid, tid, "web", ["xss"])
        result = fake.add_finding(sid, {"severity": "High", "type": "xss",
                                        "evidence": "proof", "url": "https://race.example.com/x",
                                        "confidence": "confirmed"})
        assert result == {"finding_id": fake.findings[-1]["id"], "is_new_or_reopened": True}

        # Re-detecting the identical fingerprint: not new, not reopened
        # (status was NEW, not FIXED) -- occurrence_count still bumps.
        result2 = fake.add_finding(sid, {"severity": "High", "type": "xss",
                                         "evidence": "proof", "url": "https://race.example.com/x",
                                         "confidence": "confirmed"})
        assert result2["finding_id"] == result["finding_id"]
        assert result2["is_new_or_reopened"] is False
        assert fake.findings[-1]["occurrence_count"] == 2

    def test_add_finding_reports_reopened_after_a_fix(self, fake):
        uid = fake.create_user("finduser2", "finduser2@hydrax.local", "hash")
        tid = fake.add_target("https://race2.example.com", 1)
        sid = fake.create_scan(uid, tid, "web", ["xss"])
        fake.add_finding(sid, {"severity": "High", "type": "xss", "evidence": "proof",
                               "url": "https://race2.example.com/x", "confidence": "confirmed"})
        fid = fake.findings[-1]["id"]
        fake.update_finding_status(fid, 1, "FIXED")
        result = fake.add_finding(sid, {"severity": "High", "type": "xss", "evidence": "proof",
                                        "url": "https://race2.example.com/x", "confidence": "confirmed"})
        assert result["is_new_or_reopened"] is True
        assert fake.findings[-1]["status"] == "REOPENED"

    def test_web_scan_services_own_aggregation_pattern_does_not_crash(self, fake):
        """Reproduces the exact `result["is_new_or_reopened"]` access pattern
        webapp/services/web_scan_service.py and system_scan_service.py use
        right after add_finding() -- FakeDB used to return None
        unconditionally here, which would have raised TypeError the moment
        any test exercised the real scan-aggregation loop instead of
        bypassing it (as every existing test did, until this one)."""
        uid = fake.create_user("finduser3", "finduser3@hydrax.local", "hash")
        tid = fake.add_target("https://race3.example.com", 1)
        sid = fake.create_scan(uid, tid, "web", ["xss"])
        all_findings = [{"severity": "Critical", "type": "xss", "evidence": "proof",
                         "url": "https://race3.example.com/x", "confidence": "confirmed"}]
        alerted = []
        for f in all_findings:
            result = fake.add_finding(sid, f)
            if result["is_new_or_reopened"]:
                alerted.append(result["finding_id"])
        assert len(alerted) == 1
