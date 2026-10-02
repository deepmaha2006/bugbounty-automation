"""Phase 3 regression tests: RBAC, account lockout, MFA, refresh-token
rotation with reuse detection, and API keys (CVM platform spec §17/§18).
"""
import pyotp
import pytest

from conftest import register_user, auth_headers


class TestRBAC:
    def test_viewer_can_read_but_not_write(self, fake, client):
        a = register_user(client, "rbac_admin", organization_name="RBAC Co")
        ha = auth_headers(a["access_token"])
        fake.set_user_role(a["user"]["id"], "viewer")

        # Reads still work
        assert client.get("/api/assets", headers=ha).status_code == 200
        assert client.get("/api/dashboard/stats", headers=ha).status_code == 200

        # Writes are refused
        r = client.post("/api/assets", headers=ha,
                        json={"name": "x", "asset_type": "WEB_APPLICATION", "url": "https://x.example.com"})
        assert r.status_code == 403
        r2 = client.put("/api/settings", headers=ha, json={"accent": "#000000"})
        assert r2.status_code == 403

    def test_security_analyst_can_operate_but_not_administer(self, fake, client):
        a = register_user(client, "analyst_admin", organization_name="Analyst Co")
        ha = auth_headers(a["access_token"])
        fake.set_user_role(a["user"]["id"], "security_analyst")

        r = client.post("/api/assets", headers=ha,
                        json={"name": "x", "asset_type": "WEB_APPLICATION", "url": "https://analyst.example.com"})
        assert r.status_code == 200, r.text

        # Still not admin-only routes
        assert client.get("/api/settings/admin", headers=ha).status_code == 403
        assert client.put("/api/settings", headers=ha, json={"accent": "#111111"}).status_code == 403

    def test_admin_can_change_another_users_role_and_it_is_audited(self, fake, client):
        a = register_user(client, "role_admin", organization_name="Role Co")
        b = register_user(client, "role_member", signup_email=True)
        # role_member joined the Default Org (no organization_name), not
        # role_admin's org — use FakeDB directly to put them in the same org
        # for this test, since role changes are org-scoped.
        fake.users[b["user"]["id"]]["organization_id"] = a["user"]["organization_id"]
        ha = auth_headers(a["access_token"])

        r = client.post(f"/api/settings/admin/users/{b['user']['id']}/role",
                        headers=ha, json={"role": "security_manager"})
        assert r.status_code == 200, r.text
        assert fake.users[b["user"]["id"]]["role"] == "security_manager"
        assert any(e["action"] == "role_changed" for e in fake.audit)

    def test_invalid_role_value_rejected(self, fake, client):
        a = register_user(client, "bad_role_admin", organization_name="Bad Role Co")
        ha = auth_headers(a["access_token"])
        r = client.post(f"/api/settings/admin/users/{a['user']['id']}/role",
                        headers=ha, json={"role": "superuser"})
        assert r.status_code == 422


class TestAccountLockout:
    """Simulates failures directly against FakeDB's record_login_failure —
    the sliding-window AuthLimiter (5 attempts/15min, see test_auth_rate_limit.py)
    would otherwise 429 long before ACCOUNT_LOCKOUT_THRESHOLD (10) failed HTTP
    login attempts could ever be reached; the two mechanisms are independent
    and tested independently."""

    def test_locks_after_threshold_then_correct_password_still_rejected(self, fake, client):
        from webapp import config as wcfg
        a = register_user(client, "lockout_user", organization_name="Lockout Co")
        uid = a["user"]["id"]
        for _ in range(wcfg.ACCOUNT_LOCKOUT_THRESHOLD):
            fake.record_login_failure(uid, wcfg.ACCOUNT_LOCKOUT_THRESHOLD,
                                      wcfg.ACCOUNT_LOCKOUT_DURATION_MINUTES)
        assert fake.users[uid]["locked_until"] is not None

        # Even the correct password is now refused — the account is locked,
        # not just the sliding-window rate limit (which resets much sooner).
        r = client.post("/api/auth/login", json={"username": "lockout_user", "password": "passw0rd1234"})
        assert r.status_code == 403
        assert "locked" in r.json()["detail"].lower()

    def test_admin_unlock_clears_lockout(self, fake, client):
        from webapp import config as wcfg
        a = register_user(client, "unlock_admin", organization_name="Unlock Co")
        b = register_user(client, "unlock_member", signup_email=True)
        fake.users[b["user"]["id"]]["organization_id"] = a["user"]["organization_id"]
        buid = b["user"]["id"]
        for _ in range(wcfg.ACCOUNT_LOCKOUT_THRESHOLD):
            fake.record_login_failure(buid, wcfg.ACCOUNT_LOCKOUT_THRESHOLD,
                                      wcfg.ACCOUNT_LOCKOUT_DURATION_MINUTES)
        assert client.post("/api/auth/login",
                           json={"username": "unlock_member", "password": "passw0rd1234"}).status_code == 403

        ha = auth_headers(a["access_token"])
        r = client.post(f"/api/settings/admin/users/{buid}/unlock", headers=ha)
        assert r.status_code == 200

        r2 = client.post("/api/auth/login", json={"username": "unlock_member", "password": "passw0rd1234"})
        assert r2.status_code == 200

    def test_successful_login_resets_failure_count(self, fake, client):
        register_user(client, "reset_user", organization_name="Reset Co")
        client.post("/api/auth/login", json={"username": "reset_user", "password": "wrong"})
        client.post("/api/auth/login", json={"username": "reset_user", "password": "wrong"})
        assert client.post("/api/auth/login",
                           json={"username": "reset_user", "password": "passw0rd1234"}).status_code == 200
        uid = next(u["id"] for u in fake.users.values() if u["username"] == "reset_user")
        assert fake.users[uid]["failed_login_count"] == 0


class TestMFA:
    def test_setup_enable_then_login_requires_code(self, fake, client):
        a = register_user(client, "mfa_user", organization_name="MFA Co")
        ha = auth_headers(a["access_token"])

        setup = client.post("/api/auth/mfa/setup", headers=ha).json()
        secret = setup["secret"]
        assert "otpauth://" in setup["otpauth_url"]

        code = pyotp.TOTP(secret).now()
        r = client.post("/api/auth/mfa/enable", headers=ha, json={"code": code})
        assert r.status_code == 200, r.text

        # Plain login no longer returns tokens directly
        login = client.post("/api/auth/login", json={"username": "mfa_user", "password": "passw0rd1234"}).json()
        assert login.get("mfa_required") is True
        mfa_token = login["mfa_token"]

        # Wrong code rejected
        bad = client.post("/api/auth/mfa/verify", json={"mfa_token": mfa_token, "code": "000000"})
        assert bad.status_code == 401

        # Right code issues real tokens
        good = client.post("/api/auth/mfa/verify",
                           json={"mfa_token": mfa_token, "code": pyotp.TOTP(secret).now()})
        assert good.status_code == 200, good.text
        body = good.json()
        assert "access_token" in body and "refresh_token" in body

    def test_mfa_pending_token_is_not_a_valid_bearer_token(self, fake, client):
        a = register_user(client, "mfa_bearer_user", organization_name="MFA Bearer Co")
        ha = auth_headers(a["access_token"])
        setup = client.post("/api/auth/mfa/setup", headers=ha).json()
        client.post("/api/auth/mfa/enable", headers=ha,
                   json={"code": pyotp.TOTP(setup["secret"]).now()})
        login = client.post("/api/auth/login",
                            json={"username": "mfa_bearer_user", "password": "passw0rd1234"}).json()
        # The mfa_token must never work as a normal Authorization bearer token.
        r = client.get("/api/auth/me", headers=auth_headers(login["mfa_token"]))
        assert r.status_code == 401

    def test_disable_requires_password_and_code(self, fake, client):
        a = register_user(client, "mfa_off_user", organization_name="MFA Off Co")
        ha = auth_headers(a["access_token"])
        setup = client.post("/api/auth/mfa/setup", headers=ha).json()
        client.post("/api/auth/mfa/enable", headers=ha,
                   json={"code": pyotp.TOTP(setup["secret"]).now()})

        # Wrong password refused
        bad = client.post("/api/auth/mfa/disable", headers=ha,
                          json={"password": "wrong", "code": pyotp.TOTP(setup["secret"]).now()})
        assert bad.status_code == 401

        good = client.post("/api/auth/mfa/disable", headers=ha,
                           json={"password": "passw0rd1234", "code": pyotp.TOTP(setup["secret"]).now()})
        assert good.status_code == 200
        # Login is back to issuing tokens directly
        login = client.post("/api/auth/login",
                            json={"username": "mfa_off_user", "password": "passw0rd1234"})
        assert "access_token" in login.json()


class TestRefreshTokenRotation:
    def test_refresh_issues_new_pair_and_old_stops_working(self, fake, client):
        a = register_user(client, "refresh_user", organization_name="Refresh Co")
        old_refresh = a["refresh_token"]

        r = client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
        assert r.status_code == 200, r.text
        new_tokens = r.json()
        assert new_tokens["refresh_token"] != old_refresh

        # New access token actually works
        assert client.get("/api/auth/me",
                          headers=auth_headers(new_tokens["access_token"])).status_code == 200

    def test_reused_refresh_token_revokes_whole_family(self, fake, client):
        a = register_user(client, "reuse_user", organization_name="Reuse Co")
        old_refresh = a["refresh_token"]

        first = client.post("/api/auth/refresh", json={"refresh_token": old_refresh}).json()

        # Replaying the already-rotated-away token is reuse — must be rejected
        # and must kill the legitimately-rotated token too (family-wide revoke).
        replay = client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
        assert replay.status_code == 401

        now_dead = client.post("/api/auth/refresh", json={"refresh_token": first["refresh_token"]})
        assert now_dead.status_code == 401

    def test_logout_revokes_the_refresh_token(self, fake, client):
        a = register_user(client, "logout_user", organization_name="Logout Co")
        ha = auth_headers(a["access_token"])
        r = client.post("/api/auth/logout", headers=ha, json={"refresh_token": a["refresh_token"]})
        assert r.status_code == 200
        r2 = client.post("/api/auth/refresh", json={"refresh_token": a["refresh_token"]})
        assert r2.status_code == 401

    def test_expired_refresh_token_rejected(self, fake, client):
        from datetime import datetime, timedelta, timezone
        a = register_user(client, "expired_user", organization_name="Expired Co")
        # Force the stored expiry into the past.
        for r in fake.refresh_tokens.values():
            r["expires_at"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        r = client.post("/api/auth/refresh", json={"refresh_token": a["refresh_token"]})
        assert r.status_code == 401


class TestApiKeys:
    def test_create_list_and_use_key(self, fake, client):
        a = register_user(client, "apikey_admin", organization_name="ApiKey Co")
        ha = auth_headers(a["access_token"])

        created = client.post("/api/settings/api-keys", headers=ha, json={"name": "CI key"})
        assert created.status_code == 200, created.text
        raw_key = created.json()["api_key"]
        assert raw_key.startswith("hdx_")

        listing = client.get("/api/settings/api-keys", headers=ha).json()
        assert len(listing) == 1
        assert "api_key" not in listing[0]  # never shown again

        # The raw key authenticates a normal viewer-tier route
        r = client.get("/api/assets", headers={"X-API-Key": raw_key})
        assert r.status_code == 200

    def test_revoked_key_stops_working(self, fake, client):
        a = register_user(client, "revoke_admin", organization_name="Revoke Co")
        ha = auth_headers(a["access_token"])
        created = client.post("/api/settings/api-keys", headers=ha, json={"name": "temp"}).json()
        raw_key = created["api_key"]

        assert client.get("/api/assets", headers={"X-API-Key": raw_key}).status_code == 200
        rr = client.delete(f"/api/settings/api-keys/{created['id']}", headers=ha)
        assert rr.status_code == 200
        assert client.get("/api/assets", headers={"X-API-Key": raw_key}).status_code == 401

    def test_api_key_scoped_to_its_own_organization(self, fake, client):
        a, b = (register_user(client, "org1_admin", organization_name="Org1"),
               register_user(client, "org2_admin", signup_email=True, organization_name="Org2"))
        ha = auth_headers(a["access_token"])
        raw_key = client.post("/api/settings/api-keys", headers=ha, json={"name": "org1-key"}).json()["api_key"]

        client.post("/api/assets", headers=ha,
                   json={"name": "Org1 Asset", "asset_type": "WEB_APPLICATION", "url": "https://org1.example.com"})
        via_key = client.get("/api/assets", headers={"X-API-Key": raw_key}).json()
        assert len(via_key) == 1 and via_key[0]["organization_id"] == a["user"]["organization_id"]

    def test_wrong_key_rejected(self, fake, client):
        register_user(client, "wrongkey_admin", organization_name="WrongKey Co")
        r = client.get("/api/assets", headers={"X-API-Key": "hdx_not_a_real_key"})
        assert r.status_code == 401
