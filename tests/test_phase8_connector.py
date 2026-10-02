"""Phase 8 regression tests: the Company Connector's enrollment, signed-job,
and signed-result protocol (CVM platform spec §5, §6).

Crypto is real throughout — genuine Ed25519 keypairs generated per test,
genuine signing and verification via webapp/services/connector_crypto.py.
No mocking of the cryptographic layer at all; this is the same kind of
"actually testable without external infrastructure" case as Phase 9's real
local-http-server webhook tests.
"""
from datetime import datetime, timedelta, timezone

from webapp.services import connector_crypto
from conftest import register_user, auth_headers


def _enroll(client, ha, name="test-connector"):
    """Full enrollment flow: admin issues a token, "the connector" (this
    test, playing that role) generates a real keypair and enrolls with it.
    Returns (connector_id, connector_secret, priv_key_pem, platform_pub_pem).
    """
    token = client.post("/api/connectors/enrollment-tokens", headers=ha).json()["enrollment_token"]
    priv_pem, pub_pem = connector_crypto.generate_keypair_pem()
    r = client.post("/api/connectors/enroll", json={
        "enrollment_token": token, "name": name, "public_key_pem": pub_pem,
        "version": "1.0.0", "os": "Linux",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    return body["connector_id"], body["connector_secret"], priv_pem, body["platform_public_key_pem"]


class TestEnrollment:
    def test_full_enrollment_flow(self, fake, client):
        a = register_user(client, "conn_admin", organization_name="Conn Co")
        ha = auth_headers(a["access_token"])
        connector_id, secret, priv_pem, platform_pub_pem = _enroll(client, ha)
        assert connector_id is not None
        assert secret
        # The connector can now authenticate itself with the secret.
        r = client.post("/api/connectors/me/heartbeat",
                        headers={"X-Connector-Secret": secret}, json={"version": "1.0.0", "os": "Linux"})
        assert r.status_code == 200
        assert r.json()["state"] == "ONLINE"

    def test_token_cannot_be_reused(self, fake, client):
        a = register_user(client, "reuse_conn_admin", organization_name="ReuseConn Co")
        ha = auth_headers(a["access_token"])
        token = client.post("/api/connectors/enrollment-tokens", headers=ha).json()["enrollment_token"]
        _, pub_pem = connector_crypto.generate_keypair_pem()
        body = {"enrollment_token": token, "name": "c1", "public_key_pem": pub_pem}
        assert client.post("/api/connectors/enroll", json=body).status_code == 200
        r2 = client.post("/api/connectors/enroll", json={**body, "name": "c2"})
        assert r2.status_code == 401

    def test_expired_token_rejected(self, fake, client):
        a = register_user(client, "expired_conn_admin", organization_name="ExpiredConn Co")
        token_id = fake.create_enrollment_token(
            a["user"]["organization_id"], a["user"]["id"], "some-hash",
            (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat())
        # Recompute via the real hash so get_enrollment_token can find it.
        from webapp import security
        raw = "expired-token-value"
        fake.connector_enrollment_tokens[token_id]["token_hash"] = security.hash_opaque_token(raw)
        _, pub_pem = connector_crypto.generate_keypair_pem()
        r = client.post("/api/connectors/enroll",
                        json={"enrollment_token": raw, "name": "x", "public_key_pem": pub_pem})
        assert r.status_code == 401

    def test_invalid_public_key_rejected(self, fake, client):
        a = register_user(client, "badkey_conn_admin", organization_name="BadKeyConn Co")
        ha = auth_headers(a["access_token"])
        token = client.post("/api/connectors/enrollment-tokens", headers=ha).json()["enrollment_token"]
        r = client.post("/api/connectors/enroll",
                        json={"enrollment_token": token, "name": "x", "public_key_pem": "not a real key"})
        assert r.status_code == 422

    def test_wrong_secret_rejected(self, fake, client):
        a = register_user(client, "wrongsecret_admin", organization_name="WrongSecret Co")
        ha = auth_headers(a["access_token"])
        _enroll(client, ha)
        r = client.post("/api/connectors/me/heartbeat",
                        headers={"X-Connector-Secret": "totally-wrong"}, json={})
        assert r.status_code == 401


class TestSignedJobLifecycle:
    def test_job_is_created_signed_and_verifiable(self, fake, client):
        a = register_user(client, "job_admin", organization_name="Job Co")
        ha = auth_headers(a["access_token"])
        connector_id, secret, priv_pem, platform_pub_pem = _enroll(client, ha)

        r = client.post(f"/api/connectors/{connector_id}/jobs", headers=ha,
                        json={"job_type": "inventory_check", "scope": {"paths": ["/etc"]}})
        assert r.status_code == 200, r.text

        polled = client.get("/api/connectors/me/jobs/next", headers={"X-Connector-Secret": secret})
        assert polled.status_code == 200
        job = polled.json()
        assert job["job_type"] == "inventory_check"

        # The connector independently verifies the signature against the
        # platform public key it received at enrollment — real crypto.
        payload = {"job_id": job["job_id"], "organization_id": job["organization_id"],
                  "connector_id": job["connector_id"], "job_type": job["job_type"],
                  "scope": job["scope"], "authorization": job["authorization"],
                  "created_at": job["created_at"], "expires_at": job["expires_at"]}
        assert connector_crypto.verify(platform_pub_pem, payload, job["signature"])

    def test_tampered_job_signature_fails_verification(self, fake, client):
        a = register_user(client, "tamper_admin", organization_name="Tamper Co")
        ha = auth_headers(a["access_token"])
        connector_id, secret, priv_pem, platform_pub_pem = _enroll(client, ha)
        client.post(f"/api/connectors/{connector_id}/jobs", headers=ha,
                   json={"job_type": "telemetry_collection", "scope": {}})
        job = client.get("/api/connectors/me/jobs/next", headers={"X-Connector-Secret": secret}).json()

        tampered_payload = {"job_id": job["job_id"], "organization_id": job["organization_id"],
                            "connector_id": job["connector_id"], "job_type": "configuration_check",  # tampered!
                            "scope": job["scope"], "authorization": job["authorization"],
                            "created_at": job["created_at"], "expires_at": job["expires_at"]}
        assert connector_crypto.verify(platform_pub_pem, tampered_payload, job["signature"]) is False

    def test_signature_from_wrong_key_fails_verification(self, fake, client):
        """A job signed by anything other than the real platform key must
        never verify — proves the connector isn't just checking *a*
        signature exists, but the *right* one."""
        a = register_user(client, "wrongkey_admin", organization_name="WrongKey Co")
        ha = auth_headers(a["access_token"])
        connector_id, secret, priv_pem, platform_pub_pem = _enroll(client, ha)
        client.post(f"/api/connectors/{connector_id}/jobs", headers=ha,
                   json={"job_type": "inventory_check", "scope": {}})
        job = client.get("/api/connectors/me/jobs/next", headers={"X-Connector-Secret": secret}).json()

        attacker_priv, _ = connector_crypto.generate_keypair_pem()
        payload = {"job_id": job["job_id"], "organization_id": job["organization_id"],
                  "connector_id": job["connector_id"], "job_type": job["job_type"],
                  "scope": job["scope"], "authorization": job["authorization"],
                  "created_at": job["created_at"], "expires_at": job["expires_at"]}
        forged_signature = connector_crypto.sign(attacker_priv, payload)
        assert connector_crypto.verify(platform_pub_pem, payload, forged_signature) is False

    def test_only_allowlisted_job_types_accepted(self, fake, client):
        a = register_user(client, "allowlist_admin", organization_name="Allowlist Co")
        ha = auth_headers(a["access_token"])
        connector_id, *_ = _enroll(client, ha)
        r = client.post(f"/api/connectors/{connector_id}/jobs", headers=ha,
                        json={"job_type": "rm_rf_slash", "scope": {}})
        assert r.status_code == 422

    def test_job_claimed_only_once(self, fake, client):
        a = register_user(client, "claim_admin", organization_name="Claim Co")
        ha = auth_headers(a["access_token"])
        connector_id, secret, *_ = _enroll(client, ha)
        client.post(f"/api/connectors/{connector_id}/jobs", headers=ha,
                   json={"job_type": "inventory_check", "scope": {}})
        first = client.get("/api/connectors/me/jobs/next", headers={"X-Connector-Secret": secret}).json()
        second = client.get("/api/connectors/me/jobs/next", headers={"X-Connector-Secret": secret}).json()
        assert first is not None
        assert second is None  # already sent, not handed out again

    def test_expired_job_is_never_handed_out(self, fake, client):
        a = register_user(client, "expiry_admin", organization_name="Expiry Co")
        ha = auth_headers(a["access_token"])
        connector_id, secret, *_ = _enroll(client, ha)
        client.post(f"/api/connectors/{connector_id}/jobs", headers=ha,
                   json={"job_type": "inventory_check", "scope": {}})
        # Force it into the past.
        job_row = next(iter(fake.connector_jobs.values()))
        job_row["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()

        polled = client.get("/api/connectors/me/jobs/next", headers={"X-Connector-Secret": secret})
        assert polled.json() is None
        assert job_row["status"] == "expired"

    def test_cannot_assign_job_to_revoked_connector(self, fake, client):
        a = register_user(client, "revoke_job_admin", organization_name="RevokeJob Co")
        ha = auth_headers(a["access_token"])
        connector_id, *_ = _enroll(client, ha)
        client.post(f"/api/connectors/{connector_id}/revoke", headers=ha)
        r = client.post(f"/api/connectors/{connector_id}/jobs", headers=ha,
                        json={"job_type": "inventory_check", "scope": {}})
        assert r.status_code == 422


class TestSignedResultSubmission:
    def test_correctly_signed_result_is_accepted(self, fake, client):
        a = register_user(client, "result_admin", organization_name="Result Co")
        ha = auth_headers(a["access_token"])
        connector_id, secret, priv_pem, _ = _enroll(client, ha)
        client.post(f"/api/connectors/{connector_id}/jobs", headers=ha,
                   json={"job_type": "inventory_check", "scope": {}})
        job = client.get("/api/connectors/me/jobs/next", headers={"X-Connector-Secret": secret}).json()

        result = {"hostname": "web01", "os": "Linux"}
        signature = connector_crypto.sign(priv_pem, result)
        r = client.post(f"/api/connectors/jobs/{job['job_id']}/result",
                        headers={"X-Connector-Secret": secret},
                        json={"result": result, "signature": signature})
        assert r.status_code == 200, r.text

        detail = client.get(f"/api/connectors/{connector_id}/jobs", headers=ha).json()
        assert detail[0]["status"] == "completed"
        assert detail[0]["result"] == result

    def test_forged_result_signature_is_rejected(self, fake, client):
        a = register_user(client, "forge_admin", organization_name="Forge Co")
        ha = auth_headers(a["access_token"])
        connector_id, secret, priv_pem, _ = _enroll(client, ha)
        client.post(f"/api/connectors/{connector_id}/jobs", headers=ha,
                   json={"job_type": "inventory_check", "scope": {}})
        job = client.get("/api/connectors/me/jobs/next", headers={"X-Connector-Secret": secret}).json()

        real_result = {"hostname": "web01"}
        attacker_priv, _ = connector_crypto.generate_keypair_pem()
        forged_signature = connector_crypto.sign(attacker_priv, real_result)  # signed with the WRONG key
        r = client.post(f"/api/connectors/jobs/{job['job_id']}/result",
                        headers={"X-Connector-Secret": secret},
                        json={"result": real_result, "signature": forged_signature})
        assert r.status_code == 400

        detail = client.get(f"/api/connectors/{connector_id}/jobs", headers=ha).json()
        assert detail[0]["status"] == "rejected"

    def test_result_for_someone_elses_job_rejected(self, fake, client):
        a = register_user(client, "cross_result_admin1", organization_name="CrossResult1")
        b = register_user(client, "cross_result_admin2", signup_email=True, organization_name="CrossResult2")
        c1_id, c1_secret, c1_priv, _ = _enroll(client, auth_headers(a["access_token"]), "c1")
        c2_id, c2_secret, c2_priv, _ = _enroll(client, auth_headers(b["access_token"]), "c2")
        client.post(f"/api/connectors/{c1_id}/jobs", headers=auth_headers(a["access_token"]),
                   json={"job_type": "inventory_check", "scope": {}})
        job = client.get("/api/connectors/me/jobs/next", headers={"X-Connector-Secret": c1_secret}).json()

        # connector 2 tries to submit a result for connector 1's job.
        result = {"x": 1}
        sig = connector_crypto.sign(c2_priv, result)
        r = client.post(f"/api/connectors/jobs/{job['job_id']}/result",
                        headers={"X-Connector-Secret": c2_secret},
                        json={"result": result, "signature": sig})
        assert r.status_code in (400, 404)


class TestConnectorStateAndRBAC:
    def test_state_transitions_with_heartbeat_age(self, fake, client):
        a = register_user(client, "state_admin", organization_name="State Co")
        ha = auth_headers(a["access_token"])
        connector_id, secret, *_ = _enroll(client, ha)

        assert client.get(f"/api/connectors/{connector_id}", headers=ha).json()["state"] == "ONLINE"

        from webapp import config as wcfg
        c = fake.connectors[connector_id]
        c["last_heartbeat_at"] = (datetime.now(timezone.utc)
                                  - timedelta(minutes=wcfg.CONNECTOR_DEGRADED_AFTER_MINUTES + 1)).isoformat()
        assert client.get(f"/api/connectors/{connector_id}", headers=ha).json()["state"] == "DEGRADED"

        c["last_heartbeat_at"] = (datetime.now(timezone.utc)
                                  - timedelta(minutes=wcfg.CONNECTOR_OFFLINE_AFTER_MINUTES + 1)).isoformat()
        assert client.get(f"/api/connectors/{connector_id}", headers=ha).json()["state"] == "OFFLINE"

    def test_revoked_state_overrides_everything(self, fake, client):
        a = register_user(client, "revoked_state_admin", organization_name="RevokedState Co")
        ha = auth_headers(a["access_token"])
        connector_id, secret, *_ = _enroll(client, ha)
        client.post(f"/api/connectors/{connector_id}/revoke", headers=ha)
        assert client.get(f"/api/connectors/{connector_id}", headers=ha).json()["state"] == "REVOKED"
        # And it can no longer authenticate at all.
        r = client.post("/api/connectors/me/heartbeat", headers={"X-Connector-Secret": secret}, json={})
        assert r.status_code == 403

    def test_viewer_can_list_but_not_create_jobs_or_revoke(self, fake, client):
        a = register_user(client, "conn_viewer_admin", organization_name="ConnViewer Co")
        ha = auth_headers(a["access_token"])
        connector_id, *_ = _enroll(client, ha)
        fake.set_user_role(a["user"]["id"], "viewer")

        assert client.get("/api/connectors", headers=ha).status_code == 200
        assert client.post(f"/api/connectors/{connector_id}/jobs", headers=ha,
                           json={"job_type": "inventory_check", "scope": {}}).status_code == 403
        assert client.post(f"/api/connectors/{connector_id}/revoke", headers=ha).status_code == 403

    def test_only_admin_can_revoke(self, fake, client):
        a = register_user(client, "revoke_perm_admin", organization_name="RevokePerm Co")
        ha = auth_headers(a["access_token"])
        connector_id, *_ = _enroll(client, ha)
        fake.set_user_role(a["user"]["id"], "security_manager")
        assert client.post(f"/api/connectors/{connector_id}/revoke", headers=ha).status_code == 403

    def test_connectors_scoped_to_organization(self, fake, client):
        a = register_user(client, "conn_org1_admin", organization_name="ConnOrg1")
        b = register_user(client, "conn_org2_admin", signup_email=True, organization_name="ConnOrg2")
        connector_id, *_ = _enroll(client, auth_headers(a["access_token"]))
        hb = auth_headers(b["access_token"])
        assert client.get(f"/api/connectors/{connector_id}", headers=hb).status_code == 404
        assert client.get("/api/connectors", headers=hb).json() == []
