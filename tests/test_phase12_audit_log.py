"""Phase 12 regression tests: audit log completeness (CVM platform spec §18).

Covers the gaps this phase closed: scan initiation and settings changes were
previously never audited at all, GET /api/settings/audit-log didn't exist
(the log was write-only), and audit_log.user_id was NOT NULL so events with
no human actor (a connector's own signed result, the scheduled verification-
finalization sweep) had no durable record at all.
"""
from webapp.services import connector_crypto
from webapp.services.remediation_service import check_and_finalize_verifications
from conftest import register_user, auth_headers


def _enroll(client, ha, name="audit-connector"):
    token = client.post("/api/connectors/enrollment-tokens", headers=ha).json()["enrollment_token"]
    priv_pem, pub_pem = connector_crypto.generate_keypair_pem()
    r = client.post("/api/connectors/enroll", json={
        "enrollment_token": token, "name": name, "public_key_pem": pub_pem,
        "version": "1.0.0", "os": "Linux",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    return body["connector_id"], body["connector_secret"], priv_pem


class TestScanAuditing:
    def test_web_scan_start_is_audited(self, fake, client):
        a = register_user(client, "scanaudit_admin", organization_name="ScanAudit Co")
        ha = auth_headers(a["access_token"])
        tid = fake.add_target("https://scanaudit.example.com", a["user"]["organization_id"])
        fake.update_target_verification(tid, "verified")
        r = client.post("/api/scans/web", headers=ha, json={
            "target": "https://scanaudit.example.com", "scope_authorized": True,
            "vuln_types": ["xss"],
        })
        assert r.status_code == 200, r.text
        entries = [e for e in fake.audit if e["action"] == "scan_started"]
        assert len(entries) == 1
        assert entries[0]["details"]["scan_type"] == "web"
        assert entries[0]["scan_id"] == r.json()["id"]


class TestSettingsAuditing:
    def test_settings_change_is_audited(self, fake, client):
        a = register_user(client, "settingsaudit_admin", organization_name="SettingsAudit Co")
        ha = auth_headers(a["access_token"])
        r = client.put("/api/settings", headers=ha, json={"default_threads": 20})
        assert r.status_code == 200, r.text
        entries = [e for e in fake.audit if e["action"] == "settings_changed"]
        assert len(entries) == 1
        assert entries[0]["details"] == {"default_threads": 20}

    def test_no_op_settings_update_does_not_audit(self, fake, client):
        a = register_user(client, "noopaudit_admin", organization_name="NoopAudit Co")
        ha = auth_headers(a["access_token"])
        client.put("/api/settings", headers=ha, json={})
        assert not any(e["action"] == "settings_changed" for e in fake.audit)


class TestAuditLogEndpoint:
    def test_admin_can_read_audit_log(self, fake, client):
        a = register_user(client, "readaudit_admin", organization_name="ReadAudit Co")
        ha = auth_headers(a["access_token"])
        resp = client.get("/api/settings/audit-log", headers=ha)
        assert resp.status_code == 200
        rows = resp.json()
        assert any(r["action"] == "user_created" for r in rows)
        assert all("id" in r and "timestamp" in r for r in rows)

    def test_non_admin_cannot_read_audit_log(self, fake, client):
        a = register_user(client, "viewaudit_admin", organization_name="ViewAudit Co")
        member = register_user(client, "viewaudit_member", signup_email=True)
        mh = auth_headers(member["access_token"])
        resp = client.get("/api/settings/audit-log", headers=mh)
        assert resp.status_code == 403

    def test_audit_log_is_org_scoped(self, fake, client):
        a = register_user(client, "orgaudit_admin1", organization_name="OrgAudit1")
        b = register_user(client, "orgaudit_admin2", signup_email=True, organization_name="OrgAudit2")
        ha, hb = auth_headers(a["access_token"]), auth_headers(b["access_token"])
        rows_a = client.get("/api/settings/audit-log", headers=ha).json()
        rows_b = client.get("/api/settings/audit-log", headers=hb).json()
        usernames_a = {r["username"] for r in rows_a}
        usernames_b = {r["username"] for r in rows_b}
        assert "orgaudit_admin2" not in usernames_a
        assert "orgaudit_admin1" not in usernames_b


class TestActorlessEvents:
    """user_id=None events (Phase 12) must still produce a durable,
    org-scoped audit row, and must still surface through the read endpoint
    (a LEFT JOIN fix — the original INNER JOIN would have silently hidden
    them)."""

    def test_connector_job_result_submission_is_audited_without_a_user(self, fake, client):
        a = register_user(client, "connaudit_admin", organization_name="ConnAudit Co")
        ha = auth_headers(a["access_token"])
        connector_id, secret, priv_pem = _enroll(client, ha)
        client.post(f"/api/connectors/{connector_id}/jobs", headers=ha,
                   json={"job_type": "inventory_check", "scope": {}})
        job = client.get("/api/connectors/me/jobs/next", headers={"X-Connector-Secret": secret}).json()
        result = {"hostname": "web01"}
        signature = connector_crypto.sign(priv_pem, result)
        client.post(f"/api/connectors/jobs/{job['job_id']}/result",
                   headers={"X-Connector-Secret": secret},
                   json={"result": result, "signature": signature})

        entries = [e for e in fake.audit if e["action"] == "connector_job_result_submitted"]
        assert len(entries) == 1
        assert entries[0]["user_id"] is None
        assert entries[0]["organization_id"] == a["user"]["organization_id"]

        rows = client.get("/api/settings/audit-log", headers=ha).json()
        matching = [r for r in rows if r["action"] == "connector_job_result_submitted"]
        assert len(matching) == 1
        assert matching[0]["username"] is None

    def test_forged_connector_result_rejection_is_audited(self, fake, client):
        a = register_user(client, "forgeaudit_admin", organization_name="ForgeAudit Co")
        ha = auth_headers(a["access_token"])
        connector_id, secret, _ = _enroll(client, ha)
        client.post(f"/api/connectors/{connector_id}/jobs", headers=ha,
                   json={"job_type": "inventory_check", "scope": {}})
        job = client.get("/api/connectors/me/jobs/next", headers={"X-Connector-Secret": secret}).json()
        attacker_priv, _ = connector_crypto.generate_keypair_pem()
        forged = connector_crypto.sign(attacker_priv, {"x": 1})
        client.post(f"/api/connectors/jobs/{job['job_id']}/result",
                   headers={"X-Connector-Secret": secret},
                   json={"result": {"x": 1}, "signature": forged})
        entries = [e for e in fake.audit if e["action"] == "connector_job_result_rejected"]
        assert len(entries) == 1
        assert entries[0]["user_id"] is None

    def test_verification_finalization_sweep_is_audited(self, fake, client):
        a = register_user(client, "verifyaudit_admin", organization_name="VerifyAudit Co")
        org_id, uid = a["user"]["organization_id"], a["user"]["id"]
        tid = fake.add_target("https://verifyaudit.example.com", org_id)
        fake.update_target_verification(tid, "verified")
        fake.update_asset(tid, org_id, business_criticality="high")
        sid = fake.create_scan(uid, tid, "web", ["xss"])
        fake.add_finding(sid, {"severity": "High", "type": "xss", "evidence": "proof",
                               "url": "https://verifyaudit.example.com/x", "confidence": "confirmed"})
        fid = fake.findings[-1]["id"]
        task_id = fake.create_remediation_task(org_id, fid, uid, "appsec", "high", None)

        vsid = fake.create_scan(uid, tid, "web", ["xss"])
        fake.update_scan(vsid, status="completed")
        fake.submit_fix(task_id, org_id, vsid)

        n = check_and_finalize_verifications()
        assert n == 1
        entries = [e for e in fake.audit if e["action"] == "remediation_verification_finalized"]
        assert len(entries) == 1
        assert entries[0]["user_id"] is None
        assert entries[0]["organization_id"] == org_id
        assert entries[0]["details"]["result"] == "FIXED"
