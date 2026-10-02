"""Phase 4 regression tests: finding fingerprint dedup, lifecycle status
transitions, CWE/CVSS classification, and the /api/findings API
(CVM platform spec §4, §8, §13).
"""
from conftest import register_user, auth_headers


def _make_verified_scan(fake, org_id, uid, url="https://phase4.example.com"):
    tid = fake.add_target(url, org_id)
    fake.update_target_verification(tid, "verified")
    sid = fake.create_scan(uid, tid, "web", ["xss"])
    return sid


class TestFingerprintDedup:
    def test_repeated_detection_updates_occurrence_not_duplicates(self, fake):
        sid1 = _make_verified_scan(fake, 1, 1)
        finding = {"severity": "High", "type": "xss", "description": "reflected XSS",
                  "evidence": "<script>alert(1)</script>", "url": "https://phase4.example.com/search",
                  "parameter": "q", "tool": "xss_scanner"}
        fake.add_finding(sid1, dict(finding))

        # A second scan of the SAME asset finds the SAME vulnerability again.
        sid2 = fake.create_scan(1, fake.scans[sid1]["target_id"], "web", ["xss"])
        fake.add_finding(sid2, dict(finding))

        rows = [f for f in fake.findings if f["organization_id"] == 1]
        assert len(rows) == 1, "must update the existing row, not insert a duplicate"
        assert rows[0]["occurrence_count"] == 2
        assert rows[0]["scan_id"] == sid2  # points at the most recent detection

    def test_different_evidence_is_a_different_finding(self, fake):
        sid = _make_verified_scan(fake, 1, 1)
        fake.add_finding(sid, {"severity": "High", "type": "xss", "evidence": "<script>a</script>",
                               "url": "https://x.example.com/a", "parameter": "q"})
        fake.add_finding(sid, {"severity": "High", "type": "sqli", "evidence": "' OR 1=1--",
                               "url": "https://x.example.com/a", "parameter": "id"})
        assert len(fake.findings) == 2

    def test_fixed_finding_that_reappears_becomes_reopened(self, fake):
        sid1 = _make_verified_scan(fake, 1, 1)
        finding = {"severity": "Medium", "type": "sec_misconfig", "evidence": "directory listing enabled",
                  "url": "https://phase4.example.com/backup/", "parameter": None}
        fake.add_finding(sid1, dict(finding))
        fid = fake.findings[-1]["id"]
        fake.update_finding_status(fid, 1, "FIXED")

        sid2 = fake.create_scan(1, fake.scans[sid1]["target_id"], "web", ["sec_misconfig"])
        fake.add_finding(sid2, dict(finding))

        assert fake.findings[0]["status"] == "REOPENED"
        assert fake.findings[0]["occurrence_count"] == 2

    def test_false_positive_determination_is_not_silently_overridden(self, fake):
        sid1 = _make_verified_scan(fake, 1, 1)
        finding = {"severity": "Low", "type": "info_disclosure", "evidence": "server header present",
                  "url": "https://phase4.example.com/", "parameter": None}
        fake.add_finding(sid1, dict(finding))
        fid = fake.findings[-1]["id"]
        fake.update_finding_status(fid, 1, "FALSE_POSITIVE")

        sid2 = fake.create_scan(1, fake.scans[sid1]["target_id"], "web", ["info_disclosure"])
        fake.add_finding(sid2, dict(finding))

        # Occurrence still tracked, but the human judgment call is preserved.
        assert fake.findings[0]["status"] == "FALSE_POSITIVE"
        assert fake.findings[0]["occurrence_count"] == 2


class TestClassification:
    def test_known_category_gets_real_cwe(self, fake):
        sid = _make_verified_scan(fake, 1, 1)
        fake.add_finding(sid, {"severity": "High", "type": "xss", "evidence": "e",
                               "url": "https://x.example.com", "parameter": "q"})
        assert fake.findings[-1]["cwe"] == "CWE-79"
        assert fake.findings[-1]["cvss"] == 7.0

    def test_unmapped_category_leaves_cwe_null_not_guessed(self, fake):
        sid = _make_verified_scan(fake, 1, 1)
        fake.add_finding(sid, {"severity": "Info", "type": "recon", "evidence": "e",
                               "url": "https://x.example.com"})
        assert fake.findings[-1]["cwe"] is None


class TestFindingsAPI:
    def test_list_and_detail_separate_evidence_from_remediation(self, fake, client):
        a = register_user(client, "finding_admin", organization_name="Finding Co")
        ha = auth_headers(a["access_token"])
        org_id = a["user"]["organization_id"]
        sid = _make_verified_scan(fake, org_id, a["user"]["id"])
        fake.add_finding(sid, {"severity": "Critical", "type": "sqli",
                               "evidence": "1' OR '1'='1 returned all rows",
                               "url": "https://phase4.example.com/login", "parameter": "username",
                               "remediation": "Use parameterized queries", "tool": "sqli_scanner"})

        listing = client.get("/api/findings", headers=ha).json()
        assert len(listing) == 1
        fid = listing[0]["id"]

        detail = client.get(f"/api/findings/{fid}", headers=ha).json()
        assert detail["evidence"] == "1' OR '1'='1 returned all rows"
        assert detail["remediation"] == "Use parameterized queries"
        assert detail["cwe"] == "CWE-89"
        assert detail["status"] == "NEW"

    def test_status_transition_is_operator_gated_and_audited(self, fake, client):
        a = register_user(client, "status_admin", organization_name="Status Co")
        ha = auth_headers(a["access_token"])
        fake.set_user_role(a["user"]["id"], "viewer")
        org_id = a["user"]["organization_id"]
        sid = _make_verified_scan(fake, org_id, a["user"]["id"])
        fake.add_finding(sid, {"severity": "High", "type": "xss", "evidence": "e",
                               "url": "https://phase4.example.com", "parameter": "q"})
        fid = fake.findings[-1]["id"]

        # Viewer cannot triage
        r = client.patch(f"/api/findings/{fid}/status", headers=ha, json={"status": "ACKNOWLEDGED"})
        assert r.status_code == 403

        fake.set_user_role(a["user"]["id"], "security_analyst")
        r2 = client.patch(f"/api/findings/{fid}/status", headers=ha, json={"status": "ACKNOWLEDGED"})
        assert r2.status_code == 200, r2.text
        assert r2.json()["status"] == "ACKNOWLEDGED"
        assert any(e["action"] == "finding_status_changed" for e in fake.audit)

    def test_invalid_status_rejected(self, fake, client):
        a = register_user(client, "badstatus_admin", organization_name="BadStatus Co")
        ha = auth_headers(a["access_token"])
        org_id = a["user"]["organization_id"]
        sid = _make_verified_scan(fake, org_id, a["user"]["id"])
        fake.add_finding(sid, {"severity": "Low", "type": "xss", "evidence": "e", "url": "https://x.example.com"})
        fid = fake.findings[-1]["id"]
        r = client.patch(f"/api/findings/{fid}/status", headers=ha, json={"status": "DEFINITELY_NOT_A_STATUS"})
        assert r.status_code == 422

    def test_findings_scoped_to_organization(self, fake, client):
        a = register_user(client, "org1_finding_admin", organization_name="FindOrg1")
        b = register_user(client, "org2_finding_admin", signup_email=True, organization_name="FindOrg2")
        sid = _make_verified_scan(fake, a["user"]["organization_id"], a["user"]["id"])
        fake.add_finding(sid, {"severity": "High", "type": "xss", "evidence": "e", "url": "https://x.example.com"})
        fid = fake.findings[-1]["id"]

        hb = auth_headers(b["access_token"])
        assert client.get(f"/api/findings/{fid}", headers=hb).status_code == 404
        assert client.get("/api/findings", headers=hb).json() == []
