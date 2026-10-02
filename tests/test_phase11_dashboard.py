"""Phase 11 regression tests: real-data SOC dashboard (CVM platform spec §11).

Every field asserted here must come from a real, org-scoped backend
computation — never a fabricated/static value. See the closing principle
of the spec: "This must NOT be a fake cybersecurity dashboard."
"""
from conftest import register_user, auth_headers


def _finding(fake, org_id=1, severity="Critical", category="rce", url="https://d.example.com"):
    tid = fake.add_target(url, org_id)
    fake.update_target_verification(tid, "verified")
    sid = fake.create_scan(1, tid, "web", [category])
    fake.add_finding(sid, {"severity": severity, "type": category, "evidence": f"proof-{category}",
                           "url": url + "/x", "confidence": "confirmed"})
    return fake.findings[-1]["id"], tid, sid


class TestDashboardAssets:
    def test_total_and_monitored_assets_are_real_counts(self, fake, client):
        a = register_user(client, "d1user")
        headers = auth_headers(a["access_token"])
        tid1 = fake.add_target("https://a1.example.com", 1)
        tid2 = fake.add_target("https://a2.example.com", 1)
        fake.set_asset_monitoring(tid1, 1, "active", "daily")
        # tid2 stays inactive (the default) — must not count as monitored.
        resp = client.get("/api/dashboard/stats", headers=headers)
        assert resp.status_code == 200
        d = resp.json()
        assert d["total_assets"] == 2
        assert d["monitored_assets"] == 1

    def test_assets_from_other_orgs_are_excluded(self, fake, client):
        a = register_user(client, "d2user")
        headers = auth_headers(a["access_token"])
        fake.add_target("https://other-org.example.com", organization_id=999)
        resp = client.get("/api/dashboard/stats", headers=headers)
        assert resp.json()["total_assets"] == 0


class TestDashboardConnectors:
    def test_freshly_heartbeating_connector_counts_online(self, fake, client):
        a = register_user(client, "d3user")
        headers = auth_headers(a["access_token"])
        fake.create_connector(1, "agent-1", "pem", "hash1", "1.0.0", "linux")
        resp = client.get("/api/dashboard/stats", headers=headers)
        d = resp.json()
        assert d["connectors_online"] == 1
        assert d["connectors_offline"] == 0

    def test_stale_heartbeat_counts_offline(self, fake, client):
        from datetime import datetime, timedelta, timezone
        a = register_user(client, "d4user")
        headers = auth_headers(a["access_token"])
        cid = fake.create_connector(1, "agent-2", "pem", "hash2", "1.0.0", "linux")
        stale = (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()
        fake.connectors[cid]["last_heartbeat_at"] = stale
        resp = client.get("/api/dashboard/stats", headers=headers)
        d = resp.json()
        assert d["connectors_online"] == 0
        assert d["connectors_offline"] == 1


class TestDashboardVulnerabilityCounts:
    def test_new_vulnerability_is_counted(self, fake, client):
        a = register_user(client, "d5user")
        headers = auth_headers(a["access_token"])
        _finding(fake, severity="High")
        d = client.get("/api/dashboard/stats", headers=headers).json()
        assert d["new_vulnerabilities"] == 1
        assert d["fixed_vulnerabilities"] == 0
        assert d["reopened_vulnerabilities"] == 0
        assert d["high"] == 1

    def test_fixed_and_reopened_are_tracked_separately(self, fake, client):
        a = register_user(client, "d6user")
        headers = auth_headers(a["access_token"])
        fid, _, _ = _finding(fake, severity="Medium", category="clickjack")
        fake.update_finding_status(fid, 1, "FIXED")
        d = client.get("/api/dashboard/stats", headers=headers).json()
        assert d["fixed_vulnerabilities"] == 1
        assert d["new_vulnerabilities"] == 0

        # Re-adding the same fingerprint auto-transitions FIXED -> REOPENED
        # (spec §4's fingerprint-dedup lifecycle rule) — the dashboard must
        # reflect that transition, not the stale FIXED count.
        f = next(f for f in fake.findings if f["id"] == fid)
        sid2 = fake.create_scan(1, f["target_id"], "web", ["clickjack"])
        fake.add_finding(sid2, {"severity": "Medium", "type": "clickjack",
                                "evidence": "proof-clickjack", "url": "https://d.example.com/x",
                                "confidence": "confirmed"})
        d = client.get("/api/dashboard/stats", headers=headers).json()
        assert d["reopened_vulnerabilities"] == 1
        assert d["fixed_vulnerabilities"] == 0


class TestDashboardRemediationAndAlerts:
    def test_open_remediation_task_is_counted(self, fake, client):
        a = register_user(client, "d7user")
        headers = auth_headers(a["access_token"])
        fid, _, _ = _finding(fake, severity="Critical")
        fake.create_remediation_task(1, fid, None, "appsec", "high", None)
        d = client.get("/api/dashboard/stats", headers=headers).json()
        assert d["open_remediation_tasks"] == 1

    def test_recent_alerts_reflect_real_alert_rows(self, fake, client):
        a = register_user(client, "d8user")
        headers = auth_headers(a["access_token"])
        fid, tid, _ = _finding(fake, severity="Critical")
        fake.get_or_create_alert(1, fid, tid, "Critical")
        d = client.get("/api/dashboard/stats", headers=headers).json()
        assert len(d["recent_alerts"]) == 1
        alert = d["recent_alerts"][0]
        assert alert["finding_id"] == fid
        assert alert["severity"] == "Critical"
        assert alert["vulnerability"] == "rce"

    def test_no_data_yields_zeros_not_fabricated_values(self, fake, client):
        a = register_user(client, "d9user")
        headers = auth_headers(a["access_token"])
        d = client.get("/api/dashboard/stats", headers=headers).json()
        assert d["total_assets"] == 0
        assert d["monitored_assets"] == 0
        assert d["connectors_online"] == 0
        assert d["connectors_offline"] == 0
        assert d["new_vulnerabilities"] == 0
        assert d["fixed_vulnerabilities"] == 0
        assert d["reopened_vulnerabilities"] == 0
        assert d["open_remediation_tasks"] == 0
        assert d["recent_alerts"] == []


class TestExecutiveAndTechnicalReports:
    """spec §23: exportable executive (leadership) and technical (engineer)
    reports in JSON/CSV/PDF, built fresh from real org-scoped data."""

    def _setup(self, client, fake, username):
        a = register_user(client, username)
        headers = auth_headers(a["access_token"])
        fid, tid, _ = _finding(fake, severity="Critical", category="sqli")
        fake.update_asset(tid, 1, business_criticality="high")
        return headers, fid, tid

    def test_executive_json_reflects_real_findings(self, fake, client):
        headers, fid, _ = self._setup(client, fake, "r1user")
        resp = client.get("/api/reports/executive?format=json", headers=headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")
        data = resp.json()
        assert data["vulnerability_summary"]["critical"] == 1
        assert len(data["top_risks"]) == 1
        assert data["top_risks"][0]["finding_id"] == fid

    def test_executive_csv_and_pdf_render(self, fake, client):
        headers, _, _ = self._setup(client, fake, "r2user")
        csv_resp = client.get("/api/reports/executive?format=csv", headers=headers)
        assert csv_resp.status_code == 200
        assert csv_resp.headers["content-type"].startswith("text/csv")
        assert b"vulnerability_summary.critical" in csv_resp.content

        pdf_resp = client.get("/api/reports/executive?format=pdf", headers=headers)
        assert pdf_resp.status_code == 200
        assert pdf_resp.headers["content-type"] == "application/pdf"
        assert pdf_resp.content.startswith(b"%PDF")

    def test_technical_json_includes_finding_detail(self, fake, client):
        headers, fid, _ = self._setup(client, fake, "r3user")
        resp = client.get("/api/reports/technical?format=json", headers=headers)
        rows = resp.json()
        assert len(rows) == 1
        row = rows[0]
        assert row["finding_id"] == fid
        assert row["vulnerability"] == "sqli"
        assert row["severity"] == "Critical"
        assert "evidence" in row and row["evidence"]

    def test_technical_csv_and_pdf_render(self, fake, client):
        headers, _, _ = self._setup(client, fake, "r4user")
        csv_resp = client.get("/api/reports/technical?format=csv", headers=headers)
        assert csv_resp.status_code == 200
        assert b"sqli" in csv_resp.content

        pdf_resp = client.get("/api/reports/technical?format=pdf", headers=headers)
        assert pdf_resp.status_code == 200
        assert pdf_resp.content.startswith(b"%PDF")

    def test_report_generation_is_audit_logged(self, fake, client):
        headers, _, _ = self._setup(client, fake, "r5user")
        client.get("/api/reports/executive?format=json", headers=headers)
        actions = [a["action"] for a in fake.audit]
        assert "report_generated" in actions

    def test_reports_from_other_orgs_are_excluded(self, fake, client):
        headers, _, _ = self._setup(client, fake, "r6user")
        other = register_user(client, "r6other", signup_email=True, organization_name="Other Co")
        other_org_id = other["user"]["organization_id"]
        other_uid = other["user"]["id"]
        tid = fake.add_target("https://other.example.com", other_org_id)
        sid = fake.create_scan(other_uid, tid, "web", ["xxe"])
        fake.add_finding(sid, {"severity": "Critical", "type": "xxe", "evidence": "proof-xxe",
                               "url": "https://other.example.com/x", "confidence": "confirmed"})
        resp = client.get("/api/reports/technical?format=json", headers=headers)
        rows = resp.json()
        assert all(r["vulnerability"] != "xxe" for r in rows)

    def test_invalid_format_is_rejected(self, fake, client):
        headers, _, _ = self._setup(client, fake, "r7user")
        resp = client.get("/api/reports/executive?format=xml", headers=headers)
        assert resp.status_code == 422
