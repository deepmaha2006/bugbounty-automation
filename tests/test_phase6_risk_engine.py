"""Phase 6 regression tests: risk engine — separately-stored/reported risk
factors and a composite, explainable score, never a CVSS passthrough
(CVM platform spec §10).
"""
from webapp import db as db_module
from conftest import register_user, auth_headers


class TestRiskComputation:
    def test_critical_on_critical_internet_facing_asset_scores_high(self):
        risk = db_module.compute_risk("Critical", "rce", "confirmed", "critical", "WEB_APPLICATION")
        assert risk["risk_score"] > 90
        assert risk["risk_factors"]["exploitability"] == "High"
        assert risk["risk_factors"]["exposure"] == "internet_facing"

    def test_info_on_low_criticality_internal_asset_scores_low(self):
        risk = db_module.compute_risk("Info", "sec_misconfig", "needs_verification", "low", "COMPANY_CONNECTOR")
        assert risk["risk_score"] < 10
        assert risk["risk_factors"]["exposure"] == "internal"

    def test_unconfirmed_finding_scores_lower_than_identical_confirmed_one(self):
        confirmed = db_module.compute_risk("High", "xss", "confirmed", "high", "WEB_APPLICATION")
        unconfirmed = db_module.compute_risk("High", "xss", "needs_verification", "high", "WEB_APPLICATION")
        assert unconfirmed["risk_score"] < confirmed["risk_score"]

    def test_all_five_factors_are_reported_separately(self):
        risk = db_module.compute_risk("Medium", "csrf", "confirmed", "medium", "WEB_APPLICATION")
        factors = risk["risk_factors"]
        assert set(factors.keys()) == {"severity", "exploitability", "asset_criticality",
                                       "exposure", "confidence"}

    def test_connector_asset_type_is_internal_by_construction(self):
        risk = db_module.compute_risk("High", "xss", "confirmed", "high", "COMPANY_CONNECTOR")
        assert risk["risk_factors"]["exposure"] == "internal"

    def test_unmapped_category_defaults_to_medium_exploitability_not_extreme(self):
        risk = db_module.compute_risk("High", "recon", "confirmed", "high", "WEB_APPLICATION")
        assert risk["risk_factors"]["exploitability"] == "Medium"


class TestRiskInAPI:
    def test_finding_detail_includes_risk_score_and_factors(self, fake, client):
        a = register_user(client, "risk_admin", organization_name="Risk Co")
        ha = auth_headers(a["access_token"])
        org_id = a["user"]["organization_id"]
        tid = fake.add_target("https://risk.example.com", org_id)
        fake.update_target_verification(tid, "verified")
        fake.update_asset(tid, org_id, business_criticality="critical")
        sid = fake.create_scan(a["user"]["id"], tid, "web", ["rce"])
        fake.add_finding(sid, {"severity": "Critical", "type": "rce", "evidence": "shell obtained",
                               "url": "https://risk.example.com/upload", "confidence": "confirmed"})
        fid = fake.findings[-1]["id"]

        detail = client.get(f"/api/findings/{fid}", headers=ha).json()
        assert detail["risk_score"] is not None
        assert detail["risk_factors"]["asset_criticality"] == "critical"
        assert detail["risk_factors"]["severity"] == "Critical"

    def test_same_finding_scores_higher_on_more_critical_asset(self, fake, client):
        a = register_user(client, "risk_compare_admin", organization_name="RiskCompare Co")
        ha = auth_headers(a["access_token"])
        org_id = a["user"]["organization_id"]

        low_id = fake.add_target("https://low.example.com", org_id)
        fake.update_asset(low_id, org_id, business_criticality="low")
        sid1 = fake.create_scan(a["user"]["id"], low_id, "web", ["xss"])
        fake.add_finding(sid1, {"severity": "High", "type": "xss", "evidence": "e1",
                                "url": "https://low.example.com", "confidence": "confirmed"})
        low_finding_id = fake.findings[-1]["id"]

        crit_id = fake.add_target("https://crit.example.com", org_id)
        fake.update_asset(crit_id, org_id, business_criticality="critical")
        sid2 = fake.create_scan(a["user"]["id"], crit_id, "web", ["xss"])
        fake.add_finding(sid2, {"severity": "High", "type": "xss", "evidence": "e2",
                                "url": "https://crit.example.com", "confidence": "confirmed"})
        crit_finding_id = fake.findings[-1]["id"]

        low_detail = client.get(f"/api/findings/{low_finding_id}", headers=ha).json()
        crit_detail = client.get(f"/api/findings/{crit_finding_id}", headers=ha).json()
        assert crit_detail["risk_score"] > low_detail["risk_score"]
