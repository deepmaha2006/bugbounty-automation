"""Cross-tenant isolation regression tests (CVM platform spec, section 16).

"Company A must never access Company B data" — this file tests that
explicitly, per the spec's own instruction, across every resource type the
multi-tenancy migration touches: organizations, assets, scans, reports, and
the user list. Every cross-org lookup must come back 404 (never 403, which
would confirm the resource exists), and every list endpoint must only ever
contain the caller's own organization's rows.
"""
from conftest import register_user, auth_headers


def _two_orgs(client):
    """Two independently registered companies, each admin of their own,
    fully isolated organization — no shared Default Organization involved."""
    a = register_user(client, "orgA_admin", organization_name="Acme Corp")
    b = register_user(client, "orgB_admin", signup_email=True,
                      organization_name="Globex Inc")
    return a, b


class TestOrganizationIsolation:
    def test_two_signups_get_distinct_organizations(self, fake, client):
        a, b = _two_orgs(client)
        assert a["user"]["organization_id"] != b["user"]["organization_id"]

        org_a = client.get("/api/organizations/me", headers=auth_headers(a["access_token"])).json()
        org_b = client.get("/api/organizations/me", headers=auth_headers(b["access_token"])).json()
        assert org_a["id"] == a["user"]["organization_id"]
        assert org_b["id"] == b["user"]["organization_id"]
        assert org_a["slug"] != org_b["slug"]
        assert org_a["name"] == "Acme Corp"
        assert org_b["name"] == "Globex Inc"

    def test_default_signup_without_organization_name_joins_shared_default_org(self, fake, client):
        """Preserves pre-multi-tenancy zero-config behavior: no
        organization_name means "join the platform's Default Organization",
        not "create yet another isolated org"."""
        first = register_user(client, "solo_admin")
        second = register_user(client, "solo_user", signup_email=True)
        assert first["user"]["organization_id"] == second["user"]["organization_id"]


class TestAssetIsolation:
    def test_asset_invisible_and_unreachable_from_other_org(self, fake, client):
        a, b = _two_orgs(client)
        ha, hb = auth_headers(a["access_token"]), auth_headers(b["access_token"])

        created = client.post("/api/assets", headers=ha, json={
            "name": "Acme Website", "asset_type": "WEB_APPLICATION",
            "url": "https://acme.example.com",
        })
        assert created.status_code == 200, created.text
        asset_id = created.json()["id"]

        # Not in org B's list
        listing_b = client.get("/api/assets", headers=hb).json()
        assert all(x["id"] != asset_id for x in listing_b)

        # Org B gets a plain 404 on every direct route — never a 403 that
        # would confirm the asset exists somewhere.
        assert client.get(f"/api/assets/{asset_id}", headers=hb).status_code == 404
        assert client.patch(f"/api/assets/{asset_id}", headers=hb,
                            json={"name": "hijacked"}).status_code == 404
        assert client.delete(f"/api/assets/{asset_id}", headers=hb).status_code == 404

        # Org A (the owner) can reach it fine
        assert client.get(f"/api/assets/{asset_id}", headers=ha).status_code == 200
        # ...and org B's own listing is simply empty, not an error
        assert listing_b == []

    def test_two_orgs_can_register_the_same_url_independently(self, fake, client):
        """The old global UNIQUE(url) constraint would have made this
        impossible — two different companies must each be able to register
        the same third-party-looking URL as their own asset."""
        a, b = _two_orgs(client)
        ha, hb = auth_headers(a["access_token"]), auth_headers(b["access_token"])
        url = "https://shared-saas-vendor.example.com"

        ra = client.post("/api/assets", headers=ha,
                         json={"name": "Vendor Portal", "asset_type": "WEB_APPLICATION", "url": url})
        rb = client.post("/api/assets", headers=hb,
                         json={"name": "Vendor Portal", "asset_type": "WEB_APPLICATION", "url": url})
        assert ra.status_code == 200, ra.text
        assert rb.status_code == 200, rb.text
        assert ra.json()["id"] != rb.json()["id"]
        assert ra.json()["organization_id"] != rb.json()["organization_id"]

    def test_duplicate_url_within_same_org_is_rejected(self, fake, client):
        a, _ = _two_orgs(client)
        ha = auth_headers(a["access_token"])
        body = {"name": "Dup", "asset_type": "WEB_APPLICATION", "url": "https://dup.example.com"}
        assert client.post("/api/assets", headers=ha, json=body).status_code == 200
        assert client.post("/api/assets", headers=ha, json=body).status_code == 400

    def test_connector_asset_type_supported(self, fake, client):
        a, _ = _two_orgs(client)
        ha = auth_headers(a["access_token"])
        r = client.post("/api/assets", headers=ha, json={
            "name": "HQ Connector", "asset_type": "COMPANY_CONNECTOR",
            "url": "connector://hq-01",
        })
        assert r.status_code == 200, r.text
        assert r.json()["asset_type"] == "COMPANY_CONNECTOR"


class TestScanIsolation:
    def test_scan_invisible_and_unreachable_from_other_org(self, fake, client):
        a, b = _two_orgs(client)
        ha, hb = auth_headers(a["access_token"]), auth_headers(b["access_token"])

        org_a_id = a["user"]["organization_id"]
        tid = fake.add_target("https://acme.example.com", org_a_id)
        fake.update_target_verification(tid, "verified")
        sid = fake.create_scan(a["user"]["id"], tid, "web", ["xss"])

        # Owning org sees it everywhere it should
        assert client.get(f"/api/scans/{sid}", headers=ha).status_code == 200
        assert any(s["id"] == sid for s in client.get("/api/scans", headers=ha).json())
        assert any(s["id"] == sid for s in client.get("/api/scans/all", headers=ha).json())

        # The other org can't see or reach it anywhere
        assert client.get(f"/api/scans/{sid}", headers=hb).status_code == 404
        assert all(s["id"] != sid for s in client.get("/api/scans", headers=hb).json())
        assert all(s["id"] != sid for s in client.get("/api/scans/all", headers=hb).json())

    def test_scan_events_stream_scoped_to_owning_org(self, fake, client):
        a, b = _two_orgs(client)
        ha, hb = auth_headers(a["access_token"]), auth_headers(b["access_token"])
        org_a_id = a["user"]["organization_id"]
        tid = fake.add_target("https://acme.example.com", org_a_id)
        fake.update_target_verification(tid, "verified")
        sid = fake.create_scan(a["user"]["id"], tid, "web", ["xss"])
        fake.update_scan(sid, status="completed", finished_at=fake._now())

        assert client.get(f"/api/scans/{sid}/events", headers=hb).status_code == 404


class TestReportIsolation:
    def test_report_list_and_lookup_scoped_to_owning_org(self, fake, client):
        a, b = _two_orgs(client)
        ha, hb = auth_headers(a["access_token"]), auth_headers(b["access_token"])
        org_a_id = a["user"]["organization_id"]
        tid = fake.add_target("https://acme.example.com", org_a_id)
        fake.update_target_verification(tid, "verified")
        sid = fake.create_scan(a["user"]["id"], tid, "web", ["xss"])
        fake.add_report(sid, tid, "web", "html", "/tmp/does-not-exist.html")
        report_id = fake.reports[-1]["id"]

        listing_a = client.get("/api/reports", headers=ha).json()
        listing_b = client.get("/api/reports", headers=hb).json()
        assert any(r["id"] == report_id for r in listing_a)
        assert all(r["id"] != report_id for r in listing_b)

        # Wrong org: "Report not found" (org check fails before the
        # file-existence check ever runs).
        r = client.get(f"/api/reports/{report_id}/download", headers=hb)
        assert r.status_code == 404
        assert r.json()["detail"] == "Report not found"


class TestUserListIsolation:
    def test_admin_user_list_scoped_to_own_org(self, fake, client):
        a, b = _two_orgs(client)
        ha, hb = auth_headers(a["access_token"]), auth_headers(b["access_token"])

        info_a = client.get("/api/settings/admin", headers=ha).json()
        info_b = client.get("/api/settings/admin", headers=hb).json()
        usernames_a = {u["username"] for u in info_a["users"]}
        usernames_b = {u["username"] for u in info_b["users"]}

        assert "orgA_admin" in usernames_a and "orgB_admin" not in usernames_a
        assert "orgB_admin" in usernames_b and "orgA_admin" not in usernames_b
