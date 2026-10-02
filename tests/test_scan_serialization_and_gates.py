"""P2-1 regression tests.

Covers: _scan_to_out() NULL-safety (Phase 1 lock), admin authentication
(require_admin / require_user), the verified-target scan gate, the
scope_authorized=false rejection, target_id persistence, and
GET /api/scans/{id}.
"""
from webapp.routers.scans import _scan_to_out


# --------------------------------------------------------------------------
# _scan_to_out NULL-safety — Phase 1 regression lock
# --------------------------------------------------------------------------
def test_scan_to_out_nulls_are_defaulted():
    """A fresh scan row with all-NULL nullable fields must serialize safely."""
    row = {
        "id": 7, "target": None, "scan_type": None, "status": None,
        "progress": None, "phase": None, "message": None,
        "findings": [], "stats": None, "created_at": None,
        "started_at": None, "finished_at": None, "user_id": 1,
    }
    out = _scan_to_out(row, with_findings=False)
    assert out.target == ""
    assert out.scan_type == "web"
    assert out.status == "queued"
    assert out.progress == 0.0
    assert out.phase == ""
    assert out.message == ""
    assert out.stats == {}
    assert out.created_at == ""
    assert out.started_at is None
    assert out.finished_at is None
    assert out.user_id == 1


# --------------------------------------------------------------------------
# GET /api/scans/{id}
# --------------------------------------------------------------------------
class TestScanDetail:
    def test_get_scan_detail_null_fields_serialize(self, fake, client,
                                                   admin_headers):
        uid = fake.create_user("owner", "owner@hydrax.local", "x")
        sid = fake.create_scan(uid, None, "web", [])  # NULL target_id
        row = fake.scans[sid]
        row["phase"] = None
        row["message"] = None
        assert row["target_id"] is None

        r = client.get(f"/api/scans/{sid}", headers=admin_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["id"] == sid
        assert body["target"] == ""
        assert body["status"] == "queued"
        assert body["phase"] == ""
        assert body["findings"] == []

    def test_get_scan_detail_returns_findings(self, fake, client,
                                              admin_headers):
        uid = fake.create_user("owner", "owner@hydrax.local", "x")
        tid = fake.add_target("http://127.0.0.1:8000/app",
                              verification_method="dns_txt")
        fake.update_target_verification(tid, "verified")
        sid = fake.create_scan(uid, tid, "web", ["xss"])
        fake.add_finding(sid, {
            "severity": "High", "type": "XSS", "description": "reflected",
            "evidence": "<svg/onload=1>", "url": "http://127.0.0.1:8000/app/?q=1",
            "remediation": "encode output", "tool": "python",
            "parameter": "q", "payload": "<svg/onload=1>",
            "confidence": "confirmed", "verified": True,
        })

        r = client.get(f"/api/scans/{sid}", headers=admin_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["target"] == "http://127.0.0.1:8000/app"
        assert len(body["findings"]) == 1
        f = body["findings"][0]
        assert f["severity"] == "High"
        assert f["type"] == "XSS"
        assert f["parameter"] == "q"

    def test_get_scan_detail_missing_returns_404(self, fake, client,
                                                 admin_headers):
        r = client.get("/api/scans/999", headers=admin_headers)
        assert r.status_code == 404


# --------------------------------------------------------------------------
# Admin authentication
# --------------------------------------------------------------------------
class TestAuthZ:
    def test_first_user_becomes_admin_and_reaches_admin_route(self, client,
                                                              admin_headers):
        me = client.get("/api/auth/me", headers=admin_headers)
        assert me.status_code == 200
        assert me.json()["role"] == "admin"
        r = client.get("/api/settings/scanners", headers=admin_headers)
        assert r.status_code == 200

    def test_regular_user_denied_admin_route(self, client, user_headers):
        me = client.get("/api/auth/me", headers=user_headers)
        assert me.status_code == 200
        # Legacy 'user' role was migrated to 'security_analyst' under RBAC
        # (Phase 3) — it can view the scanner catalog (require_viewer) but
        # not the admin-only settings/admin route.
        assert me.json()["role"] == "security_analyst"
        r = client.get("/api/settings/scanners", headers=user_headers)
        assert r.status_code == 200
        r2 = client.get("/api/settings/admin", headers=user_headers)
        assert r2.status_code == 403

    def test_authenticated_user_reaches_own_endpoint(self, client,
                                                     user_headers):
        me = client.get("/api/auth/me", headers=user_headers)
        assert me.status_code == 200

    def test_no_token_rejected(self, client):
        assert client.get("/api/settings/scanners").status_code in (401, 403)
        assert client.get("/api/auth/me").status_code in (401, 403)


# --------------------------------------------------------------------------
# Scan authorization gates
# --------------------------------------------------------------------------
class TestScanGates:
    def _verified_target(self, fake, url="http://127.0.0.1:8000/app"):
        tid = fake.add_target(url, verification_method="dns_txt")
        fake.update_target_verification(tid, "verified")
        return tid

    def test_scope_not_authorized_rejected(self, fake, client, admin_headers):
        self._verified_target(fake)
        r = client.post("/api/scans/web", headers=admin_headers, json={
            "target": "http://127.0.0.1:8000/app",
            "vuln_types": ["xss"], "scope_authorized": False,
        })
        assert r.status_code == 403
        assert "authorization" in r.json()["detail"].lower()

    def test_unverified_target_blocked(self, fake, client, admin_headers):
        fake.add_target("http://127.0.0.1:8000/app", verification_method="dns_txt")
        r = client.post("/api/scans/web", headers=admin_headers, json={
            "target": "http://127.0.0.1:8000/app",
            "vuln_types": ["xss"], "scope_authorized": True,
        })
        assert r.status_code == 403
        assert "verification" in r.json()["detail"].lower()

    def test_unregistered_target_404(self, fake, client, admin_headers):
        r = client.post("/api/scans/web", headers=admin_headers, json={
            "target": "http://127.0.0.1:8000/never-registered",
            "vuln_types": ["xss"], "scope_authorized": True,
        })
        assert r.status_code == 404

    def test_empty_vuln_types_rejected(self, fake, client, admin_headers):
        self._verified_target(fake)
        r = client.post("/api/scans/web", headers=admin_headers, json={
            "target": "http://127.0.0.1:8000/app",
            "vuln_types": [], "scope_authorized": True,
        })
        assert r.status_code == 422

    def test_web_scan_persists_target_id(self, fake, client, admin_headers,
                                         monkeypatch):
        tid = self._verified_target(fake)
        captured = {}

        def _fake_start(user_id, target, vuln_types):
            row = fake.get_target_by_url(target)
            t = row["id"] if row else None
            captured["target_id"] = t
            captured["url"] = target
            return fake.create_scan(user_id, t, "web", vuln_types)

        monkeypatch.setattr("webapp.services.web_scan_service.start_web_scan",
                            _fake_start)
        r = client.post("/api/scans/web", headers=admin_headers, json={
            "target": "http://127.0.0.1:8000/app",
            "vuln_types": ["xss"], "scope_authorized": True,
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert captured["target_id"] == tid
        row = fake.get_scan(body["id"])
        assert row["target_id"] == tid
        assert row["target"] == "http://127.0.0.1:8000/app"
        assert row["user_id"] == me_admin_id(client, admin_headers)


def me_admin_id(client, admin_headers):
    return client.get("/api/auth/me", headers=admin_headers).json()["id"]