"""SSE scan-events auth regression tests.

Browser EventSource cannot set an Authorization header, so
/api/scans/{id}/events must accept the JWT as a `?token=` query parameter in
addition to the normal header — see webapp/routers/auth.require_admin_sse.
These tests are hermetic: FakeDB, a scan that is already in a terminal state
so the SSE generator ends immediately instead of looping.
"""


def _make_completed_scan(fake, user_id):
    tid = fake.add_target("http://example.test", verification_method="dns_txt")
    fake.update_target_verification(tid, "verified")
    sid = fake.create_scan(user_id, tid, "web", ["xss"])
    fake.update_scan(sid, status="completed", phase="Complete", progress=1.0)
    return sid


class TestScanEventsAuth:
    def test_events_with_bearer_header_ok(self, client, admin_headers, fake):
        me = client.get("/api/auth/me", headers=admin_headers).json()
        sid = _make_completed_scan(fake, me["id"])
        r = client.get(f"/api/scans/{sid}/events", headers=admin_headers)
        assert r.status_code == 200, r.text

    def test_events_with_query_token_ok(self, client, admin_headers, fake):
        """The fix under test: EventSource-style auth via ?token=."""
        me = client.get("/api/auth/me", headers=admin_headers).json()
        sid = _make_completed_scan(fake, me["id"])
        token = admin_headers["Authorization"].split(" ", 1)[1]
        r = client.get(f"/api/scans/{sid}/events?token={token}")
        assert r.status_code == 200, r.text

    def test_events_without_any_credential_401(self, client, admin_headers, fake):
        me = client.get("/api/auth/me", headers=admin_headers).json()
        sid = _make_completed_scan(fake, me["id"])
        r = client.get(f"/api/scans/{sid}/events")
        assert r.status_code == 401

    def test_events_same_org_non_admin_allowed_under_rbac(self, client, admin_headers,
                                                          user_headers, fake):
        """Under Phase 3 RBAC, viewing a same-organization scan's events is a
        require_viewer route (any of the 4 roles), not admin-only — a
        Security Analyst legitimately needs to watch scans run. Cross-*org*
        access is still blocked; see tests/test_tenant_isolation.py."""
        me = client.get("/api/auth/me", headers=admin_headers).json()
        sid = _make_completed_scan(fake, me["id"])
        token = user_headers["Authorization"].split(" ", 1)[1]
        r = client.get(f"/api/scans/{sid}/events?token={token}")
        assert r.status_code == 200

    def test_events_invalid_role_rejected(self, client, admin_headers, fake, monkeypatch):
        """A token whose role isn't one of the 4 valid roles is still refused."""
        me = client.get("/api/auth/me", headers=admin_headers).json()
        sid = _make_completed_scan(fake, me["id"])
        fake.users[me["id"]]["role"] = "not_a_real_role"
        token = admin_headers["Authorization"].split(" ", 1)[1]
        r = client.get(f"/api/scans/{sid}/events?token={token}")
        assert r.status_code == 403
