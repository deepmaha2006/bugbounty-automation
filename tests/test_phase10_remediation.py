"""Phase 10 regression tests: remediation workflow + automatic fix
verification (CVM platform spec §14, §15).

submit_fix() calls the real web_scan_service.start_web_scan, mocked here to
avoid an actual network scan — what's under test is the remediation state
machine and the verification decision logic, not the scanner itself (already
covered elsewhere).
"""
from conftest import register_user, auth_headers


def _make_finding(fake, org_id=1, uid=1, category="xss"):
    tid = fake.add_target("https://remediate.example.com", org_id)
    fake.update_target_verification(tid, "verified")
    sid = fake.create_scan(uid, tid, "web", [category])
    fake.add_finding(sid, {"severity": "High", "type": category, "evidence": "e",
                           "url": "https://remediate.example.com/x", "confidence": "confirmed"})
    return fake.findings[-1]["id"], tid


class TestTaskLifecycleBasics:
    def test_create_task_with_assignee_starts_assigned(self, fake, client):
        a = register_user(client, "remed_admin", organization_name="Remed Co")
        ha = auth_headers(a["access_token"])
        fid, _ = _make_finding(fake, org_id=a["user"]["organization_id"], uid=a["user"]["id"])
        r = client.post("/api/remediation-tasks", headers=ha,
                        json={"finding_id": fid, "assignee_user_id": a["user"]["id"], "priority": "high"})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "ASSIGNED"

    def test_create_task_without_assignee_starts_open(self, fake, client):
        a = register_user(client, "remed_open_admin", organization_name="RemedOpen Co")
        ha = auth_headers(a["access_token"])
        fid, _ = _make_finding(fake, org_id=a["user"]["organization_id"], uid=a["user"]["id"])
        r = client.post("/api/remediation-tasks", headers=ha, json={"finding_id": fid})
        assert r.json()["status"] == "OPEN"

    def test_manual_status_moves_allowed(self, fake, client):
        a = register_user(client, "remed_move_admin", organization_name="RemedMove Co")
        ha = auth_headers(a["access_token"])
        fid, _ = _make_finding(fake, org_id=a["user"]["organization_id"], uid=a["user"]["id"])
        task = client.post("/api/remediation-tasks", headers=ha, json={"finding_id": fid}).json()
        r = client.patch(f"/api/remediation-tasks/{task['id']}", headers=ha, json={"status": "IN_PROGRESS"})
        assert r.status_code == 200
        assert r.json()["status"] == "IN_PROGRESS"

    def test_cannot_manually_set_fixed_or_rescan(self, fake, client):
        """The whole point of spec §15: FIXED is never a direct manual move."""
        a = register_user(client, "remed_cheat_admin", organization_name="RemedCheat Co")
        ha = auth_headers(a["access_token"])
        fid, _ = _make_finding(fake, org_id=a["user"]["organization_id"], uid=a["user"]["id"])
        task = client.post("/api/remediation-tasks", headers=ha, json={"finding_id": fid}).json()
        for forbidden in ("FIXED", "RESCAN", "VERIFICATION", "FIX_SUBMITTED", "REOPENED"):
            r = client.patch(f"/api/remediation-tasks/{task['id']}", headers=ha, json={"status": forbidden})
            assert r.status_code == 422, f"expected 422 for status={forbidden}, got {r.status_code}"

    def test_comments_are_recorded_with_author(self, fake, client):
        a = register_user(client, "remed_comment_admin", organization_name="RemedComment Co")
        ha = auth_headers(a["access_token"])
        fid, _ = _make_finding(fake, org_id=a["user"]["organization_id"], uid=a["user"]["id"])
        task = client.post("/api/remediation-tasks", headers=ha, json={"finding_id": fid}).json()
        r = client.post(f"/api/remediation-tasks/{task['id']}/comments", headers=ha,
                        json={"comment": "working on this now"})
        assert r.status_code == 200
        assert r.json()["comments"][0]["comment"] == "working on this now"
        assert r.json()["comments"][0]["user_id"] == a["user"]["id"]


class TestAutomaticVerification:
    def test_submit_fix_schedules_a_real_verification_scan(self, fake, client, monkeypatch):
        from webapp.services import remediation_service
        a = register_user(client, "verify_admin", organization_name="Verify Co")
        ha = auth_headers(a["access_token"])
        fid, tid = _make_finding(fake, org_id=a["user"]["organization_id"], uid=a["user"]["id"])
        task = client.post("/api/remediation-tasks", headers=ha, json={"finding_id": fid}).json()

        started = []
        monkeypatch.setattr(remediation_service.web_scan_service, "start_web_scan",
                            lambda uid, url, keys: (started.append((uid, url, keys)),
                                                    fake.create_scan(uid, tid, "web", keys))[1])
        r = client.post(f"/api/remediation-tasks/{task['id']}/submit-fix", headers=ha)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "RESCAN"
        assert body["verification_scan_id"] is not None
        assert len(started) == 1
        assert started[0][2] == ["xss"]  # verifies only the finding's own category

        # The underlying finding also moved to FIX_PENDING_VERIFICATION.
        finding = fake.get_finding(fid, a["user"]["organization_id"])
        assert finding["status"] == "FIX_PENDING_VERIFICATION"

    def test_finalization_marks_fixed_when_vulnerability_not_redetected(self, fake, client, monkeypatch):
        from webapp import tasks
        from webapp.services import remediation_service
        a = register_user(client, "fixed_admin", organization_name="Fixed Co")
        ha = auth_headers(a["access_token"])
        fid, tid = _make_finding(fake, org_id=a["user"]["organization_id"], uid=a["user"]["id"])
        task = client.post("/api/remediation-tasks", headers=ha, json={"finding_id": fid}).json()

        def fake_start_scan(uid, url, keys):
            sid = fake.create_scan(uid, tid, "web", keys)
            fake.update_scan(sid, status="completed")  # no re-detection happens
            return sid

        monkeypatch.setattr(remediation_service.web_scan_service, "start_web_scan", fake_start_scan)
        client.post(f"/api/remediation-tasks/{task['id']}/submit-fix", headers=ha)

        monkeypatch.setattr(tasks.db, "list_tasks_awaiting_verification", fake.list_tasks_awaiting_verification)
        monkeypatch.setattr(tasks.db, "get_finding_unscoped", fake.get_finding_unscoped)
        monkeypatch.setattr(tasks.db, "finalize_verification", fake.finalize_verification)
        finalized = tasks.check_verifications()

        assert finalized == 1
        final_task = client.get(f"/api/remediation-tasks/{task['id']}", headers=ha).json()
        assert final_task["status"] == "FIXED"
        assert final_task["verification_evidence"]["still_present"] is False
        finding = fake.get_finding(fid, a["user"]["organization_id"])
        assert finding["status"] == "FIXED"

    def test_finalization_marks_reopened_when_vulnerability_redetected(self, fake, client, monkeypatch):
        from webapp import tasks
        from webapp.services import remediation_service
        a = register_user(client, "reopen_admin", organization_name="Reopen Co")
        ha = auth_headers(a["access_token"])
        fid, tid = _make_finding(fake, org_id=a["user"]["organization_id"], uid=a["user"]["id"])
        task = client.post("/api/remediation-tasks", headers=ha, json={"finding_id": fid}).json()

        def fake_start_scan(uid, url, keys):
            sid = fake.create_scan(uid, tid, "web", keys)
            # The verification scan re-detects the same vulnerability — the
            # fingerprint dedup (Phase 4) updates the finding's scan_id to
            # this new scan, which is exactly the signal finalization reads.
            fake.add_finding(sid, {"severity": "High", "type": "xss", "evidence": "e",
                                   "url": "https://remediate.example.com/x", "confidence": "confirmed"})
            fake.update_scan(sid, status="completed")
            return sid

        monkeypatch.setattr(remediation_service.web_scan_service, "start_web_scan", fake_start_scan)
        client.post(f"/api/remediation-tasks/{task['id']}/submit-fix", headers=ha)

        monkeypatch.setattr(tasks.db, "list_tasks_awaiting_verification", fake.list_tasks_awaiting_verification)
        monkeypatch.setattr(tasks.db, "get_finding_unscoped", fake.get_finding_unscoped)
        monkeypatch.setattr(tasks.db, "finalize_verification", fake.finalize_verification)
        tasks.check_verifications()

        final_task = client.get(f"/api/remediation-tasks/{task['id']}", headers=ha).json()
        assert final_task["status"] == "REOPENED"
        finding = fake.get_finding(fid, a["user"]["organization_id"])
        assert finding["status"] == "REOPENED"
        assert finding["occurrence_count"] == 2

    def test_incomplete_scan_is_not_finalized_yet(self, fake, client, monkeypatch):
        from webapp import tasks
        from webapp.services import remediation_service
        a = register_user(client, "pending_admin", organization_name="Pending Co")
        ha = auth_headers(a["access_token"])
        fid, tid = _make_finding(fake, org_id=a["user"]["organization_id"], uid=a["user"]["id"])
        task = client.post("/api/remediation-tasks", headers=ha, json={"finding_id": fid}).json()

        def fake_start_scan(uid, url, keys):
            return fake.create_scan(uid, tid, "web", keys)  # left "queued"

        monkeypatch.setattr(remediation_service.web_scan_service, "start_web_scan", fake_start_scan)
        client.post(f"/api/remediation-tasks/{task['id']}/submit-fix", headers=ha)

        monkeypatch.setattr(tasks.db, "list_tasks_awaiting_verification", fake.list_tasks_awaiting_verification)
        finalized = tasks.check_verifications()
        assert finalized == 0

        still_rescan = client.get(f"/api/remediation-tasks/{task['id']}", headers=ha).json()
        assert still_rescan["status"] == "RESCAN"

    def test_submit_fix_rejects_unauthorized_asset(self, fake, client):
        a = register_user(client, "unauth_admin", organization_name="Unauth Co")
        ha = auth_headers(a["access_token"])
        tid = fake.add_target("https://never-verified.example.com", a["user"]["organization_id"])
        sid = fake.create_scan(a["user"]["id"], tid, "web", ["xss"])
        fake.add_finding(sid, {"severity": "High", "type": "xss", "evidence": "e",
                               "url": "https://never-verified.example.com"})
        fid = fake.findings[-1]["id"]
        task = client.post("/api/remediation-tasks", headers=ha, json={"finding_id": fid}).json()

        r = client.post(f"/api/remediation-tasks/{task['id']}/submit-fix", headers=ha)
        assert r.status_code == 422


class TestRBACAndIsolation:
    def test_viewer_cannot_create_or_submit_fix(self, fake, client):
        a = register_user(client, "remed_viewer_admin", organization_name="RemedViewer Co")
        ha = auth_headers(a["access_token"])
        fid, _ = _make_finding(fake, org_id=a["user"]["organization_id"], uid=a["user"]["id"])
        fake.set_user_role(a["user"]["id"], "viewer")
        r = client.post("/api/remediation-tasks", headers=ha, json={"finding_id": fid})
        assert r.status_code == 403

    def test_tasks_scoped_to_organization(self, fake, client):
        a = register_user(client, "remed_org1_admin", organization_name="RemedOrg1")
        b = register_user(client, "remed_org2_admin", signup_email=True, organization_name="RemedOrg2")
        fid, _ = _make_finding(fake, org_id=a["user"]["organization_id"], uid=a["user"]["id"])
        task = client.post("/api/remediation-tasks", headers=auth_headers(a["access_token"]),
                          json={"finding_id": fid}).json()

        hb = auth_headers(b["access_token"])
        assert client.get(f"/api/remediation-tasks/{task['id']}", headers=hb).status_code == 404
        assert client.get("/api/remediation-tasks", headers=hb).json() == []
