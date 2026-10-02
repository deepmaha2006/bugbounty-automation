"""Phase 5 regression tests: per-asset monitoring schedule configuration and
the scheduler's due-check/enqueue logic (spec §7).

Celery task bodies are called as plain Python functions here (webapp.tasks._*),
never via .delay()/.apply_async() — no Redis broker is available in this
environment, so what's verified is the scheduling *logic* (which assets are
due, how the schedule advances, the authorization re-check before a
scheduled scan runs), not the broker round-trip itself. See the caveat in
webapp/celery_app.py and docs/ROADMAP.md Phase 5.
"""
from datetime import datetime, timedelta, timezone

from conftest import register_user, auth_headers


class TestMonitoringConfigAPI:
    def test_activate_monitoring_schedules_immediate_first_check(self, fake, client):
        a = register_user(client, "sched_admin", organization_name="Sched Co")
        ha = auth_headers(a["access_token"])
        asset = client.post("/api/assets", headers=ha, json={
            "name": "Sched Site", "asset_type": "WEB_APPLICATION", "url": "https://sched.example.com",
        }).json()
        assert asset["monitoring_frequency"] == "manual"
        assert asset["next_scan_at"] is None

        r = client.patch(f"/api/assets/{asset['id']}/monitoring", headers=ha,
                         json={"monitoring_status": "active", "monitoring_frequency": "hourly"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["monitoring_status"] == "active"
        assert body["monitoring_frequency"] == "hourly"
        assert body["next_scan_at"] is not None
        assert any(e["action"] == "asset_monitoring_changed" for e in fake.audit)

    def test_setting_manual_frequency_clears_schedule(self, fake, client):
        a = register_user(client, "unsched_admin", organization_name="Unsched Co")
        ha = auth_headers(a["access_token"])
        asset = client.post("/api/assets", headers=ha, json={
            "name": "X", "asset_type": "WEB_APPLICATION", "url": "https://unsched.example.com",
        }).json()
        client.patch(f"/api/assets/{asset['id']}/monitoring", headers=ha,
                    json={"monitoring_status": "active", "monitoring_frequency": "daily"})
        r = client.patch(f"/api/assets/{asset['id']}/monitoring", headers=ha,
                         json={"monitoring_status": "paused", "monitoring_frequency": "manual"})
        assert r.json()["next_scan_at"] is None

    def test_invalid_frequency_rejected(self, fake, client):
        a = register_user(client, "badfreq_admin", organization_name="BadFreq Co")
        ha = auth_headers(a["access_token"])
        asset = client.post("/api/assets", headers=ha, json={
            "name": "X", "asset_type": "WEB_APPLICATION", "url": "https://badfreq.example.com",
        }).json()
        r = client.patch(f"/api/assets/{asset['id']}/monitoring", headers=ha,
                         json={"monitoring_status": "active", "monitoring_frequency": "every_5_seconds"})
        assert r.status_code == 422

    def test_viewer_cannot_configure_monitoring(self, fake, client):
        a = register_user(client, "viewer_sched_admin", organization_name="ViewerSched Co")
        ha = auth_headers(a["access_token"])
        asset = client.post("/api/assets", headers=ha, json={
            "name": "X", "asset_type": "WEB_APPLICATION", "url": "https://viewersched.example.com",
        }).json()
        fake.set_user_role(a["user"]["id"], "viewer")
        r = client.patch(f"/api/assets/{asset['id']}/monitoring", headers=ha,
                         json={"monitoring_status": "active", "monitoring_frequency": "daily"})
        assert r.status_code == 403


class TestDueAssetDetection:
    def test_list_due_assets_only_returns_active_scheduled_and_overdue(self, fake):
        # Due: active, real frequency, next_scan_at in the past.
        due_id = fake.add_target("https://due.example.com", 1)
        fake.set_asset_monitoring(due_id, 1, "active", "hourly")
        fake.targets[due_id]["next_scan_at"] = (
            datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

        # Not due: scheduled but in the future.
        future_id = fake.add_target("https://future.example.com", 1)
        fake.set_asset_monitoring(future_id, 1, "active", "hourly")
        fake.targets[future_id]["next_scan_at"] = (
            datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        # Not due: paused.
        paused_id = fake.add_target("https://paused.example.com", 1)
        fake.set_asset_monitoring(paused_id, 1, "active", "hourly")
        fake.targets[paused_id]["next_scan_at"] = (
            datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        fake.targets[paused_id]["monitoring_status"] = "paused"

        # Not due: manual (never scheduled at all).
        fake.add_target("https://manual.example.com", 1)

        due = fake.list_due_assets()
        due_ids = {a["id"] for a in due}
        assert due_ids == {due_id}

    def test_mark_asset_scanned_advances_by_its_own_frequency(self, fake):
        aid = fake.add_target("https://advance.example.com", 1)
        fake.set_asset_monitoring(aid, 1, "active", "15m")
        before = datetime.now(timezone.utc)
        fake.mark_asset_scanned(aid)
        next_scan = datetime.fromisoformat(fake.targets[aid]["next_scan_at"])
        assert timedelta(minutes=14) < (next_scan - before) < timedelta(minutes=16)
        assert fake.targets[aid]["last_scan_at"] is not None


class TestSchedulerTask:
    def test_check_due_scans_marks_scanned_and_enqueues_each_due_asset(self, fake, monkeypatch):
        from webapp import tasks
        monkeypatch.setattr(tasks.db, "list_due_assets", fake.list_due_assets)
        monkeypatch.setattr(tasks.db, "mark_asset_scanned", fake.mark_asset_scanned)

        aid = fake.add_target("https://taskdue.example.com", 1)
        fake.set_asset_monitoring(aid, 1, "active", "hourly")
        fake.targets[aid]["next_scan_at"] = (
            datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()

        enqueued = []
        count = tasks._check_due_scans(enqueue=lambda a_id, o_id: enqueued.append((a_id, o_id)))

        assert count == 1
        assert enqueued == [(aid, 1)]
        # Schedule was advanced so the same asset isn't picked up again immediately.
        assert fake.targets[aid]["next_scan_at"] > (datetime.now(timezone.utc)).isoformat()

    def test_check_due_scans_enqueues_nothing_when_none_due(self, fake, monkeypatch):
        from webapp import tasks
        monkeypatch.setattr(tasks.db, "list_due_assets", fake.list_due_assets)
        monkeypatch.setattr(tasks.db, "mark_asset_scanned", fake.mark_asset_scanned)
        enqueued = []
        count = tasks._check_due_scans(enqueue=lambda a_id, o_id: enqueued.append((a_id, o_id)))
        assert count == 0
        assert enqueued == []


class TestScheduledScanExecution:
    def test_authorized_verified_asset_triggers_a_scan(self, fake, monkeypatch):
        from webapp import tasks
        monkeypatch.setattr(tasks.db, "get_asset", fake.get_asset)

        uid = fake.create_user("scanowner", "scanowner@hydrax.local", "x", 1)
        aid = fake.add_target("https://execscan.example.com", 1, added_by_user_id=uid)
        fake.update_target_verification(aid, "verified")

        calls = []
        monkeypatch.setattr(tasks.web_scan_service, "start_web_scan",
                            lambda *a, **k: calls.append((a, k)))
        tasks._run_scheduled_web_scan(aid, 1)
        assert len(calls) == 1
        assert calls[0][0][0] == uid  # started as the asset's owning user

    def test_deauthorized_asset_is_skipped_not_scanned(self, fake, monkeypatch):
        """Re-checked at execution time, not trusted from when it was scheduled."""
        from webapp import tasks
        monkeypatch.setattr(tasks.db, "get_asset", fake.get_asset)

        uid = fake.create_user("deauthowner", "deauthowner@hydrax.local", "x", 1)
        aid = fake.add_target("https://deauth.example.com", 1, added_by_user_id=uid)
        # Never verified/authorized.

        calls = []
        monkeypatch.setattr(tasks.web_scan_service, "start_web_scan",
                            lambda *a, **k: calls.append((a, k)))
        tasks._run_scheduled_web_scan(aid, 1)
        assert calls == []

    def test_missing_asset_is_skipped_gracefully(self, fake, monkeypatch):
        from webapp import tasks
        monkeypatch.setattr(tasks.db, "get_asset", fake.get_asset)
        calls = []
        monkeypatch.setattr(tasks.web_scan_service, "start_web_scan",
                            lambda *a, **k: calls.append((a, k)))
        tasks._run_scheduled_web_scan(99999, 1)
        assert calls == []
