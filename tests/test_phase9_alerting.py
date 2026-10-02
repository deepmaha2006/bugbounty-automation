"""Phase 9 regression tests: real-time alerting (CVM platform spec §9).

Webhook/Slack/Teams delivery is tested against a REAL local HTTP server
(threading.Thread + http.server) — a genuine network round-trip, not a mock,
since all three are mechanically just "POST JSON to a URL". Email delivery
is tested by mocking smtplib.SMTP instead, since no real SMTP server is
available in this sandbox (Python 3.12+ removed the smtpd module this
environment could otherwise have used) — see the caveat in
webapp/services/alert_engine.py and docs/ROADMAP.md Phase 9.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from webapp.services import alert_engine
from conftest import register_user, auth_headers


class _CapturingHandler(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self._received_bodies.append(json.loads(body))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass  # keep test output quiet


@pytest.fixture()
def capture_server():
    bodies = []

    class Handler(_CapturingHandler):
        _received_bodies = bodies

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", bodies
    server.shutdown()
    thread.join(timeout=5)


def _make_finding(fake, org_id=1, severity="Critical", confidence="confirmed",
                  category="rce", uid=None):
    tid = fake.add_target("https://alert.example.com", org_id)
    fake.update_target_verification(tid, "verified")
    fake.update_asset(tid, org_id, business_criticality="high")
    sid = fake.create_scan(uid or 1, tid, "web", [category])
    fake.add_finding(sid, {"severity": severity, "type": category, "evidence": "proof of exploit",
                           "url": "https://alert.example.com/x", "confidence": confidence,
                           "remediation": "patch it"})
    return fake.findings[-1]["id"]


class TestAlertTriggerConditions:
    def test_critical_confirmed_finding_triggers_an_alert(self, fake, monkeypatch, capture_server):
        url, bodies = capture_server
        fake.create_notification_channel(1, "webhook", "test-hook", {"url": url})
        fid = _make_finding(fake, severity="Critical", confidence="confirmed")
        alert_engine.maybe_alert(fid)
        assert len(bodies) == 1
        assert bodies[0]["severity"] == "Critical"
        assert any(n["status"] == "sent" for n in fake.notifications)

    def test_medium_severity_does_not_alert(self, fake, capture_server):
        url, bodies = capture_server
        fake.create_notification_channel(1, "webhook", "test-hook", {"url": url})
        fid = _make_finding(fake, severity="Medium", category="clickjack")
        alert_engine.maybe_alert(fid)
        assert bodies == []
        assert fake.alerts == {}

    def test_unconfirmed_critical_finding_does_not_alert(self, fake, capture_server):
        url, bodies = capture_server
        fake.create_notification_channel(1, "webhook", "test-hook", {"url": url})
        fid = _make_finding(fake, severity="Critical", confidence="needs_verification")
        alert_engine.maybe_alert(fid)
        assert bodies == []

    def test_no_channels_configured_is_a_safe_noop(self, fake):
        fid = _make_finding(fake, severity="Critical")
        alert_engine.maybe_alert(fid)  # must not raise


class TestDedupAndCooldown:
    def test_same_finding_reuses_one_alert_row(self, fake, capture_server):
        url, bodies = capture_server
        fake.create_notification_channel(1, "webhook", "test-hook", {"url": url})
        fid = _make_finding(fake, severity="Critical")
        alert_engine.maybe_alert(fid)
        alert_engine.maybe_alert(fid)  # e.g. called twice in a retry path
        assert len(fake.alerts) == 1

    def test_within_cooldown_no_second_notification_sent(self, fake, capture_server):
        url, bodies = capture_server
        fake.create_notification_channel(1, "webhook", "test-hook", {"url": url})
        fid = _make_finding(fake, severity="Critical")
        alert_engine.maybe_alert(fid)
        assert len(bodies) == 1
        # Still within the default cooldown window (60 minutes) — the second
        # call must not deliver a second time.
        alert_engine.maybe_alert(fid)
        assert len(bodies) == 1

    def test_after_cooldown_expires_notifies_again(self, fake, monkeypatch, capture_server):
        from datetime import datetime, timedelta, timezone
        url, bodies = capture_server
        fake.create_notification_channel(1, "webhook", "test-hook", {"url": url})
        fid = _make_finding(fake, severity="Critical")
        alert_engine.maybe_alert(fid)
        assert len(bodies) == 1

        alert = next(iter(fake.alerts.values()))
        alert["last_notified_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        alert_engine.maybe_alert(fid)
        assert len(bodies) == 2


class TestChannelDelivery:
    def test_slack_payload_shape(self, fake, capture_server):
        url, bodies = capture_server
        fake.create_notification_channel(1, "slack", "slack-hook", {"url": url})
        fid = _make_finding(fake, severity="High", category="sqli")
        alert_engine.maybe_alert(fid)
        assert "text" in bodies[0]
        assert "sqli" in bodies[0]["text"]

    def test_teams_payload_shape(self, fake, capture_server):
        url, bodies = capture_server
        fake.create_notification_channel(1, "teams", "teams-hook", {"url": url})
        fid = _make_finding(fake, severity="Critical", category="ssrf")
        alert_engine.maybe_alert(fid)
        assert bodies[0]["@type"] == "MessageCard"

    def test_failed_channel_is_recorded_but_does_not_block_others(self, fake, capture_server):
        url, bodies = capture_server
        fake.create_notification_channel(1, "webhook", "broken-hook", {"url": "http://127.0.0.1:1"})
        fake.create_notification_channel(1, "webhook", "working-hook", {"url": url})
        fid = _make_finding(fake, severity="Critical")
        alert_engine.maybe_alert(fid)

        assert len(bodies) == 1  # the working channel still got it
        statuses = {n["status"] for n in fake.notifications}
        assert statuses == {"sent", "failed"}

    def test_email_delivery_uses_smtp(self, fake, monkeypatch):
        sent = {}

        class FakeSMTP:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def starttls(self):
                pass

            def login(self, *a):
                pass

            def sendmail(self, from_addr, to_addrs, msg):
                sent["from"] = from_addr
                sent["to"] = to_addrs
                sent["msg"] = msg

        monkeypatch.setattr(alert_engine.smtplib, "SMTP", FakeSMTP)
        fake.create_notification_channel(1, "email", "email-alerts", {"to": "soc@acme.example.com"})
        fid = _make_finding(fake, severity="Critical")
        alert_engine.maybe_alert(fid)

        assert sent["to"] == ["soc@acme.example.com"]
        assert "Critical" in sent["msg"]
        assert any(n["status"] == "sent" for n in fake.notifications)


class TestAlertsAPI:
    def test_full_flow_list_get_acknowledge(self, fake, client, capture_server):
        url, bodies = capture_server
        a = register_user(client, "alert_admin", organization_name="Alert Co")
        ha = auth_headers(a["access_token"])
        org_id = a["user"]["organization_id"]

        client.post("/api/notification-channels", headers=ha,
                   json={"channel_type": "webhook", "name": "hook", "config": {"url": url}})
        fid = _make_finding(fake, org_id=org_id, uid=a["user"]["id"])
        alert_engine.maybe_alert(fid)

        listing = client.get("/api/alerts", headers=ha).json()
        assert len(listing) == 1
        alert_id = listing[0]["id"]
        assert listing[0]["status"] == "open"
        assert len(listing[0]["notifications"]) == 1

        detail = client.get(f"/api/alerts/{alert_id}", headers=ha).json()
        assert detail["finding_id"] == fid

        ack = client.post(f"/api/alerts/{alert_id}/acknowledge", headers=ha)
        assert ack.status_code == 200
        assert ack.json()["status"] == "acknowledged"
        assert any(e["action"] == "alert_acknowledged" for e in fake.audit)

    def test_channel_management_is_admin_only(self, fake, client):
        a = register_user(client, "chan_admin", organization_name="Chan Co")
        ha = auth_headers(a["access_token"])
        fake.set_user_role(a["user"]["id"], "security_manager")
        r = client.post("/api/notification-channels", headers=ha,
                        json={"channel_type": "webhook", "name": "x", "config": {"url": "http://x"}})
        assert r.status_code == 403

    def test_viewer_can_read_and_operator_can_acknowledge(self, fake, client, capture_server):
        url, _ = capture_server
        a = register_user(client, "viewer_ack_admin", organization_name="ViewerAck Co")
        ha = auth_headers(a["access_token"])
        org_id = a["user"]["organization_id"]
        client.post("/api/notification-channels", headers=ha,
                   json={"channel_type": "webhook", "name": "hook", "config": {"url": url}})
        fid = _make_finding(fake, org_id=org_id, uid=a["user"]["id"])
        alert_engine.maybe_alert(fid)
        alert_id = next(iter(fake.alerts.values()))["id"]

        fake.set_user_role(a["user"]["id"], "viewer")
        assert client.get("/api/alerts", headers=ha).status_code == 200
        assert client.post(f"/api/alerts/{alert_id}/acknowledge", headers=ha).status_code == 403

    def test_alerts_scoped_to_organization(self, fake, client, capture_server):
        url, _ = capture_server
        a = register_user(client, "org1_alert_admin", organization_name="AlertOrg1")
        b = register_user(client, "org2_alert_admin", signup_email=True, organization_name="AlertOrg2")
        client.post("/api/notification-channels", headers=auth_headers(a["access_token"]),
                   json={"channel_type": "webhook", "name": "hook", "config": {"url": url}})
        fid = _make_finding(fake, org_id=a["user"]["organization_id"], uid=a["user"]["id"])
        alert_engine.maybe_alert(fid)
        alert_id = next(iter(fake.alerts.values()))["id"]

        hb = auth_headers(b["access_token"])
        assert client.get(f"/api/alerts/{alert_id}", headers=hb).status_code == 404
        assert client.get("/api/alerts", headers=hb).json() == []
