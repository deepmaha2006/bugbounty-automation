"""Phase 14 regression tests: observability (CVM platform spec §22).

Covers structured JSON logging with request/organization correlation, the
three real component health checks + their aggregation, the /health and
/healthz endpoints, and the admin-only org-scoped system-health metrics
endpoint.
"""
import json
import logging

import pytest

from webapp import logging_config
from webapp.routers import auth as auth_router
from webapp.services import health
from conftest import register_user, auth_headers


class TestJsonFormatter:
    def test_formats_valid_json_with_correlation_fields(self):
        logging_config.request_id_var.set("req-123")
        logging_config.organization_id_var.set(7)
        try:
            record = logging.LogRecord(
                "hydrax.test", logging.INFO, __file__, 1, "something happened", (), None)
            record.request_id = logging_config.request_id_var.get()
            record.organization_id = logging_config.organization_id_var.get()
            line = logging_config.JsonFormatter().format(record)
            parsed = json.loads(line)
        finally:
            logging_config.request_id_var.set(None)
            logging_config.organization_id_var.set(None)
        assert parsed["message"] == "something happened"
        assert parsed["level"] == "INFO"
        assert parsed["request_id"] == "req-123"
        assert parsed["organization_id"] == 7

    def test_extra_fields_are_included(self):
        record = logging.LogRecord(
            "hydrax.test", logging.INFO, __file__, 1, "job done", (), None)
        record.request_id = None
        record.organization_id = None
        record.job_id = 42
        parsed = json.loads(logging_config.JsonFormatter().format(record))
        assert parsed["job_id"] == 42


class TestRequestIdMiddleware:
    def test_response_carries_a_request_id_header(self, fake, client):
        r = client.get("/health")
        assert "X-Request-ID" in r.headers
        assert len(r.headers["X-Request-ID"]) > 0

    def test_each_request_gets_a_distinct_request_id(self, fake, client):
        r1 = client.get("/health")
        r2 = client.get("/health")
        assert r1.headers["X-Request-ID"] != r2.headers["X-Request-ID"]

    def test_client_supplied_request_id_is_honored(self, fake, client):
        r = client.get("/health", headers={"X-Request-ID": "caller-supplied-id"})
        assert r.headers["X-Request-ID"] == "caller-supplied-id"


class TestOrganizationContextBinding:
    def test_resolving_a_user_by_api_key_binds_organization_id_context(self, fake):
        from webapp import security
        uid = fake.create_user("ctxuser", "ctxuser@hydrax.local", "hash", organization_id=55)
        raw_key = "real-raw-key"
        fake.create_api_key(55, uid, "test-key", "abcd", security.hash_opaque_token(raw_key))

        logging_config.organization_id_var.set(None)
        user = auth_router._resolve_user(None, raw_key)
        assert user is not None
        assert logging_config.organization_id_var.get() == 55
        logging_config.organization_id_var.set(None)


class TestHealthChecks:
    def test_check_database_ok_against_fake(self, fake):
        assert health.check_database() == {"status": "ok"}

    def test_check_database_down_when_connection_fails(self, monkeypatch):
        from webapp import db as db_module

        def _boom():
            raise ConnectionError("no db")
        monkeypatch.setattr(db_module, "_get_conn", _boom)
        result = health.check_database()
        assert result["status"] == "down"
        assert "no db" in result["error"]

    def test_check_redis_down_when_unreachable(self, monkeypatch):
        import redis as redis_module

        class _BoomClient:
            def ping(self):
                raise redis_module.exceptions.ConnectionError("refused")
        monkeypatch.setattr(redis_module, "from_url", lambda *a, **k: _BoomClient())
        result = health.check_redis()
        assert result["status"] == "down"

    def test_check_redis_ok_when_reachable(self, monkeypatch):
        class _FakeClient:
            def ping(self):
                return True
        import redis as redis_module
        monkeypatch.setattr(redis_module, "from_url", lambda *a, **k: _FakeClient())
        assert health.check_redis() == {"status": "ok"}

    def test_check_scan_queue_reports_live_snapshot(self, fake):
        from webapp.services import scan_manager
        scan_manager.start()
        result = health.check_scan_queue()
        assert "queued" in result and "active" in result and "max_concurrent" in result

    def test_overall_health_ok_when_everything_ok(self, monkeypatch):
        monkeypatch.setattr(health, "check_database", lambda: {"status": "ok"})
        monkeypatch.setattr(health, "check_redis", lambda: {"status": "ok"})
        monkeypatch.setattr(health, "check_scan_queue", lambda: {"status": "ok"})
        assert health.overall_health()["status"] == "ok"

    def test_overall_health_degraded_when_redis_down_but_db_ok(self, monkeypatch):
        monkeypatch.setattr(health, "check_database", lambda: {"status": "ok"})
        monkeypatch.setattr(health, "check_redis", lambda: {"status": "down"})
        monkeypatch.setattr(health, "check_scan_queue", lambda: {"status": "ok"})
        assert health.overall_health()["status"] == "degraded"

    def test_overall_health_down_when_database_down(self, monkeypatch):
        monkeypatch.setattr(health, "check_database", lambda: {"status": "down"})
        monkeypatch.setattr(health, "check_redis", lambda: {"status": "ok"})
        monkeypatch.setattr(health, "check_scan_queue", lambda: {"status": "ok"})
        assert health.overall_health()["status"] == "down"


class TestHealthEndpoint:
    def test_health_endpoint_structure(self, fake, client):
        r = client.get("/health")
        body = r.json()
        assert set(body.keys()) >= {"status", "version", "components"}
        # The external HexStrike server integration was removed.
        assert "hexstrike" not in body
        assert set(body["components"].keys()) == {"database", "redis", "scan_queue"}

    def test_healthz_alias_matches_health(self, fake, client):
        r1 = client.get("/health")
        r2 = client.get("/healthz")
        assert r1.json()["status"] == r2.json()["status"]

    def test_health_returns_503_when_database_down(self, fake, client, monkeypatch):
        from webapp.services import health as health_service
        monkeypatch.setattr(health_service, "overall_health",
                            lambda: {"status": "down", "version": "x", "components": {}})
        r = client.get("/health")
        assert r.status_code == 503


class TestSystemHealthEndpoint:
    def test_admin_sees_real_scan_and_alert_metrics(self, fake, client):
        a = register_user(client, "syshealth_admin", organization_name="SysHealth Co")
        headers = auth_headers(a["access_token"])
        org_id, uid = a["user"]["organization_id"], a["user"]["id"]

        tid = fake.add_target("https://syshealth.example.com", org_id)
        fake.update_target_verification(tid, "verified")
        sid_ok = fake.create_scan(uid, tid, "web", ["xss"])
        fake.update_scan(sid_ok, status="completed",
                         started_at="2026-09-01T00:00:00+00:00",
                         finished_at="2026-09-01T00:01:40+00:00")
        sid_fail = fake.create_scan(uid, tid, "web", ["xss"])
        fake.update_scan(sid_fail, status="error")

        r = client.get("/api/dashboard/system-health", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["scan_count_7d"] == 2
        assert body["scan_failure_count_7d"] == 1
        assert body["avg_scan_duration_seconds_7d"] == 100.0
        assert "scan_queue" in body

    def test_non_admin_cannot_see_system_health(self, fake, client):
        a = register_user(client, "syshealth_admin2", organization_name="SysHealth2 Co")
        member = register_user(client, "syshealth_member", signup_email=True)
        headers = auth_headers(member["access_token"])
        r = client.get("/api/dashboard/system-health", headers=headers)
        assert r.status_code == 403
