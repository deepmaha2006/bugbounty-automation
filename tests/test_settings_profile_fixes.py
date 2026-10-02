"""Regression tests for the settings/profile API fixes (settings booleans,
profile role/email/stats)."""
import pytest

from webapp.routers.settings import _parse_bool

BOOL_KEYS = ("verify_ssl",)
REMOVED_KEYS = ("hexstrike_url", "enable_hexstrike", "enable_ai_enrichment")


# --- Item 1: settings booleans ----------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    ("true", True), ("TRUE", True), ("1", True), ("yes", True), ("on", True), (True, True),
    ("false", False), ("False", False), ("0", False), ("no", False), ("", False),
    (None, False), (False, False), ("garbage", False),
])
def test_parse_bool(raw, expected):
    assert _parse_bool(raw) is expected


def test_saved_off_toggles_read_back_off(client, admin_headers):
    r = client.put("/api/settings", headers=admin_headers,
                   json={k: False for k in BOOL_KEYS})
    assert r.status_code == 200, r.text
    got = client.get("/api/settings", headers=admin_headers).json()
    for k in BOOL_KEYS:
        assert got[k] is False, (k, got[k])


def test_saved_on_toggles_read_back_on(client, admin_headers):
    client.put("/api/settings", headers=admin_headers, json={k: True for k in BOOL_KEYS})
    got = client.get("/api/settings", headers=admin_headers).json()
    for k in BOOL_KEYS:
        assert got[k] is True, (k, got[k])


def test_unset_settings_keep_previous_shape(client, admin_headers):
    got = client.get("/api/settings", headers=admin_headers).json()
    for k in BOOL_KEYS:
        assert got[k] is None
    assert got["default_threads"] is None


def test_removed_settings_are_not_exposed_or_stored(client, admin_headers, fake):
    # HexStrike + AI-enrichment settings were removed: GET no longer returns
    # them, and PUT silently ignores them (extra fields are dropped).
    r = client.put("/api/settings", headers=admin_headers,
                   json={"hexstrike_url": "http://x", "enable_hexstrike": True,
                         "enable_ai_enrichment": True, "verify_ssl": False})
    assert r.status_code == 200, r.text
    got = client.get("/api/settings", headers=admin_headers).json()
    for k in REMOVED_KEYS:
        assert k not in got
        assert k not in fake.get_all_settings()
    assert got["verify_ssl"] is False


# --- Item 2: role in GET /profile --------------------------------------------
def test_profile_returns_role_for_admin(client, admin_headers):
    r = client.get("/api/profile", headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["role"] == "admin"          # first user is promoted to admin
    assert body["username"] == "badmin"


def test_profile_role_matches_login_response(client, admin_headers, user_headers):
    me = client.get("/api/auth/me", headers=user_headers).json()
    prof = client.get("/api/profile", headers=user_headers).json()
    assert prof["role"] == me["role"]
    assert prof["role"] != "admin"


def test_profile_role_survives_profile_save(client, admin_headers):
    r = client.put("/api/profile", headers=admin_headers,
                   json={"full_name": "Ada Admin", "organization": "HydraX"})
    assert r.status_code == 200, r.text
    body = client.get("/api/profile", headers=admin_headers).json()
    assert body["role"] == "admin"
    assert body["full_name"] == "Ada Admin"


# --- Item 4: email persistence + hero stats ------------------------------------
from datetime import datetime  # noqa: E402


def test_email_still_returned_after_profile_save(client, admin_headers):
    before = client.get("/api/profile", headers=admin_headers).json()["email"]
    assert before
    r = client.put("/api/profile", headers=admin_headers,
                   json={"full_name": "Ada Admin", "organization": "HydraX"})
    assert r.status_code == 200, r.text
    after = client.get("/api/profile", headers=admin_headers).json()
    assert after["email"] == before
    assert after["full_name"] == "Ada Admin"


def test_profile_includes_member_since_from_user_record(client, admin_headers):
    body = client.get("/api/profile", headers=admin_headers).json()
    datetime.fromisoformat(body["member_since"])        # real, parseable timestamp


def test_profile_stats_reflect_org_data(client, fake, admin_headers):
    body = client.get("/api/profile", headers=admin_headers).json()
    assert (body["total_scans"], body["total_findings"], body["stats_scope"]) == (0, 0, "organization")

    tid = fake.add_target("https://t.example", verification_method="dns_txt")
    sid = fake.create_scan(1, tid, "web", ["xss"])
    fake.add_finding(sid, {"type": "Stored XSS", "severity": "Critical", "evidence": "a",
                           "url": "https://t.example/a"})
    fake.add_finding(sid, {"type": "Open Redirect", "severity": "Medium", "evidence": "b",
                           "url": "https://t.example/b"})
    body = client.get("/api/profile", headers=admin_headers).json()
    assert (body["total_scans"], body["total_findings"]) == (1, 2)


def test_profile_still_works_if_stats_fail(client, fake, admin_headers, monkeypatch):
    from webapp import db as db_module

    def boom(_org):
        raise RuntimeError("stats down")
    monkeypatch.setattr(db_module, "dashboard_stats", boom)
    r = client.get("/api/profile", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert "total_scans" not in body and body["email"] and body["role"] == "admin"
