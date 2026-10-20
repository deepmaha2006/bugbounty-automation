"""
Phase 0 tests — Authorization scope extension.

Hermetic — no network, no Postgres required.

Covers:
  - check_authorization_scope: pure logic (None auth, no constraints, host matching,
    wildcard host, path prefix, mismatches)
  - get_active_authorization via FakeDB: returns latest authorized, ignores revoked,
    ignores expired, returns None when empty
  - _run_scheduled_web_scan gate: skips when no active auth record,
    skips when URL out of scope, proceeds when in scope
"""

import pytest
from unittest.mock import MagicMock, patch

from webapp.db import check_authorization_scope


# ---------------------------------------------------------------------------
# check_authorization_scope — pure function, no DB needed
# ---------------------------------------------------------------------------

class TestCheckAuthorizationScope:
    def _auth(self, scope_hosts=None, scope_paths=None):
        return {"status": "authorized", "scope_hosts": scope_hosts, "scope_paths": scope_paths}

    def test_none_auth_returns_false(self):
        assert check_authorization_scope("https://example.com/", None) is False

    def test_no_scope_constraints_returns_true(self):
        assert check_authorization_scope("https://example.com/api/v1", self._auth()) is True

    def test_scope_hosts_exact_match(self):
        auth = self._auth(scope_hosts=["example.com"])
        assert check_authorization_scope("https://example.com/path", auth) is True

    def test_scope_hosts_exact_mismatch_returns_false(self):
        auth = self._auth(scope_hosts=["example.com"])
        assert check_authorization_scope("https://evil.com/path", auth) is False

    def test_scope_hosts_wildcard_matches_subdomain(self):
        auth = self._auth(scope_hosts=["*.example.com"])
        assert check_authorization_scope("https://app.example.com/path", auth) is True

    def test_scope_hosts_wildcard_matches_base_domain(self):
        auth = self._auth(scope_hosts=["*.example.com"])
        assert check_authorization_scope("https://example.com/path", auth) is True

    def test_scope_hosts_wildcard_does_not_match_other_domain(self):
        auth = self._auth(scope_hosts=["*.example.com"])
        assert check_authorization_scope("https://notexample.com/path", auth) is False

    def test_scope_hosts_empty_list_allows_all(self):
        auth = self._auth(scope_hosts=[])
        assert check_authorization_scope("https://anything.io/path", auth) is True

    def test_scope_paths_prefix_match(self):
        auth = self._auth(scope_paths="/api/")
        assert check_authorization_scope("https://example.com/api/v1/users", auth) is True

    def test_scope_paths_mismatch_returns_false(self):
        auth = self._auth(scope_paths="/api/")
        assert check_authorization_scope("https://example.com/admin/secret", auth) is False

    def test_scope_paths_root_prefix_allows_all(self):
        auth = self._auth(scope_paths="/")
        assert check_authorization_scope("https://example.com/anything", auth) is True

    def test_scope_paths_empty_string_allows_all(self):
        auth = self._auth(scope_paths="")
        assert check_authorization_scope("https://example.com/anything", auth) is True

    def test_host_and_path_both_must_match(self):
        auth = self._auth(scope_hosts=["example.com"], scope_paths="/api/")
        # wrong host
        assert check_authorization_scope("https://other.com/api/v1", auth) is False
        # wrong path
        assert check_authorization_scope("https://example.com/admin/", auth) is False
        # both correct
        assert check_authorization_scope("https://example.com/api/v1", auth) is True

    def test_url_with_port_strips_port_for_host_check(self):
        auth = self._auth(scope_hosts=["example.com"])
        assert check_authorization_scope("https://example.com:8443/path", auth) is True


# ---------------------------------------------------------------------------
# get_active_authorization via FakeDB
# ---------------------------------------------------------------------------

class TestGetActiveAuthorizationFakeDB:
    def _fake_db(self):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
        from conftest import FakeDB
        return FakeDB()

    def test_returns_none_when_no_rows(self):
        db = self._fake_db()
        assert db.get_active_authorization(1, 1) is None

    def test_returns_none_when_only_revoked(self):
        db = self._fake_db()
        db.record_asset_authorization(1, 1, None, "dns_txt", "revoked")
        assert db.get_active_authorization(1, 1) is None

    def test_returns_none_when_only_pending(self):
        db = self._fake_db()
        db.record_asset_authorization(1, 1, None, "dns_txt", "pending")
        assert db.get_active_authorization(1, 1) is None

    def test_returns_authorized_row(self):
        db = self._fake_db()
        db.record_asset_authorization(1, 1, None, "dns_txt", "authorized")
        row = db.get_active_authorization(1, 1)
        assert row is not None
        assert row["status"] == "authorized"

    def test_returns_none_when_expired(self):
        db = self._fake_db()
        db.record_asset_authorization(1, 1, None, "dns_txt", "authorized",
                                      expires_at="2020-01-01T00:00:00+00:00")
        assert db.get_active_authorization(1, 1) is None

    def test_unexpired_returns_row(self):
        db = self._fake_db()
        db.record_asset_authorization(1, 1, None, "dns_txt", "authorized",
                                      expires_at="2099-01-01T00:00:00+00:00")
        row = db.get_active_authorization(1, 1)
        assert row is not None

    def test_ignores_other_asset(self):
        db = self._fake_db()
        db.record_asset_authorization(1, 99, None, "dns_txt", "authorized")
        assert db.get_active_authorization(1, 1) is None

    def test_scope_fields_stored_and_returned(self):
        db = self._fake_db()
        db.record_asset_authorization(1, 1, None, "dns_txt", "authorized",
                                      scope_hosts=["example.com"], scope_paths="/api/",
                                      max_req_per_sec=5.0)
        row = db.get_active_authorization(1, 1)
        assert row["scope_hosts"] == ["example.com"]
        assert row["scope_paths"] == "/api/"
        assert row["max_req_per_sec"] == 5.0


# ---------------------------------------------------------------------------
# _run_scheduled_web_scan authorization gate
# ---------------------------------------------------------------------------

_ASSET_BASE = {
    "id": 1, "url": "https://example.com/", "organization_id": 1,
    "verification_status": "verified", "authorization_status": "authorized",
    "added_by_user_id": 42,
}

_AUTH_ROW = {
    "status": "authorized", "scope_hosts": None, "scope_paths": None,
    "expires_at": None,
}


class TestScheduledScanAuthorizationGate:
    def _run(self, asset=None, active_auth=_AUTH_ROW, scope_ok=True):
        from webapp.tasks import _run_scheduled_web_scan
        a = dict(_ASSET_BASE)
        if asset:
            a.update(asset)
        with patch("webapp.tasks.db") as mock_db, \
             patch("webapp.tasks.web_scan_service") as mock_svc:
            mock_db.get_asset.return_value = a
            mock_db.get_active_authorization.return_value = active_auth
            mock_db.check_authorization_scope.return_value = scope_ok
            _run_scheduled_web_scan(1, 1)
            return mock_svc.start_web_scan.called

    def test_proceeds_when_authorization_in_scope(self):
        assert self._run() is True

    def test_skips_when_asset_not_found(self):
        from webapp.tasks import _run_scheduled_web_scan
        with patch("webapp.tasks.db") as mock_db, \
             patch("webapp.tasks.web_scan_service") as mock_svc:
            mock_db.get_asset.return_value = None
            _run_scheduled_web_scan(1, 1)
            assert mock_svc.start_web_scan.called is False

    def test_skips_when_not_verified(self):
        called = self._run(asset={"verification_status": "pending"})
        assert called is False

    def test_skips_when_no_active_authorization_record(self):
        called = self._run(active_auth=None, scope_ok=False)
        assert called is False

    def test_skips_when_url_out_of_scope(self):
        called = self._run(active_auth=_AUTH_ROW, scope_ok=False)
        assert called is False

    def test_skips_when_no_owning_user(self):
        called = self._run(asset={"added_by_user_id": None})
        assert called is False
