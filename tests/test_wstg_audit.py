"""OWASP WSTG / ASVS / Top 10 audit regression tests.

Locks in every fix made during the WSTG-baseline security audit documented
in docs/SECURITY_AUDIT_WSTG.md. Each test class is headed with the WSTG
test ID(s) and ASVS/Top 10 mapping it verifies, matching that document.
"""
import logging

import pytest

from webapp import security
from webapp.routers import auth as auth_router
from webapp.services import health
from utils.reporter import ReportGenerator
from conftest import register_user, auth_headers


# --- WSTG-CONF-07 / WSTG-CLNT-09 — HTTP security headers (ASVS V14.4) -------
class TestSecurityHeaders:
    def test_every_response_carries_the_core_headers(self, fake, client):
        r = client.get("/health")
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert r.headers["Referrer-Policy"] == "no-referrer"
        assert "geolocation=()" in r.headers["Permissions-Policy"]
        assert "max-age=" in r.headers["Strict-Transport-Security"]

    def test_content_security_policy_blocks_wildcard_and_unsafe_script(self, fake, client):
        csp = client.get("/health").headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp
        assert "script-src" in csp and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]

    def test_api_responses_are_never_cached(self, fake, client):
        a = register_user(client, "hdrs_admin", organization_name="Hdrs Co")
        headers = auth_headers(a["access_token"])
        r = client.get("/api/dashboard/stats", headers=headers)
        assert r.headers["Cache-Control"] == "no-store"

    def test_non_api_routes_are_not_forced_no_store(self, fake, client):
        # Cache-Control: no-store is an /api/* -specific control, not a
        # blanket rule applied to every response.
        r = client.get("/health")
        assert r.headers.get("Cache-Control") != "no-store"


# --- WSTG-ATHN-07 — weak password policy (ASVS V2.1.1) ----------------------
class TestPasswordPolicy:
    def test_registration_rejects_under_12_chars(self, fake, client):
        r = client.post("/api/auth/register", json={
            "username": "shortpw", "email": "shortpw@hydrax.local", "password": "short1234",
        })
        assert r.status_code == 422

    def test_registration_accepts_12_chars(self, fake, client):
        r = client.post("/api/auth/register", json={
            "username": "longenough", "email": "longenough@hydrax.local", "password": "twelvechars!",
        })
        assert r.status_code == 200, r.text

    def test_password_change_rejects_under_12_chars(self, fake, client):
        a = register_user(client, "pwchange_user")
        headers = auth_headers(a["access_token"])
        r = client.post("/api/profile/password", headers=headers, json={
            "current_password": "passw0rd1234", "new_password": "short1",
        })
        assert r.status_code == 422

    def test_password_change_accepts_12_chars_and_actually_changes_it(self, fake, client):
        a = register_user(client, "pwchange_user2")
        headers = auth_headers(a["access_token"])
        r = client.post("/api/profile/password", headers=headers, json={
            "current_password": "passw0rd1234", "new_password": "newlongpass1",
        })
        assert r.status_code == 200, r.text
        # Old password no longer works, new one does.
        assert client.post("/api/auth/login", json={
            "username": "pwchange_user2", "password": "passw0rd1234"}).status_code == 401
        assert client.post("/api/auth/login", json={
            "username": "pwchange_user2", "password": "newlongpass1"}).status_code == 200


# --- WSTG-CRYP / ASVS V6.2.3-6.2.4 — password storage work factor ----------
class TestPasswordHashing:
    def test_new_hashes_embed_the_current_iteration_count(self):
        h = security.hash_password("some-real-password-1")
        parts = h.split("$")
        assert len(parts) == 4
        assert parts[0] == "pbkdf2"
        assert int(parts[1]) == security.PBKDF2_ITERATIONS
        assert security.PBKDF2_ITERATIONS >= 600_000

    def test_legacy_3_part_hash_still_verifies(self):
        # Simulates an account created before the iteration count was
        # embedded in the hash string — must not be locked out.
        salt = "0123456789abcdef"
        legacy_iterations = 120_000
        import hashlib
        dk = hashlib.pbkdf2_hmac("sha256", b"legacy-password-1", salt.encode(), legacy_iterations)
        legacy_hash = f"pbkdf2${salt}${dk.hex()}"
        assert security.verify_password("legacy-password-1", legacy_hash)
        assert not security.verify_password("wrong-password-1", legacy_hash)

    def test_needs_rehash_flags_legacy_and_low_iteration_hashes(self):
        assert security.needs_rehash("pbkdf2$abcd1234$deadbeef")  # 3-part legacy
        assert security.needs_rehash("pbkdf2$1000$abcd1234$deadbeef")  # low count
        assert not security.needs_rehash(security.hash_password("x1"))  # current format

    def test_login_transparently_upgrades_a_legacy_hash(self, fake, client):
        import hashlib
        uid = fake.create_user("legacyuser", "legacyuser@hydrax.local", "placeholder")
        salt = "fedcba9876543210"
        dk = hashlib.pbkdf2_hmac("sha256", b"legacy-password-123", salt.encode(), 120_000)
        fake.users[uid]["password_hash"] = f"pbkdf2${salt}${dk.hex()}"

        r = client.post("/api/auth/login", json={"username": "legacyuser", "password": "legacy-password-123"})
        assert r.status_code == 200, r.text
        upgraded = fake.users[uid]["password_hash"]
        assert upgraded.split("$")[1] == str(security.PBKDF2_ITERATIONS)
        # The upgraded hash still authenticates with the same password.
        assert security.verify_password("legacy-password-123", upgraded)


# --- WSTG-IDNT-04 / CWE-208 — account enumeration via login timing ---------
class TestLoginTimingSideChannel:
    def test_nonexistent_user_still_triggers_a_password_verification(self, fake, client, monkeypatch):
        calls = []
        real_verify = security.verify_password

        def _spy(password, stored):
            calls.append(stored)
            return real_verify(password, stored)
        monkeypatch.setattr(auth_router.security, "verify_password", _spy)

        client.post("/api/auth/login", json={"username": "no-such-user-at-all", "password": "whatever12345"})
        assert len(calls) == 1
        assert calls[0] == auth_router._DUMMY_PASSWORD_HASH

    def test_existing_user_wrong_password_verifies_against_their_real_hash(self, fake, client, monkeypatch):
        register_user(client, "timinguser")
        calls = []
        real_verify = security.verify_password

        def _spy(password, stored):
            calls.append(stored)
            return real_verify(password, stored)
        monkeypatch.setattr(auth_router.security, "verify_password", _spy)

        client.post("/api/auth/login", json={"username": "timinguser", "password": "wrong-password-1"})
        assert len(calls) == 1
        assert calls[0] != auth_router._DUMMY_PASSWORD_HASH


# --- WSTG-ERRH-01 / ASVS V7.4.1 — no sensitive detail in error responses ---
class TestErrorMessageRedaction:
    def test_unauthenticated_health_never_leaks_raw_exception_text(self, fake, client, monkeypatch):
        monkeypatch.setattr(health, "check_database",
                            lambda: {"status": "down", "error": "FATAL: password authentication failed for user \"hydrax_admin\" at host db.internal.corp:5432"})
        r = client.get("/health")
        assert r.status_code == 503
        body_text = r.text
        assert "hydrax_admin" not in body_text
        assert "db.internal.corp" not in body_text
        assert body_text.count('"error"') == 0

    def test_health_check_failure_is_logged_server_side_instead(self, fake, client, monkeypatch, caplog):
        monkeypatch.setattr(health, "check_redis",
                            lambda: {"status": "down", "error": "redis://secret-host:6379 unreachable"})
        with caplog.at_level(logging.WARNING, logger="hydrax.health"):
            client.get("/health")
        assert any("secret-host" in r.message or "secret-host" in str(r.__dict__.get("error", ""))
                  for r in caplog.records) or any(
            getattr(r, "error", "") == "redis://secret-host:6379 unreachable" for r in caplog.records)

    def test_engagement_letter_save_failure_does_not_leak_filesystem_path(self, fake, client, monkeypatch):
        a = register_user(client, "letterfail_admin", organization_name="LetterFail Co")
        headers = auth_headers(a["access_token"])

        def _boom(*a, **k):
            raise OSError("[Errno 13] Permission denied: '/app/webapp/data/uploads/engagement_letters/secret.pdf'")
        monkeypatch.setattr("builtins.open", _boom)

        r = client.post("/api/verification/engagement-letter/upload",
                        headers=headers, data={"target_url": "https://letterfail.example.com"},
                        files={"file": ("letter.pdf", b"%PDF-1.4 fake", "application/pdf")})
        assert r.status_code == 500
        assert "/app/webapp" not in r.text
        assert "Errno" not in r.text


# --- WSTG-CLNT-01/04 — XSS / unsafe redirect via generated HTML reports ----
class TestReportHrefSanitization:
    @pytest.mark.parametrize("payload", [
        "javascript:alert(document.domain)",
        "javascript:alert(1)//",
        "JavaScript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "//evil.com/phish",
    ])
    def test_dangerous_schemes_become_inert(self, payload):
        assert ReportGenerator._safe_href(payload) == "#"

    @pytest.mark.parametrize("legit", [
        "https://example.com/path?x=1",
        "http://example.com",
        "/relative/report/path",
    ])
    def test_legitimate_urls_pass_through_escaped(self, legit):
        result = ReportGenerator._safe_href(legit)
        assert result != "#"
        assert result.startswith(("http://", "https://", "/"))

    def test_html_report_never_embeds_a_raw_javascript_href(self):
        gen = ReportGenerator()
        report_data = {
            "target": "https://target.example.com",
            "scan_date": "2026-01-01T00:00:00",
            "scanner_version": "test",
            "findings": [{
                "type": "Reflected XSS", "severity": "High",
                "description": "XSS via q parameter",
                "url": "javascript:alert(document.cookie)",
                "evidence": "<script>alert(1)</script>",
            }],
        }
        html_out = gen.generate_html_report(report_data)
        assert 'href="javascript:' not in html_out.lower()
        assert "<script>alert(1)</script>" not in html_out  # evidence must be escaped


# --- WSTG-BUSL-09 / CWE-400 — unbounded file upload (DoS) -------------------
class TestUploadSizeLimit:
    def test_oversized_engagement_letter_is_rejected(self, fake, client):
        a = register_user(client, "bigfile_admin", organization_name="BigFile Co")
        headers = auth_headers(a["access_token"])
        from webapp.routers.verification import MAX_ENGAGEMENT_LETTER_SIZE
        oversized = b"%PDF-1.4" + b"A" * (MAX_ENGAGEMENT_LETTER_SIZE + 1)
        r = client.post("/api/verification/engagement-letter/upload",
                        headers=headers, data={"target_url": "https://bigfile.example.com"},
                        files={"file": ("letter.pdf", oversized, "application/pdf")})
        assert r.status_code == 413

    def test_reasonably_sized_letter_still_accepted(self, fake, client):
        a = register_user(client, "okfile_admin", organization_name="OkFile Co")
        headers = auth_headers(a["access_token"])
        r = client.post("/api/verification/engagement-letter/upload",
                        headers=headers, data={"target_url": "https://okfile.example.com"},
                        files={"file": ("letter.pdf", b"%PDF-1.4 a small real pdf body", "application/pdf")})
        assert r.status_code == 200, r.text


# --- WSTG-INFO-10 — API schema/docs exposure --------------------------------
class TestApiDocsGating:
    def test_env_truthy_recognizes_common_true_spellings(self):
        from webapp.config import _env_truthy
        for v in ("1", "true", "True", "YES", "on"):
            assert _env_truthy(v) is True
        for v in ("", "0", "false", "no", "off"):
            assert _env_truthy(v) is False

    def test_docs_are_reachable_by_default(self, fake, client):
        # Default posture is unchanged by this audit (documented tradeoff:
        # useful for legitimate integrators) — this locks in that the
        # gating mechanism doesn't accidentally disable it by default.
        assert client.get("/openapi.json").status_code == 200
