"""Phase 13 regression tests: platform hardening pass (CVM platform spec §21).

A full review against docs/SECURITY_MODEL.md found most controls (SQLi via
parameterized queries throughout, XSS via consistent frontend escaping,
CSRF mitigated architecturally by Bearer-only auth with no cookies, IDOR/
tenant isolation already covered by every prior phase's org-scoping tests,
no secret leakage in logs) already sound on inspection — no code changes
needed there. Two concrete, previously-unguarded gaps were found and fixed;
this file locks both in.
"""
import pytest

from webapp.services.system_scan_service import _parse_target
from conftest import register_user, auth_headers


class TestArgumentInjectionGuard:
    """A system-scan target is passed as a literal argv element to real CLI
    tools (nmap/nikto/whatweb/...) via webapp/services/kali_tools.py — never
    through a shell, so classic `;`/`|` injection was never possible, but an
    unvalidated value starting with `-` could still be parsed as a FLAG by
    one of those tools (e.g. nmap's -oG/-iL/--script). _parse_target now
    rejects anything that isn't a well-formed hostname/IP/CIDR."""

    @pytest.mark.parametrize("payload", [
        "-oG=/tmp/pwned.txt",
        "--script=http-shellshock",
        "-iL/etc/passwd",
        "; rm -rf /",
        "a b c",
    ])
    def test_flag_like_or_malformed_targets_are_rejected(self, payload):
        with pytest.raises(ValueError):
            _parse_target(payload)

    @pytest.mark.parametrize("target,expected_host", [
        ("example.com", "example.com"),
        ("sub.example.com", "sub.example.com"),
        ("http://example.com/path", "example.com"),
        ("192.168.1.1", "192.168.1.1"),
        ("192.168.1.0/24", "192.168.1.0"),
        ("example.com:8443", "example.com"),
    ])
    def test_legitimate_targets_still_parse(self, target, expected_host):
        parsed = _parse_target(target)
        assert parsed["host"] == expected_host


class TestScanStartRateLimit:
    def test_excess_scan_starts_are_throttled(self, fake, client, admin_headers, monkeypatch):
        tid = fake.add_target("http://127.0.0.1:8000/app", verification_method="dns_txt")
        fake.update_target_verification(tid, "verified")
        monkeypatch.setattr(
            "webapp.services.web_scan_service.start_web_scan",
            lambda user_id, target, vuln_types:
                fake.create_scan(user_id, tid, "web", vuln_types),
        )
        body = {"target": "http://127.0.0.1:8000/app", "vuln_types": ["xss"],
                "scope_authorized": True}
        statuses = [client.post("/api/scans/web", headers=admin_headers, json=body).status_code
                   for _ in range(31)]
        assert statuses.count(200) == 30
        assert statuses[-1] == 429

    def test_rate_limit_is_per_user_not_global(self, fake, client, admin_headers, monkeypatch):
        tid = fake.add_target("http://127.0.0.1:8000/app", verification_method="dns_txt")
        fake.update_target_verification(tid, "verified")
        monkeypatch.setattr(
            "webapp.services.web_scan_service.start_web_scan",
            lambda user_id, target, vuln_types:
                fake.create_scan(user_id, tid, "web", vuln_types),
        )
        body = {"target": "http://127.0.0.1:8000/app", "vuln_types": ["xss"],
                "scope_authorized": True}
        for _ in range(30):
            client.post("/api/scans/web", headers=admin_headers, json=body)
        assert client.post("/api/scans/web", headers=admin_headers, json=body).status_code == 429

        other = register_user(client, "otheruser_ratelimit", signup_email=True)
        other_headers = auth_headers(other["access_token"])
        assert client.post("/api/scans/web", headers=other_headers, json=body).status_code == 200


class TestReportGenerationRateLimit:
    def test_excess_report_generations_are_throttled(self, fake, client):
        a = register_user(client, "reportlimit_admin", organization_name="ReportLimit Co")
        headers = auth_headers(a["access_token"])
        statuses = [client.get("/api/reports/executive?format=json", headers=headers).status_code
                   for _ in range(11)]
        assert statuses.count(200) == 10
        assert statuses[-1] == 429
