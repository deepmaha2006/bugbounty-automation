"""P2-12 regression tests — real DNS TXT target verification.

Covers: correct challenge token -> verified; wrong token / missing TXT record /
DNS failure -> never verified; _resolve_txt_records() swallows DNS errors;
simulated mode only active when explicitly enabled; and an unverified target
remains blocked from scanning.
"""
import dns.resolver

import webapp.config
from webapp.routers.verification import (_extract_domain,
                                         _resolve_txt_records)


class TestExtractDomain:
    def test_extracts_host_without_scheme_or_port(self):
        assert _extract_domain("http://lab.local:8080/app") == "lab.local"
        assert _extract_domain("https://lab.local") == "lab.local"
        assert _extract_domain("lab.local") == "lab.local"
        assert _extract_domain("http://127.0.0.1:8000") == "127.0.0.1"
        assert _extract_domain("") == ""


class TestResolveTxtRecords:
    def test_returns_empty_on_noanswer(self, monkeypatch):
        def _boom(domain, rdtype):
            raise dns.resolver.NoAnswer
        monkeypatch.setattr(dns.resolver, "resolve", _boom)
        assert _resolve_txt_records("lab.local") == []

    def test_returns_empty_on_timeout(self, monkeypatch):
        def _boom(domain, rdtype):
            raise dns.resolver.LifetimeTimeout
        monkeypatch.setattr(dns.resolver, "resolve", _boom)
        assert _resolve_txt_records("lab.local") == []

    def test_parses_txt_strings(self, monkeypatch):
        class _Rdata:
            strings = (b"hydrax-verification=TOKEN123", b"other=zzz")
        monkeypatch.setattr(
            dns.resolver, "resolve",
            lambda domain, rdtype: [_Rdata()])
        assert _resolve_txt_records("lab.local") == [
            "hydrax-verification=TOKEN123", "other=zzz"]


class TestDnsTxtVerification:
    URL = "http://lab.local"
    TOKEN = "CHALLENGE-TOKEN-123"

    def _pending_target(self, fake):
        tid = fake.add_target(self.URL, verification_method="dns_txt")
        fake.targets[tid]["dns_txt_token"] = self.TOKEN
        return tid

    def _verify(self, client, admin_headers):
        return client.post("/api/verification/dns-txt/verify",
                           headers=admin_headers,
                           data={"target_url": self.URL})

    def test_correct_txt_token_verifies(self, fake, client, admin_headers,
                                        monkeypatch):
        tid = self._pending_target(fake)
        monkeypatch.setattr(
            "webapp.routers.verification._resolve_txt_records",
            lambda d: [f"hydrax-verification={self.TOKEN}", "unrelated=zzz"])
        r = self._verify(client, admin_headers)
        assert r.status_code == 200, r.text
        assert "verified" in r.json()["message"].lower()
        assert fake.get_target(tid)["verification_status"] == "verified"

    def test_wrong_token_not_verified(self, fake, client, admin_headers,
                                      monkeypatch):
        tid = self._pending_target(fake)
        monkeypatch.setattr(
            "webapp.routers.verification._resolve_txt_records",
            lambda d: ["hydrax-verification=ANOTHER-TOKEN"])
        r = self._verify(client, admin_headers)
        assert r.status_code == 400, r.text
        assert fake.get_target(tid)["verification_status"] != "verified"

    def test_missing_txt_record_not_verified(self, fake, client,
                                             admin_headers, monkeypatch):
        tid = self._pending_target(fake)
        monkeypatch.setattr(
            "webapp.routers.verification._resolve_txt_records",
            lambda d: [])
        r = self._verify(client, admin_headers)
        assert r.status_code == 400, r.text
        assert fake.get_target(tid)["verification_status"] != "verified"

    def test_dns_failure_not_verified(self, fake, client, admin_headers,
                                      monkeypatch):
        # A failed lookup converges on an empty record list -> not verified.
        tid = self._pending_target(fake)
        monkeypatch.setattr(
            "webapp.routers.verification._resolve_txt_records",
            lambda d: [])
        r = self._verify(client, admin_headers)
        assert r.status_code == 400, r.text
        assert fake.get_target(tid)["verification_status"] != "verified"

    def test_no_challenge_generated_rejected(self, fake, client,
                                             admin_headers):
        tid = fake.add_target("http://other.local",
                              verification_method="dns_txt")
        r = client.post("/api/verification/dns-txt/verify",
                        headers=admin_headers,
                        data={"target_url": "http://other.local"})
        assert r.status_code == 400
        assert fake.get_target(tid)["verification_status"] == "pending"

    def test_error_path_sets_status_failed(self, fake, client, admin_headers,
                                           monkeypatch):
        tid = self._pending_target(fake)
        monkeypatch.setattr(
            "webapp.routers.verification._resolve_txt_records",
            lambda d: ["hydrax-verification=NOPE"])
        r = self._verify(client, admin_headers)
        assert r.status_code == 400
        assert fake.get_target(tid)["verification_status"] == "failed"


class TestSimulatedMode:
    URL = "http://127.0.0.1:8000"

    def test_default_mode_is_real(self):
        assert webapp.config.VERIFY_MODE == "real"

    def test_simulated_works_only_when_explicit(self, fake, client,
                                                admin_headers, monkeypatch):
        tid = fake.add_target(self.URL, verification_method="dns_txt")
        fake.targets[tid]["dns_txt_token"] = "LOCAL-TOKEN"
        monkeypatch.setattr(webapp.config, "VERIFY_MODE", "simulated")
        r = client.post("/api/verification/dns-txt/verify",
                        headers=admin_headers,
                        data={"target_url": self.URL})
        assert r.status_code == 200, r.text
        assert fake.get_target(tid)["verification_status"] == "verified"

    def test_simulated_is_case_and_prefix_sensitive(self, fake, client,
                                                    admin_headers,
                                                    monkeypatch):
        tid = fake.add_target(self.URL, verification_method="dns_txt")
        fake.targets[tid]["dns_txt_token"] = "LOCAL-TOKEN"
        # "simulate" (prefix) and "SIMULATED" (case) must NOT enable the branch.
        for bogus in ("simulate", "SIMULATED"):
            monkeypatch.setattr(webapp.config, "VERIFY_MODE", bogus)
            monkeypatch.setattr(
                "webapp.routers.verification._resolve_txt_records",
                lambda d: [])
            r = client.post("/api/verification/dns-txt/verify",
                            headers=admin_headers,
                            data={"target_url": self.URL})
            assert r.status_code == 400, r.text
            assert fake.get_target(tid)["verification_status"] != "verified"

    def test_generate_then_simulated_verify_roundtrip(self, fake, client,
                                                      admin_headers,
                                                      monkeypatch):
        monkeypatch.setattr(webapp.config, "VERIFY_MODE", "simulated")
        g = client.post("/api/verification/dns-txt/generate",
                        headers=admin_headers,
                        data={"target_url": self.URL})
        assert g.status_code == 200, g.text
        body = g.json()
        assert body["dns_txt_token"]
        assert body["domain"] == "127.0.0.1"
        v = client.post("/api/verification/dns-txt/verify",
                        headers=admin_headers, data={"target_url": self.URL})
        assert v.status_code == 200, v.text


class TestUnverifiedRemainsBlocked:
    URL = "http://lab.local"

    def test_failed_verify_keeps_target_blocked_from_scanning(
            self, fake, client, admin_headers, monkeypatch):
        tid = fake.add_target(self.URL, verification_method="dns_txt")
        fake.targets[tid]["dns_txt_token"] = "TOKEN"
        monkeypatch.setattr(
            "webapp.routers.verification._resolve_txt_records",
            lambda d: ["hydrax-verification=WRONG"])
        rv = client.post("/api/verification/dns-txt/verify",
                         headers=admin_headers,
                         data={"target_url": self.URL})
        assert rv.status_code == 400
        assert fake.get_target(tid)["verification_status"] != "verified"

        rs = client.post("/api/scans/web", headers=admin_headers, json={
            "target": self.URL, "vuln_types": ["xss"],
            "scope_authorized": True,
        })
        assert rs.status_code == 403  # still blocked — never weakened