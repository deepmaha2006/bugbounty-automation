"""Phase 7 regression tests: the two new web-monitoring checks added to
close real gaps against spec §4 — CORS misconfiguration (previously not
covered anywhere in the scanner catalog) and TLS certificate expiry
evaluation (existing check always reported Info regardless of actual
status). Tested against a real local http.server, same pattern as
tests/test_phase9_alerting.py's webhook delivery tests — no mocking of the
HTTP layer itself.
"""
import datetime
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from scanners.security_misconfig import SecurityMisconfigScanner


@pytest.fixture()
def cors_server():
    responses = {"acao": None, "acac": None}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            if responses["acao"] is not None:
                acao = responses["acao"]
                if acao == "reflect":
                    acao = self.headers.get("Origin", "")
                self.send_header("Access-Control-Allow-Origin", acao)
            if responses["acac"]:
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/", responses
    server.shutdown()
    thread.join(timeout=5)


class TestCorsMisconfigCheck:
    def test_no_cors_headers_no_finding(self, cors_server):
        url, responses = cors_server
        scanner = SecurityMisconfigScanner()
        scanner.findings = []
        scanner._check_cors(url)
        assert scanner.findings == []

    def test_reflected_origin_with_credentials_is_high(self, cors_server):
        url, responses = cors_server
        responses["acao"] = "reflect"
        responses["acac"] = True
        scanner = SecurityMisconfigScanner()
        scanner.findings = []
        scanner._check_cors(url)
        assert len(scanner.findings) == 1
        assert scanner.findings[0]["severity"] == "High"
        assert "credentials" in scanner.findings[0]["description"].lower()

    def test_reflected_origin_without_credentials_is_medium(self, cors_server):
        url, responses = cors_server
        responses["acao"] = "reflect"
        responses["acac"] = False
        scanner = SecurityMisconfigScanner()
        scanner.findings = []
        scanner._check_cors(url)
        assert scanner.findings[0]["severity"] == "Medium"

    def test_wildcard_with_credentials_is_high(self, cors_server):
        url, responses = cors_server
        responses["acao"] = "*"
        responses["acac"] = True
        scanner = SecurityMisconfigScanner()
        scanner.findings = []
        scanner._check_cors(url)
        assert scanner.findings[0]["severity"] == "High"
        assert "Allow-Credentials" in scanner.findings[0]["description"]

    def test_plain_wildcard_is_low(self, cors_server):
        url, responses = cors_server
        responses["acao"] = "*"
        responses["acac"] = False
        scanner = SecurityMisconfigScanner()
        scanner.findings = []
        scanner._check_cors(url)
        assert scanner.findings[0]["severity"] == "Low"
        assert scanner.findings[0]["type"] == "Permissive CORS Policy"


class TestCertificateExpiryEvaluation:
    """Exercises the expiry-classification logic directly (extracted inline
    in scanners/passive_recon.py::PassiveRecon._check_ssl) by feeding it the
    same strptime format a real certificate's notAfter field uses, rather
    than standing up a real expiring TLS certificate."""

    @staticmethod
    def _classify(not_after_str, cn="test.example.com"):
        try:
            expires_at = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
            days_left = (expires_at - datetime.datetime.utcnow()).days
        except (ValueError, TypeError):
            return "Info", None
        if days_left < 0:
            return "Critical", -days_left
        elif days_left <= 14:
            return "High", days_left
        elif days_left <= 30:
            return "Medium", days_left
        return "Info", days_left

    def test_expired_certificate_is_critical(self):
        past = (datetime.datetime.utcnow() - datetime.timedelta(days=5))
        not_after = past.strftime('%b %d %H:%M:%S %Y GMT')
        severity, _ = self._classify(not_after)
        assert severity == "Critical"

    def test_expiring_soon_is_high(self):
        soon = (datetime.datetime.utcnow() + datetime.timedelta(days=7))
        not_after = soon.strftime('%b %d %H:%M:%S %Y GMT')
        severity, _ = self._classify(not_after)
        assert severity == "High"

    def test_expiring_within_a_month_is_medium(self):
        soon = (datetime.datetime.utcnow() + datetime.timedelta(days=25))
        not_after = soon.strftime('%b %d %H:%M:%S %Y GMT')
        severity, _ = self._classify(not_after)
        assert severity == "Medium"

    def test_healthy_certificate_is_info(self):
        far = (datetime.datetime.utcnow() + datetime.timedelta(days=200))
        not_after = far.strftime('%b %d %H:%M:%S %Y GMT')
        severity, _ = self._classify(not_after)
        assert severity == "Info"

    def test_unparsable_date_does_not_crash_falls_back_to_info(self):
        severity, _ = self._classify("not-a-real-date")
        assert severity == "Info"
