"""Regression tests for the 8 false-positive and scoring fixes.

Covers:
  1. CVSS baseline table — per-type scores, no more hardcoded 9.8
  2. Minified-JS password FP — skipped for bundler output
  3. Cookies-without-Set-Cookie FP — no finding when header is absent
  4. robots.txt / sitemap.xml — not in EXPOSED_PATHS
  5. CDN-fronted DDoS downgrade — Medium → Info
  6. 405 misread — RequestSmuggler and PrototypePollutionScanner
  7. Deduplication — (type, url, parameter) collapses duplicates
  8. X-XSS-Protection removed from SECURITY_HEADERS
"""
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.finding import cvss_for_finding, CVSS_BASELINES
from utils.reporter import normalize_report_data, ReportGenerator
from scanners.security_misconfig import SecurityMisconfigScanner
from scanners.info_disclosure import InfoDisclosureScanner
from scanners.ddos_tester import DDoSTester, _is_cdn_fronted


# ---------------------------------------------------------------------------
# Fix 1 — CVSS baseline table
# ---------------------------------------------------------------------------

class TestCvssBaselines:
    def test_sql_injection_score(self):
        assert cvss_for_finding("Error-Based SQL Injection") == 9.8

    def test_stored_xss_beats_generic_xss(self):
        # "stored xss" key is longer than "xss" — must win
        assert cvss_for_finding("Stored XSS") == 8.8

    def test_reflected_xss_score(self):
        assert cvss_for_finding("Reflected XSS") == 6.1

    def test_dom_xss_score(self):
        assert cvss_for_finding("DOM-Based XSS Sinks Detected") == 6.1

    def test_missing_security_header_score(self):
        assert cvss_for_finding("Missing Security Header") == 3.7

    def test_unknown_type_returns_zero(self):
        assert cvss_for_finding("Totally Unknown Finding Type XYZ") == 0.0

    def test_empty_type_returns_zero(self):
        assert cvss_for_finding("") == 0.0

    def test_reporter_uses_table_not_formula(self):
        gen = ReportGenerator()
        finding = {"type": "Reflected XSS", "severity": "High"}
        score = gen._calculate_cvss_score(finding)
        # Must come from the table (6.1), not the old formula (~8.7)
        assert score == 6.1

    def test_reporter_stored_field_wins(self):
        gen = ReportGenerator()
        finding = {"type": "Reflected XSS", "severity": "High", "cvss_base": 5.0}
        score = gen._calculate_cvss_score(finding)
        assert score == 5.0

    def test_reporter_severity_fallback(self):
        gen = ReportGenerator()
        finding = {"type": "Completely Unknown Type", "severity": "Critical"}
        score = gen._calculate_cvss_score(finding)
        # Fallback for Critical is 9.0, not the formula's ~9.8
        assert score == 9.0

    def test_executive_summary_cvss_confirmed_only(self):
        """Unconfirmed findings must not inflate Average/Max CVSS."""
        gen = ReportGenerator()
        data = {
            "findings": [
                {"type": "Reflected XSS", "severity": "High", "confidence": "confirmed",
                 "evidence": "x", "url": "http://t.com/"},
                # Unconfirmed Critical should be excluded from CVSS calc
                {"type": "SQL Injection", "severity": "Critical", "confidence": "possible",
                 "evidence": "y", "url": "http://t.com/"},
            ]
        }
        html = gen.generate_html_report(data)
        # avg CVSS should be 6.1 (XSS only), not inflated by the 9.8 SQLi
        assert "6.1/10.0 (Average)" in html


# ---------------------------------------------------------------------------
# Fix 2 — Minified-JS password FP
# ---------------------------------------------------------------------------

class TestMinifiedJsPasswordFp:
    def test_placeholder_filter_still_works(self):
        assert InfoDisclosureScanner._is_placeholder_password("!0") is True
        assert InfoDisclosureScanner._is_placeholder_password("true") is True

    def test_real_password_not_filtered(self):
        assert InfoDisclosureScanner._is_placeholder_password("s3cr3tP@ss!") is False

    def test_minified_boolean_artefact_filtered(self):
        # `:!0` patterns are minifier output, not real credentials
        assert InfoDisclosureScanner._is_placeholder_password("!0") is True


# ---------------------------------------------------------------------------
# Fix 3 — Cookies without Set-Cookie header must not fire
# ---------------------------------------------------------------------------

class _NoCookieHandler(BaseHTTPRequestHandler):
    """Server that never emits Set-Cookie."""
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=()")
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def no_cookie_server():
    server = HTTPServer(("127.0.0.1", 0), _NoCookieHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_port}/"
    server.shutdown()


def test_no_set_cookie_no_insecure_cookie_finding(no_cookie_server):
    scanner = SecurityMisconfigScanner()
    result = scanner.scan(no_cookie_server)
    cookie_types = [f.get("type", "") for f in result["vulnerabilities"]]
    assert "Insecure Cookie" not in cookie_types, (
        "Should not report Insecure Cookie when no Set-Cookie header is present"
    )


# ---------------------------------------------------------------------------
# Fix 4 — robots.txt / sitemap.xml not in EXPOSED_PATHS
# ---------------------------------------------------------------------------

def test_robots_txt_not_in_exposed_paths():
    assert "/robots.txt" not in InfoDisclosureScanner.EXPOSED_PATHS


def test_sitemap_xml_not_in_exposed_paths():
    assert "/sitemap.xml" not in InfoDisclosureScanner.EXPOSED_PATHS


def test_git_config_still_in_exposed_paths():
    assert "/.git/config" in InfoDisclosureScanner.EXPOSED_PATHS


def test_env_still_in_exposed_paths():
    assert "/.env" in InfoDisclosureScanner.EXPOSED_PATHS


# ---------------------------------------------------------------------------
# Fix 5 — CDN-fronted DDoS downgrade
# ---------------------------------------------------------------------------

class _CdnHandler(BaseHTTPRequestHandler):
    """Simulates a Cloudflare-fronted server."""
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("server", "cloudflare")
        self.send_header("cf-ray", "abc123-LHR")
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def cdn_server():
    server = HTTPServer(("127.0.0.1", 0), _CdnHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_port}/"
    server.shutdown()


def test_cdn_detection(cdn_server):
    from utils.http_client import HTTPClient
    client = HTTPClient()
    assert _is_cdn_fronted(client, cdn_server) is True


def test_cdn_rate_limit_downgraded_to_info(cdn_server):
    tester = DDoSTester()
    result = tester.scan(cdn_server)
    rate_limit_findings = [
        f for f in result["vulnerabilities"]
        if f.get("type") in ("Missing Rate Limiting", "No Connection Limiting")
    ]
    for f in rate_limit_findings:
        assert f["severity"] == "Info", (
            f"CDN-fronted finding must be Info, got {f['severity']}: {f}"
        )


# ---------------------------------------------------------------------------
# Fix 6 — 405 misread (RequestSmuggler and PrototypePollution)
# ---------------------------------------------------------------------------

class _405Handler(BaseHTTPRequestHandler):
    """Returns 405 for POST, 404 for unknown paths."""
    def do_GET(self):
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        self.send_response(405)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def reject_405_server():
    server = HTTPServer(("127.0.0.1", 0), _405Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_port}/"
    server.shutdown()


def test_smuggling_405_not_reported(reject_405_server):
    from scanners.advanced_scanners import RequestSmuggler
    from urllib.parse import urlparse
    p = urlparse(reject_405_server)
    scanner = RequestSmuggler()
    scanner._test_cl_te(p.netloc, p.scheme)
    scanner._test_te_cl(p.netloc, p.scheme)
    assert scanner.findings == [], (
        f"405 responses must not be treated as smuggling signals: {scanner.findings}"
    )


def test_prototype_pollution_405_not_reported(reject_405_server):
    from scanners.advanced_scanners import PrototypePollutionScanner
    scanner = PrototypePollutionScanner()
    scanner._check_server_side_pollution(reject_405_server)
    pp_findings = [f for f in scanner.findings
                   if "prototype pollution" in f.get("type", "").lower()]
    assert pp_findings == [], (
        f"405 responses must not trigger prototype pollution findings: {pp_findings}"
    )


# ---------------------------------------------------------------------------
# Fix 7 — Deduplication in normalize_report_data
# ---------------------------------------------------------------------------

def test_dedup_same_type_url_param():
    data = {
        "findings": [
            {"type": "Reflected XSS", "url": "http://t.com/search", "parameter": "q",
             "severity": "High", "evidence": "first"},
            {"type": "Reflected XSS", "url": "http://t.com/search", "parameter": "q",
             "severity": "High", "evidence": "duplicate"},
        ]
    }
    out = normalize_report_data(data)
    assert len(out["findings"]) == 1, "Duplicate (type, url, param) must be collapsed"


def test_dedup_different_params_kept():
    data = {
        "findings": [
            {"type": "Reflected XSS", "url": "http://t.com/search", "parameter": "q"},
            {"type": "Reflected XSS", "url": "http://t.com/search", "parameter": "name"},
        ]
    }
    out = normalize_report_data(data)
    assert len(out["findings"]) == 2, "Different parameters must be kept as separate findings"


def test_dedup_different_urls_kept():
    data = {
        "findings": [
            {"type": "Reflected XSS", "url": "http://t.com/a", "parameter": "q"},
            {"type": "Reflected XSS", "url": "http://t.com/b", "parameter": "q"},
        ]
    }
    out = normalize_report_data(data)
    assert len(out["findings"]) == 2


def test_dedup_preserves_first_occurrence():
    data = {
        "findings": [
            {"type": "Reflected XSS", "url": "http://t.com/", "parameter": "",
             "evidence": "FIRST"},
            {"type": "Reflected XSS", "url": "http://t.com/", "parameter": "",
             "evidence": "SECOND"},
        ]
    }
    out = normalize_report_data(data)
    assert out["findings"][0]["evidence"] == "FIRST"


# ---------------------------------------------------------------------------
# Fix 8 — X-XSS-Protection removed from SECURITY_HEADERS
# ---------------------------------------------------------------------------

def test_x_xss_protection_not_in_security_headers():
    assert "X-XSS-Protection" not in SecurityMisconfigScanner.SECURITY_HEADERS, (
        "Deprecated X-XSS-Protection must not be reported as a missing security header"
    )


def test_set_cookie_not_in_security_headers():
    assert "Set-Cookie" not in SecurityMisconfigScanner.SECURITY_HEADERS, (
        "Set-Cookie absence must not be flagged — only Set-Cookie presence with missing flags matters"
    )
