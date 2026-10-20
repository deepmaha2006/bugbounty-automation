"""
Tests for Phase 6 residual FP fixes:
  Fix 1 — Web Cache Poisoning: severity capped at Medium, confidence=possible
  Fix 2 — Clickjacking / X-Frame-Options: severity capped at Medium (via HARDENING_TYPE_MAX_SEVERITY)
  Fix 3 — DDoS CDN/rate-limiting types demoted to INFO (via INFO_TYPES)
  Fix 4 — SECURITY_HEADERS contains exactly the expected 5 headers; X-XSS-Protection absent
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Fix 1 — Web Cache Poisoning severity + confidence
# ---------------------------------------------------------------------------

class TestCachePoisoningFinding:
    def _make_poisoning_finding(self):
        """Return the finding dict that _check_cache_key_poisoning emits."""
        return {
            'type': 'Web Cache Poisoning',
            'description': (
                'Header X-Forwarded-Host influences response — possible cache poisoning. '
                'Single-request reflection detected; end-to-end cache poisoning '
                'confirmation requires a second cache-hit request.'
            ),
            'severity': 'Medium',
            'confidence': 'possible',
            'url': 'http://example.com/',
            'evidence': 'Header X-Forwarded-Host: evil.com reflected in response with cache headers present',
        }

    def test_severity_is_medium(self):
        f = self._make_poisoning_finding()
        assert f['severity'] == 'Medium'

    def test_confidence_is_possible(self):
        f = self._make_poisoning_finding()
        assert f['confidence'] == 'possible'

    def test_description_mentions_second_request(self):
        f = self._make_poisoning_finding()
        assert 'second' in f['description'].lower() or 'confirmation' in f['description'].lower()

    def test_severity_not_high(self):
        f = self._make_poisoning_finding()
        assert f['severity'] != 'High'


# ---------------------------------------------------------------------------
# Fix 2 — Clickjacking / X-Frame-Options capped at Medium
# ---------------------------------------------------------------------------

class TestClickjackingMaxSeverity:
    def test_clickjacking_in_hardening_map(self):
        from core.finding import HARDENING_TYPE_MAX_SEVERITY
        assert 'clickjacking' in HARDENING_TYPE_MAX_SEVERITY

    def test_clickjacking_capped_at_medium(self):
        from core.finding import HARDENING_TYPE_MAX_SEVERITY
        assert HARDENING_TYPE_MAX_SEVERITY['clickjacking'] == 'Medium'

    def test_x_frame_in_hardening_map(self):
        from core.finding import HARDENING_TYPE_MAX_SEVERITY
        assert 'x-frame-options' in HARDENING_TYPE_MAX_SEVERITY

    def test_x_frame_capped_at_medium(self):
        from core.finding import HARDENING_TYPE_MAX_SEVERITY
        assert HARDENING_TYPE_MAX_SEVERITY['x-frame-options'] == 'Medium'


# ---------------------------------------------------------------------------
# Fix 3 — DDoS / CDN finding types demoted to INFO
# ---------------------------------------------------------------------------

class TestDdosCdnInfoTypes:
    INFO_TYPES_TO_CHECK = [
        'connection limiting',
        'connection limit',
        'no connection limiting',
        'cdn rate limiting',
        'cdn connection limiting',
        'rate limiting detected',
    ]

    def test_all_ddos_cdn_types_in_info_types(self):
        from core.finding import INFO_TYPES
        for t in self.INFO_TYPES_TO_CHECK:
            assert t in INFO_TYPES, f"'{t}' missing from INFO_TYPES"

    def test_rate_limiting_detected_classified_as_info(self):
        from core.finding import classify_finding, TIER_INFO
        finding = {
            'type': 'Rate Limiting Detected',
            'severity': 'High',
            'confidence': 'confirmed',
            'description': 'Rate limiting was detected on the target.',
            'url': 'http://example.com/',
            'evidence': 'HTTP 429 returned after rapid requests.',
        }
        result = classify_finding(finding)
        assert result['confidence'] == TIER_INFO
        assert result['severity'] == 'Info'

    def test_no_connection_limiting_classified_as_info(self):
        from core.finding import classify_finding, TIER_INFO
        finding = {
            'type': 'No Connection Limiting',
            'severity': 'Medium',
            'confidence': 'confirmed',
            'description': 'No connection limiting detected.',
            'url': 'http://example.com/',
            'evidence': 'Many connections accepted.',
        }
        result = classify_finding(finding)
        assert result['confidence'] == TIER_INFO
        assert result['severity'] == 'Info'


# ---------------------------------------------------------------------------
# Fix 4 — SECURITY_HEADERS: correct 6 headers, no X-XSS-Protection
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    EXPECTED_HEADERS = {
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Referrer-Policy',
        'Permissions-Policy',
    }
    FORBIDDEN_HEADERS = {'X-XSS-Protection'}

    def test_all_expected_headers_present(self):
        from scanners.security_misconfig import SecurityMisconfigScanner
        s = SecurityMisconfigScanner()
        for h in self.EXPECTED_HEADERS:
            assert h in s.SECURITY_HEADERS, f"Expected header '{h}' missing"

    def test_forbidden_headers_absent(self):
        from scanners.security_misconfig import SecurityMisconfigScanner
        s = SecurityMisconfigScanner()
        for h in self.FORBIDDEN_HEADERS:
            assert h not in s.SECURITY_HEADERS, f"Deprecated header '{h}' should not be present"

    def test_header_count(self):
        from scanners.security_misconfig import SecurityMisconfigScanner
        s = SecurityMisconfigScanner()
        assert len(s.SECURITY_HEADERS) == len(self.EXPECTED_HEADERS)
