"""
Tests for context-aware witness payloads and reflection-context detection.
Phase 5 of the FP-hardening build.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.payloads import Payloads
from scanners.xss_scanner import XSSScanner


# ---------------------------------------------------------------------------
# CONTEXT_PAYLOADS
# ---------------------------------------------------------------------------

class TestContextPayloads:
    REQUIRED_KEYS = {
        "html_body", "html_attribute", "js_string", "url_param", "html_comment"
    }

    def test_all_five_contexts_present(self):
        assert self.REQUIRED_KEYS == set(Payloads.CONTEXT_PAYLOADS.keys())

    def test_each_context_has_at_least_one_payload(self):
        for ctx, payloads in Payloads.CONTEXT_PAYLOADS.items():
            assert len(payloads) >= 1, f"Context '{ctx}' has no payloads"

    def test_payloads_contain_token_placeholder(self):
        for ctx, payloads in Payloads.CONTEXT_PAYLOADS.items():
            for p in payloads:
                assert "{token}" in p, (
                    f"Payload in '{ctx}' is missing {{token}} placeholder: {p!r}"
                )

    def test_payload_token_substitution(self):
        tok = "deadbeef12345678"
        for ctx, payloads in Payloads.CONTEXT_PAYLOADS.items():
            for p in payloads:
                formatted = p.format(token=tok)
                assert tok in formatted


# ---------------------------------------------------------------------------
# CONTEXT_DETECTION_PATTERNS
# ---------------------------------------------------------------------------

class TestContextDetectionPatterns:
    def test_all_five_contexts_present(self):
        expected = {
            "html_body", "html_attribute", "js_string", "html_comment", "url_param"
        }
        assert expected == set(Payloads.CONTEXT_DETECTION_PATTERNS.keys())

    def test_html_body_has_empty_pattern_list(self):
        # html_body is the fallback — no patterns needed
        assert Payloads.CONTEXT_DETECTION_PATTERNS["html_body"] == []

    def test_attribute_context_has_patterns(self):
        assert len(Payloads.CONTEXT_DETECTION_PATTERNS["html_attribute"]) >= 1

    def test_patterns_contain_marker_placeholder(self):
        for ctx, pats in Payloads.CONTEXT_DETECTION_PATTERNS.items():
            for pat in pats:
                assert "{marker}" in pat, (
                    f"Pattern in '{ctx}' missing {{marker}}: {pat!r}"
                )


# ---------------------------------------------------------------------------
# XSSScanner._detect_reflection_context
# ---------------------------------------------------------------------------

class TestDetectReflectionContext:
    def setup_method(self):
        self.scanner = XSSScanner()

    def test_detects_html_attribute_context(self):
        marker = "HYDRAXTEST123"
        html = f'<input value="{marker}" />'
        ctx = self.scanner._detect_reflection_context(html, marker)
        assert ctx == "html_attribute"

    def test_detects_js_string_context(self):
        marker = "HYDRAXTEST456"
        html = f'<script>var x = "{marker}";</script>'
        ctx = self.scanner._detect_reflection_context(html, marker)
        assert ctx == "js_string"

    def test_detects_html_comment_context(self):
        marker = "HYDRAXTEST789"
        html = f"<!-- {marker} -->"
        ctx = self.scanner._detect_reflection_context(html, marker)
        assert ctx == "html_comment"

    def test_defaults_to_html_body(self):
        marker = "HYDRAXTEST000"
        html = f"<p>Hello {marker} World</p>"
        ctx = self.scanner._detect_reflection_context(html, marker)
        assert ctx == "html_body"

    def test_detects_url_param_context(self):
        marker = "HYDRAXTEST999"
        html = f'<a href="http://example.com/?next={marker}">link</a>'
        ctx = self.scanner._detect_reflection_context(html, marker)
        assert ctx == "url_param"

    def test_marker_not_in_response_returns_html_body(self):
        ctx = self.scanner._detect_reflection_context("<p>hello world</p>", "NOSUCHMARKER")
        assert ctx == "html_body"
