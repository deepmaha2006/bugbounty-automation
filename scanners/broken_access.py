"""
Broken Access Control Scanner
Detects IDOR, privilege escalation, and missing access controls.

All checks are baseline-aware: on single-page-apps the server returns the same
generic shell for any path, so a plain HTTP 200 proves nothing. Every finding
requires the response to be distinct real content that differs from the SPA
fallback (or, for IDOR, from its sibling resource).
"""

from typing import Dict, List, Any
from urllib.parse import urljoin, urlparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.http_client import HTTPClient
from utils.baseline import BaselineDetector
from utils.concurrency import run_phases_concurrently


class BrokenAccessScanner:
    """Broken Access Control vulnerability scanner"""

    # Paths that are genuinely sensitive to expose. /login is intentionally
    # public (login pages are SUPPOSED to be open), and .git/config / .env are
    # validated with content signatures by the info-disclosure scanner instead.
    SENSITIVE_PATHS = [
        '/admin',
        '/administrator',
        '/admin/dashboard',
        '/admin/users',
        '/admin/settings',
        '/admin/config',
        '/wp-admin',
        '/user/profile',
        '/api/users',
        '/api/admin',
        '/api/v1/users',
        '/api/v1/admin',
        '/api/v2/users',
        '/api/v2/admin',
        '/graphql',
        '/config.json',
        '/config.php',
        '/backup',
        '/backup.sql',
        '/dump',
        '/database',
        '/db_backup',
        '/private',
        '/internal',
        '/debug',
        '/test',
    ]

    # Paths that should return 403/401 for unauthenticated users
    PROTECTED_PATHS = [
        '/admin',
        '/admin/dashboard',
        '/user/profile',
        '/account',
        '/settings',
        '/dashboard',
    ]

    # Methods that should never succeed on resource endpoints without auth
    METHODS_TO_TEST = ['PUT', 'DELETE', 'PATCH']

    METHOD_TEST_PATHS = [
        '/api/v1/users/1',
        '/api/v1/admin/users/1',
        '/user/delete?id=1',
        '/admin/users/1',
    ]

    def __init__(self):
        self.client = HTTPClient()
        self.baseline = BaselineDetector(self.client)
        self.name = "Broken Access Control Scanner"
        self.findings = []

    def scan(self, target_url: str) -> Dict[str, Any]:
        """
        Scan target for broken access control vulnerabilities

        Args:
            target_url: The target URL to scan

        Returns:
            Dict with scan results
        """
        self.findings = []
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Pre-warm the SPA baseline so all later checks share one fingerprint
        # — must happen before the phases below, which read it.
        self.baseline.shell_fingerprint(base_url)

        # The 4 checks below are independent (each only appends to
        # self.findings) — run them concurrently instead of one after
        # another.
        run_phases_concurrently([
            lambda: self._check_sensitive_paths(base_url),    # Phase 1
            lambda: self._check_idor(base_url),               # Phase 2
            lambda: self._check_forced_browsing(base_url),    # Phase 3
            lambda: self._check_robots_txt(base_url),         # Phase 4
        ])

        return {
            'scanner': self.name,
            'target': target_url,
            'vulnerabilities': self.findings,
            'total_findings': len(self.findings)
        }

    def _check_sensitive_paths(self, base_url: str):
        """Check if sensitive paths are accessible"""
        for path in self.SENSITIVE_PATHS:
            url = urljoin(base_url, path)
            try:
                resp = self.client.get(url)
                # Must be real distinct content, not the SPA fallback shell
                if not self.baseline.is_distinct(base_url, resp):
                    continue
                if not self._is_redirect_page(resp):
                    severity = 'Critical' if 'admin' in path.lower() else 'High'
                    self.findings.append({
                        'type': 'Broken Access Control - Exposed Path',
                        'description': f'Sensitive path "{path}" is accessible without authentication',
                        'severity': severity,
                        'url': url,
                        'evidence': f'HTTP {resp.status_code} - Response length: {len(resp.text)} bytes'
                    })
            except Exception:
                continue

    def _check_idor(self, base_url: str):
        """Check for Insecure Direct Object References using sibling comparison"""
        # Test user ID enumeration patterns - compare two sequential resources.
        # A real IDOR shows different bodies for id=1 vs id=2 (or at least one
        # resolves to distinct content that differs from the sibling). An SPA
        # shell returns byte-identical bodies for both => not an IDOR.
        id_patterns = [
            ('/api/v1/users/1', '/api/v1/users/2'),
            ('/api/v1/users/2', '/api/v1/users/3'),
            ('/user/profile?id=1', '/user/profile?id=2'),
            ('/account?id=1', '/account?id=2'),
            ('/order?id=1001', '/order?id=1002'),
            ('/download?id=1', '/download?id=2'),
            ('/api/v1/users/1', '/api/v1/users/999999'),
        ]

        for path_a, path_b in id_patterns:
            try:
                url_a = urljoin(base_url, path_a)
                url_b = urljoin(base_url, path_b)
                resp_a = self.client.get(url_a)
                resp_b = self.client.get(url_b)

                # Both must be distinct real content...
                if not self.baseline.is_distinct(base_url, resp_a):
                    continue
                if not self.baseline.is_distinct(base_url, resp_b):
                    continue

                # ...and they must actually differ from each other.
                # Identical bodies => same shell/page returned for every ID, so
                # there is no object enumeration happening.
                if self._same_body(resp_a, resp_b):
                    continue

                # Skip if both responses look like generic API errors (no data)
                if self._looks_like_api_error(resp_a) and self._looks_like_api_error(resp_b):
                    continue

                self.findings.append({
                    'type': 'Potential IDOR',
                    'description': f'Sequential ID access possible at "{path_a}" / "{path_b}"',
                    'severity': 'High',
                    'url': url_a,
                    'evidence': (f'HTTP {resp_a.status_code} vs HTTP {resp_b.status_code} - '
                                 f'different bodies for sibling IDs')
                })
            except Exception:
                continue

        # Test for privilege escalation via HTTP method manipulation.
        # A non-2xx is fine; the danger is a method that is NOT rejected with a
        # standard 403/401/404/405 AND returns real distinct content or a 204.
        for path in self.METHOD_TEST_PATHS:
            url = urljoin(base_url, path)
            for method in self.METHODS_TO_TEST:
                try:
                    resp = self.client.session.request(method, url,
                                                       headers=self.client._get_headers(),
                                                       timeout=10,
                                                       verify=False)
                    if resp.status_code in (403, 401, 404, 405):
                        continue

                    if resp.status_code == 204:
                        # Empty success - still notable for DELETE-like methods
                        self.findings.append({
                            'type': 'Privilege Escalation via HTTP Method',
                            'description': f'{method} method accepted on "{path}" without proper authorization',
                            'severity': 'Critical',
                            'url': url,
                            'evidence': f'HTTP 204 - {method} request accepted'
                        })
                        continue

                    # Non-denied status with real distinct content
                    if resp.status_code == 200 and self.baseline.is_distinct(base_url, resp):
                        self.findings.append({
                            'type': 'Privilege Escalation via HTTP Method',
                            'description': f'{method} method allowed on "{path}" without proper authorization',
                            'severity': 'Critical',
                            'url': url,
                            'evidence': f'HTTP {resp.status_code} - {method} request succeeded'
                        })
                    elif resp.status_code not in (200,):
                        # e.g. 500/501 on DELETE - server accepted the verb
                        self.findings.append({
                            'type': 'Privilege Escalation via HTTP Method',
                            'description': f'{method} method accepted on "{path}" without proper authorization',
                            'severity': 'High',
                            'url': url,
                            'evidence': f'HTTP {resp.status_code} - {method} request processed'
                        })
                except Exception:
                    continue

    def _check_forced_browsing(self, base_url: str):
        """Check for forced browsing vulnerabilities"""
        for path in self.PROTECTED_PATHS:
            url = urljoin(base_url, path)
            try:
                resp = self.client.get(url)
                # Must be distinct real content, not the SPA fallback
                if not self.baseline.is_distinct(base_url, resp, min_len=200):
                    continue
                self.findings.append({
                    'type': 'Forced Browsing',
                    'description': f'Protected path "{path}" accessible without authentication',
                    'severity': 'High',
                    'url': url,
                    'evidence': f'HTTP {resp.status_code} - Page size: {len(resp.text)} bytes'
                })
            except Exception:
                continue

    def _check_robots_txt(self, base_url: str):
        """Check robots.txt for exposed sensitive paths.
        Only flagged when robots.txt is a REAL robots file (has User-agent or
        Disallow directives); SPA shells and generic index pages are ignored.
        """
        url = urljoin(base_url, '/robots.txt')
        try:
            resp = self.client.get(url)
            if resp.status_code != 200 or not resp.text:
                return
            lines = [l.strip() for l in resp.text.split('\n') if l.strip()]
            has_directive = any(
                l.lower().startswith(('user-agent:', 'disallow:', 'allow:', 'sitemap:'))
                for l in lines
            )
            if not has_directive:
                # Either the SPA shell or an HTML page that isn't a robots file
                return

            disallowed_paths = []
            for line in lines:
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        disallowed_paths.append(path)

            if disallowed_paths:
                self.findings.append({
                    'type': 'Information Disclosure - Robots.txt',
                    'description': f'robots.txt exposes {len(disallowed_paths)} disallowed paths',
                    'severity': 'Low',
                    'url': url,
                    'evidence': f'Disallowed paths: {", ".join(disallowed_paths[:10])}'
                })
        except Exception:
            pass

    @staticmethod
    def _same_body(resp_a, resp_b) -> bool:
        """True if two responses have byte-identical bodies."""
        return (resp_a.content or b'') == (resp_b.content or b'')

    @staticmethod
    def _looks_like_api_error(resp) -> bool:
        """Heuristic: a tiny JSON error body like {"error": "not found"}."""
        text = (resp.text or '').strip()
        if len(text) < 250 and text.startswith('{') and text.endswith('}'):
            lowered = text.lower()
            return any(k in lowered for k in ('error', 'not found', 'unauthorized',
                                              'forbidden', 'invalid', 'fail'))
        return False

    def _is_redirect_page(self, response) -> bool:
        """Check if response is just a redirect page"""
        text = response.text.lower()
        redirect_indicators = ['window.location', 'location.href', 'location.replace',
                               'window.location.href', 'meta http-equiv="refresh"']
        return any(indicator in text for indicator in redirect_indicators)
