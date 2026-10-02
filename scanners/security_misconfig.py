"""
Security Misconfiguration Scanner
Detects directory listing, default credentials, missing security headers, etc.
"""

from typing import Dict, List, Any
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import re
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.http_client import HTTPClient
from utils.payloads import Payloads
from utils.baseline import BaselineDetector
from utils.concurrency import run_phases_concurrently


class SecurityMisconfigScanner:
    """Security Misconfiguration vulnerability scanner"""

    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'Missing HSTS header',
        'Content-Security-Policy': 'Missing CSP header',
        'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
        'X-Frame-Options': 'Missing clickjacking protection header',
        'X-XSS-Protection': 'Missing X-XSS-Protection header',
        'Referrer-Policy': 'Missing Referrer-Policy header',
        'Permissions-Policy': 'Missing Permissions-Policy header',
        'Set-Cookie': 'Cookies set without Secure/HttpOnly flags (check)',
    }

    def __init__(self):
        self.client = HTTPClient()
        self.baseline = BaselineDetector(self.client)
        self.name = "Security Misconfiguration Scanner"
        self.findings = []

    def scan(self, target_url: str) -> Dict[str, Any]:
        self.findings = []
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Pre-warm the SPA baseline so every check shares one shell fingerprint
        # — must happen before the phases below, which read it.
        self.baseline.shell_fingerprint(base_url)

        # The 5 checks below are independent (each only appends to
        # self.findings) — run them concurrently instead of one after
        # another.
        run_phases_concurrently([
            lambda: self._check_security_headers(target_url),   # Phase 1
            lambda: self._check_directory_listing(base_url),    # Phase 2
            lambda: self._check_exposed_config(base_url),       # Phase 3
            lambda: self._check_http_methods(target_url),       # Phase 4
            lambda: self._check_server_info(target_url),        # Phase 5
            lambda: self._check_cors(target_url),                # Phase 6
        ])

        return {
            'scanner': self.name,
            'target': target_url,
            'vulnerabilities': self.findings,
            'total_findings': len(self.findings)
        }

    def _check_security_headers(self, url: str):
        try:
            resp = self.client.get(url)
            headers = resp.headers

            for header, msg in self.SECURITY_HEADERS.items():
                if header not in headers:
                    self.findings.append({
                        'type': 'Missing Security Header',
                        'description': msg,
                        'severity': 'Medium',
                        'evidence': f'Header "{header}" not present in response'
                    })

            # Check cookie flags
            if 'Set-Cookie' in headers:
                cookie = headers['Set-Cookie']
                if 'Secure' not in cookie:
                    self.findings.append({
                        'type': 'Insecure Cookie',
                        'description': 'Cookie missing Secure flag',
                        'severity': 'Medium',
                        'evidence': f'Cookie: {cookie[:100]}'
                    })
                if 'HttpOnly' not in cookie:
                    self.findings.append({
                        'type': 'Insecure Cookie',
                        'description': 'Cookie missing HttpOnly flag',
                        'severity': 'Medium',
                        'evidence': f'Cookie: {cookie[:100]}'
                    })

            # Check Server header
            if 'Server' in headers:
                server = headers['Server']
                self.findings.append({
                    'type': 'Server Information Disclosure',
                    'description': f'Server header reveals: {server}',
                    'severity': 'Low',
                    'evidence': f'Server: {server}'
                })

        except Exception as e:
            pass

    def _check_cors(self, url: str):
        """CORS misconfiguration (spec §4's explicit "CORS configuration"
        check — previously not covered anywhere in the scanner catalog).

        Sends a probe Origin header that's never legitimately allowed and
        inspects the response: a server that reflects an arbitrary Origin
        back (optionally with credentials allowed) lets any third-party site
        read authenticated responses on a victim's behalf — a real,
        well-established CORS vulnerability class, not a synthesized one.
        """
        probe_origin = "https://hydrax-cors-probe.invalid"
        try:
            resp = self.client.get(url, headers={"Origin": probe_origin})
        except Exception:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin")
        if not acao:
            return
        acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"

        if acao == probe_origin:
            self.findings.append({
                'type': 'CORS Misconfiguration',
                'description': ('Server reflects an arbitrary Origin header back in '
                               'Access-Control-Allow-Origin' + (' with credentials allowed' if acac else '')),
                'severity': 'High' if acac else 'Medium',
                'url': url,
                'evidence': (f'Sent Origin: {probe_origin}, received ACAO: {acao}, '
                            f'ACAC: {resp.headers.get("Access-Control-Allow-Credentials", "")}')
            })
        elif acao == '*' and acac:
            # Browsers reject this exact combination, but it's still a real,
            # visible misconfiguration worth flagging (and some proxies/CDNs
            # don't enforce the spec strictly).
            self.findings.append({
                'type': 'CORS Misconfiguration',
                'description': 'Access-Control-Allow-Origin: * combined with Allow-Credentials: true',
                'severity': 'High',
                'url': url,
                'evidence': f'ACAO: {acao}, ACAC: {resp.headers.get("Access-Control-Allow-Credentials")}'
            })
        elif acao == '*':
            self.findings.append({
                'type': 'Permissive CORS Policy',
                'description': ('Access-Control-Allow-Origin: * allows any site to read responses '
                               '— acceptable only for public, non-authenticated content'),
                'severity': 'Low',
                'url': url,
                'evidence': f'ACAO: {acao}'
            })

    def _check_directory_listing(self, base_url: str):
        dirs_to_test = ['/images/', '/css/', '/js/', '/uploads/', '/assets/', '/static/', '/media/', '/files/', '/backup/']

        for dir_path in dirs_to_test:
            url = urljoin(base_url, dir_path)
            try:
                resp = self.client.get(url)
                if resp.status_code == 200 and self.baseline.is_distinct(base_url, resp):
                    # Check for directory listing indicators
                    if re.search(r'<title>.*Index\s+of|\[DIR\]|Parent Directory|Directory Listing', resp.text, re.IGNORECASE):
                        self.findings.append({
                            'type': 'Directory Listing Enabled',
                            'description': f'Directory listing enabled at {dir_path}',
                            'severity': 'Medium',
                            'url': url,
                            'evidence': 'Directory index page served with file listing'
                        })
            except Exception:
                continue

    def _check_exposed_config(self, base_url: str):
        """Probe Payloads.COMMON_PATHS (141 entries) for exposed config/secret
        files. Each path is independent and can produce at most one finding
        of its own — no "first match wins" ordering to preserve — so this
        fans out across a thread pool instead of testing 141 paths one at a
        time, which alone used to dominate this scanner's total runtime."""
        config_paths = Payloads.COMMON_PATHS

        def probe(path: str):
            url = urljoin(base_url, path)
            try:
                resp = self.client.get(url)
                if (resp.status_code == 200 and self.baseline.is_distinct(base_url, resp)
                        and len(resp.text) > 50):
                    content_lower = resp.text.lower()
                    if path == '/.git/config' and 'repository' in content_lower:
                        return {
                            'type': '.git Repository Exposure',
                            'description': 'Git repository exposed at /.git/config',
                            'severity': 'Critical',
                            'url': url,
                            'evidence': 'Git config file accessible'
                        }
                    elif path == '/.env' and any(kw in content_lower for kw in ['app_key', 'db_password', 'secret', 'api_key']):
                        return {
                            'type': 'Environment File Exposure',
                            'description': '.env file exposed containing sensitive configuration',
                            'severity': 'Critical',
                            'url': url,
                            'evidence': 'Sensitive environment variables accessible'
                        }
                    elif 'phpinfo' in content_lower or 'php version' in content_lower:
                        return {
                            'type': 'PHPInfo Exposure',
                            'description': 'PHP information page exposed',
                            'severity': 'High',
                            'url': url,
                            'evidence': 'phpinfo() output accessible'
                        }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=min(20, len(config_paths))) as executor:
            for finding in executor.map(probe, config_paths):
                if finding is not None:
                    self.findings.append(finding)

    def _check_http_methods(self, url: str):
        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']
        allowed_methods = []

        try:
            resp = self.client.session.request('OPTIONS', url, headers=self.client._get_headers(), timeout=10, verify=False)
            if 'Allow' in resp.headers:
                allowed = resp.headers['Allow']
                allowed_methods = [m.strip() for m in allowed.split(',')]
                for method in dangerous_methods:
                    if method in allowed_methods:
                        self.findings.append({
                            'type': 'Dangerous HTTP Method Enabled',
                            'description': f'{method} method is enabled',
                            'severity': 'Medium',
                            'url': url,
                            'evidence': f'Allowed methods: {allowed}'
                        })
        except Exception:
            pass

    def _check_server_info(self, url: str):
        try:
            resp = self.client.get(url)
            # Check for X-Powered-By
            if 'X-Powered-By' in resp.headers:
                self.findings.append({
                    'type': 'Technology Disclosure',
                    'description': f'X-Powered-By header reveals: {resp.headers["X-Powered-By"]}',
                    'severity': 'Low',
                    'evidence': f'X-Powered-By: {resp.headers["X-Powered-By"]}'
                })

            # Check for debug mode indicators — skip the SPA fallback shell, which
            # is served for every path and proves nothing about debug output.
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            if self.baseline.is_shell(base, resp):
                return
            debug_indicators = ['debug', 'trace', 'stack trace', 'exception', 'on line ', 'in /var/www', 'in /app']
            if any(indicator in resp.text.lower() for indicator in debug_indicators):
                self.findings.append({
                    'type': 'Debug Mode Enabled',
                    'description': 'Debug information may be leaked in responses',
                    'severity': 'High',
                    'url': url,
                    'evidence': 'Stack traces or debug output detected in response'
                })
        except Exception:
            pass