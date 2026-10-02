"""
Information Disclosure Scanner
Detects sensitive data exposure, stack traces, .git exposure, credentials in source, etc.

False-positive controls (SPA-aware):
- Exposed sensitive files (.git/config, .env, dump.sql, phpinfo.php ...) are
  only reported when the response body matches the real file's content
  signature. An SPA fallback returning HTTP 200 for every path proves nothing.
- Regex findings in HTML/JS source are filtered against placeholder values
  (example.com emails, "xxxx" fake passwords, minified-JS identifier/boolean
  lookalikes) so demo and framework boilerplate code is not reported as a leak.
"""

from typing import Dict, List, Any
from urllib.parse import urljoin, urlparse
import re
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.http_client import HTTPClient
from utils.baseline import BaselineDetector


class InfoDisclosureScanner:
    """Information Disclosure vulnerability scanner"""

    SENSITIVE_PATTERNS = {
        'Email Addresses': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'API Keys / Tokens': r'(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token|access[_-]?token|secret[_-]?key)\s*[:=]\s*["\']([^"\'\s&]+)',
        'AWS Keys': r'(?i)\bAKIA[0-9A-Z]{16}\b',
        'Private SSH Keys': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        'JWT Tokens': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        'Database URLs': r'(?:postgres|mysql|mongodb|redis|sqlite)://[^\s<>"\']+',
        'S3 Buckets': r'\b[a-zA-Z0-9._-]+\.s3\.amazonaws\.com\b',
        'Internal IPs': r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
        'Passwords in Comments': r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\'&]+)',
        'SQL Dump Statements': r'(?i)\b(?:INSERT INTO|CREATE TABLE|DROP TABLE)\b',
        'Stack Traces': r'(?:at\s+[\w.]+\([\w./]+:\d+\)|File\s+"[\w/\]+",\s+line\s+\d+|Exception\s+in\s+thread)',
        'Credit Cards': r'\b(?:\d[ -]*?){13,16}\b',
        'Social Security Numbers': r'\b\d{3}-\d{2}-\d{4}\b',
    }

    # Placeholder domains / local parts / values that are almost certainly
    # demo or boilerplate content, not real leaked data.
    PLACEHOLDER_DOMAINS = {
        'example.com', 'example.org', 'example.net', 'example.edu',
        'domain.com', 'domain.org', 'domain.net', 'yourdomain.com',
        'yoursite.com', 'yourcompany.com', 'your-email.com', 'myemail.com',
        'test.com', 'test.org', 'test.net', 'foo.com', 'bar.com', 'baz.com',
        'sample.com', 'somesite.com', 'somedomain.com', 'something.com',
        'email.com', 'company.com', 'site.com', 'acme.com', 'mailinator.com',
    }
    PLACEHOLDER_LOCALPARTS = {
        'user', 'admin', 'info', 'contact', 'noreply', 'no-reply', 'support',
        'someone', 'name', 'email', 'mail', 'test', 'nobody', 'you',
        'yourname', 'username', 'user1', 'admin1', 'testuser', 'demo',
        'developer', 'sample',
    }
    PLACEHOLDER_PASSWORD_VALUES = {
        'true', 'false', 'null', 'undefined', 'none', 'n/a',
        'xxxx', 'xxx', 'xxxxxxxx', '****', '******', '********',
        'changeme', 'changeit', 'password', 'passwd', 'pwd', 'secret',
        'todo', 'fixme', 'test', 'example', 'yourpassword', 'your_password',
        'sample', 'dummy', 'placeholder', 'default', 'temp', 'temporary',
        'foobar', 'qwerty', 'abc123', '123456', '12345678', '111111',
        '000000', 'letmein', 'welcome', 'monkey', 'dragon', 'admin',
        'administrator', 'root', 'guest', 'newpassword', 'password123',
        'user123', 'test123', 'demo123', 'example123',
    }

    EXPOSED_PATHS = [
        '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/.htaccess',
        '/.git/config', '/.git/HEAD', '/.svn/entries', '/.DS_Store',
        '/phpinfo.php', '/info.php', '/test.php', '/.env', '/.env.example',
        '/config.php.bak', '/config.bak', '/config.old', '/dump.sql',
        '/backup.sql', '/database.sql', '/db.sql', '/error.log',
        '/access.log', '/debug.log', '/wp-config.php.bak',
        '/server-status', '/server-info', '/actuator/health',
        '/actuator/env', '/actuator/info',
    ]

    def __init__(self):
        self.client = HTTPClient()
        self.baseline = BaselineDetector(self.client)
        self.name = "Information Disclosure Scanner"
        self.findings = []

    def scan(self, target_url: str) -> Dict[str, Any]:
        self.findings = []
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Pre-warm the SPA baseline so all later checks share one fingerprint
        self.baseline.shell_fingerprint(base_url)

        # Phase 1: Check for exposed sensitive files (content-signature based)
        self._check_exposed_files(base_url)

        # Phase 2: Scan HTML source for sensitive data
        self._scan_source_for_sensitive_data(target_url, base_url)

        # Phase 3: Check JavaScript files
        self._scan_js_files(base_url, target_url)

        # Phase 4: Check response headers for info leakage
        self._check_header_disclosure(target_url)

        return {
            'scanner': self.name,
            'target': target_url,
            'vulnerabilities': self.findings,
            'total_findings': len(self.findings)
        }

    def _check_exposed_files(self, base_url: str):
        for path in self.EXPOSED_PATHS:
            url = urljoin(base_url, path)
            try:
                resp = self.client.get(url)
                if resp.status_code != 200 or len(resp.content or b'') < 20:
                    continue
                # 1) Must be real distinct content, not the SPA fallback shell
                if not self.baseline.is_distinct(base_url, resp):
                    continue
                # 2) Must actually look like the real file (content signature)
                if not self._matches_signature(path, resp):
                    continue

                if '.git' in path or '.env' in path or 'dump' in path or 'backup' in path:
                    severity = 'Critical'
                elif path in ('/phpinfo.php', '/info.php', '/test.php'):
                    severity = 'High'
                elif 'actuator' in path:
                    severity = 'Medium'
                elif path in ('/robots.txt',):
                    severity = 'Low'
                else:
                    severity = 'Medium'

                self.findings.append({
                    'type': 'Exposed Sensitive File',
                    'description': f'Sensitive file accessible: {path}',
                    'severity': severity,
                    'url': url,
                    'evidence': (f'HTTP {resp.status_code} - {len(resp.content)} bytes, '
                                 f'content signature matched')
                })
            except Exception:
                continue

    @staticmethod
    def _matches_signature(path: str, resp) -> bool:
        """True only if the body plausibly IS the real file for this path."""
        text = resp.text or ''
        p = path.lower()

        if p.startswith('/.git/'):
            if p.endswith('/config'):
                return bool(re.search(r'(?i)\[core\]|\[remote\s+"|repositoryformatversion', text))
            if p.endswith('/head'):
                return bool(re.search(r'(?m)^ref:\s*refs/', text))
            return False

        if p in ('/.env', '/.env.example'):
            # At least one line of KEY=value, e.g. DB_PASSWORD=...
            return bool(re.search(r'(?m)^[a-z_][a-z0-9_]*\s*=\s*\S', text))

        if p.endswith('.sql') or 'dump' in p or 'backup' in p:
            return bool(re.search(r'(?i)\b(create\s+table|insert\s+into|drop\s+table)\b', text))

        if p in ('/phpinfo.php', '/info.php', '/test.php'):
            return bool(re.search(r'(?i)php\s+version|phpinfo\(\)|php\s+license', text))

        if p == '/robots.txt':
            return bool(re.search(r'(?im)^(user-agent|disallow|allow|sitemap)\s*:', text))

        if p == '/sitemap.xml':
            return '<urlset' in text or '<url>' in text

        if p == '/crossdomain.xml':
            return 'cross-domain-policy' in text.lower()

        if p == '/.htaccess':
            return bool(re.search(r'(?i)rewriteengine|options\s+[-+]|deny\s+from|<files|errordocument', text))

        if p in ('/error.log', '/access.log', '/debug.log'):
            return bool(re.search(r'(?i)(\d{4}-\d{2}-\d{2}|\[?\d{1,2}/[a-z]{3}/\d{4}|'
                                  r'get\s+\S+\s+http|post\s+\S+\s+http|php\s+(warning|error|fatal)|'
                                  r'stack\s+trace)', text))

        if '/actuator/' in p:
            return text.strip().startswith('{') or re.search(r'(?i)"status"\s*:', text)

        if p == '/.svn/entries':
            return bool(re.search(r'(?m)^(12|dir)\b', text))

        if p == '/.ds_store':
            return text.startswith('Bud1')

        # Paths without a strict signature still needed the distinct check above
        return True

    def _scan_source_for_sensitive_data(self, url: str, base_url: str):
        try:
            resp = self.client.get(url)
            # Only analyze the real page, not an SPA fallback shell
            if not self.baseline.is_distinct(base_url, resp, min_len=100):
                return
            text = resp.text

            for data_type, pattern in self.SENSITIVE_PATTERNS.items():
                matches = re.findall(pattern, str(text))
                if not matches:
                    continue
                matches = [m for m in matches
                           if not self._is_placeholder_match(data_type, m)]
                unique_matches = list(dict.fromkeys(matches))[:5]
                if not unique_matches:
                    continue

                severity = ('Critical' if data_type in ('API Keys / Tokens', 'AWS Keys',
                                                        'Private SSH Keys',
                                                        'Passwords in Comments',
                                                        'Database URLs') else 'Medium')
                if data_type == 'Email Addresses':
                    severity = 'Low'

                self.findings.append({
                    'type': f'Information Disclosure - {data_type}',
                    'description': f'Found {len(unique_matches)} potential {data_type} in response body',
                    'severity': severity,
                    'url': url,
                    'evidence': f'Example: {unique_matches[0][:100]}'
                })
        except Exception:
            pass

    @classmethod
    def _is_placeholder_match(cls, data_type: str, match: str) -> bool:
        """Filter demo/placeholder regex matches so they are not reported."""
        m = (match or '').strip()
        if not m:
            return True
        if data_type == 'Email Addresses':
            return cls._is_placeholder_email(m)
        if data_type == 'Passwords in Comments':
            return cls._is_placeholder_password(m)
        if data_type == 'Stack Traces':
            # Short fragments or bundler source maps are not server stack traces
            if len(m) < 25:
                return True
            return 'webpack://' in m or re.search(r'\.js\(\d+:\d+\)', m) is not None
        if data_type == 'Credit Cards':
            return cls._is_placeholder_number(m)
        if data_type == 'Social Security Numbers':
            return all(set(p) == {'0'} for p in m.split('-'))
        return False

    @staticmethod
    def _is_placeholder_email(email: str) -> bool:
        if '@' not in email:
            return True
        local, _, domain = email.partition('@')
        local = local.strip().strip('."\'').lower()
        domain = domain.strip().strip('."\'').lower()
        if not local or '.' not in domain:
            return True
        if domain in InfoDisclosureScanner.PLACEHOLDER_DOMAINS:
            return True
        if any(t in domain for t in ('example', 'test', 'sample', 'fake', 'yourdomain')):
            return True
        if local in InfoDisclosureScanner.PLACEHOLDER_LOCALPARTS:
            return True
        if any(t in local for t in ('example', 'sample', 'fake', 'your', 'placeholder', 'xxxx')):
            return True
        if re.fullmatch(r'\d+', local):
            return True
        return False

    @staticmethod
    def _is_placeholder_password(value: str) -> bool:
        v = (value or '').strip().strip('"\'').strip()
        if not v:
            return True
        low = v.lower()
        if low in InfoDisclosureScanner.PLACEHOLDER_PASSWORD_VALUES:
            return True
        if re.fullmatch(r'[a-z_$][\w$]*', v):
            return True   # bare identifier/variable reference, not a literal
        if re.fullmatch(r'!?-?\d+', v):
            return True   # minified boolean/number lookalikes: !0, 1
        if re.fullmatch(r'[*xX\s]+', v):
            return True   # masked: ****, xxx
        if len(v) < 6:
            return True
        return False

    @staticmethod
    def _is_placeholder_number(value: str) -> bool:
        digits = re.sub(r'[^0-9]', '', value)
        if not digits or len(digits) < 15:
            return True
        if len(set(digits)) == 1:
            return True
        seq = ''.join(str(i % 10) for i in range(1, len(digits) + 1))
        return digits == seq or digits == seq[::-1]

    def _scan_js_files(self, base_url: str, page_url: str):
        from bs4 import BeautifulSoup
        try:
            resp = self.client.get(page_url)
            if not self.baseline.is_distinct(base_url, resp, min_len=100):
                return
            soup = BeautifulSoup(resp.text, 'html.parser')
            script_tags = soup.find_all('script', src=True)

            for script in script_tags:
                src = script.get('src', '')
                if not src:
                    continue
                js_url = src if src.startswith('http') else urljoin(base_url, src)
                try:
                    js_resp = self.client.get(js_url)
                    if js_resp.status_code != 200:
                        continue
                    text = js_resp.text or ''
                    # The file must be real distinct content AND look like JS,
                    # not an HTML shell served for every path.
                    if not self.baseline.is_distinct(base_url, js_resp, min_len=100):
                        continue
                    if not re.search(r'function|=>|const\s|let\s|var\s|document\.|window\.|\{', text):
                        continue

                    for data_type, pattern in self.SENSITIVE_PATTERNS.items():
                        matches = re.findall(pattern, text)
                        if not matches:
                            continue
                        matches = [m for m in matches
                                   if not self._is_placeholder_match(data_type, m)]
                        unique = list(dict.fromkeys(matches))[:3]
                        if not unique:
                            continue
                        severity = 'Medium' if data_type == 'Email Addresses' else 'High'
                        self.findings.append({
                            'type': f'JS Info Disclosure - {data_type}',
                            'description': f'Found potential {data_type} in {src}',
                            'severity': severity,
                            'url': js_url,
                            'evidence': f'Example: {unique[0][:100]}'
                        })
                except Exception:
                    continue
        except Exception:
            pass

    def _check_header_disclosure(self, url: str):
        try:
            resp = self.client.get(url)
            for header in ('x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'):
                if header in {k.lower() for k in resp.headers}:
                    pass  # Handled by the security-misconfig scanner
        except Exception:
            pass
