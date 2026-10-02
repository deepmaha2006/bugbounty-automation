"""
Passive Reconnaissance Scanner
WHOIS, DNS enumeration, technology fingerprinting, OSINT
"""

from typing import Dict, List, Any
import sys, os, socket, json, re
import dns.resolver
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.http_client import HTTPClient


class PassiveRecon:
    """Passive Reconnaissance scanner"""

    TECHNOLOGY_PATTERNS = {
        'PHP': [r'PHP\s*[\d.]+', r'X-Powered-By:\s*PHP', r'\.php\b'],
        'ASP.NET': [r'ASP\.NET', r'X-AspNet-Version', r'__VIEWSTATE'],
        'WordPress': [r'/wp-content/', r'/wp-admin/', r'/wp-includes/', r'wp-json'],
        'Joomla': [r'/components/', r'/modules/', r'joomla!', r'Joomla'],
        'Drupal': [r'/sites/default/', r'drupal.js', r'Drupal.settings'],
        'nginx': [r'nginx/[\d.]+', r'Server:\s*nginx'],
        'Apache': [r'Apache/[\d.]+', r'Server:\s*Apache'],
        'Cloudflare': [r'cloudflare', r'__cfduid', r'cf-ray'],
        'CloudFront': [r'x-amz-cf-id', r'CloudFront'],
        'Fastly': [r'Fastly', r'X-Served-By:\s*cache'],
        'Google Analytics': [r'google-analytics\.com', r'gtag\('],
        'jQuery': [r'jquery[.-][\d.]+', r'jQuery v'],
        'React': [r'react\.js', r'react\.min\.js', r'__REACT_DEVTOOLS'],
        'Vue.js': [r'vue\.js', r'vue\.min\.js', r'__VUE_'],
        'Angular': [r'angular\.js', r'ng-app', r'angular\.min\.js'],
        'Bootstrap': [r'bootstrap\.min\.css', r'bootstrap\.css', r'col-xs-\d+'],
        'Stripe': [r'stripe\.com', r'pk_live_', r'stripe\.js'],
        'PayPal': [r'paypal\.com', r'paypalobjects\.com'],
        'Laravel': [r'Laravel', r'XSRF-TOKEN', r'laravel_session'],
        'Django': [r'django\.core', r'csrftoken', r'__admin__'],
        'Ruby on Rails': [r'rails', r'ruby on rails', r'csrf-param'],
    }

    def __init__(self):
        self.client = HTTPClient(timeout=15, delay=0)
        self.name = "Passive Reconnaissance"
        self.findings = []

    def scan(self, target_url: str) -> Dict[str, Any]:
        self.findings = []
        parsed = urlparse(target_url)
        domain = parsed.netloc or target_url.replace('http://', '').replace('https://', '').split('/')[0]

        # Phase 1: DNS records
        self._enumerate_dns(domain)

        # Phase 2: Technology fingerprinting
        self._fingerprint_technology(target_url)

        # Phase 3: SSL/TLS info
        self._check_ssl(target_url)

        # Phase 4: URL structure analysis
        self._analyze_url_structure(target_url, parsed)

        return {
            'scanner': self.name,
            'target': target_url,
            'vulnerabilities': self.findings,
            'total_findings': len(self.findings)
        }

    def _enumerate_dns(self, domain: str):
        """Enumerate DNS records (best-effort; failures are non-findings)."""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=3)
                records = [str(r) for r in answers]

                if records:
                    self.findings.append({
                        'type': f'DNS {rtype} Records',
                        'description': f'Found {len(records)} DNS {rtype} record(s)',
                        'severity': 'Info',
                        'evidence': f'Records: {", ".join(records[:5])}'
                    })
            except Exception:
                # NXDOMAIN, timeout, no resolver, etc. are not vulnerabilities.
                continue

    def _fingerprint_technology(self, url: str):
        """Identify web technologies"""
        try:
            resp = self.client.get(url)
            headers_text = str(resp.headers)
            body_text = str(resp.text)

            detected = []
            for tech, patterns in self.TECHNOLOGY_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, body_text, re.IGNORECASE) or re.search(pattern, headers_text, re.IGNORECASE):
                        detected.append(tech)
                        break

            if detected:
                self.findings.append({
                    'type': 'Technology Stack Fingerprinting',
                    'description': f'Detected {len(detected)} technologies',
                    'severity': 'Info',
                    'evidence': f'Technologies: {", ".join(detected)}'
                })
        except:
            pass

    def _check_ssl(self, url: str):
        """Check SSL/TLS configuration"""
        if not url.startswith('https'):
            self.findings.append({
                'type': 'Non-HTTPS Connection',
                'description': 'Target does not enforce HTTPS',
                'severity': 'Medium',
                'url': url,
                'evidence': 'URL uses HTTP instead of HTTPS'
            })
            return

        import ssl
        import socket as sock_mod

        parsed = urlparse(url)
        host = parsed.netloc.split(':')[0]

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(sock_mod.socket(), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, 443))
                cert = s.getpeercert()

                if cert:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    not_after = cert.get('notAfter', 'Unknown')

                    cn = subject.get('commonName', 'Unknown')
                    issuer_org = issuer.get("organizationName", "Unknown")

                    # Actually evaluate expiry (spec §4: "certificate status")
                    # instead of just reporting the raw date as Info regardless.
                    severity, status_desc = 'Info', f'SSL certificate issued to {cn}'
                    try:
                        import datetime
                        expires_at = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expires_at - datetime.datetime.utcnow()).days
                        if days_left < 0:
                            severity = 'Critical'
                            status_desc = f'SSL certificate for {cn} EXPIRED {-days_left} day(s) ago'
                        elif days_left <= 14:
                            severity = 'High'
                            status_desc = f'SSL certificate for {cn} expires in {days_left} day(s)'
                        elif days_left <= 30:
                            severity = 'Medium'
                            status_desc = f'SSL certificate for {cn} expires in {days_left} day(s)'
                    except (ValueError, TypeError):
                        pass  # unparsable date format — keep the Info-level report, don't guess

                    self.findings.append({
                        'type': 'SSL Certificate',
                        'description': status_desc,
                        'severity': severity,
                        'evidence': f'Issuer: {issuer_org}, Expires: {not_after}'
                    })

        except (ssl.SSLError, sock_mod.timeout, sock_mod.gaierror, ConnectionRefusedError, OSError) as e:
            self.findings.append({
                'type': 'SSL/TLS Issue',
                'description': f'SSL connection failed: {str(e)}',
                'severity': 'High',
                'evidence': str(e)
            })

    def _analyze_url_structure(self, url: str, parsed):
        """Analyze URL structure for recon"""
        # Check for common API patterns
        if '/api/' in parsed.path:
            self.findings.append({
                'type': 'API Endpoint Detected',
                'description': f'API endpoint found: {parsed.path}',
                'severity': 'Info',
                'evidence': f'Path contains /api/ — may expose additional endpoints'
            })

        # Check query parameters
        if parsed.query:
            self.findings.append({
                'type': 'URL Parameters',
                'description': f'URL contains query parameters: {parsed.query}',
                'severity': 'Info',
                'evidence': 'May indicate state-modifying or IDOR-prone parameters'
            })