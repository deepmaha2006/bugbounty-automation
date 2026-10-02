"""
Subdomain Takeover Scanner
Detects dangling DNS records vulnerable to subdomain takeover
"""

from typing import Dict, List, Any
import sys, os, socket, dns.resolver

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.http_client import HTTPClient


class SubdomainTakeoverScanner:
    """Subdomain takeover vulnerability scanner"""

    TAKEOVER_SIGNATURES = {
        'aws.s3': ['NoSuchBucket', 'The specified bucket does not exist'],
        'aws.cloudfront': ['CloudFront Distribution Not Found', 'BadRequest'],
        'aws.elb': ['404 Not Found', 'There is no Action'],
        'azure.cloudapp': ['This website is hosted by Azure', '404'],
        'azure.trafficmanager': ['The resource you are looking for has been removed'],
        'github.pages': ['There isn\x27t a GitHub Pages site here'],
        'heroku': ['No such app', 'Heroku | No such app'],
        'shopify': ['Sorry, this shop is currently unavailable'],
        'fastly': ['Fastly error: unknown domain'],
        'bitbucket': ['The page you are looking for does not exist'],
        'surge': ['project not found'],
        'unbounce': ['The page you requested was not found'],
        'wordpress': ['Domain mapping update for'],
        'squarespace': ['No Such Account'],
        'zendesk': ['Help Center Closed', 'This help site has been closed'],
        'readme': ['Project doesnt exist...'],
        'tumblr': ['There\x27s nothing here'],
        'cargo': ['404 - File Not Found'],
        'strikingly': ['The page you are looking for no longer exists'],
    }

    # Common subdomains to check
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
        'smtp', 'secure', 'vpn', 'admin', 'cdn', 'api', 'dev', 'test',
        'stage', 'staging', 'beta', 'demo', 'app', 'm', 'mobile', 'portal',
        'help', 'support', 'docs', 'status', 'ftp', 'ssh', 'git', 'svn',
        'db', 'database', 'mysql', 'backup', 'monitor', 'logs', 'assets',
        'img', 'static', 'media', 'upload', 'download', 'store', 'shop',
        'web', 'intranet', 'internal', 'jenkins', 'jira', 'wiki', 'confluence',
    ]

    def __init__(self):
        self.client = HTTPClient()
        self.name = "Subdomain Takeover Scanner"
        self.findings = []

    def scan(self, target_url: str) -> Dict[str, Any]:
        self.findings = []
        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc or target_url.replace('http://', '').replace('https://', '').split('/')[0]

        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]

        # Enumerate subdomains (lifetime caps each DNS query at 2s so a slow
        # or unreachable resolver cannot hang the whole scan).
        found_subdomains = []
        for sub in self.COMMON_SUBDOMAINS:
            subdomain = f"{sub}.{domain}"
            try:
                dns.resolver.resolve(subdomain, 'A', lifetime=2)
                found_subdomains.append(subdomain)
            except Exception:
                pass

        if not found_subdomains:
            self.findings.append({
                'type': 'No Subdomains Found',
                'description': 'No common subdomains resolved for this domain',
                'severity': 'Info',
                'evidence': 'All common subdomain queries returned NXDOMAIN'
            })
            return {'scanner': self.name, 'target': target_url, 'vulnerabilities': self.findings, 'total_findings': 0}

        self.findings.append({
            'type': 'Subdomain Enumeration',
            'description': f'Found {len(found_subdomains)} live subdomains',
            'severity': 'Info',
            'evidence': f'Subdomains: {", ".join(found_subdomains[:20])}'
        })

        # Check each for takeover (try https first, then http)
        for subdomain in found_subdomains:
            for service, signatures in self.TAKEOVER_SIGNATURES.items():
                for scheme in ("https", "http"):
                    try:
                        resp = self.client.get(f"{scheme}://{subdomain}")
                        text = (resp.text or "").lower()
                        for sig in signatures:
                            if sig.lower() in text:
                                self.findings.append({
                                    'type': 'Subdomain Takeover',
                                    'description': f'{subdomain} appears vulnerable to {service} takeover',
                                    'severity': 'Critical',
                                    'url': f"{scheme}://{subdomain}",
                                    'evidence': f'Signature "{sig}" found in response (HTTP {resp.status_code})'
                                })
                                break
                    except Exception:
                        continue
                if any(f.get('url', '').endswith(subdomain) for f in self.findings):
                    break

        return {
            'scanner': self.name,
            'target': target_url,
            'vulnerabilities': self.findings,
            'total_findings': len(self.findings)
        }