"""
DDoS Resilience Testing Scanner (AUTHORIZED INTERNAL USE ONLY)

This scanner performs *bounded resilience probes* — it verifies whether the
target enforces rate limiting and connection thresholds. It is intentionally
non-destructive: it sends at most a few dozen requests and never floods.

It MUST only be run against systems the operator is authorized to test
(company-owned infrastructure). The raw low-level socket probe is further
restricted to internal/loopback hosts so the tool never emits anomalous raw
traffic toward external third-party hosts.
"""

from typing import Dict, List, Any
import sys, os, time, threading, socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.http_client import HTTPClient


def _is_internal_host(host: str) -> bool:
    """True for loopback / private / reserved ranges only."""
    import ipaddress
    host = (host or "").split(":")[0].strip()
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):  # nosec B104 - denylist check, not a bind
        return True
    try:
        ip = ipaddress.ip_address(host)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
        )
    except ValueError:
        # Not an IP literal — fall back to name-based caution.
        return host.endswith((".local", ".internal", ".lan", ".corp"))


_CDN_KEYWORDS = frozenset({
    'cloudflare', 'fastly', 'akamai', 'cloudfront', 'github.com',
    'cdn77', 'stackpath', 'sucuri', 'imperva', 'edgecast', 'varnish',
    'nginx/cloudflare',
})


def _is_cdn_fronted(client: 'HTTPClient', url: str) -> bool:
    """True when the target sits behind a CDN/edge node.

    CDN edge nodes absorb traffic before it reaches origin, so rate-limit and
    connection-limit probes measure the CDN's own thresholds, not the app's.
    Reporting Missing Rate Limiting against a Cloudflare/Fastly-fronted target
    creates a near-certain false positive class.
    """
    try:
        resp = client.get(url)
        server = (resp.headers.get('server') or '').lower()
        via = (resp.headers.get('via') or '').lower()
        x_cache = (resp.headers.get('x-cache') or '').lower()
        combined = f"{server} {via} {x_cache}"
        # cf-ray is Cloudflare-specific; its presence alone is definitive.
        if resp.headers.get('cf-ray') or resp.headers.get('cf-cache-status'):
            return True
        return any(kw in combined for kw in _CDN_KEYWORDS)
    except Exception:
        return False


class DDoSTester:
    """DDoS Resilience testing (bounded, authorized-internal targets only)"""

    def __init__(self):
        self.client = HTTPClient(timeout=10, delay=0)
        self.name = "DDoS Resilience Tester"
        self.findings = []
        self._cdn_fronted = False

    def scan(self, target_url: str) -> Dict[str, Any]:
        self.findings = []

        self._cdn_fronted = _is_cdn_fronted(self.client, target_url)

        # Test 1: Rate limiting (rapid requests)
        self._test_rate_limiting(target_url)

        # Test 2: Concurrent connections
        self._test_concurrent_connections(target_url)

        # Test 3: Large payload handling
        self._test_large_payloads(target_url)

        # Test 4: Slow response handling
        self._test_slow_requests(target_url)

        return {
            'scanner': self.name,
            'target': target_url,
            'vulnerabilities': self.findings,
            'total_findings': len(self.findings)
        }

    def _test_rate_limiting(self, url: str):
        """Send rapid requests to test rate limiting"""
        responses = []
        start = time.time()

        for i in range(20):
            try:
                resp = self.client.get(url)
                responses.append(resp.status_code)
            except:
                responses.append(0)

        duration = time.time() - start
        rate = len(responses) / duration if duration > 0 else 0

        # Check if all requests went through without rate limiting
        success_count = sum(1 for r in responses if r == 200)
        if success_count == 20:
            # CDN edge nodes handle rate limiting on behalf of origin — a passing
            # result proves only that the CDN allows it, not the app.
            severity = 'Info' if self._cdn_fronted else 'Medium'
            desc_suffix = ' (CDN-fronted — origin rate limit not tested)' if self._cdn_fronted else ''
            self.findings.append({
                'type': 'Missing Rate Limiting',
                'description': f'No rate limiting detected — {success_count}/20 requests succeeded at {rate:.1f} req/s{desc_suffix}',
                'severity': severity,
                'evidence': f'Rate: {rate:.1f} requests/second. All requests returned HTTP 200'
            })
        elif success_count > 15:
            severity = 'Info' if self._cdn_fronted else 'Low'
            self.findings.append({
                'type': 'Weak Rate Limiting',
                'description': f'Rate limiting appears weak — {success_count}/20 rapid requests succeeded',
                'severity': severity,
                'evidence': f'Rate: {rate:.1f} req/s. {20-success_count} requests were blocked'
            })
        else:
            self.findings.append({
                'type': 'Rate Limiting Detected',
                'description': f'Rate limiting is active — only {success_count}/20 rapid requests succeeded',
                'severity': 'Info',
                'evidence': f'Rate: {rate:.1f} req/s. Rate limiting kicked in'
            })

    def _test_concurrent_connections(self, url: str):
        """Test with multiple concurrent connections"""
        def make_request():
            try:
                c = HTTPClient(timeout=10, delay=0)
                return c.get(url).status_code
            except:
                return 0

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(make_request) for _ in range(30)]
            results = [f.result() for f in as_completed(futures)]

        success = sum(1 for r in results if r == 200)
        if success == 30:
            severity = 'Info' if self._cdn_fronted else 'Low'
            desc_suffix = ' (CDN-fronted — connection limit not tested at origin)' if self._cdn_fronted else ''
            self.findings.append({
                'type': 'No Connection Limiting',
                'description': f'No concurrent connection limiting detected — 30 parallel requests all succeeded{desc_suffix}',
                'severity': severity,
                'evidence': 'All concurrent requests returned HTTP 200'
            })

    def _test_large_payloads(self, url: str):
        """Test with large query parameters"""
        large_param = 'A' * 10000
        test_url = f"{url}?test={large_param}"

        try:
            start = time.time()
            resp = self.client.get(test_url)
            elapsed = time.time() - start

            if resp.status_code == 200 and elapsed < 5:
                self.findings.append({
                    'type': 'Large Payload Accepted',
                    'description': 'Accepts very large query parameters (10KB+) without restriction',
                    'severity': 'Low',
                    'url': test_url,
                    'evidence': f'HTTP {resp.status_code} - Response time: {elapsed:.2f}s'
                })
        except:
            pass

    def _test_slow_requests(self, url: str):
        """Test timeout handling with slow read (internal hosts only)"""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Only test slow-read against internal hosts to avoid external impact
        if not _is_internal_host(host):
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            if port == 443:
                import ssl
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)

            # Send partial request then stall
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\n"
            sock.send(request.encode())

            # Don't complete the request - see if server times out
            time.sleep(2)
            sock.close()
        except Exception:
            pass