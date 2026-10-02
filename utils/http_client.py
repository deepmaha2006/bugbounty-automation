"""
Advanced HTTP client with evasion capabilities for bug bounty scanning
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import random
import threading
import time
from typing import Optional, Dict, List, Any

from utils.sync_rate_limiter import get_shared_rate_limiter

# One requests.Session — and therefore one connection pool — shared by
# every HTTPClient instance in the process, instead of each scanner
# creating its own. Scanner modules targeting the same host now reuse
# already-open TCP/TLS connections instead of each paying for its own
# handshake. Sized well above the old per-instance default (20) since many
# scanners' HTTPClients now share this one pool concurrently.
_shared_session: Optional[requests.Session] = None
_shared_session_lock = threading.Lock()


def _get_shared_session() -> requests.Session:
    global _shared_session
    if _shared_session is None:
        with _shared_session_lock:
            if _shared_session is None:
                session = requests.Session()
                retry_strategy = Retry(
                    total=3,
                    backoff_factor=0.3,
                    status_forcelist=[429, 500, 502, 503, 504],
                )
                adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=50, pool_maxsize=100)
                session.mount("https://", adapter)
                session.mount("http://", adapter)
                _shared_session = session
    return _shared_session


class HTTPClient:
    """Advanced HTTP client with evasion capabilities"""

    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    ]

    def __init__(self, timeout: Optional[int] = None, delay: Optional[float] = None,
                 verify_ssl: Optional[bool] = None):
        # Pull defaults from live config so runtime apply_settings() updates propagate.
        # Scanners used to hardcode their own timeout/delay here, which meant
        # Settings changes had zero effect on most scans — pass explicit
        # values only when a caller genuinely needs to deviate.
        from config import settings
        self.session = _get_shared_session()
        self.timeout = timeout if timeout is not None else settings.DEFAULT_TIMEOUT
        self.delay = delay if delay is not None else settings.DEFAULT_REQUEST_DELAY
        self.verify_ssl = settings.VERIFY_SSL if verify_ssl is None else verify_ssl
        self._rate_limiter = get_shared_rate_limiter()

        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _check_stop(self):
        """Abort politely when the user stopped the scan mid-request."""
        from core.scan_context import stop_requested, ScanAborted
        if stop_requested():
            raise ScanAborted("Scan stopped by user")


    def _get_headers(self, additional_headers: Optional[Dict] = None) -> Dict:
        """Generate randomized headers"""
        headers = {
            'User-Agent': random.choice(self.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        }
        if additional_headers:
            headers.update(additional_headers)
        return headers

    def get(self, url: str, params: Optional[Dict] = None, headers: Optional[Dict] = None,
            cookies: Optional[Dict] = None, allow_redirects: bool = True,
            timeout: Optional[float] = None) -> requests.Response:
        """Send GET request with evasion"""
        self._check_stop()
        self._rate_limiter.acquire(url)
        if self.delay > 0:
            time.sleep(self.delay + random.uniform(0, 0.15))

        response = self.session.get(
            url,
            params=params,
            headers=self._get_headers(headers),
            cookies=cookies,
            timeout=self.timeout if timeout is None else timeout,
            verify=self.verify_ssl,
            allow_redirects=allow_redirects
        )
        return response

    def post(self, url: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None,
             headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
             allow_redirects: bool = True, timeout: Optional[float] = None) -> requests.Response:
        """Send POST request with evasion"""
        self._check_stop()
        self._rate_limiter.acquire(url)
        if self.delay > 0:
            time.sleep(self.delay + random.uniform(0, 0.15))

        response = self.session.post(
            url,
            data=data,
            json=json_data,
            headers=self._get_headers(headers),
            cookies=cookies,
            timeout=self.timeout if timeout is None else timeout,
            verify=self.verify_ssl,
            allow_redirects=allow_redirects
        )
        return response

    def close(self):
        """No-op: self.session is the process-wide shared session (see
        _get_shared_session) — closing it here would break every other
        HTTPClient instance still using it. Nothing currently calls this,
        but keep it safe rather than removing it outright."""
        pass