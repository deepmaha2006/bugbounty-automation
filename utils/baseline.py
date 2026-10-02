"""
SPA-aware response baseline detection.

Single-page applications (React/Vue/Angular/Vite/Next.js static export, ...)
serve the same generic index.html shell with HTTP 200 for *every* path so that
client-side routing works. A naive scanner sees "HTTP 200" on /admin,
/.git/config, /phpinfo.php ... and reports them all as exposed, which produces
hundreds of false positives (all sharing the identical shell byte count).

The BaselineDetector requests 2-3 random non-existent paths. If two of them
return byte-identical responses, that body IS the fallback shell. Any other
response with the same fingerprint is treated as the shell too, so scanners can
ignore it. On classic server-rendered sites the random paths return 404s (or
distinct pages), no shell is registered, and plain HTTP-200 checks keep their
usual meaning.

The result is cached per origin (scheme://host) because the shell is a property
of the origin server, not of any individual request.
"""

import hashlib
import secrets
import threading
from typing import Any, Dict, Optional, Tuple

from urllib.parse import urljoin

Fingerprint = Tuple[Any, ...]

_CACHE: Dict[str, Optional[Fingerprint]] = {}
_LOCK = threading.Lock()


class BaselineDetector:
    """Detects a server's generic fallback page so it is never misreported."""

    def __init__(self, client, samples: int = 3):
        self.client = client
        self.samples = max(2, samples)

    @staticmethod
    def fingerprint(resp) -> Fingerprint:
        """Fingerprint a response: (status, content-type, body hash, body len)."""
        body = getattr(resp, "content", b"") or b""
        if isinstance(body, str):
            body = body.encode("utf-8", "ignore")
        ct = (resp.headers.get("Content-Type", "") or "").split(";")[0].strip().lower()
        return (resp.status_code, ct, hashlib.sha256(body).hexdigest()[:16], len(body))

    def shell_fingerprint(self, base_url: str) -> Optional[Fingerprint]:
        """Return the fallback-shell fingerprint for base_url, or None if there is none."""
        with _LOCK:
            if base_url in _CACHE:
                return _CACHE[base_url]

        fingerprints = []
        for _ in range(self.samples):
            rand_path = "/zz" + secrets.token_hex(8)
            try:
                resp = self.client.get(urljoin(base_url, rand_path), timeout=10)
                fingerprints.append(self.fingerprint(resp))
            except Exception:
                continue

        shell = None
        if len(fingerprints) >= 2:
            counts: Dict[Fingerprint, int] = {}
            for fp in fingerprints:
                counts[fp] = counts.get(fp, 0) + 1
            # Two byte-identical responses to different random paths => shell.
            for fp, n in counts.items():
                if n >= 2:
                    shell = fp
                    break

        with _LOCK:
            _CACHE[base_url] = shell
        return shell

    def is_shell(self, base_url: str, resp) -> bool:
        """True if resp is byte-identical to the origin's fallback shell."""
        shell = self.shell_fingerprint(base_url)
        if shell is None:
            return False
        return self.fingerprint(resp) == shell

    def is_distinct(self, base_url: str, resp, min_len: int = 50) -> bool:
        """True if resp is real, distinct content and not the fallback shell."""
        if resp.status_code != 200:
            return False
        if self.is_shell(base_url, resp):
            return False
        return len(resp.content or b"") >= min_len
