"""
Out-of-band confirmation tracker.

Points at an Interactsh server (https://github.com/projectdiscovery/interactsh)
via HYDRAX_OOB_SERVER env var. Each blind probe uses a unique correlation-token
subdomain. A finding in blind/stored/OOB classes is confirmed ONLY when a
callback arrives matching its token within the scan window.

When HYDRAX_OOB_SERVER is not set:
- All OOB-dependent checks are skipped.
- Reports note "OOB server not configured — blind checks skipped."

Usage
-----
    from utils.oob_tracker import oob_configured, generate_token, oob_url
    from utils.oob_tracker import register_token, wait_for_callback

    if oob_configured():
        token = generate_token()
        callback = oob_url(token)     # e.g. http://<token>.interact.sh
        register_token(token)
        # … embed callback in probe payload …
        confirmed = wait_for_callback(token, timeout=30)
    else:
        print(oob_skipped_note())
"""

import os
import time
import threading
import uuid
from typing import Dict, Optional

_OOB_SERVER: str = os.environ.get("HYDRAX_OOB_SERVER", "").strip()

# In-memory correlation table: token → callback_received
_callbacks: Dict[str, bool] = {}
_callbacks_lock = threading.Lock()


def oob_configured() -> bool:
    """True when an OOB interaction server is configured."""
    return bool(_OOB_SERVER)


def generate_token() -> str:
    """Return a unique 16-character hex correlation token."""
    return uuid.uuid4().hex[:16]


def oob_url(token: str) -> Optional[str]:
    """Build a callback subdomain URL for the given token.

    Returns None when no OOB server is configured.
    """
    if not _OOB_SERVER:
        return None
    server = _OOB_SERVER.rstrip("/")
    return f"http://{token}.{server}"


def register_token(token: str) -> None:
    """Register a token, initialising its callback state to False."""
    with _callbacks_lock:
        _callbacks[token] = False


def mark_callback_received(token: str) -> None:
    """Mark a token as having received its OOB callback.

    Call this from the Interactsh polling loop when a callback arrives.
    """
    with _callbacks_lock:
        _callbacks[token] = True


def check_callback(token: str) -> bool:
    """Return whether a callback has been received for this token."""
    with _callbacks_lock:
        return _callbacks.get(token, False)


def wait_for_callback(token: str, timeout: int = 30) -> bool:
    """Poll for a callback arrival for up to *timeout* seconds.

    Returns True if a callback arrived within the timeout, False otherwise.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check_callback(token):
            return True
        time.sleep(0.5)
    return False


def oob_skipped_note() -> str:
    """Human-readable note to include in reports when OOB is unconfigured."""
    return (
        "OOB server not configured — blind XSS, OOB SQL injection, blind SSRF, "
        "and RCE callback checks were skipped. Set the HYDRAX_OOB_SERVER "
        "environment variable to an Interactsh endpoint "
        "(https://github.com/projectdiscovery/interactsh) to enable them."
    )
