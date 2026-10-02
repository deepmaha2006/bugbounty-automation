"""Generic in-memory, per-key, fixed-window rate limiter for expensive or
abuse-prone authenticated API endpoints (CVM platform spec §21's "API abuse"
review) — scan creation and report generation today.

Distinct from `webapp/services/auth_limiter.py` (failed-attempt brute-force
protection, keyed by outcome) and `utils/rate_limiter.py` (async, per-host
pacing of *outbound* scanner requests against a target). This one counts
every call regardless of outcome, keyed by the calling user.

In-memory and per-process: a multi-worker deployment (multiple uvicorn/
gunicorn processes) gets one independent limit per process, not one global
limit. Acceptable for now (bounds abuse per-process rather than not at all);
a shared Redis-backed limiter would be needed for a strict cross-process
guarantee. See docs/ROADMAP.md Phase 13.
"""
import threading
import time
from collections import OrderedDict
from typing import Optional


class FixedWindowLimiter:
    def __init__(self, max_requests: int, window_seconds: int,
                max_keys: int = 10_000, now=None):
        self.max_requests = max(1, int(max_requests))
        self.window_seconds = max(1, int(window_seconds))
        self.max_keys = max(1, int(max_keys))
        self.now = now if now is not None else time.time
        self._lock = threading.Lock()
        self._data: "OrderedDict[object, list]" = OrderedDict()  # key -> [window_start, count]

    def reset(self) -> None:
        with self._lock:
            self._data.clear()

    def allow(self, key) -> bool:
        """True if this call is within the limit (and counts it); False if
        the key has exhausted its quota for the current window."""
        now = self.now()
        with self._lock:
            entry = self._data.get(key)
            if entry is None or now - entry[0] >= self.window_seconds:
                self._data[key] = [now, 1]
                self._data.move_to_end(key)
                self._evict()
                return True
            if entry[1] >= self.max_requests:
                self._data.move_to_end(key)
                return False
            entry[1] += 1
            self._data.move_to_end(key)
            return True

    def _evict(self) -> None:
        while len(self._data) > self.max_keys:
            self._data.popitem(last=False)
