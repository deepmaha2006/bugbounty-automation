"""
Thread-safe, synchronous per-host token-bucket rate limiter, shared by every
HTTPClient instance for the lifetime of the process.

utils/rate_limiter.py already implements an adaptive rate limiter, but it's
built on asyncio/aiohttp — incompatible with HTTPClient, which is
synchronous (requests + threads). A repo-wide grep confirms nothing actually
calls into rate_limiter.py; it has never been wired into the real request
path. That means there has never been any cap on *aggregate* request rate:
each HTTPClient only slept its own small per-request delay, with zero
coordination across threads. Once scanners (and their internal phases/
payload loops) run concurrently, that gap turns into real risk — N
concurrently-running threads each politely sleeping their own delay still
adds up to N times the intended request rate against the target.

This module is the actual cap: every HTTPClient.get()/post() call acquires
a token from the shared, per-host bucket before firing, so the aggregate
rate across every scanner and every internal worker thread stays within
whatever a scan's ScopeConfig.requests_per_second/burst_limit says,
regardless of how many threads are running.
"""

import threading
import time
from typing import Dict
from urllib.parse import urlparse


class _TokenBucket:
    """A single host's token bucket. Not exposed directly — go through
    SyncRateLimiter, which keys buckets by host."""

    def __init__(self, rate: float, burst: float):
        self.rate = max(0.01, rate)
        self.burst = max(1.0, burst)
        self.tokens = self.burst
        self.last_refill = time.monotonic()
        self._lock = threading.Lock()

    def configure(self, rate: float, burst: float) -> None:
        with self._lock:
            self.rate = max(0.01, rate)
            self.burst = max(1.0, burst)
            self.tokens = min(self.tokens, self.burst)

    def acquire(self) -> None:
        """Block the calling thread until one token is available."""
        while True:
            with self._lock:
                now = time.monotonic()
                self.tokens = min(self.burst, self.tokens + (now - self.last_refill) * self.rate)
                self.last_refill = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                wait = (1 - self.tokens) / self.rate
            time.sleep(min(wait, 1.0))


class SyncRateLimiter:
    """Per-host token buckets, safe to share across threads and scanners."""

    def __init__(self, default_rate: float = 10.0, default_burst: float = 20.0):
        self._default_rate = default_rate
        self._default_burst = default_burst
        self._buckets: Dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()

    def configure(self, rate: float, burst: float) -> None:
        """Update the rate/burst applied to every bucket (existing hosts and
        any created afterward). Called once per scan from ScanEngine using
        that scan's ScopeConfig, so the limit reflects the target actually
        being scanned rather than a single process-wide constant."""
        rate = rate or self._default_rate
        burst = burst or self._default_burst
        with self._lock:
            self._default_rate = rate
            self._default_burst = burst
            buckets = list(self._buckets.values())
        for bucket in buckets:
            bucket.configure(rate, burst)

    def _host_key(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"

    def acquire(self, url: str) -> None:
        host_key = self._host_key(url)
        with self._lock:
            bucket = self._buckets.get(host_key)
            if bucket is None:
                bucket = _TokenBucket(self._default_rate, self._default_burst)
                self._buckets[host_key] = bucket
        bucket.acquire()


# One shared limiter for the process. Reconfigured at the start of every
# scan (see ScanEngine.scan) — not per-HTTPClient-instance — so every
# scanner, and every worker thread inside every scanner, draws from the
# same budget for a given host instead of each getting its own.
_shared_limiter = SyncRateLimiter()


def get_shared_rate_limiter() -> SyncRateLimiter:
    return _shared_limiter
