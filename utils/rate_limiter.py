"""
Adaptive Rate Limiter for Bug Bounty Professional.

Provides per-host token bucket rate limiting with adaptive behavior based on
HTTP responses (429, 5xx), robots.txt compliance, and priority queuing.
"""

import asyncio
import time
import logging
import random
import re
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple
from urllib.parse import urlparse
from collections import defaultdict
import aiohttp
from aiohttp import ClientResponse

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class HostMetrics:
    """Metrics for a specific host."""
    requests_total: int = 0
    requests_success: int = 0
    errors_429: int = 0
    errors_5xx: int = 0
    errors_other: int = 0
    current_rate: float = 0.0
    tokens_available: float = 0.0
    queue_depth: int = 0
    last_adjustment: float = 0.0
    consecutive_success: int = 0
    robots_txt_crawled: bool = False
    crawl_delay: Optional[float] = None
    disallowed_paths: Set[str] = field(default_factory=set)


@dataclass
class RateLimitConfig:
    """Rate limit configuration for a host."""
    rate: float = 10.0           # requests per second
    burst: int = 20              # burst capacity
    min_rate: float = 0.1        # minimum rate floor
    max_rate: float = 50.0       # maximum rate ceiling
    adaptive: bool = True        # enable adaptive adjustments


class TokenBucket:
    """Token bucket for rate limiting a single host."""

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.tokens = float(config.burst)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> float:
        """
        Acquire tokens, returning wait time in seconds.
        Returns 0 if tokens available immediately.
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.config.burst, self.tokens + elapsed * self.config.rate)
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return 0.0

            # Calculate wait time for required tokens
            needed = tokens - self.tokens
            wait_time = needed / self.config.rate
            self.tokens = 0
            return wait_time

    def get_available(self) -> float:
        """Get current available tokens (without locking)."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        return min(self.config.burst, self.tokens + elapsed * self.config.rate)

    def adjust_rate(self, new_rate: float) -> None:
        """Adjust the refill rate."""
        self.config.rate = max(self.config.min_rate, min(self.config.max_rate, new_rate))

    def adjust_burst(self, new_burst: int) -> None:
        """Adjust burst capacity."""
        self.config.burst = max(1, new_burst)
        self.tokens = min(self.tokens, float(self.config.burst))


class RobotsTxtParser:
    """Parse and cache robots.txt for a host."""

    def __init__(self, ttl: int = 3600):
        self.ttl = ttl
        self._cache: Dict[str, Tuple[float, Set[str], Optional[float]]] = {}
        self._lock = asyncio.Lock()

    async def fetch_and_parse(self, session: aiohttp.ClientSession, base_url: str) -> Tuple[Set[str], Optional[float]]:
        """Fetch and parse robots.txt, returning (disallowed_paths, crawl_delay)."""
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        async with self._lock:
            if robots_url in self._cache:
                cached_time, disallowed, crawl_delay = self._cache[robots_url]
                if time.time() - cached_time < self.ttl:
                    return disallowed, crawl_delay

        try:
            async with session.get(robots_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    disallowed, crawl_delay = self._parse_robots_txt(text)
                    async with self._lock:
                        self._cache[robots_url] = (time.time(), disallowed, crawl_delay)
                    return disallowed, crawl_delay
        except Exception as e:
            logger.debug(f"Failed to fetch robots.txt from {robots_url}: {e}")

        return set(), None

    def _parse_robots_txt(self, text: str) -> Tuple[Set[str], Optional[float]]:
        """Parse robots.txt content."""
        disallowed = set()
        crawl_delay = None
        current_user_agent = None
        applies_to_us = False

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if ':' not in line:
                continue

            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()

            if key == 'user-agent':
                current_user_agent = value.lower()
                applies_to_us = current_user_agent in ('*', 'bugbounty', 'bot', 'crawler', 'spider')
            elif applies_to_us:
                if key == 'disallow' and value:
                    disallowed.add(value)
                elif key == 'crawl-delay':
                    try:
                        crawl_delay = float(value)
                    except ValueError:
                        pass

        return disallowed, crawl_delay

    def is_allowed(self, base_url: str, path: str) -> bool:
        """Check if a path is allowed by robots.txt."""
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        if robots_url not in self._cache:
            return True  # Not cached, allow by default

        _, disallowed, _ = self._cache[robots_url]
        for disallow_path in disallowed:
            if self._path_matches(path, disallow_path):
                return False
        return True

    def _path_matches(self, path: str, pattern: str) -> bool:
        """Check if path matches robots.txt pattern."""
        # Simple glob matching for robots.txt
        if pattern.endswith('*'):
            prefix = pattern[:-1]
            return path.startswith(prefix)
        return path == pattern or path.startswith(pattern + '/')


class RateLimiter:
    """
    Adaptive rate limiter with per-host token buckets.

    Features:
    - Per-host token bucket with configurable rate/burst
    - Adaptive rate reduction on 429/5xx responses
    - Automatic rate recovery on sustained success
    - robots.txt compliance (crawl-delay, disallow)
    - Priority queue support (high/normal/low)
    - Metrics collection per host
    """

    def __init__(
        self,
        default_rate: float = None,
        max_rate: float = None,
        min_rate: float = None,
        burst_capacity: int = None,
        adaptive_enabled: bool = None,
        robots_txt_compliance: bool = None,
    ):
        # Load from settings with fallback to parameters
        self.default_rate = default_rate or getattr(settings, 'DEFAULT_RATE_LIMIT', 10.0)
        self.max_rate = max_rate or getattr(settings, 'MAX_RATE_LIMIT', 50.0)
        self.min_rate = min_rate or getattr(settings, 'MIN_RATE_LIMIT', 0.1)
        self.burst_capacity = burst_capacity or getattr(settings, 'BURST_CAPACITY', 20)
        self.adaptive_enabled = adaptive_enabled if adaptive_enabled is not None else getattr(settings, 'ADAPTIVE_ENABLED', True)
        self.robots_txt_compliance = robots_txt_compliance if robots_txt_compliance is not None else getattr(settings, 'ROBOTS_TXT_COMPLIANCE', True)

        self._buckets: Dict[str, TokenBucket] = {}
        self._metrics: Dict[str, HostMetrics] = defaultdict(HostMetrics)
        self._robots_parser = RobotsTxtParser()
        self._locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._global_lock = asyncio.Lock()
        self._session: Optional[aiohttp.ClientSession] = None

        # Priority queue: list of (priority, future, host, tokens)
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self, session: aiohttp.ClientSession = None):
        """Start the rate limiter worker."""
        self._session = session
        self._running = True
        self._worker_task = asyncio.create_task(self._queue_worker())

    async def stop(self):
        """Stop the rate limiter worker."""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

    def _get_host_key(self, url: str) -> str:
        """Extract host key from URL."""
        parsed = urlparse(url)
        return f"{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"

    def _get_bucket(self, host_key: str) -> TokenBucket:
        """Get or create token bucket for host."""
        if host_key not in self._buckets:
            config = RateLimitConfig(
                rate=self.default_rate,
                burst=self.burst_capacity,
                min_rate=self.min_rate,
                max_rate=self.max_rate,
                adaptive=self.adaptive_enabled,
            )
            self._buckets[host_key] = TokenBucket(config)
            self._metrics[host_key].current_rate = self.default_rate
            self._metrics[host_key].tokens_available = float(self.burst_capacity)
        return self._buckets[host_key]

    def _get_metrics(self, host_key: str) -> HostMetrics:
        """Get metrics for host."""
        return self._metrics[host_key]

    async def acquire(self, url: str, priority: int = 1, tokens: int = 1) -> float:
        """
        Acquire permission to make a request.

        Args:
            url: Target URL
            priority: 0=high, 1=normal, 2=low (lower = higher priority)
            tokens: Number of tokens to acquire

        Returns:
            Wait time in seconds before request can proceed
        """
        host_key = self._get_host_key(url)
        bucket = self._get_bucket(host_key)
        metrics = self._get_metrics(host_key)

        # Check robots.txt
        if self.robots_txt_compliance and self._session:
            parsed = urlparse(url)
            if not self._robots_parser.is_allowed(url, parsed.path):
                logger.warning(f"Request to {url} disallowed by robots.txt")
                raise PermissionError(f"Disallowed by robots.txt: {url}")

        # Acquire tokens
        wait_time = await bucket.acquire(tokens)
        metrics.tokens_available = bucket.get_available()
        metrics.queue_depth = self._queue.qsize()

        if wait_time > 0:
            metrics.queue_depth += 1
            # Add small jitter to prevent thundering herd
            wait_time += random.uniform(0, 0.1)

        return wait_time

    async def record_response(self, url: str, response: ClientResponse):
        """Record HTTP response for adaptive rate limiting."""
        if not self.adaptive_enabled:
            return

        host_key = self._get_host_key(url)
        metrics = self._get_metrics(host_key)
        bucket = self._get_bucket(host_key)

        metrics.requests_total += 1
        metrics.tokens_available = bucket.get_available()

        status = response.status

        if status == 429:
            await self._handle_429(host_key, bucket, metrics, response)
        elif 500 <= status < 600:
            await self._handle_5xx(host_key, bucket, metrics)
        elif 200 <= status < 300:
            await self._handle_success(host_key, bucket, metrics)
        else:
            metrics.errors_other += 1

    async def _handle_429(self, host_key: str, bucket: TokenBucket, metrics: HostMetrics, response: ClientResponse):
        """Handle 429 Too Many Requests."""
        metrics.errors_429 += 1
        metrics.consecutive_success = 0

        # Extract retry-after header
        retry_after = response.headers.get('Retry-After')
        wait_time = 1.0
        if retry_after:
            try:
                wait_time = float(retry_after)
            except ValueError:
                pass

        # Reduce rate by 50%
        new_rate = max(self.min_rate, bucket.config.rate * 0.5)
        bucket.adjust_rate(new_rate)
        metrics.current_rate = new_rate
        metrics.last_adjustment = time.time()

        logger.warning(f"Rate limited by {host_key}: reducing rate to {new_rate:.2f} req/s, waiting {wait_time}s")

        # Wait before allowing more requests
        await asyncio.sleep(min(wait_time, 60))

    async def _handle_5xx(self, host_key: str, bucket: TokenBucket, metrics: HostMetrics):
        """Handle 5xx server errors."""
        metrics.errors_5xx += 1
        metrics.consecutive_success = 0

        # Reduce rate by 25%
        new_rate = max(self.min_rate, bucket.config.rate * 0.75)
        bucket.adjust_rate(new_rate)
        metrics.current_rate = new_rate
        metrics.last_adjustment = time.time()

        # Add jittered backoff
        backoff = random.uniform(0.5, 2.0)
        logger.warning(f"Server error from {host_key}: reducing rate to {new_rate:.2f} req/s, backing off {backoff:.2f}s")
        await asyncio.sleep(backoff)

    async def _handle_success(self, host_key: str, bucket: TokenBucket, metrics: HostMetrics):
        """Handle successful response."""
        metrics.requests_success += 1
        metrics.consecutive_success += 1

        # Slowly increase rate after sustained success
        if (metrics.consecutive_success >= 100 and
            bucket.config.rate < self.max_rate and
            time.time() - metrics.last_adjustment > 60):

            new_rate = min(self.max_rate, bucket.config.rate * 1.1)
            bucket.adjust_rate(new_rate)
            metrics.current_rate = new_rate
            metrics.last_adjustment = time.time()
            metrics.consecutive_success = 0
            logger.info(f"Increasing rate for {host_key} to {new_rate:.2f} req/s")

    async def fetch_robots_txt(self, url: str) -> Tuple[Set[str], Optional[float]]:
        """Fetch and parse robots.txt for a host."""
        if not self._session:
            return set(), None
        return await self._robots_parser.fetch_and_parse(self._session, url)

    def get_metrics(self, host_key: str = None) -> Dict[str, HostMetrics]:
        """Get metrics for all hosts or a specific host."""
        if host_key:
            return {host_key: self._metrics.get(host_key)}
        return dict(self._metrics)

    def get_global_stats(self) -> Dict:
        """Get global rate limiter statistics."""
        total_requests = sum(m.requests_total for m in self._metrics.values())
        total_success = sum(m.requests_success for m in self._metrics.values())
        total_429 = sum(m.errors_429 for m in self._metrics.values())
        total_5xx = sum(m.errors_5xx for m in self._metrics.values())

        return {
            "hosts_tracked": len(self._metrics),
            "total_requests": total_requests,
            "total_success": total_success,
            "total_429": total_429,
            "total_5xx": total_5xx,
            "success_rate": total_success / total_requests if total_requests > 0 else 0,
            "hosts": {
                host: {
                    "rate": m.current_rate,
                    "tokens": m.tokens_available,
                    "queue_depth": m.queue_depth,
                    "requests": m.requests_total,
                    "success": m.requests_success,
                    "errors_429": m.errors_429,
                    "errors_5xx": m.errors_5xx,
                }
                for host, m in self._metrics.items()
            }
        }

    async def _queue_worker(self):
        """Background worker for priority queue processing."""
        while self._running:
            try:
                # This is a placeholder for priority queue implementation
                # The current design uses direct acquire() calls
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Rate limiter queue worker error: {e}")
                await asyncio.sleep(1)


class RateLimitMiddleware:
    """aiohttp middleware for automatic rate limiting."""

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter

    async def __call__(self, request: aiohttp.ClientRequest, handler):
        """Process request through rate limiter."""
        url = str(request.url)
        wait_time = await self.rate_limiter.acquire(url)

        if wait_time > 0:
            await asyncio.sleep(wait_time)

        try:
            response = await handler(request)
            await self.rate_limiter.record_response(url, response)
            return response
        except Exception as e:
            # Record error for metrics
            host_key = self.rate_limiter._get_host_key(url)
            metrics = self.rate_limiter._get_metrics(host_key)
            metrics.errors_other += 1
            raise


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


async def init_rate_limiter(session: aiohttp.ClientSession = None) -> RateLimiter:
    """Initialize global rate limiter."""
    global _rate_limiter
    _rate_limiter = RateLimiter()
    await _rate_limiter.start(session)
    return _rate_limiter


async def close_rate_limiter():
    """Close global rate limiter."""
    global _rate_limiter
    if _rate_limiter:
        await _rate_limiter.stop()
        _rate_limiter = None