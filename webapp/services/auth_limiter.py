"""In-memory, bounded brute-force rate limiter for auth endpoints (P2-3).

Design notes:
  * Keyed by whatever identity the routes hand in — ``(username, client_ip)``
    for login, ``(client_ip,)`` for registration.
  * Strict per-key serialization: the whole "check -> verify -> record/reset"
    sequence for one key runs under a per-key lock, so concurrent requests can
    never race past the configured failure limit. The per-key lock pool is
    reference-counted and LRU-capped, so it cannot grow without bound either.
  * The limiter stores only a failure count and the window start — never
    passwords, hashes, or tokens.
  * ``now`` is injectable so tests are deterministic without sleeping.
"""
import threading
import time
from collections import OrderedDict


class _Entry:
    __slots__ = ("count", "start")

    def __init__(self, count: int, start: float):
        self.count = count
        self.start = start


class _Slot:
    """A per-key lock with a reference count so idle slots can be evicted."""

    __slots__ = ("lock", "refs")

    def __init__(self):
        self.lock = threading.Lock()
        self.refs = 0


class AuthLimiter:
    def __init__(self, max_attempts, window_seconds, max_keys=10_000,
                 now=None):
        self.max_attempts = max(1, int(max_attempts))
        self.window_seconds = max(1, int(window_seconds))
        self.max_keys = max(1, int(max_keys))
        self.now = now if now is not None else time.time
        self._lock = threading.Lock()   # guards both tables below
        self._data = OrderedDict()      # key -> _Entry (access-ordered)
        self._locks = OrderedDict()     # key -> _Slot (access-ordered)

    # ------------------------------------------------------------------
    # State introspection / reset (tests + admin)
    # ------------------------------------------------------------------
    def reset(self):
        """Drop all tracked state (used between tests so no state bleeds)."""
        with self._lock:
            self._data.clear()
            self._locks.clear()

    # ------------------------------------------------------------------
    # Per-key serialization
    # ------------------------------------------------------------------
    def guard(self, *parts):
        """Context manager serializing one auth attempt for this key.

        The returned gate object re-checks the limiter state fresh on every
        call, so the route's check -> verify -> record/reset sequence for a
        single key is atomic across threads.
        """
        return _Gate(self, self._key(parts))

    @staticmethod
    def _key(parts):
        return tuple(parts)

    def _lock_for(self, key):
        """Return the per-key lock, keeping the pool bounded."""
        with self._lock:
            slot = self._locks.get(key)
            if slot is None:
                self._evict_unused_slots()
                slot = self._locks[key] = _Slot()
            else:
                self._locks.move_to_end(key)
            slot.refs += 1
            return slot.lock

    def _release_lock(self, key, lock):
        lock.release()
        with self._lock:
            slot = self._locks.get(key)
            if slot is not None and slot.lock is lock:
                slot.refs -= 1
                if slot.refs <= 0:
                    self._locks.pop(key, None)

    def _evict_unused_slots(self):
        while len(self._locks) >= self.max_keys:
            victim = None
            for k in list(self._locks):
                if self._locks[k].refs == 0:
                    victim = k
                    break
            if victim is None:      # every slot is mid-attempt; let it run
                return
            self._locks.pop(victim)

    # ------------------------------------------------------------------
    # Limiter state (call while holding the per-key lock)
    # ------------------------------------------------------------------
    def _entry(self, key):
        now = self.now()
        entry = self._data.get(key)
        if entry is None or now - entry.start >= self.window_seconds:
            entry = _Entry(0, now)          # expired window -> fresh state
        return entry

    def allowed(self, key) -> bool:
        with self._lock:
            return self._entry(key).count < self.max_attempts

    def fail(self, key) -> int:
        """Record one failed attempt; returns the new failure count."""
        with self._lock:
            entry = self._entry(key)     # expired window already reset
            entry.count += 1             # keeps the original window start
            self._data[key] = entry
            self._data.move_to_end(key)
            while len(self._data) >= self.max_keys:
                self._data.popitem(last=False)
            return entry.count

    def success(self, key) -> None:
        """Reset the failure counter after a successful authentication."""
        with self._lock:
            self._data.pop(key, None)


class _Gate:
    """Per-key view of an AuthLimiter, held for the duration of one attempt."""

    def __init__(self, limiter, key):
        self._limiter = limiter
        self._key = key
        self._lock = None

    def __enter__(self):
        self._lock = self._limiter._lock_for(self._key)
        self._lock.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._limiter._release_lock(self._key, self._lock)
        return False

    def allowed(self) -> bool:
        return self._limiter.allowed(self._key)

    def fail(self) -> int:
        return self._limiter.fail(self._key)

    def success(self) -> None:
        self._limiter.success(self._key)