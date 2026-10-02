"""P2-3 regression tests — brute-force rate limiting for login/register.

Covers: failed attempts are counted; the 5-attempt threshold is enforced;
a successful login resets the counter; different IPs are independent;
different usernames are independent; state expires after the window;
existing successful login/register flows keep working; concurrent requests
cannot race past the configured limit.

Hermetic: in-memory AuthLimiter + FakeDB-backed TestClient, local only.
"""
import os
import threading
import time

from starlette.testclient import TestClient

from webapp import config, security
from webapp.main import app
from webapp.routers.auth import login_limiter, register_limiter
from webapp.services.auth_limiter import AuthLimiter

RATE_MSG = "Too many attempts. Please try again later."


class _Clock:
    """Deterministic time: tests advance it instead of sleeping."""

    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def _make(now, max_attempts=5, window_seconds=900, max_keys=10_000):
    return AuthLimiter(max_attempts=max_attempts,
                       window_seconds=window_seconds,
                       max_keys=max_keys, now=now)


def _attempt(limiter, ok, *key):
    """One full attempt through the gate: ok=True is a successful auth."""
    with limiter.guard(*key) as gate:
        if not gate.allowed():
            return "blocked"
        if ok:
            gate.success()
            return "success"
        gate.fail()
        return "failed"


# ---------------------------------------------------------------------------
# Unit tests — deterministic injected clock
# ---------------------------------------------------------------------------
class TestFailedAttemptsCounted:
    def test_failures_are_counted_and_threshold_enforced(self):
        clock = _Clock(0)
        limiter = _make(clock)
        for i in range(5):
            assert _attempt(limiter, False, "alice", "10.0.0.1") == "failed"
        assert _attempt(limiter, False, "alice", "10.0.0.1") == "blocked"
        # Even a correct credential is rejected while the key is blocked.
        assert _attempt(limiter, True, "alice", "10.0.0.1") == "blocked"

    def test_successful_login_resets_the_counter(self):
        clock = _Clock(0)
        limiter = _make(clock)
        for _ in range(3):
            assert _attempt(limiter, False, "bob", "10.0.0.1") == "failed"
        assert _attempt(limiter, True, "bob", "10.0.0.1") == "success"
        for _ in range(3):
            assert _attempt(limiter, False, "bob", "10.0.0.1") == "failed"
        assert _attempt(limiter, True, "bob", "10.0.0.1") == "success"

    def test_different_ips_are_independently_limited(self):
        clock = _Clock(0)
        limiter = _make(clock)
        for _ in range(5):
            assert _attempt(limiter, False, "carol", "1.1.1.1") == "failed"
        assert _attempt(limiter, False, "carol", "1.1.1.1") == "blocked"
        # Same username from a different source is not throttled yet.
        for _ in range(3):
            assert _attempt(limiter, False, "carol", "2.2.2.2") == "failed"
        assert _attempt(limiter, False, "carol", "2.2.2.2") == "failed"
        assert _attempt(limiter, True, "carol", "2.2.2.2") == "success"

    def test_different_usernames_are_independently_limited(self):
        clock = _Clock(0)
        limiter = _make(clock)
        for _ in range(5):
            assert _attempt(limiter, False, "dave", "10.0.0.1") == "failed"
        assert _attempt(limiter, False, "dave", "10.0.0.1") == "blocked"
        assert _attempt(limiter, False, "erin", "10.0.0.1") == "failed"
        assert _attempt(limiter, True, "erin", "10.0.0.1") == "success"

    def test_state_expires_after_the_window(self):
        clock = _Clock(0)
        limiter = _make(clock, window_seconds=900)
        for _ in range(5):
            assert _attempt(limiter, False, "frank", "10.0.0.1") == "failed"
        assert _attempt(limiter, False, "frank", "10.0.0.1") == "blocked"
        clock.advance(900.5)  # window elapsed
        assert _attempt(limiter, False, "frank", "10.0.0.1") == "failed"
        assert _attempt(limiter, True, "frank", "10.0.0.1") == "success"

    def test_rate_limit_state_is_bounded(self):
        clock = _Clock(0)
        limiter = _make(clock, max_keys=3)
        for i in range(30):
            assert _attempt(limiter, False, f"user{i}", f"ip{i}") == "failed"
        with limiter._lock:
            assert len(limiter._data) <= 3, "attacker inputs must not grow memory"
            assert len(limiter._locks) <= 3, "lock pool must stay bounded"
        # The oldest key was evicted, not just capped at the newest end.
        assert ("user0", "ip0") not in limiter._data
        assert ("user29", "ip29") in limiter._data

    def test_concurrent_requests_cannot_race_past_the_limit(self):
        clock = _Clock(0)
        limiter = _make(clock, max_attempts=5)
        results, rlock = [], threading.Lock()

        def worker():
            with limiter.guard("alice", "10.0.0.1") as gate:
                if not gate.allowed():
                    with rlock:
                        results.append("blocked")
                    return
                # widen any possible race window while inside the gate
                time.sleep(0.002)
                gate.fail()
                with rlock:
                    results.append("failed")

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        # Per-key serialization means exactly max_attempts failures are
        # recorded; every other concurrent attempt is turned away.
        assert results.count("failed") == 5, results
        assert results.count("blocked") == 15, results


# ---------------------------------------------------------------------------
# Route-level tests — real /login and /register through the ASGI app
# ---------------------------------------------------------------------------
class TestLoginRateLimitRoute:
    def _cli(self, ip):
        return TestClient(app, client=(ip, 50000))

    def _make_user(self, fake, username, password="passw0rd1234"):
        fake.create_user(username, f"{username}@hydrax.local",
                         security.hash_password(password))

    def test_failed_logins_are_counted_and_threshold_enforced(self, fake):
        self._make_user(fake, "grace")
        c = self._cli("7.7.7.7")
        for i in range(5):
            r = c.post("/api/auth/login", json={
                "username": "grace", "password": "wrong"})
            assert r.status_code == 401, (i, r.text)
        r = c.post("/api/auth/login", json={
            "username": "grace", "password": "wrong"})
        assert r.status_code == 429
        assert r.json()["detail"] == RATE_MSG
        assert r.headers.get("Retry-After") is not None
        # A correct password is rejected too, so the block is credential-agnostic.
        r = c.post("/api/auth/login", json={
            "username": "grace", "password": "passw0rd1234"})
        assert r.status_code == 429, r.text

    def test_successful_login_resets_counter(self, fake):
        self._make_user(fake, "harry")
        c = self._cli("8.8.8.8")
        for _ in range(3):
            assert c.post("/api/auth/login", json={
                "username": "harry", "password": "wrong"}).status_code == 401
        ok = c.post("/api/auth/login", json={
            "username": "harry", "password": "passw0rd1234"})
        assert ok.status_code == 200, ok.text
        for _ in range(3):
            assert c.post("/api/auth/login", json={
                "username": "harry", "password": "wrong"}).status_code == 401
        ok2 = c.post("/api/auth/login", json={
            "username": "harry", "password": "passw0rd1234"})
        assert ok2.status_code == 200, ok2.text

    def test_different_ips_are_independently_limited(self, fake):
        self._make_user(fake, "iris")
        a = self._cli("9.9.9.9")
        b = self._cli("10.1.1.1")
        for _ in range(5):
            assert a.post("/api/auth/login", json={
                "username": "iris", "password": "wrong"}).status_code == 401
        assert a.post("/api/auth/login", json={
            "username": "iris", "password": "wrong"}).status_code == 429
        # Different source: not throttled and can still log in.
        ok = b.post("/api/auth/login", json={
            "username": "iris", "password": "passw0rd1234"})
        assert ok.status_code == 200, ok.text
        assert login_limiter.allowed(("iris", "10.1.1.1"))

    def test_different_usernames_are_independently_limited(self, fake):
        self._make_user(fake, "jim")
        self._make_user(fake, "kim")
        c = self._cli("11.1.1.1")
        for _ in range(5):
            assert c.post("/api/auth/login", json={
                "username": "jim", "password": "wrong"}).status_code == 401
        assert c.post("/api/auth/login", json={
            "username": "jim", "password": "wrong"}).status_code == 429
        # kim is on a fresh counter for the same IP.
        ok = c.post("/api/auth/login", json={
            "username": "kim", "password": "passw0rd1234"})
        assert ok.status_code == 200, ok.text

    def test_rate_limit_expires_after_window(self, fake, monkeypatch):
        self._make_user(fake, "liam")
        c = self._cli("12.1.1.1")
        clock = _Clock(0)
        monkeypatch.setattr(login_limiter, "now", clock)
        for _ in range(5):
            assert c.post("/api/auth/login", json={
                "username": "liam", "password": "wrong"}).status_code == 401
        assert c.post("/api/auth/login", json={
            "username": "liam", "password": "wrong"}).status_code == 429
        clock.advance(config.RATE_LIMIT_WINDOW_SECONDS + 1)
        ok = c.post("/api/auth/login", json={
            "username": "liam", "password": "passw0rd1234"})
        assert ok.status_code == 200, ok.text

    def test_limiter_does_not_store_passwords(self, fake):
        self._make_user(fake, "mia")
        c = self._cli("13.1.1.1")
        c.post("/api/auth/login", json={
            "username": "mia", "password": "not-the-real-one"})
        # Only counts + window start live in the limiter — never credentials.
        with login_limiter._lock:
            entry = login_limiter._data.get(("mia", "13.1.1.1"))
            assert entry is not None and entry.count == 1
            stored = str(login_limiter._data)
        assert "not-the-real-one" not in stored


class TestRegisterRateLimitRoute:
    def test_register_attempts_are_throttled_per_ip(self, fake):
        # Seed one user so registration requires the signup token.
        fake.create_user("root", "root@hydrax.local",
                         security.hash_password("x"))
        c = TestClient(app, client=("20.0.0.1", 50000))
        payload = {"username": "user1", "email": "bad@hydrax.local",
                   "password": "passw0rd1234"}
        for i in range(config.RATE_LIMIT_REGISTER_MAX_ATTEMPTS):
            r = c.post("/api/auth/register", json=payload)
            assert r.status_code == 403, (i, r.text)
        # The attempt *after* the cap is uniformly rate limited.
        r = c.post("/api/auth/register", json=payload)
        assert r.status_code == 429
        assert r.json()["detail"] == RATE_MSG

    def test_legit_registration_still_works_after_other_ip_throttled(self,
                                                                     fake):
        fake.create_user("root", "root@hydrax.local",
                         security.hash_password("x"))
        bad = TestClient(app, client=("21.0.0.1", 50000))
        for _ in range(config.RATE_LIMIT_REGISTER_MAX_ATTEMPTS):
            bad.post("/api/auth/register", json={
                "username": "user1", "email": "bad@hydrax.local",
                "password": "passw0rd1234"})
        assert bad.post("/api/auth/register", json={
            "username": "user1", "email": "bad@hydrax.local",
            "password": "passw0rd1234"}).status_code == 429
        # A legitimate signup with the bootstrap token from another IP works.
        good = TestClient(app, client=("22.0.0.1", 50000))
        r = good.post("/api/auth/register", json={
            "username": "newborn",
            "email": f"{os.environ['HYDRAX_ADMIN_SIGNUP_TOKEN']}@hydrax.local",
            "password": "passw0rd1234"})
        assert r.status_code == 200, r.text
        assert fake.get_user_by_username("newborn") is not None


# ---------------------------------------------------------------------------
# Existing successful auth still works end-to-end
# ---------------------------------------------------------------------------
class TestExistingAuthStillWorks:
    def test_first_user_registers_and_reaches_me(self, fake, client):
        r = client.post("/api/auth/register", json={
            "username": "bootuser", "email": "bootuser@hydrax.local",
            "password": "passw0rd1234"})
        assert r.status_code == 200, r.text
        token = r.json()["access_token"]
        me = client.get("/api/auth/me",
                        headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200 and me.json()["username"] == "bootuser"

    def test_login_returns_valid_token(self, fake, client):
        r = client.post("/api/auth/register", json={
            "username": "loginuser", "email": "loginuser@hydrax.local",
            "password": "passw0rd1234"})
        assert r.status_code == 200, r.text
        # token signed by the configured secret decodes
        assert security.decode_token(r.json()["access_token"]) is not None
        lg = client.post("/api/auth/login", json={
            "username": "loginuser", "password": "passw0rd1234"})
        assert lg.status_code == 200, lg.text
        me = client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer " + lg.json()["access_token"]})
        assert me.status_code == 200