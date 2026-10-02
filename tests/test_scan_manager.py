"""P2-7 regression tests — shared ScanManager (scan scheduling/lifecycle).

Covers: FIFO queued execution, max-concurrency enforcement, parallel runs up
to the limit, no duplicate execution, worker-failure -> terminal state,
queued-scan cancellation, running-scan cancel is a no-op, restart recovery
(never falsely marks incomplete scans successful), and the web-scan route
submitting through the manager. All hermetic: FakeDB, in-process stub runners,
no scanners/tools, no production DB, no public targets.
"""
import threading
import time

from webapp.services.scan_manager import (COMPLETED, FAILED, RUNNING,
                                          QUEUED, ScanManager)


def _await(predicate, timeout=3.0, interval=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


class TestFifoQueuedExecution:
    def test_fifo_start_order(self, fake):
        mgr = ScanManager(max_concurrent=1)
        mgr.start()
        order, release = [], {1: threading.Event(), 2: threading.Event(),
                              3: threading.Event()}

        def runner(sid):
            order.append(sid)
            release[sid].wait(timeout=5)

        for sid in (1, 2, 3):
            assert mgr.submit(sid, 1, "web", runner, sid) is True

        assert _await(lambda: order == [1]), "job 2 must not start before job 1"
        release[1].set()
        assert _await(lambda: order == [1, 2])
        release[2].set()
        assert _await(lambda: order == [1, 2, 3])
        release[3].set()
        assert _await(lambda: all(s in (COMPLETED, FAILED)
                                  for s in mgr.states().values()))


class TestConcurrency:
    def test_max_concurrency_enforced_and_parallel_up_to_limit(self, fake):
        mgr = ScanManager(max_concurrent=2)
        mgr.start()
        lock = threading.Lock()
        active, peak, started, finished = [0], [0], [0], [0]
        release = threading.Event()

        def runner(_sid):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
                started[0] += 1
            release.wait(timeout=10)
            with lock:
                active[0] -= 1
                finished[0] += 1

        for sid in (1, 2, 3, 4):
            assert mgr.submit(sid, 1, "web", runner, sid) is True

        # With max=2 the first two jobs run together; the rest stay queued.
        assert _await(lambda: started[0] == 2), "two should start immediately"
        assert peak[0] == 2, "never exceed the configured limit"

        release.set()
        assert _await(lambda: finished[0] == 4), "all four complete"
        assert peak[0] == 2, "concurrency limit held for the whole run"

    def test_parallel_runs_are_concurrent(self, fake):
        mgr = ScanManager(max_concurrent=2)
        mgr.start()
        arrived, lock, release = [0], threading.Lock(), threading.Event()

        def runner(_sid):
            with lock:
                arrived[0] += 1
            release.wait(timeout=5)

        assert mgr.submit(1, 1, "web", runner, 1) is True
        assert mgr.submit(2, 1, "web", runner, 2) is True
        # max_concurrent=2 must let TWO workers run at once: both registry
        # entries sit RUNNING and both runners are resident before release.
        assert _await(lambda: (len([s for s in mgr.states().values()
                                    if s == RUNNING]) == 2 and arrived[0] == 2)), \
            "two workers must be concurrently resident in the runner"
        release.set()
        assert _await(lambda: all(s in (COMPLETED, FAILED)
                                  for s in mgr.states().values()))


class TestNoDuplicateExecution:
    def test_same_scan_id_submitted_twice_runs_once(self, fake):
        mgr = ScanManager(max_concurrent=1)
        mgr.start()
        calls = []

        def runner(sid):
            calls.append(sid)
            time.sleep(0.02)

        assert mgr.submit(7, 1, "web", runner, 7) is True
        assert mgr.submit(7, 1, "web", runner, 7) is False  # duplicate rejected
        assert mgr.submit(8, 1, "web", runner, 8) is True
        assert _await(lambda: all(s in (COMPLETED, FAILED)
                                  for s in mgr.states().values()))
        assert calls.count(7) == 1, "scan 7 must execute exactly once"


class TestWorkerFailureTerminal:
    def test_worker_exception_transitions_to_error(self, fake):
        mgr = ScanManager(max_concurrent=1)
        mgr.start()
        sid = fake.create_scan(1, None, "web", ["xss"])

        def boom():
            raise RuntimeError("simulated worker crash")

        mgr.submit(sid, 1, "web", boom)
        assert _await(lambda: fake.get_scan(sid)["status"] == "error")
        assert mgr.states()[sid] == FAILED

    def test_worker_returning_without_terminal_status_lands_in_error(self, fake):
        mgr = ScanManager(max_concurrent=1)
        mgr.start()
        sid = fake.create_scan(1, None, "web", ["xss"])

        def forgetful():
            fake.update_scan(sid, status="running")  # leaves it running

        mgr.submit(sid, 1, "web", forgetful)
        # Safety net: never stranded 'running' forever.
        assert _await(lambda: fake.get_scan(sid)["status"] == "error")
        assert "terminal" in fake.get_scan(sid)["message"]


class TestCancellation:
    def test_queued_scan_cancelled_never_runs(self, fake):
        mgr = ScanManager(max_concurrent=1)
        mgr.start()
        a = fake.create_scan(1, None, "web", [])
        b = fake.create_scan(1, None, "web", [])
        release_a = threading.Event()
        ran_b = []

        def run_a():
            release_a.wait(timeout=5)

        def run_b():
            ran_b.append(1)

        mgr.submit(a, 1, "web", run_a)
        mgr.submit(b, 1, "web", run_b)
        assert _await(lambda: mgr.states().get(a) == RUNNING)
        assert _await(lambda: mgr.states().get(b) == QUEUED)

        assert mgr.cancel(b) is True
        assert fake.get_scan(b)["status"] == "cancelled"
        assert mgr.states()[b] == "cancelled"

        release_a.set()
        assert _await(lambda: mgr.states().get(a) != RUNNING)
        assert not ran_b, "cancelled scan must never execute"

    def test_cancel_running_is_noop_and_leaves_db_untouched(self, fake):
        mgr = ScanManager(max_concurrent=1)
        mgr.start()
        sid = fake.create_scan(1, None, "web", [])
        release = threading.Event()

        def run():
            fake.update_scan(sid, status="running")
            release.wait(timeout=5)
            fake.update_scan(sid, status="completed", phase="Complete",
                             progress=1.0)

        mgr.submit(sid, 1, "web", run)
        assert _await(lambda: fake.get_scan(sid)["status"] == "running")

        assert mgr.cancel(sid) is False, "running scan is not cancellable"
        assert fake.get_scan(sid)["status"] == "running", "cancel must not touch DB"

        release.set()
        assert _await(lambda: fake.get_scan(sid)["status"] == "completed")

    def test_cancel_unknown_scan_returns_false(self, fake):
        mgr = ScanManager(max_concurrent=1)
        assert mgr.cancel(999) is False


class TestSubmissionNonBlocking:
    def test_submit_returns_immediately_with_queued_row(self, fake):
        mgr = ScanManager(max_concurrent=1)
        mgr.start()
        sid = fake.create_scan(1, None, "web", [])
        release = threading.Event()

        def run():
            release.wait(timeout=5)

        t0 = time.monotonic()
        ok = mgr.submit(sid, 1, "web", run)
        assert ok is True
        assert time.monotonic() - t0 < 1.0, "submit() must not block"
        assert fake.get_scan(sid)["status"] == QUEUED

        release.set()
        assert _await(lambda: fake.get_scan(sid)["status"] != QUEUED)


class TestRestartRecovery:
    def test_stale_running_and_queued_scans_interrupted_never_completed(self, fake):
        mgr = ScanManager(max_concurrent=1)  # NOT started — run recovery alone
        running = fake.create_scan(1, None, "web", ["xss"])
        queued = fake.create_scan(1, None, "system", ["nmap"])
        finished = fake.create_scan(1, None, "web", ["xss"])
        fake.update_scan(running, status="running")
        fake.update_scan(finished, status="completed")

        mgr.recover_interrupted()

        assert fake.get_scan(running)["status"] == "error"
        assert fake.get_scan(queued)["status"] == "error"   # never-started, interrupted
        assert fake.get_scan(finished)["status"] == "completed"  # untouched
        assert "restart" in fake.get_scan(running)["message"]
        assert fake.get_scan(running)["finished_at"] is not None


class TestWebScanRouteThroughManager:
    def test_web_scan_route_submits_via_manager_and_completes(self, fake, client,
                                                               admin_headers,
                                                               monkeypatch):
        url = "http://127.0.0.1:8000/app"
        tid = fake.add_target(url, verification_method="dns_txt")
        fake.update_target_verification(tid, "verified")
        ran = {}

        def stub_run(scan_id, user_id, target, target_id, keys):
            ran["scan_id"] = scan_id
            fake.update_scan(scan_id, status="completed", phase="Complete",
                             progress=1.0, message="stub done",
                             stats={"total_findings": 0, "security_score": 100},
                             finished_at=fake._now())

        monkeypatch.setattr("webapp.services.web_scan_service._run", stub_run)
        r = client.post("/api/scans/web", headers=admin_headers, json={
            "target": url, "vuln_types": ["xss"], "scope_authorized": True,
        })
        assert r.status_code == 200, r.text
        sid = r.json()["id"]
        # Dispatch is asynchronous (coordinator thread) — the worker may not
        # have run yet the instant the HTTP response comes back, so await it
        # rather than asserting it synchronously.
        assert _await(lambda: ran.get("scan_id") == sid), \
            "worker must receive the created scan id"
        assert _await(lambda: fake.get_scan(sid)["status"] == "completed")
        d = client.get(f"/api/scans/{sid}", headers=admin_headers)
        assert d.status_code == 200, d.text
        assert d.json()["status"] == "completed"
        me = client.get("/api/auth/me", headers=admin_headers).json()
        assert d.json()["user_id"] == me["id"]