"""Shared scan lifecycle manager (P2-7).

Replaces the previous pattern of each scan service spawning its own unmanaged
daemon thread. A single in-process coordinator thread owns a FIFO queue of
pending scan jobs and dispatches them to worker threads, bounded by
``MAX_CONCURRENT_SCANS`` (default 3, env ``HYDRAX_MAX_CONCURRENT_SCANS``).

Design notes:
  * Pure in-process scheduler: no Redis / Celery / distributed queue.
  * ``submit()`` never blocks the caller (FastAPI request thread).
  * Each service keeps its own ``_run`` worker; the manager only schedules it
    and provides a safety net so a job can never be stranded as "running".
  * Duplicate execution of the same scan_id is rejected.
  * Cancellation is meaningful for *queued* jobs (removed before dispatch, DB
    set to ``cancelled``). Running jobs cannot be force-killed in Python, so
    ``cancel()`` returns ``False`` for them and leaves them untouched.
  * On process start, scans left ``running``/``queued`` by a previous process
    are moved to an honest terminal state (``error``, "interrupted") — never
    falsely marked completed.

The DB lifecycle is otherwise left exactly as the services implement it:
``create_scan`` inserts as ``queued``, the service ``_run`` flips to
``running`` at entry and to ``completed``/``error`` on success/failure.
"""
import threading
from collections import deque

from webapp import config, db
from webapp.services import events

QUEUED = "queued"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
CANCELLED = "cancelled"

_TERMINAL = {COMPLETED, FAILED, CANCELLED}
_DB_TERMINAL = {"completed", "error", "cancelled"}


class ScanJob:
    """A registered scan and its in-memory lifecycle state."""

    __slots__ = ("scan_id", "user_id", "scan_type", "fn", "args", "kwargs",
                 "state", "thread")

    def __init__(self, scan_id, user_id, scan_type, fn, args, kwargs):
        self.scan_id = scan_id
        self.user_id = user_id
        self.scan_type = scan_type
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.state = QUEUED
        self.thread = None


class ScanManager:
    """FIFO scan scheduler with a configurable concurrency limit."""

    def __init__(self, max_concurrent=None):
        if max_concurrent is None:
            max_concurrent = getattr(config, "MAX_CONCURRENT_SCANS", 3)
        self.max_concurrent = max(1, int(max_concurrent))
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._registry = {}      # scan_id -> ScanJob
        self._queue = deque()    # scan_ids, FIFO
        self._active = set()     # scan_ids currently dispatched
        self._shutdown = False
        self._coordinator = None
        self._recovered = False

    # ------------------------------------------------------------------
    # Startup / recovery
    # ------------------------------------------------------------------
    def start(self):
        """Idempotent startup: run one-time restart recovery, then ensure the
        coordinator thread is alive."""
        self.recover_interrupted()
        self._ensure_coordinator()

    def recover_interrupted(self):
        """Scans left 'running'/'queued' by a previous process must not be
        resumed or falsely marked successful. Land them in an honest terminal
        state (error / interrupted). Runs once per process."""
        with self._lock:
            if self._recovered:
                return
            self._recovered = True
        try:
            rows = db.list_interrupted_scans()
        except Exception:  # noqa: BLE001 — DB not reachable; already marked
            return
        for s in rows or []:
            if s.get("status") not in ("running", "queued"):
                continue
            try:
                db.update_scan(
                    s["id"], status="error", phase="Interrupted",
                    message="Scan interrupted by service restart (not resumed)",
                    finished_at=db._now())
            except Exception:  # noqa: BLE001
                pass
            events.emit(s["id"], {"type": "error",
                                  "text": "Scan interrupted by service restart (not resumed)"})

    def shutdown(self):
        """Signal the coordinator to stop and wait for it to exit.

        Pending queued jobs are not run. Joining here (bounded) prevents
        coordinator threads from a previous start()/reset() cycle from
        lingering and piling up — each has up to a 0.5s wait-loop tick before
        it notices ``_shutdown`` and exits.
        """
        coordinator = None
        with self._cond:
            self._shutdown = True
            self._cond.notify_all()
            coordinator = self._coordinator
        if (coordinator is not None and coordinator.is_alive()
                and coordinator is not threading.current_thread()):
            coordinator.join(timeout=2.0)

    def reset(self):
        """Drop all registry/queue/thread state (used by tests so no state
        bleeds between cases)."""
        self.shutdown()
        with self._lock:
            self._registry.clear()
            self._queue.clear()
            self._active.clear()
            self._coordinator = None
            self._recovered = False

    def states(self) -> dict:
        """Snapshot of scan_id -> state for introspection/tests."""
        with self._lock:
            return {sid: job.state for sid, job in self._registry.items()}

    def stats(self) -> dict:
        """Live queue-depth/concurrency snapshot for the observability
        endpoints (spec §22) — never stored, always computed from the real
        in-memory state at read time."""
        with self._lock:
            return {
                "queued": len(self._queue),
                "active": len(self._active),
                "max_concurrent": self.max_concurrent,
                "coordinator_alive": bool(self._coordinator and self._coordinator.is_alive()),
            }

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------
    def submit(self, scan_id, user_id, scan_type, fn, *args, **kwargs) -> bool:
        """Register a scan job for FIFO execution.

        Non-blocking — the caller (FastAPI request thread) returns immediately;
        the scan row is already on disk and its visible status is 'queued'
        until the coordinator assigns a worker slot.

        Returns ``False`` when the same scan_id is already pending/running or
        has already been executed this process (duplicate-execution guard).
        """
        self._ensure_coordinator()
        with self._cond:
            existing = self._registry.get(scan_id)
            if existing is not None:
                return False
            job = ScanJob(scan_id, user_id, scan_type, fn, args, kwargs)
            self._registry[scan_id] = job
            self._queue.append(scan_id)
            self._cond.notify_all()
            return True

    def cancel(self, scan_id) -> bool:
        """Cancel a *queued* scan deterministically.

        Queued: removed from the queue, DB moved to ``cancelled`` (terminal),
        never executed. Running/terminal/unknown: no-op returning ``False`` —
        we never force-kill a running Python thread, and the scan's DB state is
        left untouched.
        """
        with self._cond:
            job = self._registry.get(scan_id)
            if job is None or job.state != QUEUED:
                return False
            job.state = CANCELLED
            try:
                self._queue.remove(scan_id)
            except ValueError:
                pass
        try:
            db.update_scan(scan_id, status="cancelled", phase="Cancelled",
                           message="Scan cancelled by user", finished_at=db._now())
        except Exception:  # noqa: BLE001
            pass
        events.emit(scan_id, {"type": "cancelled", "text": "Scan cancelled by user"})
        with self._cond:
            self._cond.notify_all()
        return True

    # ------------------------------------------------------------------
    # Coordinator + workers
    # ------------------------------------------------------------------
    def _ensure_coordinator(self):
        with self._lock:
            if self._coordinator is not None and self._coordinator.is_alive():
                return
            self._shutdown = False
            self._coordinator = threading.Thread(
                target=self._coordinator_loop, daemon=True,
                name="hydrax-scan-coordinator")
            self._coordinator.start()

    def _coordinator_loop(self):
        """Dispatch FIFO; never exceed ``max_concurrent`` active workers."""
        while True:
            job = None
            with self._cond:
                while not self._shutdown:
                    if self._queue and len(self._active) < self.max_concurrent:
                        scan_id = self._queue.popleft()
                        job = self._registry.get(scan_id)
                        if job is None or job.state != QUEUED:
                            continue  # cancelled/removed — skip
                        self._active.add(scan_id)
                        job.state = RUNNING
                        break
                    self._cond.wait(timeout=0.5)
                if self._shutdown:
                    break  # exit without touching the remaining queue
            if job is None:
                continue
            worker = threading.Thread(
                target=self._run_job, args=(job,), daemon=True,
                name=f"hydrax-scan-{job.scan_id}")
            job.thread = worker
            worker.start()

    def _run_job(self, job):
        """Run the worker with a safety net so a job is never stranded.

        The service's own ``_run`` owns the normal DB lifecycle
        (running -> completed/error). If it raises, or returns without a
        terminal DB status, this wrapper lands the scan in ``error``.
        """
        try:
            job.fn(*job.args, **job.kwargs)
        except Exception as exc:  # noqa: BLE001
            try:
                db.update_scan(job.scan_id, status="error", phase="Error",
                               message=f"Scan worker failed: {exc}",
                               finished_at=db._now())
            except Exception:  # noqa: BLE001
                pass
            job.state = FAILED
        else:
            try:
                status = db.get_scan_status(job.scan_id) or ""
                if status not in _DB_TERMINAL:
                    db.update_scan(job.scan_id, status="error", phase="Error",
                                   message="Scan worker exited without a terminal status",
                                   finished_at=db._now())
                    job.state = FAILED
                else:
                    job.state = COMPLETED if status == "completed" else FAILED
            except Exception:  # noqa: BLE001
                job.state = FAILED
        finally:
            with self._cond:
                self._active.discard(job.scan_id)
                job.thread = None
                self._cond.notify_all()
            # Safety-net cleanup for the SSE event bus (webapp/services/events.py).
            # The /events route drops its own bus entry once it has delivered the
            # terminal event to a connected client, but not every scan has a
            # listener. Give any still-polling SSE consumer a grace window to
            # drain the final event(s) before reclaiming the memory.
            cleanup_timer = threading.Timer(10.0, events.drop, args=(job.scan_id,))
            cleanup_timer.daemon = True
            cleanup_timer.start()


# --- Module-level singleton + delegate functions ---------------------------
manager = ScanManager()


def start() -> None:
    manager.start()


def reset() -> None:
    manager.reset()


def shutdown() -> None:
    manager.shutdown()


def submit(scan_id, user_id, scan_type, fn, *args, **kwargs) -> bool:
    return manager.submit(scan_id, user_id, scan_type, fn, *args, **kwargs)


def cancel(scan_id) -> bool:
    return manager.cancel(scan_id)


def states() -> dict:
    return manager.states()


def stats() -> dict:
    return manager.stats()