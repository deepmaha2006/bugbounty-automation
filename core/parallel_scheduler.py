"""
Parallel scan module scheduler for HydraX.

Runs scan modules concurrently with configurable concurrency (2–8 workers).
Each module transitions through QUEUED → RUNNING → DONE / FAILED and emits
real-time status events to the UI event queue.

Event format emitted to the queue:
  ("module_status", key, status, elapsed_secs, findings_count)
      status: "queued" | "running" | "done" | "failed"

Usage:
    scheduler = ParallelScanScheduler(
        modules=[("sqli", "SQLi", run_sqli), ("xss", "XSS", run_xss), ...],
        target="https://example.com",
        emit=event_queue.put_nowait,
        stop_event=threading.Event(),
        max_workers=4,
    )
    scheduler.run()   # blocks until all modules complete or stop fires
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple


class ModuleDef(NamedTuple):
    """Definition of a single scan module."""
    key: str                    # chip key, e.g. "sqli"
    label: str                  # display name, e.g. "SQLi"
    run: Callable               # run(target: str, stop: threading.Event) -> List[dict]


class ParallelScanScheduler:
    """
    Runs scan modules in a ThreadPoolExecutor with configurable max_workers.

    Emits ("module_status", key, status, elapsed, findings_count) events so
    the UI can update per-chip state in real time without blocking the main thread.
    """

    MIN_WORKERS = 2
    MAX_WORKERS = 8

    def __init__(
        self,
        modules: List[ModuleDef],
        target: str,
        emit: Callable,
        stop_event: Optional[threading.Event] = None,
        max_workers: int = 4,
    ) -> None:
        self._modules = modules
        self._target = target
        self._emit = emit
        self._stop = stop_event or threading.Event()
        self._max_workers = max(
            self.MIN_WORKERS, min(self.MAX_WORKERS, max_workers)
        )
        # Per-module tracking
        self._start_times: Dict[str, float] = {}
        self._results: Dict[str, List[dict]] = {}
        self._errors: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        """
        Submit all modules to the thread pool and block until all finish.
        Returns a summary dict {key: {"findings": [...], "error": str|None}}.
        """
        # Mark everything as queued first
        for m in self._modules:
            self._emit_status(m.key, "queued", 0.0, 0)

        with ThreadPoolExecutor(
            max_workers=self._max_workers,
            thread_name_prefix="hydrax-scan",
        ) as pool:
            future_map: Dict[Future, ModuleDef] = {
                pool.submit(self._run_module, m): m
                for m in self._modules
            }
            for future in as_completed(future_map):
                # Results are handled inside _run_module via callbacks;
                # exceptions that escaped the wrapper are swallowed here
                # (they were already emitted as "failed" events).
                _ = future.result() if not future.cancelled() else None

        return {
            m.key: {
                "findings": self._results.get(m.key, []),
                "error": self._errors.get(m.key),
            }
            for m in self._modules
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_module(self, module: ModuleDef) -> None:
        """Worker target: wraps a module callable with status bookkeeping."""
        if self._stop.is_set():
            self._emit_status(module.key, "failed", 0.0, 0, "stopped before start")
            return

        start = time.monotonic()
        self._start_times[module.key] = start
        self._emit_status(module.key, "running", 0.0, 0)

        try:
            findings: List[dict] = module.run(self._target, self._stop)
            elapsed = time.monotonic() - start
            self._results[module.key] = findings or []
            self._emit_status(module.key, "done", elapsed, len(findings or []))
        except Exception as exc:
            elapsed = time.monotonic() - start
            err = str(exc)
            self._errors[module.key] = err
            self._emit_status(module.key, "failed", elapsed, 0, err)

    def _emit_status(
        self,
        key: str,
        status: str,
        elapsed: float,
        findings: int,
        error: str = "",
    ) -> None:
        try:
            self._emit(("module_status", key, status, elapsed, findings, error))
        except Exception:
            pass
