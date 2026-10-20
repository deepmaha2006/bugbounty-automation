"""
Threaded scan engine — delegates all scan orchestration to AgentSupervisor.

The ScanEngine starts a background thread, hands control to AgentSupervisor,
streams progress events to the UI queue, and saves the finished ScanReport.
The circuit breaker and exponential-backoff helpers are used by the safe HTTP
request wrapper so individual scanners get automatic retry + host isolation.
"""

import threading
import queue
import datetime
import traceback
import time
from typing import Dict, List, Optional, Union
from enum import Enum

from config import settings
from config.scope import ScopeConfig
from config.profiles import ScanProfile, load_profile
from core.models import ScanResult, ScanReport
from core.scan_context import ScanAborted, clear_scan_context
from utils.http_client import HTTPClient


class CircuitBreakerState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """Circuit breaker pattern implementation for handling repeated failures"""

    def __init__(self, failure_threshold=5, timeout=60, expected_exception=Exception):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitBreakerState.CLOSED

    def call(self, func, *args, **kwargs):
        if self.state == CircuitBreakerState.OPEN:
            if self.last_failure_time and time.time() - self.last_failure_time > self.timeout:
                self.state = CircuitBreakerState.HALF_OPEN
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = func(*args, **kwargs)
            self.on_success()
            return result
        except self.expected_exception as e:
            self.on_failure()
            raise e

    def on_success(self):
        self.failure_count = 0
        self.state = CircuitBreakerState.CLOSED

    def on_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN


class ScanEngine:
    """Runs a set of scanners against a target URL in a background thread with enhanced error handling."""

    # Event message types pushed to the callback queue:
    #   ("status", text)                     -> generic status line
    #   ("log", text, tag)                   -> console log line
    #   ("progress", float)                  -> overall progress 0..1
    #   ("phase", text)                      -> UI banner text
    #   ("discovery", summary_dict)          -> discovery phase summary
    #   ("error", text, traceback_str)       -> error occurred
    #   ("recovery", text)                   -> recovery action taken
    #   ("circuit_breaker", state)           -> circuit breaker status change
    #   ("scan_complete", target, report_dict) -> scan finished
    #   ("scanner_update", scanner_key, status, findings_count) -> per-scanner progress

    def __init__(self, event_queue: queue.Queue):
        """Initialize the scan engine with event queue for communication."""
        self.events = event_queue
        self.scan_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.report_store = None  # Lazy init

        # Error handling and recovery components
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}  # Per-host circuit breakers
        self.retry_counts: Dict[str, int] = {}  # Track retry attempts per target
        self.max_retries = 3
        self.base_retry_delay = 1.0  # Base delay in seconds for exponential backoff
        self.max_retry_delay = 30.0  # Maximum delay between retries

        # Scan state tracking
        self.is_scanning = False
        self.current_target = None
        self.scan_start_time = None
        self.last_heartbeat = None

        # Performance monitoring
        self.request_stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'retried': 0
        }

    def _get_report_store(self):
        """Lazy-init report store to avoid circular imports."""
        if self.report_store is None:
            from core.storage import ReportStore
            self.report_store = ReportStore()
        return self.report_store

    def apply_settings(self, new_settings: Dict) -> None:
        """Apply Settings-page changes to future scans.

        This didn't exist before — ui/main_window.py's apply_settings()
        called self.scan_engine.apply_settings(settings) inside a bare
        `except AttributeError: pass`, so every Settings save silently did
        nothing. Mutates the live config.settings module (not any
        ScanEngine-instance-local state), since HTTPClient, this engine's
        own thread-pool sizing, and every scanner already read those module
        attributes fresh on every use via getattr(settings, ...) — updating
        them here is what makes them take effect on the *next* scan,
        regardless of which view's ScanEngine instance received the call.
        """
        mapping = {
            "timeout": "DEFAULT_TIMEOUT",
            "delay": "DEFAULT_REQUEST_DELAY",
            "threads": "DEFAULT_THREADS",
            "verify_ssl": "VERIFY_SSL",
            "max_findings": "MAX_FINDINGS_PER_SCANNER",
        }
        for key, attr in mapping.items():
            if key in new_settings:
                setattr(settings, attr, new_settings[key])

    def _get_circuit_breaker(self, host: str) -> CircuitBreaker:
        """Get or create a circuit breaker for a specific host."""
        if host not in self.circuit_breakers:
            self.circuit_breakers[host] = CircuitBreaker(
                failure_threshold=getattr(settings, 'CB_FAILURE_THRESHOLD', 5),
                timeout=getattr(settings, 'CB_TIMEOUT', 60),
                expected_exception=Exception
            )
        return self.circuit_breakers[host]

    def _exponential_backoff(self, attempt: int) -> float:
        """Calculate delay for exponential backoff with jitter."""
        delay = min(self.base_retry_delay * (2 ** attempt), self.max_retry_delay)
        # Add jitter to prevent thundering herd
        import random
        jitter = delay * 0.1 * random.random()
        return delay + jitter

    def _safe_http_request(self, method: str, url: str, **kwargs) -> Optional[object]:
        """Make an HTTP request with circuit breaker and retry logic."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc or parsed.hostname or "unknown"

        cb = self._get_circuit_breaker(host)
        max_attempts = self.max_retries + 1  # Initial attempt + retries

        for attempt in range(max_attempts):
            try:
                # Update stats
                self.request_stats['total'] += 1

                # Make the request through circuit breaker
                response = cb.call(
                    HTTPClient().request,
                    method,
                    url,
                    timeout=settings.DEFAULT_TIMEOUT,
                    verify=settings.VERIFY_SSL,
                    allow_redirects=settings.FOLLOW_REDIRECTS,
                    **kwargs
                )

                # Success!
                self.request_stats['success'] += 1
                if attempt > 0:
                    self.request_stats['retried'] += 1
                    self._put_event(("recovery", f"Request succeeded after {attempt} retries: {url}"))

                return response

            except Exception as e:
                self.request_stats['failed'] += 1

                # If this was the last attempt, don't retry
                if attempt == max_attempts - 1:
                    self._put_event(("error", f"Request failed after {max_attempts} attempts: {url}", traceback.format_exc()))
                    raise e

                # Calculate retry delay
                delay = self._exponential_backoff(attempt)
                self._put_event(("status", f"Request failed (attempt {attempt+1}/{max_attempts}), retrying in {delay:.1f}s: {str(e)[:100]}"))
                time.sleep(delay)

        return None  # Should not reach here

    def _put_event(self, event_tuple):
        """Safely put an event in the queue."""
        try:
            self.events.put_nowait(event_tuple)
        except queue.Full:
            # If queue is full, we can drop non-critical events or wait briefly
            try:
                self.events.put(event_tuple, timeout=0.1)
            except queue.Full:
                pass  # Drop the event if we still can't put it

    def scan(self, target_url: str, scanner_keys: List[str], scope_config: Optional[ScopeConfig] = None):
        """Start a scan in a background thread."""
        if self.is_scanning:
            self._put_event(("status", "Scan already in progress. Please wait for current scan to complete."))
            return

        self.is_scanning = True
        self.current_target = target_url
        self.scan_start_time = datetime.datetime.now()
        self.last_heartbeat = time.time()

        # Reset stats for this scan
        self.request_stats = {'total': 0, 'success': 0, 'failed': 0, 'retried': 0}

        # Clear any previous stop event
        self.stop_event.clear()

        # Start scan thread
        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(target_url, scanner_keys, scope_config),
            daemon=True
        )
        self.scan_thread.start()

        self._put_event(("status", f"Starting scan of {target_url} with {len(scanner_keys)} scanners"))

    def stop(self):
        """Request the current scan to stop."""
        if not self.is_scanning:
            return

        self._put_event(("status", "Stopping scan..."))
        self.stop_event.set()

        # Wait for thread to finish (with timeout)
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=10.0)

        self.is_scanning = False
        self._put_event(("status", "Scan stopped by user"))

    def _scan_worker(self, target_url: str, scanner_keys: List[str], scope_config: Optional[ScopeConfig]):
        """Main scan worker running in background thread.

        Delegates all orchestration to AgentSupervisor so agents run with
        preflight, lifecycle events, and the SSRF guard applied before any
        packet leaves.  The existing event types emitted to the UI queue are
        preserved unchanged — the supervisor emits them in the same format.
        """
        from agents.supervisor import AgentSupervisor
        from utils.ssrf_guard import UnsafeScanTargetError

        final_report = None
        try:
            self._put_event(("phase", "Initializing scan"))

            supervisor = AgentSupervisor(
                target=target_url,
                scope=scope_config,
                selected_keys=scanner_keys,
                emit=self._put_event,
                stop=self.stop_event,
            )

            final_report = supervisor.run()

            self._put_event(("status",
                f"Scan completed. Found {final_report.total_findings} vulnerabilities."))

            # Save reports
            try:
                report_dict = final_report.to_dict()
                report_path = self._get_report_store().save(report_dict, fmt="html")
                self._put_event(("report_saved", str(report_path)))
                json_path = self._get_report_store().save(report_dict, fmt="json")
                self._put_event(("report_saved", str(json_path)))
            except Exception as e:
                self._put_event(("error", f"Failed to save report: {str(e)}", traceback.format_exc()))

            self._put_event(("scan_complete", target_url, final_report.to_dict()))

        except UnsafeScanTargetError as e:
            self._put_event(("error", f"Scan blocked — unsafe target: {e}", ""))
        except ScanAborted:
            self._put_event(("status", "Scan aborted by user"))
        except Exception as e:
            self._put_event(("error", f"Scan engine crashed: {str(e)}", traceback.format_exc()))
        finally:
            clear_scan_context()
            self.is_scanning = False
            self.current_target = None
            self.scan_start_time = None
            self._put_event(("phase", "Scan finished"))

    def get_scan_status(self) -> Dict:
        """Get current scan status information."""
        return {
            "is_scanning": self.is_scanning,
            "current_target": self.current_target,
            "scan_duration": (datetime.datetime.now() - self.scan_start_time).total_seconds() if self.scan_start_time else 0,
            "request_stats": self.request_stats.copy(),
            "circuit_breaker_states": {host: cb.state.value for host, cb in self.circuit_breakers.items()}
        }