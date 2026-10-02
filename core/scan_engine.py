"""
Threaded scan engine with enhanced error handling and recovery mechanisms.

The ScanEngine runs scanners in a background thread and reports progress
through a callback queue so the UI stays responsive. It decouples the
"how to run a scan" logic from the presentation layer entirely.

Pipeline for every scan run:

    1. Discovery phase — the target is crawled (links, forms, scripts,
       robots.txt, sitemap + smart parameter probing) by URLDiscovery.
    2. A ScanContext is built holding the discovered attack surface and
       the stop event. The context is bound to every scanner worker
       thread so scanners can:
         * test every discovered endpoint/parameter via get_test_targets()
         * abort promptly when the user clicks Stop (stop_requested()).
    3. The selected scanners run in parallel (ThreadPoolExecutor window)
       and every normalized ScanResult is aggregated into a ScanReport.
    4. Enhanced error handling with automatic recovery, circuit breaker,
       and retry mechanisms for robust continuous operation.
"""

import threading
import queue
import datetime
import traceback
import time
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait
from typing import Dict, List, Optional, Union
from enum import Enum

from config import settings
from config.settings import SCANNER_MAP, SCANNER_META
from config.scope import ScopeConfig
from config.profiles import ScanProfile, load_profile
from core.models import Finding, ScanResult, ScanReport
from core.scan_context import (
    ScanContext,
    ScanAborted,
    set_scan_context,
    clear_scan_context,
)
from utils.discovery import URLDiscovery
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
        """Main scan worker running in background thread."""
        try:
            self._put_event(("phase", "Initializing scan"))

            # Reconfigure the process-wide shared rate limiter for THIS
            # scan's target — every scanner (and every internal worker
            # thread inside every scanner) shares this one limiter, so the
            # aggregate request rate against the target stays within the
            # scope's configured budget no matter how many threads are
            # running concurrently, instead of being multiplied by however
            # many scanners/phases happen to be in flight at once.
            from utils.sync_rate_limiter import get_shared_rate_limiter
            rate = getattr(scope_config, "requests_per_second", None) or getattr(settings, "DEFAULT_RATE_LIMIT", 10.0)
            burst = getattr(scope_config, "burst_limit", None) or getattr(settings, "BURST_CAPACITY", 20)
            get_shared_rate_limiter().configure(rate=rate, burst=burst)

            # Initialize scan context with correct constructor args
            scan_context = ScanContext(target=target_url, options={"scope": scope_config})
            if scope_config:
                scan_context.scope = scope_config
            set_scan_context(scan_context)

            # Phase 1: Discovery
            self._put_event(("phase", "Discovery phase"))
            self._put_event(("status", "Crawling target for links, forms, and parameters..."))

            try:
                discovery_result = self._run_discovery_with_recovery(target_url)
                # Wire discovered targets into scan context so scanners can use them
                if hasattr(discovery_result, 'targets'):
                    scan_context.discovered_targets = discovery_result.targets
                    scan_context.discovery_summary = discovery_result.summary()
                elif isinstance(discovery_result, dict):
                    # Fallback for dict-based results
                    scan_context.discovered_targets = discovery_result.get("targets", [])
                    scan_context.discovery_summary = discovery_result
                elif isinstance(discovery_result, list):
                    scan_context.discovered_targets = discovery_result
                self._put_event(("discovery", scan_context.discovery_summary))
            except Exception as e:
                self._put_event(("error", f"Discovery phase failed: {str(e)}", traceback.format_exc()))
                # Continue with basic target if discovery fails
                scan_context.discovery_summary = {"urls": [target_url], "forms": [], "parameters": {}}

            # Phase 2: Run scanners
            self._put_event(("phase", "Vulnerability scanning"))
            active_scanners = [key for key in scanner_keys if key in SCANNER_MAP]

            if not active_scanners:
                self._put_event(("error", "No valid scanners selected"))
                return

            self._put_event(("status", f"Running {len(active_scanners)} scanners..."))
            self._put_event(("scanners_queued", [
                (key, SCANNER_META.get(key, {}).get("name", key)) for key in active_scanners
            ]))

            # Run scanners with error handling
            scan_results = self._run_scanners_with_recovery(active_scanners, scan_context)

            # Phase 3: Aggregate results
            self._put_event(("phase", "Aggregating results"))
            self._put_event(("status", "Aggregating scan results..."))

            final_report = None
            try:
                final_report = self._aggregate_results(scan_results, target_url)
                self._put_event(("status", f"Scan completed. Found {final_report.total_findings} vulnerabilities."))

                # Save report
                report_dict = final_report.to_dict()
                report_path = self._get_report_store().save(report_dict, fmt="html")
                self._put_event(("report_saved", str(report_path)))

                # Also save JSON
                json_path = self._get_report_store().save(report_dict, fmt="json")
                self._put_event(("report_saved", str(json_path)))

            except Exception as e:
                self._put_event(("error", f"Failed to aggregate results: {str(e)}", traceback.format_exc()))

            # Notify scan complete with full report data. An "error" event was
            # already emitted above if aggregation failed — don't also send a
            # scan_complete with no report to work from.
            if final_report is not None:
                self._put_event(("scan_complete", target_url, final_report.to_dict()))

        except ScanAborted:
            self._put_event(("status", "Scan aborted by user"))
        except Exception as e:
            self._put_event(("error", f"Scan engine crashed: {str(e)}", traceback.format_exc()))
        finally:
            # Cleanup
            clear_scan_context()
            self.is_scanning = False
            self.current_target = None
            self.scan_start_time = None
            self._put_event(("phase", "Scan finished"))

    def _run_discovery_with_recovery(self, target_url: str) -> Dict:
        """Run discovery phase with error handling and recovery."""
        try:
            # Use enhanced discovery with our safe HTTP requests
            discovery = URLDiscovery(
                target=target_url,
                max_pages=getattr(settings, 'CRAWL_MAX_PAGES', 200),
                max_depth=getattr(settings, 'CRAWL_MAX_DEPTH', 5),
                request_delay=getattr(settings, 'CRAWL_REQUEST_DELAY', 0.05),
                request_timeout=getattr(settings, 'CRAWL_REQUEST_TIMEOUT', 15),
            )

            return discovery.discover()

        except Exception as e:
            # Fallback to basic discovery if enhanced fails
            self._put_event(("recovery", f"Falling back to basic discovery: {str(e)}"))

            # Basic discovery - just return the target URL
            return {
                "urls": [target_url],
                "forms": [],
                "parameters": {},
                "links": [],
                "scripts": [],
                "technologies": []
            }

    def _run_scanners_with_recovery(self, scanner_keys: List[str], scan_context: ScanContext) -> List[ScanResult]:
        """Run scanners with error handling, circuit breaking, and recovery."""
        from concurrent.futures import as_completed

        results = []

        # Use ThreadPoolExecutor but with our error handling
        max_workers = min(getattr(settings, 'DEFAULT_THREADS', 8), len(scanner_keys))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scanner tasks
            future_to_scanner = {
                executor.submit(self._run_single_scanner_with_recovery, key, scan_context): key
                for key in scanner_keys
            }

            # Process results as they complete
            for future in as_completed(future_to_scanner):
                scanner_key = future_to_scanner[future]
                try:
                    result = future.result(timeout=120)  # 2 minute timeout per scanner
                    if result:
                        results.append(result)
                        self._put_event(("progress", len(results) / len(scanner_keys)))
                except Exception as e:
                    self._put_event(("error", f"Scanner {scanner_key} failed: {str(e)}", traceback.format_exc()))

        return results

    def _run_single_scanner_with_recovery(self, scanner_key: str, scan_context: ScanContext) -> Optional[ScanResult]:
        """Run a single scanner with error handling and recovery."""
        scanner_class = SCANNER_MAP.get(scanner_key)
        if not scanner_class:
            self._put_event(("error", f"Unknown scanner: {scanner_key}"))
            return None

        scanner_name = SCANNER_META.get(scanner_key, {}).get("name", scanner_key)

        started_at = datetime.datetime.now()
        self._put_event(("scanner_start", scanner_key, scanner_name))
        try:
            # Instantiate scanner and bind scan context
            scanner = scanner_class()
            set_scan_context(scan_context)

            # All scanners implement scan(target_url) -> dict with 'vulnerabilities' key
            result = scanner.scan(scan_context.target)

            # Extract findings from scanner result
            raw_findings = []
            if isinstance(result, dict):
                raw_findings = result.get("vulnerabilities", []) or result.get("findings", [])

            # Cap findings to prevent bloat
            max_findings = getattr(settings, 'MAX_FINDINGS_PER_SCANNER', 50)
            raw_findings = raw_findings[:max_findings]

            # Normalize into Finding objects — downstream code (report
            # generation, severity counts, to_dict()) expects Finding
            # instances, not the raw dicts scanners return.
            findings = [
                f if isinstance(f, Finding) else Finding.from_dict(f, scan_type=scanner_key)
                for f in raw_findings
            ]

            finished_at = datetime.datetime.now()
            duration = (finished_at - started_at).total_seconds()
            self._put_event(("scanner_done", scanner_key, scanner_name, len(findings), duration))

            return ScanResult(
                scanner_key=scanner_key,
                scanner_name=scanner_name,
                target=scan_context.target,
                findings=findings,
                status="done",
                started_at=started_at,
                finished_at=finished_at,
            )

        except ScanAborted:
            raise
        except Exception as e:
            duration = (datetime.datetime.now() - started_at).total_seconds()
            self._put_event(("scanner_error", scanner_key, scanner_name, str(e), duration))
            self._put_event(("error", f"Scanner {scanner_name} failed: {str(e)}", traceback.format_exc()))
            return None
        finally:
            clear_scan_context()

    def _aggregate_results(self, scan_results: List[ScanResult], target_url: str) -> ScanReport:
        """Aggregate scan results into a final report."""
        all_findings = []

        for result in scan_results:
            all_findings.extend(result.findings)

        # Sort findings by severity (Finding objects expose .severity)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        all_findings.sort(key=lambda f: severity_order.get(getattr(f, "severity", "Info"), 5))

        started_at = datetime.datetime.fromisoformat(self.scan_start_time.isoformat()) if self.scan_start_time else datetime.datetime.now()
        finished_at = datetime.datetime.now()

        return ScanReport(
            target=target_url,
            results=scan_results,  # Include the actual results, not empty list
            started_at=started_at,
            finished_at=finished_at,
            selected_keys=[],  # TODO: Pass the actual selected scanner keys
        )

    def get_scan_status(self) -> Dict:
        """Get current scan status information."""
        return {
            "is_scanning": self.is_scanning,
            "current_target": self.current_target,
            "scan_duration": (datetime.datetime.now() - self.scan_start_time).total_seconds() if self.scan_start_time else 0,
            "request_stats": self.request_stats.copy(),
            "circuit_breaker_states": {host: cb.state.value for host, cb in self.circuit_breakers.items()}
        }