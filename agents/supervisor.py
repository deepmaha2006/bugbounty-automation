"""
AgentSupervisor — orchestrates concurrent agent execution, lifecycle events,
and report aggregation for a single scan run.

All target validation (SSRF guard + scope check) runs here, before any packet
is sent.  Preflight for each agent runs first; agents whose required tools are
missing are marked 'skipped' rather than allowed to crash mid-scan.

Events emitted (all via the ``emit`` callable supplied by the caller):

  Legacy (backward-compat with ScanEngine / UI event pump):
    ("phase",            text)
    ("status",           text)
    ("discovery",        summary_dict)
    ("scanners_queued",  [(key, name), ...])
    ("progress",         float 0..1)
    ("scanner_start",    key, name)
    ("scanner_done",     key, name, count, duration)
    ("scanner_error",    key, name, error, duration)

  Agent lifecycle (for Phase 5/6 animated UI):
    ("agent_lifecycle",  key, "queued")
    ("agent_lifecycle",  key, "preflight",  tool_report)
    ("agent_lifecycle",  key, "running")
    ("agent_lifecycle",  key, "finding",    finding)
    ("agent_lifecycle",  key, "done",       duration)
    ("agent_lifecycle",  key, "error",      error_msg, duration)
    ("agent_lifecycle",  key, "skipped",    reason)
    ("tool_report",      key, tool_report)
"""

import datetime
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional

from config import settings
from config.scope import ScopeConfig
from core.models import Finding, ScanReport, ScanResult
from core.scan_context import (
    ScanContext,
    ScanAborted,
    set_scan_context,
    clear_scan_context,
)
from utils.ssrf_guard import assert_safe_scan_target, UnsafeScanTargetError


class AgentSupervisor:
    """Runs a set of agents against a target, surfacing per-agent lifecycle
    events and aggregating findings into a ScanReport.

    Usage::

        sup = AgentSupervisor(
            target="https://example.com",
            scope=scope_config,
            selected_keys=["xss", "sqli", "headers"],
            emit=engine._put_event,
            stop=engine.stop_event,
        )
        report = sup.run()
    """

    def __init__(
        self,
        target: str,
        scope: Optional[ScopeConfig],
        selected_keys: List[str],
        emit: Callable,
        stop: threading.Event,
        asset_id: Optional[int] = None,
        org_id: Optional[int] = None,
    ):
        self.target = target
        self.scope = scope
        self.selected_keys = selected_keys
        self._emit = emit
        self.stop = stop
        self.asset_id = asset_id
        self.org_id = org_id
        self._started_at: Optional[datetime.datetime] = None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> ScanReport:
        """Execute the full scan pipeline and return an aggregated report.

        Raises UnsafeScanTargetError (from ssrf_guard) if the target is
        disallowed; callers should treat that as a hard abort.
        """
        self._started_at = datetime.datetime.now()

        # 1. Validate target — SSRF guard + scope, before any packet leaves
        self._emit(("phase", "Validating target"))
        assert_safe_scan_target(self.target)
        if self.scope is not None:
            self._check_scope()

        # 2. Configure shared rate limiter
        from utils.sync_rate_limiter import get_shared_rate_limiter
        rate = getattr(self.scope, "requests_per_second", None) or getattr(settings, "DEFAULT_RATE_LIMIT", 10.0)
        burst = getattr(self.scope, "burst_limit", None) or getattr(settings, "BURST_CAPACITY", 20)

        # Apply max_req_per_sec ceiling from authorization record (§10 loose end).
        # The authorization always wins if it is more restrictive than the scope config.
        if self.asset_id is not None and self.org_id is not None:
            try:
                import webapp.db as _db
                auth = _db.get_active_authorization(self.asset_id, self.org_id)
                if auth and auth.get("max_req_per_sec"):
                    rate = min(float(rate), float(auth["max_req_per_sec"]))
            except Exception:
                pass  # no DB context (e.g. pure-desktop run); use scope rate

        get_shared_rate_limiter().configure(rate=rate, burst=burst)

        # 3. Preflight all selected agents
        from agents.registry import AGENT_MAP
        from agents.toolchain import preflight
        agents = {k: AGENT_MAP[k] for k in self.selected_keys if k in AGENT_MAP}

        runnable: List[str] = []
        for key, agent in agents.items():
            report = preflight(agent)
            self._emit(("tool_report", key, report))
            self._emit(("agent_lifecycle", key, "preflight", report))
            if report.can_run:
                runnable.append(key)
            else:
                reason = "missing required tools: " + ", ".join(report.missing)
                self._emit(("agent_lifecycle", key, "skipped", reason))
                self._emit(("status", f"[{key}] skipped — {reason}"))

        if not runnable:
            self._emit(("status", "No runnable agents after preflight"))
            return self._empty_report()

        # 4. Discovery
        self._emit(("phase", "Discovery phase"))
        self._emit(("status", "Crawling target for links, forms, and parameters…"))
        discovery_result = self._run_discovery()

        # 5. Queue all agents; emit queued events + legacy scanners_queued
        self._emit(("scanners_queued", [
            (k, AGENT_MAP[k].manifest.name) for k in runnable
        ]))
        for key in runnable:
            self._emit(("agent_lifecycle", key, "queued"))

        # 6. Build shared HTTP client + rate limiter references once
        from utils.http_client import HTTPClient
        http_client = HTTPClient()
        rate_limiter = get_shared_rate_limiter()

        # 7. Dispatch agents concurrently
        self._emit(("phase", "Vulnerability scanning"))
        self._emit(("status", f"Running {len(runnable)} agents…"))

        max_workers = min(
            getattr(settings, "HYDRAX_MAX_CONCURRENT_SCANS",
                    getattr(settings, "DEFAULT_THREADS", 8)),
            len(runnable),
        )

        scan_results: List[ScanResult] = []
        completed = 0

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(
                    self._run_agent,
                    key,
                    agents[key],
                    discovery_result,
                    http_client,
                    rate_limiter,
                ): key
                for key in runnable
            }
            for future in as_completed(futures):
                key = futures[future]
                try:
                    result = future.result(timeout=300)
                    if result is not None:
                        scan_results.append(result)
                except ScanAborted:
                    raise
                except Exception as exc:
                    name = agents[key].manifest.name
                    self._emit(("scanner_error", key, name, str(exc), 0.0))
                finally:
                    completed += 1
                    self._emit(("progress", completed / len(runnable)))

        # 8. Aggregate
        self._emit(("phase", "Aggregating results"))
        return self._build_report(scan_results)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_scope(self) -> None:
        """Abort early if target is outside the declared scope."""
        try:
            if not self.scope.is_in_scope(self.target):
                raise UnsafeScanTargetError(
                    f"Target {self.target!r} is outside the configured scope."
                )
        except AttributeError:
            pass  # scope object doesn't implement is_in_scope(); treat as ok

    def _run_discovery(self) -> dict:
        from utils.discovery import URLDiscovery
        try:
            disc = URLDiscovery(
                target=self.target,
                max_pages=getattr(settings, "CRAWL_MAX_PAGES", 200),
                max_depth=getattr(settings, "CRAWL_MAX_DEPTH", 5),
                request_delay=getattr(settings, "CRAWL_REQUEST_DELAY", 0.05),
                request_timeout=getattr(settings, "CRAWL_REQUEST_TIMEOUT", 15),
            )
            result = disc.discover()
            summary = result if isinstance(result, dict) else {"urls": [self.target]}
            self._emit(("discovery", summary))
            return summary
        except Exception as exc:
            self._emit(("status", f"Discovery fallback: {exc}"))
            fallback = {"urls": [self.target], "forms": [], "parameters": {}}
            self._emit(("discovery", fallback))
            return fallback

    def _run_agent(
        self,
        key: str,
        agent,
        discovery: dict,
        http_client,
        rate_limiter,
    ) -> Optional[ScanResult]:
        from agents.base import AgentContext

        name = agent.manifest.name
        started_at = datetime.datetime.now()

        self._emit(("scanner_start", key, name))
        self._emit(("agent_lifecycle", key, "running"))

        # Build a per-agent emit that also routes to the top-level emitter
        def agent_emit(*args):
            self._emit(args)

        # Build AgentContext
        from pathlib import Path
        from config import settings as _cfg
        workdir = Path(getattr(_cfg, "REPORTS_DIR", "."))
        ctx = AgentContext(
            target=self.target,
            scope=self.scope,
            stop=self.stop,
            rate_limiter=rate_limiter,
            http_client=http_client,
            emit=agent_emit,
            workdir=workdir,
        )
        # Wire in discovery results
        ctx.discovered_targets = discovery.get("urls", [self.target])
        ctx.discovery_summary = discovery

        # Also bind a legacy ScanContext so wrapped scanners keep working
        legacy = ScanContext(target=self.target, options={"scope": self.scope})
        if self.scope:
            legacy.scope = self.scope
        legacy.stop_event = self.stop
        legacy.discovered_targets = ctx.discovered_targets
        legacy.discovery_summary = ctx.discovery_summary
        set_scan_context(legacy)

        findings: List[Finding] = []
        try:
            if self.stop.is_set():
                raise ScanAborted()

            raw_findings = agent.run(ctx)
            max_findings = getattr(settings, "MAX_FINDINGS_PER_SCANNER", 50)
            for f in (raw_findings or [])[:max_findings]:
                if self.stop.is_set():
                    break
                findings.append(f)
                self._emit(("agent_lifecycle", key, "finding", f))

        except ScanAborted:
            raise
        except Exception as exc:
            duration = (datetime.datetime.now() - started_at).total_seconds()
            self._emit(("agent_lifecycle", key, "error", str(exc), duration))
            self._emit(("scanner_error", key, name, str(exc), duration))
            self._emit(("status", f"[{key}] failed: {exc}"))
            return None
        finally:
            clear_scan_context()

        finished_at = datetime.datetime.now()
        duration = (finished_at - started_at).total_seconds()
        self._emit(("scanner_done", key, name, len(findings), duration))
        self._emit(("agent_lifecycle", key, "done", duration))

        return ScanResult(
            scanner_key=key,
            scanner_name=name,
            target=self.target,
            findings=findings,
            status="done",
            started_at=started_at,
            finished_at=finished_at,
        )

    def _build_report(self, scan_results: List[ScanResult]) -> ScanReport:
        finished_at = datetime.datetime.now()
        return ScanReport(
            target=self.target,
            results=scan_results,
            started_at=self._started_at or finished_at,
            finished_at=finished_at,
            selected_keys=self.selected_keys,
        )

    def _empty_report(self) -> ScanReport:
        now = datetime.datetime.now()
        return ScanReport(
            target=self.target,
            results=[],
            started_at=self._started_at or now,
            finished_at=now,
            selected_keys=self.selected_keys,
        )
