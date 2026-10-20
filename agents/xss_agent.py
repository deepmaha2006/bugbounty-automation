"""
XSSAgent — adapter wrapping the existing XSSScanner as a ScanAgent.

Phase 1 strategy: wrap, not rewrite. The scanner logic stays in
scanners/xss_scanner.py; this agent bridges it into the new interface.
The old ScanContext thread-local is set up so XSSScanner.scan() can still
call get_test_targets() and abort_if_stopped() unchanged.
"""

from typing import List

from agents.base import ScanAgent, AgentManifest, AgentContext
from core.models import Finding
from core.scan_context import ScanContext, set_scan_context, clear_scan_context
from scanners.xss_scanner import XSSScanner


class XSSAgent(ScanAgent):
    manifest = AgentManifest(
        key="xss",
        name="Cross-Site Scripting (XSS)",
        category="Web Application Security",
        target_kinds=frozenset({"url"}),
        tools=(),                          # pure-Python; no external binaries required
        payload_sets=("reflected", "stored", "dom", "blind"),
        default=True,
        intensity="active",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        # Bridge AgentContext into the legacy thread-local so the wrapped
        # scanner's get_test_targets() / abort_if_stopped() still work.
        legacy = ScanContext(ctx.target)
        legacy.stop_event = ctx.stop
        legacy.discovered_targets = list(ctx.discovered_targets)
        legacy.discovery_summary = dict(ctx.discovery_summary)
        if ctx.scope is not None:
            legacy.scope = ctx.scope

        set_scan_context(legacy)
        try:
            scanner = XSSScanner()
            # Reuse the shared HTTP client so the rate limiter governs all
            # requests from this agent alongside every other concurrent agent.
            scanner.client = ctx.http_client
            raw = scanner.scan(ctx.target)
        except Exception:
            return []
        finally:
            clear_scan_context()

        findings: List[Finding] = []
        for v in raw.get("vulnerabilities", []):
            if ctx.stop.is_set():
                break
            findings.append(Finding.from_dict(v, scan_type="xss"))
        return findings
