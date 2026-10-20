"""BusinessLogicAgent — proper ScanAgent wrapping BusinessLogicScanner."""

from typing import List

from agents.base import ScanAgent, AgentManifest, AgentContext
from core.models import Finding
from core.scan_context import ScanContext, set_scan_context, clear_scan_context
from scanners.advanced_scanners import BusinessLogicScanner


class BusinessLogicAgent(ScanAgent):
    manifest = AgentManifest(
        key="business_logic",
        name="Business Logic",
        category="Authentication & Business Logic",
        target_kinds=frozenset({"url"}),
        tools=(),
        payload_sets=(),
        default=True,
        intensity="active",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        legacy = ScanContext(ctx.target)
        legacy.stop_event = ctx.stop
        legacy.discovered_targets = list(ctx.discovered_targets)
        legacy.discovery_summary = dict(ctx.discovery_summary)
        if ctx.scope is not None:
            legacy.scope = ctx.scope

        set_scan_context(legacy)
        try:
            scanner = BusinessLogicScanner()
            if hasattr(scanner, 'client'):
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
            findings.append(Finding.from_dict(v, scan_type="business_logic"))
        return findings
