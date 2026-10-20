"""SqlmapAgent — proper ScanAgent wrapping SqlmapScanner.

sqlmap is a REQUIRED tool: can_run=False when absent.
default=False: sqlmap is aggressive (modifies DB state) and must be explicitly selected.
"""

from typing import List

from agents.base import ScanAgent, AgentManifest, AgentContext, ToolRequirement
from core.models import Finding
from core.scan_context import ScanContext, set_scan_context, clear_scan_context
from scanners.kali_scanners import SqlmapScanner


class SqlmapAgent(ScanAgent):
    manifest = AgentManifest(
        key="sqlmap",
        name="sqlmap",
        category="Kali Power Tools",
        target_kinds=frozenset({"url"}),
        tools=(
            ToolRequirement(
                name="sqlmap",
                check_cmd=("sqlmap", "--version"),
                install=(
                    ("apt", ["apt", "-y", "install", "sqlmap"]),
                    ("pip", ["pip", "install", "sqlmap"]),
                ),
                optional=False,
            ),
        ),
        payload_sets=(),
        default=False,
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
            scanner = SqlmapScanner()
            raw = scanner.scan(ctx.target)
        except Exception:
            return []
        finally:
            clear_scan_context()

        findings: List[Finding] = []
        for v in raw.get("vulnerabilities", []):
            if ctx.stop.is_set():
                break
            findings.append(Finding.from_dict(v, scan_type="sqlmap"))
        return findings
