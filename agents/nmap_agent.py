"""NmapAgent — proper ScanAgent wrapping NmapScanner.

nmap is a REQUIRED tool: can_run=False when absent.
default=False: port scanning is heavy and must be explicitly selected.
"""

from typing import List

from agents.base import ScanAgent, AgentManifest, AgentContext, ToolRequirement
from core.models import Finding
from core.scan_context import ScanContext, set_scan_context, clear_scan_context
from scanners.kali_scanners import NmapScanner


class NmapAgent(ScanAgent):
    manifest = AgentManifest(
        key="nmap",
        name="Nmap Port Scan",
        category="Kali Power Tools",
        target_kinds=frozenset({"url", "domain"}),
        tools=(
            ToolRequirement(
                name="nmap",
                check_cmd=("nmap", "--version"),
                install=(
                    ("apt", ["apt", "-y", "install", "nmap"]),
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
            scanner = NmapScanner()
            raw = scanner.scan(ctx.target)
        except Exception:
            return []
        finally:
            clear_scan_context()

        findings: List[Finding] = []
        for v in raw.get("vulnerabilities", []):
            if ctx.stop.is_set():
                break
            findings.append(Finding.from_dict(v, scan_type="nmap"))
        return findings
