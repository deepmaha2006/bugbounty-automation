"""NucleiAgent — proper ScanAgent wrapping NucleiScanner.

nuclei is a REQUIRED tool: can_run=False when absent, making this the first agent
that genuinely exercises the preflight gate's "skip with reason" path.
default=False: the user must explicitly opt in to nuclei scanning.
"""

from typing import List

from agents.base import ScanAgent, AgentManifest, AgentContext, ToolRequirement
from core.models import Finding
from core.scan_context import ScanContext, set_scan_context, clear_scan_context
from scanners.kali_scanners import NucleiScanner


class NucleiAgent(ScanAgent):
    manifest = AgentManifest(
        key="nuclei",
        name="Nuclei",
        category="Kali Power Tools",
        target_kinds=frozenset({"url"}),
        tools=(
            ToolRequirement(
                name="nuclei",
                check_cmd=("nuclei", "-version"),
                install=(
                    ("go", ["go", "install", "-v",
                            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"]),
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
            scanner = NucleiScanner()
            raw = scanner.scan(ctx.target)
        except Exception:
            return []
        finally:
            clear_scan_context()

        findings: List[Finding] = []
        for v in raw.get("vulnerabilities", []):
            if ctx.stop.is_set():
                break
            findings.append(Finding.from_dict(v, scan_type="nuclei"))
        return findings
