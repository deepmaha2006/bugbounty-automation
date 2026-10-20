"""SubTakeoverAgent — proper ScanAgent wrapping SubdomainTakeoverScanner.

subfinder and amass are optional tools: the agent runs with pure-Python DNS
checks when they are absent. Installing them enriches subdomain enumeration
depth; the ToolReadinessPanel surfaces their absence so the user can opt in.
"""

from typing import List

from agents.base import ScanAgent, AgentManifest, AgentContext, ToolRequirement
from core.models import Finding
from core.scan_context import ScanContext, set_scan_context, clear_scan_context
from scanners.subdomain_takeover import SubdomainTakeoverScanner


class SubTakeoverAgent(ScanAgent):
    manifest = AgentManifest(
        key="sub_takeover",
        name="Subdomain Takeover",
        category="Access Control & Misconfiguration",
        target_kinds=frozenset({"url", "domain"}),
        tools=(
            ToolRequirement(
                name="subfinder",
                check_cmd=("subfinder", "-version"),
                install=(
                    ("go", ["go", "install", "-v",
                            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"]),
                ),
                optional=True,
            ),
            ToolRequirement(
                name="amass",
                check_cmd=("amass", "-version"),
                install=(
                    ("apt", ["apt", "-y", "install", "amass"]),
                ),
                optional=True,
            ),
        ),
        payload_sets=(),
        default=True,
        intensity="passive",
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
            scanner = SubdomainTakeoverScanner()
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
            findings.append(Finding.from_dict(v, scan_type="sub_takeover"))
        return findings
