"""ReconAgent — proper ScanAgent wrapping PassiveRecon.

nmap, whatweb, and dnsrecon are declared as optional tools: PassiveRecon
performs pure-Python DNS, WHOIS, and HTTP fingerprinting when they are
absent. Installing them enriches port-scan and technology-fingerprint depth;
the ToolReadinessPanel surfaces their absence so the user can opt in.
"""

from typing import List

from agents.base import ScanAgent, AgentManifest, AgentContext, ToolRequirement
from core.models import Finding
from core.scan_context import ScanContext, set_scan_context, clear_scan_context
from scanners.passive_recon import PassiveRecon


class ReconAgent(ScanAgent):
    manifest = AgentManifest(
        key="recon",
        name="Passive Reconnaissance",
        category="Network, Cloud & Recon",
        target_kinds=frozenset({"url", "domain"}),
        tools=(
            ToolRequirement(
                name="nmap",
                check_cmd=("nmap", "--version"),
                install=(
                    ("apt", ["apt", "-y", "install", "nmap"]),
                ),
                optional=True,
            ),
            ToolRequirement(
                name="whatweb",
                check_cmd=("whatweb", "--version"),
                install=(
                    ("apt", ["apt", "-y", "install", "whatweb"]),
                ),
                optional=True,
            ),
            ToolRequirement(
                name="dnsrecon",
                check_cmd=("dnsrecon", "--version"),
                install=(
                    ("apt", ["apt", "-y", "install", "dnsrecon"]),
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
            scanner = PassiveRecon()
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
            findings.append(Finding.from_dict(v, scan_type="recon"))
        return findings
