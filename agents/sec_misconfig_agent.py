"""SecMisconfigAgent — proper ScanAgent wrapping SecurityMisconfigScanner.

nikto is declared as an optional tool: the agent runs cleanly without it
(pure-Python checks still execute), but the ToolReadinessPanel surfaces the
suggestion to install it for deeper server-banner and directory enumeration.
"""

from typing import List

from agents.base import ScanAgent, AgentManifest, AgentContext, ToolRequirement
from core.models import Finding
from core.scan_context import ScanContext, set_scan_context, clear_scan_context
from scanners.security_misconfig import SecurityMisconfigScanner


class SecMisconfigAgent(ScanAgent):
    manifest = AgentManifest(
        key="sec_misconfig",
        name="Security Misconfiguration",
        category="Access Control & Misconfiguration",
        target_kinds=frozenset({"url"}),
        tools=(
            ToolRequirement(
                name="nikto",
                check_cmd=("nikto", "-Version"),
                install=(
                    ("apt", ["apt", "-y", "install", "nikto"]),
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
            scanner = SecurityMisconfigScanner()
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
            findings.append(Finding.from_dict(v, scan_type="sec_misconfig"))
        return findings
