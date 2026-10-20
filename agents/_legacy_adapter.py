"""
LegacyAdapter — thin ScanAgent wrapper around pre-agent scanner classes.

Used by the registry for every scanner key that hasn't been ported to a
proper ScanAgent yet. The manifest exposes no external tool requirements
(preflight always passes), and run() delegates to the wrapped class's
existing .scan(target_url) method, converting raw dict output to Finding
instances via Finding.from_dict().
"""

from typing import Any, Dict, List

from agents.base import ScanAgent, AgentManifest, AgentContext, ToolReport
from core.models import Finding
from core.scan_context import ScanContext, set_scan_context, clear_scan_context

# Marker so the registry skips this class during discovery.
_is_legacy_adapter = True


class LegacyAdapter(ScanAgent):
    """Wraps one existing scanner class as a ScanAgent."""

    _is_legacy_adapter = True

    def __init__(self, scanner_cls: Any, meta: Dict[str, Any]):
        self.scanner_cls = scanner_cls
        self._meta = meta
        self.manifest = AgentManifest(
            key=meta["key"],
            name=meta["name"],
            category=meta.get("category", ""),
            target_kinds=frozenset({"url"}),
            tools=(),
            payload_sets=(),
            default=bool(meta.get("default", True)),
            intensity="active",
        )

    def preflight(self) -> ToolReport:
        return ToolReport(
            agent_key=self.manifest.key,
            present=[],
            missing=[],
            optional_missing=[],
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
            scanner = self.scanner_cls()
            if hasattr(scanner, "client") and ctx.http_client is not None:
                scanner.client = ctx.http_client
            raw = scanner.scan(ctx.target)
        except Exception:
            return []
        finally:
            clear_scan_context()

        # Normalise the raw return value — scanners return dict or list.
        vulns: list = []
        if isinstance(raw, dict):
            vulns = raw.get("vulnerabilities", raw.get("findings", []))
        elif isinstance(raw, list):
            vulns = raw

        findings: List[Finding] = []
        for v in vulns:
            if ctx.stop.is_set():
                break
            if isinstance(v, dict):
                findings.append(Finding.from_dict(v, scan_type=self.manifest.key))
            elif hasattr(v, "to_dict"):
                findings.append(Finding.from_dict(v.to_dict(), scan_type=self.manifest.key))
        return findings
