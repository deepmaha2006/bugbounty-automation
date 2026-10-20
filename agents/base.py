"""
ScanAgent base class, manifest dataclasses, AgentContext, and ToolReport.

Every scan type is a self-contained agent that declares the external tools it
needs, its payload bundles, its run logic against a target, and how it
normalises output into Finding instances. Agents are discovered by
agents/registry.py and orchestrated by agents/supervisor.py.
"""

import subprocess
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from config.scope import ScopeConfig
    from core.models import Finding
    from utils.http_client import HTTPClient
    from utils.sync_rate_limiter import SyncRateLimiter


# ---------------------------------------------------------------------------
# Manifest dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolRequirement:
    """One external binary an agent depends on."""
    name: str                              # binary name, e.g. "dalfox"
    check_cmd: tuple = ()                  # run to verify presence; empty = always present
    install: tuple = ()                    # ((pm, cmd_list), ...) install recipes per PM
    optional: bool = False                 # agent still runs (degraded) if missing

    def install_dict(self) -> Dict[str, List[str]]:
        """Return install recipes as {pm: [cmd, ...]}."""
        return dict(self.install)


@dataclass(frozen=True)
class AgentManifest:
    """Static descriptor for one scan agent."""
    key: str                               # must match existing SCANNER_MAP key
    name: str
    category: str                          # reuse SCANNER_CATEGORIES category name
    target_kinds: frozenset = field(       # which target types this agent accepts
        default_factory=lambda: frozenset({"url"}))
    tools: tuple = ()                      # tuple[ToolRequirement, ...]
    payload_sets: tuple = ()               # names of payload bundles under agents/payloads/
    default: bool = True                   # included in the "full" preset
    intensity: str = "active"             # passive | active | aggressive


# ---------------------------------------------------------------------------
# Tool-readiness report
# ---------------------------------------------------------------------------

@dataclass
class ToolReport:
    """Result of a preflight tool-readiness check for one agent."""
    agent_key: str
    present: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    optional_missing: List[str] = field(default_factory=list)

    @property
    def can_run(self) -> bool:
        """True when no required tools are absent."""
        return len(self.missing) == 0


# ---------------------------------------------------------------------------
# Agent execution context
# ---------------------------------------------------------------------------

@dataclass
class AgentContext:
    """Everything an agent needs for one scan run.

    Agents MUST check ctx.stop.is_set() at reasonable intervals and return
    early if it is set. They MUST call ctx.scope.is_in_scope(...) before
    sending any request to a URL derived from the target.
    """
    target: str
    scope: Any                             # ScopeConfig (Any to avoid import cycle)
    stop: threading.Event
    rate_limiter: Any                      # SyncRateLimiter
    http_client: Any                       # HTTPClient
    emit: Callable                         # emit(event_type, **kwargs) → None
    workdir: Path
    discovered_targets: List[Any] = field(default_factory=list)
    discovery_summary: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class ScanAgent(ABC):
    """Abstract base for all scan agents.

    Subclasses must set a class-level ``manifest: AgentManifest`` attribute and
    implement ``run(ctx) -> list[Finding]``.
    """

    manifest: AgentManifest   # class-level; each subclass defines this

    @abstractmethod
    def run(self, ctx: AgentContext) -> List["Finding"]:
        """Run the scan. Must honour ctx.stop and ctx.scope."""
        ...

    def preflight(self) -> ToolReport:
        """Check which tools in the manifest are present.

        The default implementation runs each ToolRequirement.check_cmd and
        reports present / missing / optional_missing. Override for custom logic.
        """
        report = ToolReport(agent_key=self.manifest.key)
        for req in self.manifest.tools:
            if _tool_present(req.check_cmd):
                report.present.append(req.name)
            elif req.optional:
                report.optional_missing.append(req.name)
            else:
                report.missing.append(req.name)
        return report


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _tool_present(check_cmd: tuple) -> bool:
    """Return True if check_cmd exits 0 (or check_cmd is empty)."""
    if not check_cmd:
        return True
    try:
        result = subprocess.run(
            list(check_cmd),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False
