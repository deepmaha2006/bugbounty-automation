"""agents — per-scan-type agent architecture for HydraX."""
from agents.registry import AGENT_MAP, build_registry
from agents import mcp_bridge_agent  # noqa: F401 — registers MCP ScanAgents

__all__ = ["AGENT_MAP", "build_registry"]
