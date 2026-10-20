"""
Tool-chain preflight and (explicit opt-in only) installation.

Preflight checks run automatically — before every scan — and report which
required tools are present or missing. Installation only happens on a
deliberate user action (mode="install", or by calling install_missing
directly). It is never triggered automatically.
"""

import platform
import subprocess
from typing import Dict, List

from agents.base import ScanAgent, ToolReport, ToolRequirement


def preflight(agent: ScanAgent) -> ToolReport:
    """Check tool readiness for one agent. Safe to call at any time."""
    return agent.preflight()


def preflight_all(agents: List[ScanAgent]) -> Dict[str, ToolReport]:
    """Run preflight for every agent in the list, keyed by agent key."""
    return {a.manifest.key: preflight(a) for a in agents}


def install_tool(req: ToolRequirement, dry_run: bool = False) -> bool:
    """
    Install a single tool using the first available package manager.

    IMPORTANT: Only call this on explicit user request — never automatically.

    Returns True when an install command was found and succeeded.
    Raises RuntimeError when no supported package manager is available.
    """
    install_dict = req.install_dict()
    if not install_dict:
        raise RuntimeError(f"No install recipe defined for '{req.name}'.")

    system = platform.system().lower()
    if system == "linux":
        pm_order = ["apt", "go", "pip"]
    elif system == "darwin":
        pm_order = ["brew", "go", "pip"]
    else:
        pm_order = ["go", "pip"]

    for pm in pm_order:
        cmd = install_dict.get(pm)
        if not cmd:
            continue
        if dry_run:
            return True
        try:
            result = subprocess.run(cmd, timeout=120, check=False)
            return result.returncode == 0
        except Exception:
            continue

    raise RuntimeError(
        f"No supported package manager found to install '{req.name}'. "
        f"Available recipes: {list(install_dict)}"
    )


def install_missing(
    agent: ScanAgent, dry_run: bool = False
) -> Dict[str, bool]:
    """
    Install all missing required tools for one agent.

    Only call this on explicit user opt-in.

    Returns {tool_name: install_succeeded}.
    """
    report = preflight(agent)
    results: Dict[str, bool] = {}
    for req in agent.manifest.tools:
        if req.name not in report.missing:
            continue
        try:
            results[req.name] = install_tool(req, dry_run=dry_run)
        except RuntimeError:
            results[req.name] = False
    return results
