"""Thin scanner stubs that delegate to kali_tools run_* wrappers.

Each class exposes the standard scan(target) -> {"vulnerabilities": [...]} interface
so the agent layer can use the identical ScanContext bridge pattern as all other agents.
The kali_tools functions already guard with tool_available(); if the tool is absent they
return [] — the agent preflight gate (required ToolRequirement) blocks execution before
this point, so the fallback is purely a safety net.
"""

from webapp.services.kali_tools import run_nuclei, run_nmap, run_sqlmap


class NucleiScanner:
    """Run Nuclei template-based vulnerability scanning against a URL."""

    def scan(self, target: str) -> dict:
        return {"vulnerabilities": run_nuclei(target)}


class NmapScanner:
    """Run Nmap port and service discovery against a host."""

    def scan(self, target: str) -> dict:
        return {"vulnerabilities": run_nmap(target)}


class SqlmapScanner:
    """Run sqlmap SQL injection testing against a URL."""

    def scan(self, target: str) -> dict:
        return {"vulnerabilities": run_sqlmap(target)}
