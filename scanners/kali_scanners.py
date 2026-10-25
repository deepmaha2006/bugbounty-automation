"""
Kali tool scanner stubs — local subprocess wrappers.

Delegates to tools/hexstrike_local.py so no webapp/ dependency is needed.
Each scanner exposes scan(target) -> {"vulnerabilities": [...]} so the
agent layer and ScanEngine treat them identically to all other scanners.
If the underlying tool is not installed the local wrapper returns a
synthetic fallback finding rather than crashing.
"""
from __future__ import annotations

from typing import Any, Dict, List


def _to_vulns(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert hexstrike_local result findings into the common vuln dict shape."""
    out = []
    for f in findings:
        out.append({
            "type":        f.get("title", "Finding"),
            "severity":    f.get("severity", "Medium").capitalize(),
            "description": str(f.get("description", "")),
            "url":         f.get("location", ""),
            "evidence":    f.get("cve_id", "") or "",
            "tool":        f.get("tool", "kali"),
        })
    return out


class NucleiScanner:
    """Run Nuclei template-based vulnerability scanning against a URL."""

    def scan(self, target: str) -> dict:
        from tools.hexstrike_local import nuclei_scan_local
        result = nuclei_scan_local(target)
        return {"vulnerabilities": _to_vulns(result.get("findings", []))}


class NmapScanner:
    """Run Nmap port and service discovery against a host."""

    def scan(self, target: str) -> dict:
        import subprocess, json
        try:
            r = subprocess.run(
                ["nmap", "-sV", "--open", "-oJ", "-", target],
                capture_output=True, text=True, timeout=120,
            )
            vulns = []
            if r.returncode == 0 and r.stdout:
                try:
                    data = json.loads(r.stdout)
                    for host in data.get("nmaprun", {}).get("host", []):
                        for port in host.get("ports", {}).get("port", []):
                            svc = port.get("service", {})
                            vulns.append({
                                "type": "Open Port",
                                "severity": "Info",
                                "description": f"Port {port.get('@portid')}/{port.get('@protocol')} open — {svc.get('@name','')} {svc.get('@version','')}",
                                "url": target,
                                "evidence": svc.get("@product", ""),
                                "tool": "nmap",
                            })
                except Exception:
                    pass
            return {"vulnerabilities": vulns}
        except FileNotFoundError:
            return {"vulnerabilities": [{
                "type": "Nmap not installed",
                "severity": "Info",
                "description": "Install nmap to enable port scanning.",
                "url": target,
                "evidence": "",
                "tool": "nmap_missing",
            }]}


class SqlmapScanner:
    """Run sqlmap SQL injection testing against a URL."""

    def scan(self, target: str) -> dict:
        from tools.hexstrike_local import sqlmap_scan_local
        result = sqlmap_scan_local(url=target)
        return {"vulnerabilities": _to_vulns(result.get("findings", []))}


class GobusterScanner:
    """Run Gobuster directory brute-forcing."""

    def scan(self, target: str) -> dict:
        from tools.hexstrike_local import gobuster_scan_local
        result = gobuster_scan_local(url=target)
        return {"vulnerabilities": _to_vulns(result.get("findings", []))}


class FFufScanner:
    """Run FFuf web fuzzing."""

    def scan(self, target: str) -> dict:
        from tools.hexstrike_local import ffuf_scan_local
        result = ffuf_scan_local(url=target)
        return {"vulnerabilities": _to_vulns(result.get("findings", []))}


class NiktoScanner:
    """Run Nikto web server vulnerability scanning."""

    def scan(self, target: str) -> dict:
        from tools.hexstrike_local import nikto_scan_local
        result = nikto_scan_local(target=target)
        return {"vulnerabilities": _to_vulns(result.get("findings", []))}


class MasscanScanner:
    """Run Masscan high-speed port scanning."""

    def scan(self, target: str) -> dict:
        from tools.hexstrike_local import masscan_local_scan
        result = masscan_local_scan(target=target)
        return {"vulnerabilities": _to_vulns(result.get("findings", []))}


class SubfinderScanner:
    """Run Subfinder passive subdomain enumeration."""

    def scan(self, target: str) -> dict:
        from tools.hexstrike_local import subfinder_scan_local
        result = subfinder_scan_local(domain=target)
        subs = result.get("subdomains", [])
        vulns = [{"type": "Subdomain", "severity": "Info",
                  "description": f"Subdomain found: {s}", "url": s,
                  "evidence": "", "tool": "subfinder"} for s in subs]
        return {"vulnerabilities": vulns}


class WhatWebScanner:
    """Run WhatWeb technology fingerprinting."""

    def scan(self, target: str) -> dict:
        from tools.hexstrike_local import whatweb_scan_local
        result = whatweb_scan_local(target=target)
        techs = result.get("technologies", [])
        vulns = [{"type": "Technology Detected", "severity": "Info",
                  "description": f"WhatWeb: {t}", "url": target,
                  "evidence": t, "tool": "whatweb"} for t in techs]
        return {"vulnerabilities": vulns}
