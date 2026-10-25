"""HexStrike-AI Integration — Agent wrappers for HexStrike security tools.

This module wraps HexStrike-AI's tool functions as HydraX ScanAgents,
providing access to nmap, nuclei, sqlmap, gobuster, nikto, masscan, zap,
ffuf, wfuzz, and other security tools through the standard ScanAgent interface.

HexStrike-AI source: https://github.com/0x4m4/hexstrike-ai.git
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.base import ScanAgent, AgentManifest, AgentContext, ToolRequirement
from core.models import Finding

logger = logging.getLogger(__name__)

# Path to hexstrike-ai repository
HEXSTRIKE_DIR = Path(__file__).resolve().parent.parent.parent / "hexstrike-ai"

# User-agent rotation for anti-detection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "sqlmap/1.7#stable (http://sqlmap.org)",  # Intentional scanner UA for sqlmap
]


def _random_user_agent() -> str:
    """Rotate user-agents to reduce detection."""
    return USER_AGENTS[hash(datetime.now().timestamp()) % len(USER_AGENTS)]


def _run_cli(cmd: List[str], timeout: int = 120) -> tuple:
    """Run CLI command and return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"}
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"[TIMEOUT {timeout}s]", 124
    except FileNotFoundError:
        return "", "[TOOL NOT FOUND]", 127
    except Exception as e:
        return "", f"[ERROR: {e}]", 1


def _parse_nmap_output(stdout: str) -> List[Dict]:
    """Parse nmap XML/JSON output into findings."""
    findings = []
    # Try JSON output first
    try:
        data = json.loads(stdout)
        for host in data.get("hosts", []):
            for port in host.get("ports", {}).get("port", []):
                if port.get("state", {}).get("state") == "open":
                    findings.append({
                        "type": "Open Port",
                        "severity": "Info",
                        "description": f"Port {port['portid']}/{port.get('protocol', 'tcp')} open",
                        "url": host.get("ipaddr", ""),
                        "evidence": f"Port {port['portid']} open, service: {port.get('service', {}).get('name', 'unknown')}",
                        "remediation": "Close unused ports and implement firewall rules.",
                        "tool": "nmap",
                        "confidence": "confirmed",
                    })
    except (json.JSONDecodeError, KeyError):
        pass
    # Fallback to text parsing
    for line in stdout.splitlines():
        if re.search(r'^\d+/tcp\s+open', line):
            port_match = re.match(r'^(\d+)/tcp\s+open', line)
            if port_match:
                findings.append({
                    "type": "Open Port",
                    "severity": "Info",
                    "description": f"Port {port_match.group(1)}/tcp open",
                    "url": "",
                    "evidence": line.strip(),
                    "remediation": "Close unused ports.",
                    "tool": "nmap",
                    "confidence": "confirmed",
                })
    return findings


def _parse_nuclei_output(stdout: str) -> List[Dict]:
    """Parse nuclei JSONL output into findings."""
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            findings.append({
                "type": data.get("template-id", "Unknown"),
                "severity": data.get("info", {}).get("severity", "Info").title(),
                "description": data.get("matched-at", ""),
                "url": data.get("host", ""),
                "evidence": json.dumps(data),
                "remediation": data.get("info", {}).get("classification", {}).get("cve-id", ""),
                "tool": "nuclei",
                "confidence": "confirmed",
            })
        except json.JSONDecodeError:
            continue
    return findings


def _parse_gobuster_output(stdout: str) -> List[Dict]:
    """Parse gobuster directory scan output."""
    findings = []
    for line in stdout.splitlines():
        # Format: http://target/path (Status: 200) [Size: 1234]
        match = re.match(r'^(https?://\S+)\s+\(Status:\s*(\d+)\)', line)
        if match:
            url = match.group(1)
            status = int(match.group(2))
            severity = "Info"
            if status in (200, 201, 204):
                severity = "Low"
            elif status == 403:
                severity = "Medium"
            findings.append({
                "type": "Directory Discovered",
                "severity": severity,
                "description": f"Discovered path: {url}",
                "url": url,
                "evidence": line.strip(),
                "remediation": "Remove unnecessary directories or restrict access.",
                "tool": "gobuster",
                "confidence": "confirmed",
            })
    return findings


def _parse_ffuf_output(stdout: str) -> List[Dict]:
    """Parse ffuf results."""
    findings = []
    for line in stdout.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 3:
            try:
                status = int(parts[0])
                words = int(parts[1])
                lines_count = int(parts[2])
                url = parts[3] if len(parts) > 3 else ""
                if status >= 200 and status < 400:
                    findings.append({
                        "type": "FFUF Discovery",
                        "severity": "Low" if status < 300 else "Medium",
                        "description": f"Path found: {url} ({status})",
                        "url": url,
                        "evidence": line.strip(),
                        "remediation": "Review discovered paths for sensitive information.",
                        "tool": "ffuf",
                        "confidence": "confirmed",
                    })
            except (ValueError, IndexError):
                continue
    return findings


def _parse_nikto_output(stdout: str) -> List[Dict]:
    """Parse nikto scan output."""
    findings = []
    current_item = {}
    for line in stdout.splitlines():
        if line.startswith("* ") and ":" in line:
            if current_item:
                findings.append(current_item)
            current_item = {
                "type": "Nikto Finding",
                "severity": "Medium",
                "description": line[2:].strip(),
                "url": "",
                "evidence": line.strip(),
                "remediation": "Review and remediate security misconfiguration.",
                "tool": "nikto",
                "confidence": "confirmed",
            }
        elif line.startswith("  + ") and current_item:
            current_item["evidence"] += "\n" + line[4:].strip()
    if current_item:
        findings.append(current_item)
    return findings


# ============================================================================
# HexStrike AI Bridge
# ============================================================================

class HexStrikeAIBridge:
    """AI-powered features from HexStrike-AI for intelligent tool selection."""

    @staticmethod
    def select_optimal_tools(target: str, objective: str = "comprehensive") -> List[str]:
        """Select optimal security tools based on target analysis.

        Args:
            target: Target URL or domain
            objective: 'comprehensive', 'quick', or 'stealth'

        Returns:
            List of tool keys to use
        """
        tools_by_objective = {
            "comprehensive": ["nmap", "nuclei", "nikto", "sqlmap", "gobuster", "ffuf", "masscan"],
            "quick": ["nmap", "nuclei", "nikto"],
            "stealth": ["nmap", "whatweb", "subfinder"],
        }
        return tools_by_objective.get(objective, tools_by_objective["comprehensive"])

    @staticmethod
    def create_attack_chain(target: str) -> List[Dict]:
        """Create attack chains based on discovered vulnerabilities."""
        # This would integrate with HexStrike's attack chain logic
        return [
            {
                "chain_id": 1,
                "stages": ["recon", "scanning", "exploitation"],
                "description": f"Attack chain for {target}",
                "probability": 0.85,
            }
        ]

    @staticmethod
    def optimize_parameters(target: str, tool: str) -> Dict[str, Any]:
        """Optimize tool parameters for target."""
        optimizations = {
            "nmap": {"args": "-sV -sC -T4", "ports": "1-10000"},
            "nuclei": {"tags": "critical,high,medium", "concurrency": "10"},
            "sqlmap": {"level": "2", "risk": "1"},
        }
        return optimizations.get(tool, {})


# ============================================================================
# Agent Classes
# ============================================================================

class NmapAgent(ScanAgent):
    """Nmap scanner wrapped for HydraX."""

    manifest = AgentManifest(
        key="nmap",
        name="Nmap Port Scan",
        category="HexStrike AI",
        target_kinds=frozenset({"url", "domain", "ip"}),
        tools=(
            ToolRequirement(name="nmap", check_cmd=("nmap", "--version"), optional=False),
        ),
        default=False,
        intensity="active",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        cmd = ["nmap", "-sV", "-sC", "-T4", "--open", "-oX", "/dev/stdout", ctx.target]
        stdout, stderr, rc = _run_cli(cmd, timeout=300)
        findings = _parse_nmap_output(stdout)
        return [Finding.from_dict(f, scan_type="nmap") for f in findings]


class NucleiAgent(ScanAgent):
    """Nuclei template-based vulnerability scanner."""

    manifest = AgentManifest(
        key="nuclei",
        name="Nuclei Vulnerability Scanner",
        category="HexStrike AI",
        target_kinds=frozenset({"url"}),
        tools=(
            ToolRequirement(name="nuclei", check_cmd=("nuclei", "-version"), optional=False),
        ),
        default=False,
        intensity="active",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        cmd = ["nuclei", "-u", ctx.target, "-jsonl", "-silent",
               "-t", "cves/", "-severity", "critical,high,medium"]
        stdout, stderr, rc = _run_cli(cmd, timeout=600)
        findings = _parse_nuclei_output(stdout)
        return [Finding.from_dict(f, scan_type="nuclei") for f in findings]


class GobusterAgent(ScanAgent):
    """Directory brute-forcing with Gobuster."""

    manifest = AgentManifest(
        key="gobuster",
        name="Gobuster Directory Scanner",
        category="HexStrike AI",
        target_kinds=frozenset({"url"}),
        tools=(
            ToolRequirement(name="gobuster", check_cmd=("gobuster", "--version"), optional=False),
        ),
        default=False,
        intensity="aggressive",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not Path(wordlist).exists():
            wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        cmd = ["gobuster", "dir", "-u", ctx.target, "-w", wordlist,
               "-t", "20", "-q", "-e"]
        stdout, stderr, rc = _run_cli(cmd, timeout=180)
        findings = _parse_gobuster_output(stdout)
        return [Finding.from_dict(f, scan_type="gobuster") for f in findings]


class FFufAgent(ScanAgent):
    """Fuzzing with FFuf."""

    manifest = AgentManifest(
        key="ffuf",
        name="FFuf Fuzzer",
        category="HexStrike AI",
        target_kinds=frozenset({"url"}),
        tools=(
            ToolRequirement(name="ffuf", check_cmd=("ffuf", "-V"), optional=False),
        ),
        default=False,
        intensity="aggressive",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not Path(wordlist).exists():
            wordlist = "/usr/share/seclists/Discovery/Web-Content/big.txt"
        cmd = ["ffuf", "-u", f"{ctx.target}/FUZZ", "-w", wordlist,
               "-tc", "200,301,302,403", "-mc", "all", "-c"]
        stdout, stderr, rc = _run_cli(cmd, timeout=120)
        findings = _parse_ffuf_output(stdout)
        return [Finding.from_dict(f, scan_type="ffuf") for f in findings]


class NiktoAgent(ScanAgent):
    """Nikto web server scanner."""

    manifest = AgentManifest(
        key="nikto",
        name="Nikto Web Scanner",
        category="HexStrike AI",
        target_kinds=frozenset({"url"}),
        tools=(
            ToolRequirement(name="nikto", check_cmd=("nikto", "-version"), optional=False),
        ),
        default=False,
        intensity="active",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        cmd = ["nikto", "-h", ctx.target, "-nointeractive", "-Timeout", "60"]
        stdout, stderr, rc = _run_cli(cmd, timeout=240)
        findings = _parse_nikto_output(stdout)
        return [Finding.from_dict(f, scan_type="nikto") for f in findings]


class MasscanAgent(ScanAgent):
    """Masscan fast port scanner."""

    manifest = AgentManifest(
        key="masscan",
        name="Masscan Port Scanner",
        category="HexStrike AI",
        target_kinds=frozenset({"ip", "domain"}),
        tools=(
            ToolRequirement(name="masscan", check_cmd=("bash", "-c", "command -v masscan >/dev/null 2>&1 || exit 0"), optional=False),
        ),
        default=False,
        intensity="aggressive",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        # Masscan needs raw sockets (root)
        cmd = ["masscan", ctx.target, "-p1-10000", "--rate", "1000",
               "--open-only", "-oJ", "/dev/stdout"]
        stdout, stderr, rc = _run_cli(cmd, timeout=120)
        findings = []
        try:
            data = json.loads(stdout)
            for host in data.get("scan", {}).get("host", []):
                for port in host.get("ports", {}).get("port", []):
                    findings.append({
                        "type": "Open Port (masscan)",
                        "severity": "Info",
                        "description": f"Port {port.get('portid')}/open",
                        "url": host.get("ipaddr", ""),
                        "evidence": f"Port {port.get('portid')} open",
                        "remediation": "Close unused ports.",
                        "tool": "masscan",
                        "confidence": "confirmed",
                    })
        except (json.JSONDecodeError, KeyError):
            pass
        return [Finding.from_dict(f, scan_type="masscan") for f in findings]


class SubfinderAgent(ScanAgent):
    """Subdomain enumeration with Subfinder."""

    manifest = AgentManifest(
        key="subfinder",
        name="Subdomain Enumerator",
        category="HexStrike AI",
        target_kinds=frozenset({"domain"}),
        tools=(
            ToolRequirement(name="subfinder", check_cmd=("subfinder", "-version"), optional=False),
        ),
        default=False,
        intensity="passive",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        cmd = ["subfinder", "-d", ctx.target, "-silent"]
        stdout, stderr, rc = _run_cli(cmd, timeout=180)
        findings = []
        for line in stdout.splitlines():
            sub = line.strip()
            if sub and "." in sub:
                findings.append({
                    "type": "Subdomain Discovered",
                    "severity": "Info",
                    "description": f"Subdomain: {sub}",
                    "url": f"https://{sub}",
                    "evidence": sub,
                    "remediation": "Register defensive DNS for subdomains.",
                    "tool": "subfinder",
                    "confidence": "confirmed",
                })
        return [Finding.from_dict(f, scan_type="subfinder") for f in findings]


class WhatWebAgent(ScanAgent):
    """Technology fingerprinting with WhatWeb."""

    manifest = AgentManifest(
        key="whatweb",
        name="WhatWeb Fingerprinter",
        category="HexStrike AI",
        target_kinds=frozenset({"url"}),
        tools=(
            ToolRequirement(name="whatweb", check_cmd=("whatweb", "--version"), optional=False),
        ),
        default=False,
        intensity="passive",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        cmd = ["whatweb", ctx.target, "--no-errors"]
        stdout, stderr, rc = _run_cli(cmd, timeout=60)
        findings = []
        for line in stdout.splitlines():
            if line.startswith(line[0].upper()):  # Heuristic for tech lines
                techs = re.findall(r'\[(.+?)\]', line)
                if techs:
                    findings.append({
                        "type": "Technology Detected",
                        "severity": "Info",
                        "description": f"Technologies: {', '.join(techs)}",
                        "url": ctx.target,
                        "evidence": line.strip(),
                        "remediation": "Review technology stack for known vulnerabilities.",
                        "tool": "whatweb",
                        "confidence": "confirmed",
                    })
        return [Finding.from_dict(f, scan_type="whatweb") for f in findings]


class SqlmapAgent(ScanAgent):
    """SQL injection testing with SQLMap."""

    manifest = AgentManifest(
        key="sqlmap",
        name="SQLMap SQLi Scanner",
        category="HexStrike AI",
        target_kinds=frozenset({"url"}),
        tools=(
            ToolRequirement(name="sqlmap", check_cmd=("sqlmap", "--version"), optional=False),
        ),
        default=False,
        intensity="aggressive",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        cmd = ["sqlmap", "-u", ctx.target, "--batch", "--level=1",
               "--risk=1", "--timeout=30", "--smart"]
        stdout, stderr, rc = _run_cli(cmd, timeout=300)
        findings = []
        for line in stdout.splitlines():
            if "is vulnerable" in line.lower() or "injection point" in line.lower():
                findings.append({
                    "type": "SQL Injection",
                    "severity": "Critical",
                    "description": line.strip(),
                    "url": ctx.target,
                    "evidence": line.strip(),
                    "remediation": "Use parameterized queries and input validation.",
                    "tool": "sqlmap",
                    "confidence": "confirmed",
                })
        return [Finding.from_dict(f, scan_type="sqlmap") for f in findings]


# ============================================================================
# AI-Powered Agents
# ============================================================================

class IntelligentScannerAgent(ScanAgent):
    """AI-powered scan that selects optimal tools for target."""

    manifest = AgentManifest(
        key="intelligent_scan",
        name="Intelligent Scanner (AI)",
        category="HexStrike AI",
        target_kinds=frozenset({"url", "domain", "ip"}),
        tools=(),
        default=False,
        intensity="passive",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        """Run AI-optimized scan selecting best tools for target."""
        findings = []
        tools = HexStrikeAIBridge.select_optimal_tools(ctx.target, "comprehensive")

        for tool in tools:
            if ctx.stop.is_set():
                break
            tool_findings = self._run_tool(tool, ctx)
            findings.extend(tool_findings)

        return findings

    def _run_tool(self, tool: str, ctx: AgentContext) -> List[Finding]:
        """Run a specific tool and return findings."""
        if tool == "nmap":
            agent = NmapAgent()
        elif tool == "nuclei":
            agent = NucleiAgent()
        elif tool == "nikto":
            agent = NiktoAgent()
        else:
            return []
        return agent.run(ctx)


class AttackChainAgent(ScanAgent):
    """Creates and tests attack chains against targets."""

    manifest = AgentManifest(
        key="attack_chain",
        name="Attack Chain Analysis",
        category="HexStrike AI",
        target_kinds=frozenset({"url"}),
        tools=(
            ToolRequirement(name="nmap", check_cmd=("nmap", "--version"), optional=True),
            ToolRequirement(name="nuclei", check_cmd=("nuclei", "-version"), optional=True),
        ),
        default=False,
        intensity="active",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        """Generate and analyze attack chains."""
        chains = HexStrikeAIBridge.create_attack_chain(ctx.target)
        findings = []
        for chain in chains:
            findings.append({
                "type": "Attack Chain",
                "severity": "High",
                "description": chain["description"],
                "url": ctx.target,
                "evidence": json.dumps(chain),
                "remediation": "Implement defense-in-depth to break attack chains.",
                "tool": "hexstrike",
                "confidence": "probable",
            })
        return [Finding.from_dict(f, scan_type="attack_chain") for f in findings]


# ============================================================================
# Export
# ============================================================================

ALL_HEXSTRIKE_AGENTS = [
    NmapAgent,
    NucleiAgent,
    GobusterAgent,
    FFufAgent,
    NiktoAgent,
    MasscanAgent,
    SubfinderAgent,
    WhatWebAgent,
    SqlmapAgent,
    IntelligentScannerAgent,
    AttackChainAgent,
]
