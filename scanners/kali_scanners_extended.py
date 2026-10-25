"""Extended Kali scanners for HexStrike AI integration.

These wrappers provide the standard scan(target) -> {"vulnerabilities": [...]} interface
so the agent layer can use the identical ScanContext bridge pattern.
The actual execution is delegated to webapp/services/kali_tools.py or direct CLI calls.
"""
import json
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


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


def _parse_gobuster_output(stdout: str) -> List[Dict]:
    """Parse gobuster directory scan output."""
    findings = []
    for line in stdout.splitlines():
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
        if len(parts) >= 4:
            try:
                status = int(parts[0])
                url = parts[3]
                if 200 <= status < 400:
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


def _parse_masscan_output(stdout: str) -> List[Dict]:
    """Parse masscan JSON output."""
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
    return findings


def _parse_subfinder_output(stdout: str) -> List[Dict]:
    """Parse subfinder output."""
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
    return findings


def _parse_whatweb_output(stdout: str) -> List[Dict]:
    """Parse whatweb output."""
    findings = []
    for line in stdout.splitlines():
        if line and '[' in line and ']' in line:
            techs = re.findall(r'\[(.+?)\]', line)
            if techs:
                findings.append({
                    "type": "Technology Detected",
                    "severity": "Info",
                    "description": f"Technologies: {', '.join(techs)}",
                    "url": "",
                    "evidence": line.strip(),
                    "remediation": "Review technology stack for known vulnerabilities.",
                    "tool": "whatweb",
                    "confidence": "confirmed",
                })
    return findings


# ============================================================================
# Scanner Classes
# ============================================================================

class GobusterScanner:
    """Run Gobuster directory scanner against a URL."""

    def scan(self, target: str) -> Dict[str, List[Dict]]:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not Path(wordlist).exists():
            wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        cmd = ["gobuster", "dir", "-u", target, "-w", wordlist, "-t", "20", "-q", "-e"]
        stdout, stderr, rc = _run_cli(cmd, timeout=180)
        findings = _parse_gobuster_output(stdout)
        return {"vulnerabilities": findings}


class FFufScanner:
    """Run FFuf fuzzer against a URL."""

    def scan(self, target: str) -> Dict[str, List[Dict]]:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not Path(wordlist).exists():
            wordlist = "/usr/share/seclists/Discovery/Web-Content/big.txt"
        cmd = ["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist, "-tc", "200,301,302,403", "-mc", "all", "-c"]
        stdout, stderr, rc = _run_cli(cmd, timeout=120)
        findings = _parse_ffuf_output(stdout)
        return {"vulnerabilities": findings}


class NiktoScanner:
    """Run Nikto web server scanner against a URL."""

    def scan(self, target: str) -> Dict[str, List[Dict]]:
        cmd = ["nikto", "-h", target, "-nointeractive", "-Timeout", "60"]
        stdout, stderr, rc = _run_cli(cmd, timeout=240)
        findings = _parse_nikto_output(stdout)
        return {"vulnerabilities": findings}


class MasscanScanner:
    """Run Masscan fast port scanner against a target."""

    def scan(self, target: str) -> Dict[str, List[Dict]]:
        cmd = ["masscan", target, "-p1-10000", "--rate", "1000", "--open-only", "-oJ", "/dev/stdout"]
        stdout, stderr, rc = _run_cli(cmd, timeout=120)
        findings = _parse_masscan_output(stdout)
        return {"vulnerabilities": findings}


class SubfinderScanner:
    """Run Subfinder for subdomain enumeration."""

    def scan(self, target: str) -> Dict[str, List[Dict]]:
        # Extract domain from URL if needed
        domain = target
        if domain.startswith("http"):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc
            if ":" in domain:
                domain = domain.split(":")[0]
        cmd = ["subfinder", "-d", domain, "-silent"]
        stdout, stderr, rc = _run_cli(cmd, timeout=180)
        findings = _parse_subfinder_output(stdout)
        return {"vulnerabilities": findings}


class WhatWebScanner:
    """Run WhatWeb for technology fingerprinting."""

    def scan(self, target: str) -> Dict[str, List[Dict]]:
        cmd = ["whatweb", target, "--no-errors"]
        stdout, stderr, rc = _run_cli(cmd, timeout=60)
        findings = _parse_whatweb_output(stdout)
        return {"vulnerabilities": findings}


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "GobusterScanner",
    "FFufScanner",
    "NiktoScanner",
    "MasscanScanner",
    "SubfinderScanner",
    "WhatWebScanner",
]