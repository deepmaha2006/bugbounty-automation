"""
Composite scan agents for HydraX chip keys that have no dedicated scanner:
  hexstrike  — orchestrates HexStrike tool-chain (nmap, nuclei, nikto + fallbacks)
  web        — full web-app scan (XSS, BAC, open-redirect, CSRF, file-upload)
  network    — network-level recon + port scanning
  headers    — security-headers / misconfiguration audit
  ssl        — SSL/TLS certificate and protocol checks

All agents are discovered automatically by agents/registry.py (file ends in _agent).
"""
from __future__ import annotations

import datetime
import logging
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List
from urllib.parse import urlparse

from agents.base import ScanAgent, AgentManifest, AgentContext
from core.models import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_scanner(cls, target: str, stop: threading.Event) -> List[Dict]:
    """Run a scanner class safely and return its vulnerability dicts."""
    from core.scan_context import ScanContext, set_scan_context, clear_scan_context
    sc = ScanContext(target)
    sc.stop_event = stop
    set_scan_context(sc)
    try:
        result = cls().scan(target)
        return result.get("vulnerabilities", [])
    except Exception as exc:
        logger.debug("%s error: %s", cls.__name__, exc)
        return []
    finally:
        clear_scan_context()


def _run_all(scanner_classes: list, target: str, ctx: AgentContext) -> List[Dict]:
    """Run scanner classes in parallel and merge findings."""
    findings: List[Dict] = []
    lock = threading.Lock()

    def _task(cls):
        if ctx.stop.is_set():
            return
        for f in _run_scanner(cls, target, ctx.stop):
            with lock:
                findings.append(f)

    n = max(1, min(len(scanner_classes), 4))
    try:
        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(_task, scanner_classes))
    except RuntimeError:
        pass
    return findings


def _to_finding(raw, scan_type: str) -> Finding:
    if isinstance(raw, Finding):
        return raw
    return Finding.from_dict(raw, scan_type=scan_type)


# ---------------------------------------------------------------------------
# HexStrike Orchestrator  (key="hexstrike")
# ---------------------------------------------------------------------------

class HexStrikeAgent(ScanAgent):
    """Orchestrates HexStrike toolkit: nuclei, nmap, nikto with Python fallbacks."""

    manifest = AgentManifest(
        key="hexstrike",
        name="HexStrike AI",
        category="HexStrike AI",
        target_kinds=frozenset({"url"}),
        tools=(),
        default=False,
        intensity="active",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        raw: List[Dict] = []

        # Attempt each HexStrike CLI sub-agent; skip gracefully if tool absent
        for agent_name in ("NucleiAgent", "NmapAgent", "NiktoAgent"):
            if ctx.stop.is_set():
                break
            try:
                import agents.hexstrike_agent as _hx
                agent_cls = getattr(_hx, agent_name)
                agent = agent_cls()
                for f in (agent.run(ctx) or []):
                    d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
                    d.setdefault("hexstrike_tool", agent_name)
                    raw.append(d)
            except Exception as exc:
                logger.debug("HexStrike %s: %s", agent_name, exc)

        # Fallback to pure-Python scanners when no CLI findings
        if not raw and not ctx.stop.is_set():
            try:
                from scanners.advanced_scanners import APIScanner, CloudScanner, SSRFScanner
                raw.extend(_run_all([APIScanner, CloudScanner, SSRFScanner], ctx.target, ctx))
            except Exception as exc:
                logger.debug("HexStrike fallback scanners: %s", exc)

        return [_to_finding(f, "hexstrike") for f in raw]


# ---------------------------------------------------------------------------
# Web Application Agent  (key="web")
# ---------------------------------------------------------------------------

class WebScanAgent(ScanAgent):
    """Full web-app vulnerability scan: XSS, BAC, open-redirect, CSRF, file-upload."""

    manifest = AgentManifest(
        key="web",
        name="Web Scan",
        category="Web Application Security",
        target_kinds=frozenset({"url"}),
        tools=(),
        default=False,
        intensity="active",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        from scanners.xss_scanner import XSSScanner
        from scanners.broken_access import BrokenAccessScanner
        from scanners.advanced_scanners import (
            OpenRedirectScanner, CSRFTester, FileUploadScanner,
            AuthSessionScanner, BusinessLogicScanner,
        )
        raw = _run_all(
            [XSSScanner, BrokenAccessScanner, OpenRedirectScanner,
             CSRFTester, FileUploadScanner, AuthSessionScanner, BusinessLogicScanner],
            ctx.target, ctx,
        )
        return [_to_finding(f, "web") for f in raw]


# ---------------------------------------------------------------------------
# Network Scanner Agent  (key="network")
# ---------------------------------------------------------------------------

class NetworkScanAgent(ScanAgent):
    """Network-level scanning: passive recon, port scan (nmap if available), info-disclosure."""

    manifest = AgentManifest(
        key="network",
        name="Network",
        category="Network, Cloud & Recon",
        target_kinds=frozenset({"url"}),
        tools=(),
        default=False,
        intensity="active",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        raw: List[Dict] = []

        # Passive recon (DNS, WHOIS, SSL fingerprint)
        try:
            from scanners.passive_recon import PassiveRecon
            raw.extend(_run_scanner(PassiveRecon, ctx.target, ctx.stop))
        except Exception as exc:
            logger.debug("NetworkScan PassiveRecon: %s", exc)

        # Nmap via sub-agent (skipped gracefully if nmap not installed)
        if not ctx.stop.is_set():
            try:
                from agents.hexstrike_agent import NmapAgent
                for f in (NmapAgent().run(ctx) or []):
                    d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
                    raw.append(d)
            except Exception as exc:
                logger.debug("NetworkScan NmapAgent: %s", exc)

        # Info disclosure (exposed secrets, .git, API keys)
        if not ctx.stop.is_set():
            try:
                from scanners.advanced_scanners import APIScanner
                raw.extend(_run_scanner(APIScanner, ctx.target, ctx.stop))
            except Exception as exc:
                logger.debug("NetworkScan APIScanner: %s", exc)

        return [_to_finding(f, "network") for f in raw]


# ---------------------------------------------------------------------------
# Security Headers Agent  (key="headers")
# ---------------------------------------------------------------------------

class HeadersAgent(ScanAgent):
    """Security headers / misconfiguration audit: CSP, HSTS, X-Frame-Options, CORS."""

    manifest = AgentManifest(
        key="headers",
        name="Headers",
        category="Access Control & Misconfiguration",
        target_kinds=frozenset({"url"}),
        tools=(),
        default=False,
        intensity="passive",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        from scanners.security_misconfig import SecurityMisconfigScanner
        from scanners.advanced_scanners import ClickjackTester
        raw = _run_all([SecurityMisconfigScanner, ClickjackTester], ctx.target, ctx)
        return [_to_finding(f, "headers") for f in raw]


# ---------------------------------------------------------------------------
# SSL/TLS Agent  (key="ssl")
# ---------------------------------------------------------------------------

class SSLScanAgent(ScanAgent):
    """SSL/TLS checks: cert validity & expiry, protocol versions, cipher strength."""

    manifest = AgentManifest(
        key="ssl",
        name="SSL/TLS",
        category="Network, Cloud & Recon",
        target_kinds=frozenset({"url"}),
        tools=(),
        default=False,
        intensity="passive",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        target = ctx.target
        raw: List[Dict] = []

        parsed = urlparse(target if "://" in target else f"https://{target}")
        hostname = parsed.hostname or target
        port = parsed.port or 443
        if parsed.scheme == "http" and not parsed.port:
            # Plain HTTP — no SSL to check; report as informational
            raw.append({
                "type": "No SSL/TLS",
                "severity": "Medium",
                "description": "Target is served over plain HTTP — no TLS encryption",
                "url": target,
                "evidence": "Scheme: http",
                "remediation": "Configure HTTPS with a valid certificate",
                "tool": "ssl_check",
            })
            return [_to_finding(f, "ssl") for f in raw]

        try:
            ctx_ssl = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=hostname) as tls:
                    cert = tls.getpeercert()
                    proto = tls.version()
                    cipher_name, _, bits = tls.cipher()

                    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
                        raw.append({
                            "type": "Deprecated TLS Protocol",
                            "severity": "High",
                            "description": f"Server supports deprecated protocol {proto}",
                            "url": target,
                            "evidence": f"Connected with {proto}",
                            "remediation": "Disable TLS 1.0/1.1; require TLS 1.2+",
                            "tool": "ssl_check",
                        })

                    if bits and bits < 128:
                        raw.append({
                            "type": "Weak Cipher Suite",
                            "severity": "High",
                            "description": f"Weak cipher in use: {cipher_name} ({bits}-bit)",
                            "url": target,
                            "evidence": f"Cipher: {cipher_name}, bits: {bits}",
                            "remediation": "Enforce AES-GCM 128-bit+ cipher suites",
                            "tool": "ssl_check",
                        })

                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days = (exp - datetime.datetime.utcnow()).days
                            if days < 30:
                                sev = "Critical" if days < 7 else "High" if days < 14 else "Medium"
                                raw.append({
                                    "type": "SSL Certificate Expiring Soon",
                                    "severity": sev,
                                    "description": f"Certificate expires in {days} days ({not_after})",
                                    "url": target,
                                    "evidence": f"notAfter: {not_after}",
                                    "remediation": "Renew the SSL certificate before expiry",
                                    "tool": "ssl_check",
                                })
                        except Exception:
                            pass

        except ssl.SSLError as exc:
            raw.append({
                "type": "SSL Handshake Failure",
                "severity": "High",
                "description": f"SSL/TLS handshake failed: {exc}",
                "url": target,
                "evidence": str(exc),
                "remediation": "Review and fix SSL/TLS server configuration",
                "tool": "ssl_check",
            })
        except (socket.timeout, socket.gaierror, OSError) as exc:
            logger.debug("SSL scan connection error (%s): %s", target, exc)
        except Exception as exc:
            logger.debug("SSL scan unexpected error (%s): %s", target, exc)

        return [_to_finding(f, "ssl") for f in raw]


ALL_COMPOSITE_AGENTS = [
    HexStrikeAgent,
    WebScanAgent,
    NetworkScanAgent,
    HeadersAgent,
    SSLScanAgent,
]
