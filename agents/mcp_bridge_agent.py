"""
HexStrike AI agents — local in-process implementation.

Replaces the old MCP HTTP bridge (port 8888) with direct calls to
tools/hexstrike_local.py.  No server, no port, no Docker, zero dependencies
beyond what HydraX already ships.

Agents:
  HexStrikeVulnScanAgent   — payload + scan suite generation
  HexStrikePayloadAgent    — per-type payload packs
  HexStrikeAttackChainAgent — AI-assisted attack chain via brain
  HexStrikeIntelligentAgent — full intelligent scan (local equivalent)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from agents.base import ScanAgent, AgentManifest, AgentContext
from core.models import Finding

logger = logging.getLogger(__name__)


def _hex_payloads(attack_type: str, target: str) -> List[Dict]:
    try:
        from tools.hexstrike_local import ai_generate_payload_local
        result = ai_generate_payload_local(attack_type=attack_type, url=target)
        return result.get("payloads", [])
    except Exception as exc:
        logger.debug("hexstrike payload gen failed (%s): %s", attack_type, exc)
        return []


def _finding(title: str, desc: str, sev: str, url: str, evidence: str, tool: str) -> Finding:
    return Finding.from_dict({
        "type":        title,
        "severity":    sev,
        "description": desc,
        "url":         url,
        "evidence":    evidence,
        "remediation": "",
        "tool":        tool,
        "confidence":  "confirmed",
    }, scan_type="hexstrike")


# ---------------------------------------------------------------------------
# Agent 1: Vulnerability Scan (payload suite approach)
# ---------------------------------------------------------------------------

class HexStrikeVulnScanAgent(ScanAgent):
    """Run all local payload suites and report what the target echoes back."""

    manifest = AgentManifest(
        key="hexstrike_vuln",
        name="HexStrike Vuln Scan",
        category="HexStrike AI",
        target_kinds=frozenset({"url"}),
        tools=(),
        default=False,
        intensity="active",
    )

    _ATTACK_TYPES = ["sqli", "xss", "ssrf", "rce", "lfi"]

    def run(self, ctx: AgentContext) -> List[Finding]:
        import requests

        findings: List[Finding] = []
        session = requests.Session()
        session.verify = False

        for atype in self._ATTACK_TYPES:
            if ctx.stop.is_set():
                break
            for payload in _hex_payloads(atype, ctx.target):
                if ctx.stop.is_set():
                    break
                raw = payload.get("payload", "")
                desc = payload.get("description", atype)
                risk = payload.get("risk", "medium").capitalize()

                probe_url = f"{ctx.target}?q={requests.utils.quote(raw, safe='')}"
                try:
                    resp = session.get(probe_url, timeout=8, allow_redirects=True)
                    if raw.lower() in resp.text.lower():
                        findings.append(_finding(
                            title=f"{atype.upper()} Reflection Detected",
                            desc=desc,
                            sev=risk,
                            url=probe_url,
                            evidence=f"Payload reflected in response: {raw[:80]}",
                            tool="hexstrike_vuln",
                        ))
                except Exception:
                    pass

        return findings


# ---------------------------------------------------------------------------
# Agent 2: Payload Generator (informational, no HTTP)
# ---------------------------------------------------------------------------

class HexStrikePayloadAgent(ScanAgent):
    """Enumerate payload suites — informational finding per type."""

    manifest = AgentManifest(
        key="hexstrike_payloads",
        name="HexStrike Payload Generator",
        category="HexStrike AI",
        target_kinds=frozenset({"url"}),
        tools=(),
        default=False,
        intensity="passive",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        findings: List[Finding] = []
        for atype in ["sqli", "xss", "ssrf", "rce", "lfi"]:
            if ctx.stop.is_set():
                break
            payloads = _hex_payloads(atype, ctx.target)
            if payloads:
                findings.append(_finding(
                    title=f"HexStrike {atype.upper()} Payload Pack",
                    desc=f"{len(payloads)} test payloads generated for {atype}",
                    sev="Info",
                    url=ctx.target,
                    evidence="; ".join(p.get("payload", "")[:40] for p in payloads[:3]),
                    tool="hexstrike_payloads",
                ))
        return findings


# ---------------------------------------------------------------------------
# Agent 3: Attack Chain (uses VulnBrain)
# ---------------------------------------------------------------------------

class HexStrikeAttackChainAgent(ScanAgent):
    """Build an AI attack chain from prior scan findings via VulnBrain."""

    manifest = AgentManifest(
        key="hexstrike_attack_chain",
        name="HexStrike Attack Chain",
        category="HexStrike AI",
        target_kinds=frozenset({"url"}),
        tools=(),
        default=False,
        intensity="passive",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        try:
            from brain.vuln_brain import brain
            history = brain.scan_history()
            recent = [h for h in history if h.get("target") == ctx.target][-5:]
            if not recent:
                return []

            patterns = brain.top_patterns(n=5)
            chain_desc = " → ".join(p for p, _ in patterns) if patterns else "No patterns yet"

            return [_finding(
                title="Attack Chain Blueprint",
                desc=f"Top vulnerability chain for {ctx.target}: {chain_desc}",
                sev="High",
                url=ctx.target,
                evidence=f"Based on {len(recent)} prior scans. Top patterns: {patterns[:3]}",
                tool="hexstrike_attack_chain",
            )]
        except Exception as exc:
            logger.debug("attack chain error: %s", exc)
            return []


# ---------------------------------------------------------------------------
# Agent 4: Intelligent Scan (local tool dispatch)
# ---------------------------------------------------------------------------

class HexStrikeIntelligentAgent(ScanAgent):
    """Run locally available tools (nuclei, sqlmap, etc.) intelligently."""

    manifest = AgentManifest(
        key="hexstrike_intelligent",
        name="HexStrike Intelligent Scan",
        category="HexStrike AI",
        target_kinds=frozenset({"url"}),
        tools=(),
        default=False,
        intensity="active",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        findings: List[Finding] = []
        try:
            from tools.hexstrike_local import nuclei_scan_local, whatweb_scan_local
        except ImportError:
            return findings

        if ctx.stop.is_set():
            return findings

        # Fingerprint first
        try:
            ww = whatweb_scan_local(ctx.target)
            for tech in ww.get("technologies", []):
                findings.append(_finding(
                    title="Technology Detected",
                    desc=f"WhatWeb fingerprint: {tech}",
                    sev="Info",
                    url=ctx.target,
                    evidence=tech,
                    tool="whatweb",
                ))
        except Exception:
            pass

        if ctx.stop.is_set():
            return findings

        # Nuclei CVE scan
        try:
            nuc = nuclei_scan_local(ctx.target)
            for f in nuc.get("findings", []):
                findings.append(_finding(
                    title=f.get("title", "Nuclei Finding"),
                    desc=f.get("description", ""),
                    sev=f.get("severity", "Medium").capitalize(),
                    url=f.get("url", ctx.target),
                    evidence=f.get("evidence", ""),
                    tool="nuclei",
                ))
        except Exception:
            pass

        return findings


ALL_HEXSTRIKE_AGENTS = [
    HexStrikeVulnScanAgent,
    HexStrikePayloadAgent,
    HexStrikeAttackChainAgent,
    HexStrikeIntelligentAgent,
]
