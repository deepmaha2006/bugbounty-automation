"""
Shannon AI Pentester — native Python implementation.

Implements Shannon's five-phase pentest pipeline directly in Python using
HydraX's existing infrastructure.  No external CLI, no Docker, no API key.

  Phase 1: Pre-Recon   — fingerprint target, gather attack surface
  Phase 2: Recon       — deep crawl, parameter discovery
  Phase 3: Vuln Scan   — parallel scanner execution (5 agents)
  Phase 4: Correlation — AI-assisted finding enrichment & chain building
  Phase 5: Report      — structured JSON + markdown output

Local LLM (Ollama) powers phases 4-5. Falls back gracefully when Ollama
is not running — phases 1-3 still produce full findings.
"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.base import ScanAgent, AgentManifest, AgentContext, ToolRequirement
from core.models import Finding

logger = logging.getLogger(__name__)

_WORKSPACE_ROOT = Path(__file__).resolve().parent.parent / "pentest_workspaces" / "shannon"


def _workspace(target: str) -> Path:
    safe = target.replace("://", "_").replace("/", "_").replace(":", "_")[:60]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    p = _WORKSPACE_ROOT / f"{safe}_{ts}"
    p.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# Phase helpers
# ---------------------------------------------------------------------------

def _phase_recon(target: str, ctx: AgentContext) -> List[Dict]:
    """Phase 1+2: Passive + active recon via existing PassiveRecon scanner."""
    findings: List[Dict] = []
    try:
        from scanners.passive_recon import PassiveRecon
        from core.scan_context import ScanContext, set_scan_context, clear_scan_context
        sc = ScanContext(target)
        sc.stop_event = ctx.stop
        set_scan_context(sc)
        try:
            scanner = PassiveRecon()
            results = scanner.scan(target)
            for v in results.get("vulnerabilities", []):
                v["shannon_phase"] = "recon"
                findings.append(v)
        finally:
            clear_scan_context()
    except Exception as exc:
        logger.debug("Shannon recon phase error: %s", exc)
    return findings


def _phase_vuln(target: str, ctx: AgentContext) -> List[Dict]:
    """Phase 3: Parallel vulnerability analysis — XSS, SQLi, SSRF, Auth, BAC."""
    from core.scan_context import ScanContext, set_scan_context, clear_scan_context
    from scanners.xss_scanner import XSSScanner
    from scanners.sql_injection import SQLInjectionScanner
    from scanners.advanced_scanners import SSRFScanner, AuthSessionScanner
    from scanners.broken_access import BrokenAccessScanner

    scanner_classes = [
        XSSScanner,
        SQLInjectionScanner,
        SSRFScanner,
        AuthSessionScanner,
        BrokenAccessScanner,
    ]

    all_findings: List[Dict] = []
    lock = threading.Lock()

    def _run_one(cls):
        if ctx.stop.is_set():
            return
        sc = ScanContext(target)
        sc.stop_event = ctx.stop
        set_scan_context(sc)
        try:
            results = cls().scan(target)
            for v in results.get("vulnerabilities", []):
                v["shannon_phase"] = "vuln_analysis"
                with lock:
                    all_findings.append(v)
        except Exception as exc:
            logger.debug("Shannon vuln phase (%s) error: %s", cls.__name__, exc)
        finally:
            clear_scan_context()

    try:
        with ThreadPoolExecutor(max_workers=5) as pool:
            list(pool.map(_run_one, scanner_classes))
    except RuntimeError:
        # Interpreter shutdown — return whatever was collected so far
        pass

    return all_findings


def _phase_correlate(findings: List[Dict], target: str) -> List[Dict]:
    """Phase 4: AI-assisted correlation — CVE tags, severity escalation."""
    try:
        from brain.cve_db import enrich_with_cve
        from brain.vuln_brain import brain
        enriched = [enrich_with_cve(brain.enrich_finding(f)) for f in findings]
        return enriched
    except Exception as exc:
        logger.debug("Shannon correlate phase error: %s", exc)
        return findings


def _phase_report(
    findings: List[Dict], target: str, workspace: Path
) -> Optional[str]:
    """Phase 5: Generate structured report in workspace."""
    try:
        from brain.vuln_brain import brain
        triage = brain.analyze(findings, target)

        report = {
            "target":      target,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "risk_score":  triage.risk_score,
            "total":       triage.total,
            "critical":    triage.critical,
            "high":        triage.high,
            "owasp":       triage.owasp_hits,
            "summary":     triage.ai_summary,
            "attack_chain": [
                {"step": s.step, "action": s.action, "severity": s.severity}
                for s in triage.attack_chain
            ],
            "findings": findings,
        }

        import json
        report_path = workspace / "shannon_report.json"
        report_path.write_text(json.dumps(report, indent=2, default=str))
        logger.info("Shannon report saved: %s", report_path)
        return str(report_path)
    except Exception as exc:
        logger.debug("Shannon report phase error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class ShannonPentestAgent(ScanAgent):
    """Native 5-phase AI pentest pipeline — no external CLI or API key."""

    manifest = AgentManifest(
        key="shannon",
        name="Shannon AI Pentester",
        category="Shannon AI Pentester",
        target_kinds=frozenset({"url"}),
        tools=(),
        payload_sets=(),
        default=False,
        intensity="active",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        target = ctx.target
        workspace = _workspace(target)
        logger.info("Shannon pipeline starting: target=%s workspace=%s", target, workspace)

        all_raw: List[Dict] = []

        # Phase 1+2: Recon
        if not ctx.stop.is_set():
            logger.info("Shannon Phase 1+2: Recon")
            all_raw.extend(_phase_recon(target, ctx))

        # Phase 3: Vulnerability analysis
        if not ctx.stop.is_set():
            logger.info("Shannon Phase 3: Vulnerability scan (5 parallel agents)")
            all_raw.extend(_phase_vuln(target, ctx))

        # Phase 4: Correlation + enrichment
        if not ctx.stop.is_set():
            logger.info("Shannon Phase 4: AI correlation")
            all_raw = _phase_correlate(all_raw, target)

        # Phase 5: Report
        if not ctx.stop.is_set():
            logger.info("Shannon Phase 5: Report generation")
            _phase_report(all_raw, target, workspace)

        return [Finding.from_dict(f, scan_type="shannon") for f in all_raw]


class ShannonStatusAgent(ScanAgent):
    """List completed Shannon workspace reports."""

    manifest = AgentManifest(
        key="shannon_status",
        name="Shannon Status",
        category="Shannon AI Pentester",
        target_kinds=frozenset(),
        tools=(),
        default=False,
        intensity="passive",
    )

    def run(self, ctx: AgentContext) -> List[Finding]:
        findings: List[Finding] = []
        if not _WORKSPACE_ROOT.exists():
            return findings
        for report in sorted(_WORKSPACE_ROOT.rglob("shannon_report.json"))[-10:]:
            try:
                import json
                data = json.loads(report.read_text())
                findings.append(Finding.from_dict({
                    "type":        "Shannon Report",
                    "severity":    "Info",
                    "description": f"Risk score {data.get('risk_score',0)} — {data.get('total',0)} findings",
                    "url":         data.get("target", ""),
                    "evidence":    str(report),
                    "remediation": "",
                    "tool":        "shannon",
                    "confidence":  "confirmed",
                }, scan_type="shannon_status"))
            except Exception:
                pass
        return findings


ALL_SHANNON_AGENTS = [ShannonPentestAgent, ShannonStatusAgent]
