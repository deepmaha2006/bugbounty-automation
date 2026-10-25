"""
VulnBrain — autonomous SOC analyst brain for HydraX.

Combines deterministic heuristics with local LLM analysis (no external API).
Runs post-scan to:
  1. Correlate findings into attack chains
  2. Score and prioritize by exploitability
  3. Suggest targeted remediation
  4. Learn from repeated finding patterns across scans

All state is persisted to memory/vuln_brain.json and survives restarts.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_STATE_FILE = Path(__file__).resolve().parent.parent / "memory" / "vuln_brain.json"

# ---------------------------------------------------------------------------
# Severity → numeric exploitability score (0–100)
# ---------------------------------------------------------------------------
_SEV_SCORE: Dict[str, int] = {
    "Critical": 95,
    "High":     75,
    "Medium":   50,
    "Low":      25,
    "Info":     5,
}

# Known critical vuln patterns that should auto-escalate
_ESCALATION_PATTERNS: List[Tuple[str, str]] = [
    ("SQL Injection", "Critical"),
    ("Remote Code Execution", "Critical"),
    ("Command Injection", "Critical"),
    ("Server-Side Request Forgery", "High"),
    ("Broken Access Control", "High"),
    ("IDOR", "High"),
    ("Authentication Bypass", "Critical"),
    ("XXE", "High"),
    ("Deserialization", "Critical"),
    ("Path Traversal", "High"),
    ("File Inclusion", "High"),
    ("Open Redirect", "Medium"),
    ("XSS", "High"),
    ("CSRF", "Medium"),
    ("Clickjacking", "Low"),
    ("Information Disclosure", "Medium"),
    ("Subdomain Takeover", "High"),
]

# OWASP Top 10 2021 mapping
_OWASP_MAP: Dict[str, str] = {
    "SQL Injection":             "A03:2021 – Injection",
    "XSS":                       "A03:2021 – Injection",
    "Cross-Site Scripting":      "A03:2021 – Injection",
    "Command Injection":         "A03:2021 – Injection",
    "SSRF":                      "A10:2021 – SSRF",
    "Server-Side Request Forgery": "A10:2021 – SSRF",
    "Broken Access Control":     "A01:2021 – Broken Access Control",
    "IDOR":                      "A01:2021 – Broken Access Control",
    "Insecure Design":           "A04:2021 – Insecure Design",
    "Security Misconfiguration": "A05:2021 – Security Misconfiguration",
    "Cryptographic Failure":     "A02:2021 – Cryptographic Failures",
    "Authentication":            "A07:2021 – Identification & Auth Failures",
    "Session Management":        "A07:2021 – Identification & Auth Failures",
    "XXE":                       "A05:2021 – Security Misconfiguration",
    "Deserialization":           "A08:2021 – Software & Data Integrity",
    "Prototype Pollution":       "A08:2021 – Software & Data Integrity",
    "Subdomain Takeover":        "A01:2021 – Broken Access Control",
    "Open Redirect":             "A01:2021 – Broken Access Control",
    "File Upload":               "A04:2021 – Insecure Design",
    "CSRF":                      "A01:2021 – Broken Access Control",
    "Information Disclosure":    "A02:2021 – Cryptographic Failures",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AttackChainStep:
    step:        int
    action:      str
    vuln_type:   str
    severity:    str
    url:         str = ""


@dataclass
class TriageReport:
    target:        str
    total:         int
    critical:      int
    high:          int
    risk_score:    int          # 0-100
    owasp_hits:    List[str]
    attack_chain:  List[AttackChainStep]
    ai_summary:    str
    timestamp:     str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Brain
# ---------------------------------------------------------------------------

class VulnBrain:
    """Autonomous vulnerability analysis and learning engine.

    Thread-safe.  All public methods may be called from any thread.
    """

    def __init__(self, state_file: Path = _STATE_FILE):
        self._lock = threading.Lock()
        self._state_file = state_file
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state: Dict[str, Any] = self._load_state()

        # Lazy LLM — only imported when used so the brain works without Ollama.
        self._llm: Any = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, findings: List[Dict[str, Any]], target: str) -> TriageReport:
        """Full analysis: score + chain + LLM summary.  Returns TriageReport."""
        counts = Counter(f.get("severity", "Info") for f in findings)
        risk = self._risk_score(findings)
        owasp = self._owasp_hits(findings)
        chain = self._build_attack_chain(findings, target)

        ai_summary = ""
        if findings:
            ai_summary = self._llm_triage(findings, target)

        # Persist learning
        self._record_scan(target, findings, risk)

        return TriageReport(
            target=target,
            total=len(findings),
            critical=counts.get("Critical", 0),
            high=counts.get("High", 0),
            risk_score=risk,
            owasp_hits=owasp,
            attack_chain=chain,
            ai_summary=ai_summary,
        )

    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Add OWASP tag, escalated severity, and AI remediation to a finding."""
        f = dict(finding)
        vuln_type = f.get("type", "")

        # Deterministic OWASP tag
        owasp = self._owasp_tag(vuln_type)
        if owasp:
            f["owasp"] = owasp

        # Deterministic severity escalation
        new_sev = self._escalate_severity(vuln_type, f.get("severity", "Info"))
        if new_sev != f.get("severity"):
            f["severity"] = new_sev
            f["severity_escalated"] = True

        # AI remediation (non-blocking — empty string on LLM failure)
        ai_remed = self._llm_finding(f)
        if ai_remed:
            f["ai_remediation"] = ai_remed

        return f

    def top_patterns(self, n: int = 5) -> List[Tuple[str, int]]:
        """Return the n most frequently seen vuln types across all scans."""
        with self._lock:
            counts: Counter = Counter(self._state.get("type_counts", {}))
        return counts.most_common(n)

    def scan_history(self) -> List[Dict[str, Any]]:
        """Return scan history records (target, timestamp, risk_score, count)."""
        with self._lock:
            return list(self._state.get("scan_history", []))

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def _risk_score(self, findings: List[Dict]) -> int:
        """Weighted risk score 0–100."""
        if not findings:
            return 100
        penalty = 0
        for f in findings:
            sev = f.get("severity", "Info")
            penalty += _SEV_SCORE.get(sev, 5)
        # Normalize: each critical = -10 from 100, cap at 0
        return max(0, 100 - min(100, penalty // max(1, len(findings))))

    def _owasp_hits(self, findings: List[Dict]) -> List[str]:
        hits: set[str] = set()
        for f in findings:
            tag = self._owasp_tag(f.get("type", ""))
            if tag:
                hits.add(tag)
        return sorted(hits)

    def _owasp_tag(self, vuln_type: str) -> str:
        for key, tag in _OWASP_MAP.items():
            if key.lower() in vuln_type.lower():
                return tag
        return ""

    def _escalate_severity(self, vuln_type: str, current: str) -> str:
        for pattern, forced_sev in _ESCALATION_PATTERNS:
            if pattern.lower() in vuln_type.lower():
                # Only escalate, never downgrade
                if _SEV_SCORE.get(forced_sev, 0) > _SEV_SCORE.get(current, 0):
                    return forced_sev
        return current

    def _build_attack_chain(
        self, findings: List[Dict], target: str
    ) -> List[AttackChainStep]:
        """Deterministic chain: recon → initial access → privilege escalation → exfil."""
        step_order = ["Info", "Low", "Medium", "High", "Critical"]
        sorted_findings = sorted(
            findings,
            key=lambda f: step_order.index(f.get("severity", "Info")) if f.get("severity", "Info") in step_order else 0
        )

        chain: List[AttackChainStep] = []
        step = 1

        # Phase 1: Recon (Info/Low)
        for f in sorted_findings:
            if f.get("severity") in ("Info", "Low") and len(chain) < 2:
                chain.append(AttackChainStep(
                    step=step,
                    action=f"Recon: {f.get('type', 'Discovery')}",
                    vuln_type=f.get("type", ""),
                    severity=f.get("severity", "Info"),
                    url=f.get("url", target),
                ))
                step += 1

        # Phase 2: Initial access (Medium/High)
        for f in sorted_findings:
            if f.get("severity") in ("Medium", "High") and len(chain) < 5:
                chain.append(AttackChainStep(
                    step=step,
                    action=f"Exploit: {f.get('type', 'Vulnerability')}",
                    vuln_type=f.get("type", ""),
                    severity=f.get("severity", "Medium"),
                    url=f.get("url", target),
                ))
                step += 1

        # Phase 3: Critical impact
        for f in sorted_findings:
            if f.get("severity") == "Critical" and len(chain) < 8:
                chain.append(AttackChainStep(
                    step=step,
                    action=f"Critical: {f.get('type', 'Impact')}",
                    vuln_type=f.get("type", ""),
                    severity="Critical",
                    url=f.get("url", target),
                ))
                step += 1

        return chain

    # ------------------------------------------------------------------
    # LLM integration (graceful no-op when Ollama is down)
    # ------------------------------------------------------------------

    def _get_llm(self):
        if self._llm is None:
            try:
                from ai.local_llm import llm
                self._llm = llm
            except ImportError:
                self._llm = False
        return self._llm if self._llm else None

    def _llm_triage(self, findings: List[Dict], target: str) -> str:
        llm = self._get_llm()
        if not llm:
            return ""
        try:
            return llm.triage_findings(findings)
        except Exception as exc:
            logger.debug("LLM triage failed: %s", exc)
            return ""

    def _llm_finding(self, finding: Dict) -> str:
        llm = self._get_llm()
        if not llm:
            return ""
        try:
            return llm.analyze_finding(finding)
        except Exception as exc:
            logger.debug("LLM finding enrichment failed: %s", exc)
            return ""

    # ------------------------------------------------------------------
    # Persistence / learning
    # ------------------------------------------------------------------

    def _load_state(self) -> Dict[str, Any]:
        if self._state_file.exists():
            try:
                return json.loads(self._state_file.read_text())
            except Exception:
                pass
        return {"type_counts": {}, "scan_history": []}

    def _save_state(self) -> None:
        try:
            self._state_file.write_text(json.dumps(self._state, indent=2))
        except Exception as exc:
            logger.debug("Brain state save failed: %s", exc)

    def _record_scan(
        self, target: str, findings: List[Dict], risk_score: int
    ) -> None:
        with self._lock:
            counts: Counter = Counter(self._state.get("type_counts", {}))
            for f in findings:
                counts[f.get("type", "Unknown")] += 1
            self._state["type_counts"] = dict(counts)

            history: list = self._state.setdefault("scan_history", [])
            history.append({
                "target":     target,
                "timestamp":  datetime.now(timezone.utc).isoformat(),
                "risk_score": risk_score,
                "count":      len(findings),
            })
            # Keep last 200 scans
            self._state["scan_history"] = history[-200:]
            self._save_state()


# Module-level singleton
brain = VulnBrain()
