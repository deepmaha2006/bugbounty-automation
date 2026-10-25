"""
Autonomous Brain — background cybersecurity intelligence agent.
Starts with the app, monitors findings, auto-enriches them with CVE + OWASP
tags + fix recommendations, and pushes results back to the event queue.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_STATE_FILE = Path(__file__).resolve().parent.parent / "memory" / "autonomous_brain.json"

_FIX_TEMPLATES: Dict[str, str] = {
    "SQL Injection":             "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
    "XSS":                       "Encode output with htmlspecialchars(). Implement Content-Security-Policy header.",
    "Cross-Site Scripting":      "Encode output with htmlspecialchars(). Implement Content-Security-Policy header.",
    "SSRF":                      "Whitelist allowed outbound destinations. Block metadata endpoints (169.254.169.254).",
    "Command Injection":         "Use subprocess with argument lists, never shell=True. Validate all inputs strictly.",
    "RCE":                       "Avoid eval/exec with user input. Sandbox execution. Validate all serialized data.",
    "Broken Access Control":     "Enforce RBAC server-side. Validate user permissions on every request.",
    "IDOR":                      "Use indirect references mapped server-side. Verify ownership on every resource access.",
    "Security Misconfiguration": "Run automated config scanners. Disable debug mode. Remove default credentials.",
    "Information Disclosure":    "Suppress stack traces in production. Remove server version banners.",
    "Path Traversal":            "Normalize paths. Use realpath(). Reject paths containing '../'.",
    "File Upload":               "Validate MIME type server-side. Store outside web root. Rename uploaded files.",
    "CSRF":                      "Use CSRF tokens (SameSite=Strict cookies). Validate Origin/Referer headers.",
    "Clickjacking":              "Set X-Frame-Options: DENY. Use CSP frame-ancestors 'none'.",
    "Subdomain Takeover":        "Audit all DNS CNAME records. Remove dangling records immediately.",
    "Open Redirect":             "Whitelist redirect destinations. Never use raw user input as redirect target.",
    "XXE":                       "Disable external entity processing in XML parsers (FEATURE_SECURE_PROCESSING).",
    "Prototype Pollution":       "Freeze prototypes. Validate input keys against a whitelist. Use Object.create(null).",
    "Deserialization":           "Never deserialize untrusted data. Use schema validation before deserialization.",
    "WebSocket":                 "Enforce authentication on WebSocket upgrade. Validate Origin headers.",
    "Missing Security Headers":  "Add X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Strict-Transport-Security.",
    "Outdated SSL":              "Disable TLS 1.0/1.1. Enforce TLS 1.2+ with strong cipher suites.",
}


class AutonomousBrain:
    """Background security brain — enriches findings and learns from scans."""

    def __init__(self, event_queue: Optional[queue.Queue] = None):
        self._event_queue = event_queue
        self._lock = threading.Lock()
        self._state: Dict[str, Any] = self._load_state()
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="brain")
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._inbox: queue.Queue = queue.Queue()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, event_queue: queue.Queue) -> None:
        self._event_queue = event_queue
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="autonomous-brain"
        )
        self._monitor_thread.start()
        logger.info("AutonomousBrain started")

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Event inbox (called by main window's event pump)
    # ------------------------------------------------------------------

    def feed(self, event: tuple) -> None:
        if event and len(event) > 0 and event[0] in ("scan_complete",):
            self._inbox.put(event)

    # ------------------------------------------------------------------
    # Monitor loop
    # ------------------------------------------------------------------

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                event = self._inbox.get(timeout=1.0)
                self._handle_event(event)
            except queue.Empty:
                continue
            except Exception as exc:
                logger.debug("Brain monitor error: %s", exc)

    def _handle_event(self, event: tuple) -> None:
        if event[0] == "scan_complete":
            report = event[2] if len(event) > 2 else None
            if report:
                self._executor.submit(self._process_report, report)

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------

    def _process_report(self, report: Any) -> None:
        try:
            findings = self._extract_findings(report)
            if not findings:
                return

            enriched = []
            for f in findings:
                try:
                    enriched.append(self.enrich(f))
                except Exception:
                    enriched.append(f)

            summary = self._summarize(enriched)
            self._learn(enriched)

            if self._event_queue:
                self._event_queue.put(("brain_analysis_complete", enriched, summary))
        except Exception as exc:
            logger.debug("Brain process_report error: %s", exc)

    def enrich(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Add CVE, OWASP, fix text, and brain metadata to a finding."""
        f = dict(finding)

        try:
            from brain.cve_db import enrich_with_cve
            f = enrich_with_cve(f)
        except Exception:
            pass

        try:
            from brain.vuln_brain import brain
            f = brain.enrich_finding(f)
        except Exception:
            pass

        if not f.get("fix"):
            f["fix"] = self._get_fix(f.get("type", "") or f.get("name", ""))

        try:
            from ai.local_llm import llm
            if llm.available:
                ai_remed = llm.analyze_finding(f)
                if ai_remed:
                    f["ai_fix"] = ai_remed
        except Exception:
            pass

        f["brain_processed"] = True
        f["brain_ts"] = datetime.now(timezone.utc).isoformat()
        return f

    def _get_fix(self, vuln_type: str) -> str:
        vuln_lower = vuln_type.lower()
        for key, fix in _FIX_TEMPLATES.items():
            if key.lower() in vuln_lower:
                return fix
        return "Review the finding manually. Apply principle of least privilege and input validation."

    def _summarize(self, findings: List[Dict]) -> Dict[str, Any]:
        counts = Counter(f.get("severity", "Info") for f in findings)
        owasp_hits = list({f.get("owasp", "") for f in findings if f.get("owasp")})
        return {
            "total":    len(findings),
            "critical": counts.get("Critical", 0) + counts.get("critical", 0),
            "high":     counts.get("High", 0) + counts.get("high", 0),
            "medium":   counts.get("Medium", 0) + counts.get("medium", 0),
            "low":      counts.get("Low", 0) + counts.get("low", 0),
            "owasp":    owasp_hits[:5],
        }

    def _extract_findings(self, report: Any) -> List[Dict]:
        if isinstance(report, dict):
            findings = report.get("findings") or report.get("vulnerabilities") or []
            # Convert objects to dicts if needed
            result = []
            for f in findings:
                if isinstance(f, dict):
                    result.append(f)
                elif hasattr(f, "__dict__"):
                    result.append(vars(f))
                elif hasattr(f, "to_dict"):
                    result.append(f.to_dict())
            return result
        if hasattr(report, "findings"):
            raw = report.findings
            result = []
            for f in raw:
                if isinstance(f, dict):
                    result.append(f)
                elif hasattr(f, "to_dict"):
                    result.append(f.to_dict())
                elif hasattr(f, "__dict__"):
                    result.append(vars(f))
            return result
        return []

    # ------------------------------------------------------------------
    # Learning
    # ------------------------------------------------------------------

    def _learn(self, findings: List[Dict]) -> None:
        with self._lock:
            counts: Dict[str, int] = self._state.setdefault("type_counts", {})
            for f in findings:
                t = f.get("type") or f.get("name", "Unknown")
                counts[t] = counts.get(t, 0) + 1
            self._state["total_findings"] = self._state.get("total_findings", 0) + len(findings)
            self._state["last_scan"] = datetime.now(timezone.utc).isoformat()
        self._save_state()

    def top_patterns(self, n: int = 5) -> list:
        counts = self._state.get("type_counts", {})
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]

    @property
    def total_findings(self) -> int:
        return self._state.get("total_findings", 0)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_state(self) -> Dict[str, Any]:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        if _STATE_FILE.exists():
            try:
                return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_state(self) -> None:
        try:
            with self._lock:
                _STATE_FILE.write_text(json.dumps(self._state, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.debug("Brain state save error: %s", exc)


# Module singleton — started by main_window on app boot
brain = AutonomousBrain()
