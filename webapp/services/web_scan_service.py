"""
HydraX — website scan orchestration.

Runs a full, real scan for a target URL by combining:
  1. URL discovery (real crawling) -> shared ScanContext
  2. Python scanners (real HTTP detection, no synthesis)
  3. Kali tools executed directly (nuclei / sqlmap / nmap / nikto / gobuster)
  4. False-positive reduction pass (evidence checks + dedupe)

Python scanners and the Kali tool layer run CONCURRENTLY. Every finding is
produced by real tool/HTTP output; nothing is synthesized. Progress is
streamed over the in-memory event bus for SSE.
"""
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import SCANNER_MAP, SCANNER_META, resolve_target_url  # noqa: E402
from utils.ssrf_guard import assert_safe_scan_target  # noqa: E402
from core.scan_context import set_scan_context, clear_scan_context, ScanContext  # noqa: E402

from webapp import db  # noqa: E402
from webapp import config as wcfg  # noqa: E402
from webapp.services import alert_engine  # noqa: E402
from webapp.services import events  # noqa: E402
from webapp.services import scan_manager  # noqa: E402
from webapp.services.discovery_service import discover  # noqa: E402
from webapp.services.web_scan_tools import run_web_tools  # noqa: E402

# Finding types that must carry concrete evidence to be accepted
EVIDENCE_REQUIRED_TYPES = {
    "SQL Injection", "XSS", "Reflected XSS", "Stored XSS", "DOM XSS",
    "Command Injection", "SSRF", "RCE", "Open Redirect", "Path Traversal",
    "File Upload", "XXE", "CSRF",
}


def _normalize_finding(f: dict, tool: str = "python") -> dict:
    sev = str(f.get("severity", "Info") or "Info")
    sev_map = {"critical": "Critical", "high": "High", "medium": "Medium",
               "low": "Low", "info": "Info"}
    sev = sev_map.get(sev.lower(), sev if sev in ("Critical", "High", "Medium", "Low", "Info") else "Info")
    return {
        "severity": sev,
        "type": f.get("type") or f.get("name") or "Finding",
        "description": f.get("description") or f.get("name") or "",
        "evidence": f.get("evidence") or "",
        "url": f.get("url") or "",
        "remediation": f.get("remediation") or "",
        "tool": f.get("tool") or tool,
        "parameter": f.get("parameter"),
        "payload": f.get("payload"),
        "confidence": f.get("confidence", "confirmed"),
        "verified": bool(f.get("verified", True)),
        "tool_command": f.get("tool_command", f"{tool}:{f.get('type', 'unknown')}"),
        "raw_output": f.get("raw_output", "")
    }


def _verify_findings(findings: list) -> list:
    """False-positive reduction: drop payload-based findings that carry no
    concrete evidence, and deduplicate by (type, url, severity, payload)."""
    out, seen = [], set()
    for f in findings:
        # Payload-driven detection must include the observed evidence string.
        if f["type"] in EVIDENCE_REQUIRED_TYPES and not f.get("evidence", "").strip():
            continue
        # URL-less findings are not actionable — drop them.
        if not f.get("url", "").strip():
            continue
        key = (f["type"], f["url"], f["severity"], f.get("payload") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def start_web_scan(user_id, target: str, vuln_types: list) -> int:
    """Persist the scan record and start it in a background thread.

    The target must already exist (and be verified); its integer ID is passed
    to create_scan/add_report instead of the URL string.
    """
    try:
        target = resolve_target_url(target)
    except ValueError as e:
        raise ValueError(str(e)) from e

    # SSRF self-protection (spec's threat model, docs/THREAT_MODEL.md
    # boundary 5): re-checked here every time, immediately before the scan
    # that actually matters, regardless of whether the caller is a manual
    # scan request, the Phase 5 scheduler, or Phase 10's fix-verification
    # scan — this is the one choke point all three funnel through.
    assert_safe_scan_target(target)

    requester = db.get_user_by_id(user_id)
    organization_id = requester["organization_id"] if requester else None
    target_row = db.get_target_by_url(target, organization_id)
    if not target_row:
        raise ValueError(f"Target is not registered: {target}. Add it and complete verification first.")
    if target_row["verification_status"] != "verified":
        raise ValueError(
            f"Target verification required for {target} (status: "
            f"{target_row['verification_status']}). Complete DNS TXT or "
            "engagement-letter verification before scanning."
        )
    target_id = target_row["id"]

    keys = [k for k in vuln_types if k in SCANNER_MAP]
    if not keys:
        raise ValueError("Select at least one vulnerability type.")
    scan_id = db.create_scan(user_id, target_id, "web", keys)
    events.new_scan_bus(scan_id)
    scan_manager.submit(scan_id, user_id, "web", _run,
                        scan_id, user_id, target, target_id, keys)
    return scan_id


def _run(scan_id, user_id, target, target_id, keys) -> None:
    db.update_scan(scan_id, status="running", phase="Starting", progress=0.02,
                   started_at=db._now())
    try:
        all_findings = []

        # ---- Phase 1: Discovery ------------------------------------------
        db.update_scan(scan_id, phase="Discovery", progress=0.05)
        events.emit(scan_id, {"type": "phase", "text": "Discovery", "message": "Crawling target…"})
        ctx = ScanContext(target=target)
        disc = discover(target)
        ctx.discovered_targets = disc["targets"]
        ctx.discovery_summary = disc["summary"]
        summary = disc["summary"]
        events.emit(scan_id, {"type": "status",
                              "text": f"Discovered {summary.get('total', 0)} endpoints, "
                                      f"{summary.get('params_found', 0)} parameters"})
        events.emit(scan_id, {"type": "phase_done", "text": "Discovery"})

        # ---- Phase 2+3: Python scanners AND Kali tools in parallel -------
        db.update_scan(scan_id, phase="Vulnerability scanning", progress=0.3)
        events.emit(scan_id, {"type": "phase", "text": "Vulnerability scanning",
                              "message": "Python engines + Kali toolchain — parallel"})

        results = {}
        with ThreadPoolExecutor(max_workers=2) as ex:
            f_py = ex.submit(_run_python_scanners, scan_id, ctx, keys)
            f_tools = ex.submit(_run_kali_tools, scan_id, target, keys)
            results["py"] = f_py.result(timeout=1800)
            results["tools"] = f_tools.result(timeout=1800)

        py_findings, tool_findings = results["py"], results["tools"]
        events.emit(scan_id, {"type": "status",
                              "text": f"Python scanners: {len(py_findings)} findings, "
                                      f"Kali tools: {len(tool_findings)} findings"})
        events.emit(scan_id, {"type": "phase_done", "text": "Vulnerability scanning"})
        events.emit(scan_id, {"type": "progress", "progress": 0.75})
        all_findings = py_findings + tool_findings

        # ---- Phase 4: Verify + aggregate + persist -----------------------
        db.update_scan(scan_id, phase="Aggregating", progress=0.9)
        all_findings = _verify_findings(
            [_normalize_finding(f) for f in all_findings])
        for f in all_findings:
            result = db.add_finding(scan_id, f)
            if result["is_new_or_reopened"]:
                alert_engine.maybe_alert(result["finding_id"])
            events.emit(scan_id, {"type": "finding", **f})

        stats = _build_stats(all_findings)
        db.update_scan(scan_id, status="completed", progress=1.0, phase="Complete",
                       message=f"Found {len(all_findings)} vulnerabilities",
                       stats=stats, finished_at=db._now())
        events.emit(scan_id, {"type": "phase_done", "text": "Aggregating"})
        events.emit(scan_id, {"type": "progress", "progress": 1.0})

        # ---- Reports (HTML + JSON) --------------------------------------
        from webapp.services.report_service import (generate_html_report,
                                                    generate_json_report)
        html_path = generate_html_report(scan_id, target, "web", all_findings, stats)
        db.add_report(scan_id, target_id, "web", "html", str(html_path))
        json_path = generate_json_report(scan_id, target, "web", all_findings, stats)
        db.add_report(scan_id, target_id, "web", "json", str(json_path))
        events.emit(scan_id, {"type": "done", "text": "Scan complete",
                              "report": str(html_path), "total": len(all_findings)})
    except Exception as e:  # noqa: BLE001
        db.update_scan(scan_id, status="error", phase="Error",
                       message=str(e), finished_at=db._now())
        events.emit(scan_id, {"type": "error", "text": f"Scan failed: {e}"})
        traceback.print_exc()
    finally:
        clear_scan_context()


def _run_kali_tools(scan_id, target, keys) -> list:
    events.emit(scan_id, {"type": "phase", "text": "Kali toolchain",
                          "message": "nuclei / sqlmap / nmap / nikto / gobuster…"})
    try:
        return run_web_tools(target, keys)
    except Exception as e:  # noqa: BLE001
        events.emit(scan_id, {"type": "error", "text": f"Kali tools step failed: {e}"})
        return []


def _run_python_scanners(scan_id, ctx, keys) -> list:
    """Run each selected Python scanner in its own thread (context-bound)."""
    if not keys:
        return []
    findings = []
    lock = threading.Lock()
    db.update_scan(scan_id, phase="Python engines", progress=0.2)
    events.emit(scan_id, {"type": "phase", "text": "Python engines",
                          "message": f"Running {len(keys)} scanners…"})

    def _one(key):
        scanner_cls = SCANNER_MAP.get(key)
        meta = SCANNER_META.get(key, {})
        if not scanner_cls:
            return
        events.emit(scan_id, {"type": "status", "text": f"Running {meta.get('name', key)}…"})
        try:
            set_scan_context(ctx)
            scanner = scanner_cls()
            result = scanner.scan(ctx.target) if hasattr(scanner, "scan") else {}
            for f in (result.get("vulnerabilities") or []):
                # Add tool command and raw output for audit trail
                f_with_audit = f.copy()
                f_with_audit["tool_command"] = f"python_scanner:{key}"
                f_with_audit["raw_output"] = str(result.get("raw", "")) if isinstance(result, dict) else ""
                with lock:
                    findings.append(f_with_audit)
        except Exception as e:  # noqa: BLE001
            events.emit(scan_id, {"type": "error",
                                  "text": f"{meta.get('name', key)} failed: {e}"})
        finally:
            clear_scan_context()

    with ThreadPoolExecutor(max_workers=min(len(keys), wcfg.DEFAULT_THREADS)) as ex:
        list(ex.map(_one, keys))
    return findings


def _build_stats(findings: list) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    weights = {"Critical": -40, "High": -20, "Medium": -10, "Low": -3, "Info": 0}
    score = 100 + sum(counts[s] * weights[s] for s in counts)
    score = max(0, min(100, score))
    return {"total_findings": len(findings), **counts, "security_score": score}
