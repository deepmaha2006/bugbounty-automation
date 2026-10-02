"""
Report generation for the web platform.

Reuses the existing ReportGenerator (rich HTML) plus a JSON export, writing
into webapp/data/reports and returning the path.
"""
import json
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.reporter import ReportGenerator  # noqa: E402

from webapp import config as wcfg  # noqa: E402
from webapp.services import remediation_service  # noqa: E402


def _slug(target: str) -> str:
    import re
    return re.sub(r"[^a-zA-Z0-9._-]", "_", target)[:60]


def generate_html_report(scan_id: int, target: str, scan_type: str,
                         findings: list, stats: dict) -> Path:
    gen = ReportGenerator()
    report_data = {
        "target": target,
        "scan_date": datetime.utcnow().isoformat(),
        "scanner_version": wcfg.APP_VERSION,
        "findings": findings,
    }
    html = gen.generate_html_report(report_data)
    analysis = remediation_service.analyze_scan(findings, _context(scan_type))
    html = _insert_after_body(html, _analyst_section_html(analysis))

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"report_{_slug(target)}_{scan_id}_{ts}.html"
    path = wcfg.REPORT_DIR / fname
    path.write_text(html, encoding="utf-8")
    return path


def generate_json_report(scan_id: int, target: str, scan_type: str,
                         findings: list, stats: dict, endpoints: list = None) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"report_{_slug(target)}_{scan_id}_{ts}.json"
    path = wcfg.REPORT_DIR / fname
    payload = {
        "scan_id": scan_id,
        "target": target,
        "scan_type": scan_type,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "stats": stats,
        "endpoints": endpoints or [],
        "findings": findings,
    }
    # Additive: analyst report per finding + scan-level summary.
    analysis = remediation_service.analyze_scan(findings, _context(scan_type))
    payload["findings"] = [dict(f, analyst=r) for f, r in zip(findings, analysis["reports"])]         if analysis["reports"] else findings
    payload["analyst_summary"] = {"top_priorities": analysis["top_priorities"],
                                  "issues": analysis["issues"]}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path

# --- Analyst section (remediation engine) ------------------------------------
# Rendered here, not in utils/reporter.ReportGenerator, because that renderer is
# shared with the desktop GUI. Every value is HTML-escaped.
_PRIORITY_COLOR = {"P1": "#d14b4b", "P2": "#cf7f2e", "P3": "#bda14a", "P4": "#7f97ad"}


def _context(scan_type: str) -> dict:
    return {"exposure": "internet_facing" if (scan_type or "web") == "web" else "unknown"}


def _insert_after_body(html: str, section: str) -> str:
    import re
    m = re.search(r"<body[^>]*>", html)
    if not m:
        return section + html
    return html[:m.end()] + section + html[m.end():]


def _analyst_section_html(analysis: dict) -> str:
    from html import escape as e

    def badge(p):
        return (f'<span style="display:inline-block;padding:2px 8px;border-radius:999px;'
                f'font-weight:700;font-size:12px;color:#111;background:{_PRIORITY_COLOR.get(p, "#8f8f8f")}">'
                f'{e(p)}</span>')

    reports = analysis.get("reports") or []
    if not reports:
        return ""
    rows = []
    for item in analysis.get("top_priorities") or []:
        label = "Issue" if item["kind"] == "issue" else "Finding"
        extra = f' ({item["count"]} findings)' if item["kind"] == "issue" else ""
        rows.append(f"<tr><td>{badge(item['priority'])}</td><td>{item['risk_score']}</td>"
                    f"<td>{label}</td><td>{e(item['title'])}{e(extra)}</td></tr>")
    cards = []
    for r in reports:
        rem = r["remediation"]
        refs = "".join(f'<li><a href="{e(u)}" rel="noopener noreferrer">{e(u)}</a></li>'
                       for u in r["references"])
        cards.append(
            '<div style="border:1px solid #333;border-radius:8px;padding:12px 16px;margin:10px 0">'
            f'<div>{badge(r["priority"])} <strong>{e(r["title"])}</strong> '
            f'<span style="color:#888">risk {r["risk_score"]} · {e(r["cwe"])} · {e(r["owasp"])}</span></div>'
            f'<p style="color:#aaa;margin:6px 0">{e(r["rationale"])}</p>'
            f'<p>{e(r["why_it_matters"])}</p>'
            f'<p><strong>Triage:</strong> {e(r["triage_note"])}</p>'
            f'<p><strong>Immediate:</strong> {e(rem["immediate"])}</p>'
            f'<p><strong>Short term:</strong> {e(rem["short_term"])}</p>'
            f'<p><strong>Long term:</strong> {e(rem["long_term"])}</p>'
            f'<p><strong>Verification:</strong> {e(r["verification"])}</p>'
            f'<ul>{refs}</ul></div>')
    return (
        '<section id="analyst-summary" style="font-family:Inter,Segoe UI,sans-serif;'
        'max-width:1100px;margin:24px auto;padding:0 16px">'
        '<h2>Top Priorities</h2>'
        '<table style="width:100%;border-collapse:collapse" cellpadding="6">'
        '<tr><th align="left">Priority</th><th align="left">Risk</th>'
        '<th align="left">Type</th><th align="left">Title</th></tr>'
        + "".join(rows) + '</table>'
        '<h2>Analyst Remediation</h2>' + "".join(cards) + '</section>')
