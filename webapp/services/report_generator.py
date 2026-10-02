"""Org-wide executive & technical reporting (CVM platform spec §23).

Every figure here is computed fresh from the same real, org-scoped tables
the dashboard and finding APIs use (findings/targets/connectors/
remediation_tasks/alerts) — nothing is fabricated, cached, or hardcoded.
Reports are generated on demand and streamed back; none are persisted to
disk, so there is no stale-report problem to manage.
"""
import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from webapp import db
from webapp.services import remediation_service

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _asset_lookup(organization_id: int) -> Dict[int, Dict[str, Any]]:
    return {a["id"]: a for a in db.list_assets(organization_id, limit=10000)}


def build_executive_summary(organization_id: int) -> Dict[str, Any]:
    """High-level, non-technical posture summary for leadership."""
    stats = db.dashboard_stats(organization_id)
    findings = db.list_findings(organization_id, limit=10000)
    assets = _asset_lookup(organization_id)

    open_findings = [f for f in findings if f["status"] not in ("FIXED", "FALSE_POSITIVE")]
    top_risks = sorted(open_findings, key=lambda f: f.get("risk_score", 0), reverse=True)[:5]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "organization_id": organization_id,
        "asset_posture": {
            "total_assets": stats["total_assets"],
            "monitored_assets": stats["monitored_assets"],
            "connectors_online": stats["connectors_online"],
            "connectors_offline": stats["connectors_offline"],
        },
        "vulnerability_summary": {
            "critical": stats["critical"], "high": stats["high"],
            "medium": stats["medium"], "low": stats["low"], "info": stats["info"],
            "new": stats["new_vulnerabilities"], "fixed": stats["fixed_vulnerabilities"],
            "reopened": stats["reopened_vulnerabilities"],
        },
        "remediation": {"open_tasks": stats["open_remediation_tasks"]},
        "top_risks": [
            {
                "finding_id": f["id"],
                "asset": assets.get(f.get("target_id"), {}).get("name") or assets.get(f.get("target_id"), {}).get("url"),
                "vulnerability": f["type"],
                "severity": f["severity"],
                "risk_score": f.get("risk_score"),
                "status": f["status"],
            }
            for f in top_risks
        ],
        "recent_alerts": stats["recent_alerts"],
    }


def build_technical_findings(organization_id: int) -> List[Dict[str, Any]]:
    """Full finding-level detail for engineers: evidence, classification,
    affected asset, remediation guidance, and live risk factors."""
    findings = db.list_findings(organization_id, limit=10000)
    assets = _asset_lookup(organization_id)
    rows = []
    for f in findings:
        asset = assets.get(f.get("target_id")) or {}
        rows.append({
            "finding_id": f["id"],
            "asset": asset.get("name") or asset.get("url") or "",
            "asset_url": asset.get("url") or "",
            "vulnerability": f["type"],
            "severity": f["severity"],
            "status": f["status"],
            "cve": f.get("cve") or "",
            "cwe": f.get("cwe") or "",
            "cvss": f.get("cvss"),
            "risk_score": f.get("risk_score"),
            "confidence": f["confidence"],
            "affected_component": f.get("affected_component") or "",
            "url": f.get("url") or "",
            "description": f.get("description") or "",
            "evidence": f.get("evidence") or "",
            "remediation": f.get("remediation") or "",
            "occurrence_count": f.get("occurrence_count", 1),
            "last_seen": f.get("last_seen"),
        })
    # Additive analyst columns (remediation engine). Named distinctly so the
    # existing DB risk_score (compute_risk) is not shadowed.
    analysis = remediation_service.analyze_scan(
        [{"type": r["vulnerability"], "severity": r["severity"],
          "confidence": r["confidence"], "cwe": r["cwe"]} for r in rows])
    for r, a in zip(rows, analysis["reports"]):
        r.update({
            "priority": a["priority"], "analyst_risk_score": a["risk_score"],
            "kb_key": a["key"],
            "remediation_immediate": a["remediation"]["immediate"],
            "remediation_short_term": a["remediation"]["short_term"],
            "remediation_long_term": a["remediation"]["long_term"],
            "verification": a["verification"],
        })
    rows.sort(key=lambda r: _SEVERITY_ORDER.get(r["severity"], 9))
    return rows


# --- renderers --------------------------------------------------------------

def render_json(data: Any) -> bytes:
    return json.dumps(data, indent=2, default=str).encode("utf-8")


def render_csv_executive(data: Dict[str, Any]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Metric", "Value"])
    for section in ("asset_posture", "vulnerability_summary", "remediation"):
        for k, v in data[section].items():
            w.writerow([f"{section}.{k}", v])
    w.writerow([])
    w.writerow(["Top Risk Finding ID", "Asset", "Vulnerability", "Severity", "Risk Score", "Status"])
    for r in data["top_risks"]:
        w.writerow([r["finding_id"], r["asset"], r["vulnerability"], r["severity"],
                   r["risk_score"], r["status"]])
    return buf.getvalue().encode("utf-8")


_TECHNICAL_FIELDS = ["finding_id", "asset", "asset_url", "vulnerability", "severity", "status",
                     "cve", "cwe", "cvss", "risk_score", "confidence", "affected_component",
                     "url", "description", "evidence", "remediation", "occurrence_count", "last_seen",
                     # additive analyst columns, appended so existing positions are unchanged
                     "priority", "analyst_risk_score", "kb_key", "remediation_immediate",
                     "remediation_short_term", "remediation_long_term", "verification"]


def render_csv_technical(rows: List[Dict[str, Any]]) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=_TECHNICAL_FIELDS)
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in _TECHNICAL_FIELDS})
    return buf.getvalue().encode("utf-8")


def render_pdf_executive(data: Dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    story = [
        Paragraph("Executive Security Summary", styles["Title"]),
        Paragraph(f"Generated: {data['generated_at']}", styles["Normal"]),
        Spacer(1, 16),
        Paragraph("Asset Posture", styles["Heading2"]),
        _table([[k.replace("_", " ").title(), v] for k, v in data["asset_posture"].items()]),
        Spacer(1, 12),
        Paragraph("Vulnerability Summary", styles["Heading2"]),
        _table([[k.replace("_", " ").title(), v] for k, v in data["vulnerability_summary"].items()]),
        Spacer(1, 12),
        Paragraph("Remediation", styles["Heading2"]),
        _table([[k.replace("_", " ").title(), v] for k, v in data["remediation"].items()]),
        Spacer(1, 12),
        Paragraph("Top Risks", styles["Heading2"]),
    ]
    if data["top_risks"]:
        head = ["Asset", "Vulnerability", "Severity", "Risk Score", "Status"]
        body = [[r["asset"], r["vulnerability"], r["severity"], r["risk_score"], r["status"]]
               for r in data["top_risks"]]
        story.append(_table([head] + body, header=True))
    else:
        story.append(Paragraph("No open findings.", styles["Normal"]))
    doc.build(story)
    return buf.getvalue()


def render_pdf_technical(rows: List[Dict[str, Any]]) -> bytes:
    from reportlab.lib.pagesizes import landscape, letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(letter))
    story = [
        Paragraph("Technical Vulnerability Report", styles["Heading1"]),
        Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat()}", styles["Normal"]),
        Spacer(1, 12),
    ]
    head = ["ID", "Asset", "Vulnerability", "Sev", "CVE", "CWE", "CVSS", "Status", "Component"]
    body = [[r["finding_id"], r["asset"], r["vulnerability"], r["severity"], r["cve"],
            r["cwe"], r["cvss"], r["status"], r["affected_component"]] for r in rows]
    if body:
        story.append(_table([head] + body, header=True, small=True))
    else:
        story.append(Paragraph("No findings recorded.", styles["Normal"]))
    doc.build(story)
    return buf.getvalue()


def _table(rows: List[List[Any]], header: bool = False, small: bool = False):
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle

    rows = [[str(c) if c is not None else "" for c in row] for row in rows]
    t = Table(rows)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7 if small else 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2b2f38")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    t.setStyle(TableStyle(style))
    return t
