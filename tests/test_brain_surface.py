"""Stage 3: analyst reports surfaced in scan results, reports, and the UI."""
import csv
import io
import json
import re

import pytest

from webapp import config as wcfg
from webapp.services import remediation_service, report_service

FINDINGS = [
    {"type": "Missing Security Header", "severity": "Medium", "description": "x",
     "evidence": "hdr-1", "url": "https://t.example/a", "confidence": "confirmed"},
    {"type": "Stored XSS", "severity": "Critical", "description": "y",
     "evidence": "marker", "url": "https://t.example/b", "confidence": "confirmed"},
    {"type": "Totally Unknown Finding Type", "severity": "Low", "description": "z",
     "evidence": "e", "url": "https://t.example/c", "confidence": "needs_verification"},
]


@pytest.fixture(autouse=True)
def _clean_unresolved():
    remediation_service.clear_unresolved()
    yield
    remediation_service.clear_unresolved()


def _scan_with_findings(fake, findings=FINDINGS):
    tid = fake.add_target("https://t.example", verification_method="dns_txt")
    fake.update_target_verification(tid, "verified")
    sid = fake.create_scan(1, tid, "web", ["xss"])
    for f in findings:
        fake.add_finding(sid, dict(f))
    fake.update_scan(sid, status="completed", progress=1.0)
    return sid


# --- Scan result API ----------------------------------------------------------
def test_scan_detail_attaches_analyst_report_per_finding(fake, client, admin_headers):
    sid = _scan_with_findings(fake)
    body = client.get(f"/api/scans/{sid}", headers=admin_headers).json()
    by_type = {f["type"]: f for f in body["findings"]}
    xss = by_type["Stored XSS"]["analyst"]
    assert xss["key"] == "xss.stored" and xss["resolved_by"] == "alias"
    assert xss["priority"] == "P1" and 0 <= xss["risk_score"] <= 100
    assert set(xss["remediation"]) == {"immediate", "short_term", "long_term",
                                       "code_examples", "config_examples"}
    # original fields untouched (backward compatible)
    assert by_type["Stored XSS"]["severity"] == "Critical"
    assert by_type["Stored XSS"]["description"] == "y"


def test_scan_detail_unknown_finding_uses_generic_fallback(fake, client, admin_headers):
    sid = _scan_with_findings(fake)
    body = client.get(f"/api/scans/{sid}", headers=admin_headers).json()
    unknown = next(f for f in body["findings"] if f["type"] == "Totally Unknown Finding Type")
    assert unknown["analyst"]["unresolved"] is True
    assert unknown["analyst"]["resolved_by"] == "generic"
    assert unknown["analyst"]["remediation"]["short_term"]
    assert any(u["type"] == "Totally Unknown Finding Type"
               for u in remediation_service.get_unresolved())


def test_scan_detail_top_priorities_sorted_by_risk(fake, client, admin_headers):
    sid = _scan_with_findings(fake)
    summary = client.get(f"/api/scans/{sid}", headers=admin_headers).json()["analyst_summary"]
    findings = [t for t in summary["top_priorities"] if t["kind"] == "finding"]
    scores = [t["risk_score"] for t in findings]
    assert scores == sorted(scores, reverse=True) and len(findings) == 3
    assert findings[0]["key"] == "xss.stored"
    assert "issues" in summary


def test_scan_list_items_are_unchanged(fake, client, admin_headers):
    """with_findings=False paths (e.g. start response) carry no analyst payload."""
    tid = fake.add_target("http://127.0.0.1:8000/app", verification_method="dns_txt")
    fake.update_target_verification(tid, "verified")
    from webapp.routers.scans import _scan_to_out
    sid = fake.create_scan(1, tid, "web", ["xss"])
    out = _scan_to_out(fake.get_scan(sid), with_findings=False)
    assert out.findings == [] and out.analyst_summary is None


# --- Per-scan JSON + HTML reports --------------------------------------------
@pytest.fixture()
def report_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(wcfg, "REPORT_DIR", tmp_path)
    return tmp_path


def test_json_report_includes_analyst_fields(report_dir):
    path = report_service.generate_json_report(7, "https://t.example", "web",
                                               [dict(f) for f in FINDINGS], {})
    data = json.loads(path.read_text(encoding="utf-8"))
    assert all("analyst" in f for f in data["findings"])
    assert data["findings"][1]["analyst"]["key"] == "xss.stored"
    assert data["findings"][2]["analyst"]["unresolved"] is True
    tp = data["analyst_summary"]["top_priorities"]
    assert tp[0]["key"] == "xss.stored"
    assert data["findings"][0]["type"] == "Missing Security Header"   # originals intact


def test_html_report_has_top_priorities_and_escapes(report_dir):
    evil = dict(FINDINGS[2], type="<script>alert(1)</script> Weird Thing")
    path = report_service.generate_html_report(8, "https://t.example", "web",
                                               [dict(FINDINGS[1]), evil], {})
    html = path.read_text(encoding="utf-8")
    section = html[html.index('<section id="analyst-summary"'):]
    section = section[:section.index("</section>")]
    assert "Top Priorities" in section and "Analyst Remediation" in section
    assert "<script>alert(1)</script>" not in section
    assert "&lt;script&gt;" in section
    # section sits right after <body>, i.e. at the top of the report
    body_open = re.search(r"<body[^>]*>", html).end()
    assert html.index('<section id="analyst-summary"') == body_open


def test_html_report_without_findings_adds_no_section(report_dir):
    path = report_service.generate_html_report(9, "https://t.example", "web", [], {})
    assert 'id="analyst-summary"' not in path.read_text(encoding="utf-8")


# --- Org-wide technical report -------------------------------------------------
def test_technical_report_json_and_csv_have_analyst_columns(fake, client, admin_headers):
    _scan_with_findings(fake)
    rows = client.get("/api/reports/technical?format=json", headers=admin_headers).json()
    assert rows and all("priority" in r and "analyst_risk_score" in r for r in rows)
    xss = next(r for r in rows if r["vulnerability"] == "Stored XSS")
    assert xss["kb_key"] == "xss.stored" and xss["remediation_short_term"]
    assert "risk_score" in xss          # existing DB risk score still present, not replaced

    raw = client.get("/api/reports/technical?format=csv", headers=admin_headers).content
    header = next(csv.reader(io.StringIO(raw.decode("utf-8"))))
    assert header[:18] == ["finding_id", "asset", "asset_url", "vulnerability", "severity",
                           "status", "cve", "cwe", "cvss", "risk_score", "confidence",
                           "affected_component", "url", "description", "evidence",
                           "remediation", "occurrence_count", "last_seen"]
    assert header[18:] == ["priority", "analyst_risk_score", "kb_key", "remediation_immediate",
                           "remediation_short_term", "remediation_long_term", "verification"]
