"""Desktop app: the saved HTML/JSON reports must show the same findings and
counts as the Results screen (which reads the engine's nested report dict),
plus a regression lock for the SeverityBadge UnboundLocalError."""
import ast
import json
import pathlib
from datetime import datetime, timedelta

import pytest

from config.settings import VERSION
from core.models import Finding, ScanReport, ScanResult
from core.storage import ReportStore
from utils.reporter import ReportGenerator, normalize_report_data


def _finding(sev, typ):
    return Finding(severity=sev, type=typ, description=f"{typ} desc", evidence="ev",
                   url="https://t.example/x", remediation="fix", scan_type="",
                   confidence="confirmed", evidence_kind="observed", verified=True)


def _engine_report_dict():
    """What core.scan_engine hands to the UI and the report store:
    ScanReport.to_dict(), findings nested under results[*]['vulnerabilities']."""
    started = datetime(2026, 9, 29, 10, 0, 0)
    sqli = ScanResult("sqli", "SQL Injection", "https://t.example",
                      findings=[_finding("Critical", f"SQLi #{i}") for i in range(11)], status="done")
    misc = ScanResult("sec_misconfig", "Security Misconfiguration", "https://t.example",
                      findings=[_finding("Medium", "Missing Security Header"),
                                _finding("Low", "Technology Disclosure")], status="done")
    empty = ScanResult("xss", "XSS", "https://t.example", findings=[], status="done")
    report = ScanReport("https://t.example", [sqli, misc, empty],
                        started, started + timedelta(seconds=42), ["sqli", "sec_misconfig", "xss"])
    return report.to_dict()


def _ui_counts(report):
    """Exactly what ui/views/results_view.py displays."""
    return report["severity_counts"]


def _ui_findings(report):
    """Every finding row the Results screen lists (results[*]['vulnerabilities'])."""
    return [v for res in report["results"].values() for v in res["vulnerabilities"]]


# --- normalization ------------------------------------------------------------
def test_nested_report_is_flattened_without_mutating_input():
    report = _engine_report_dict()
    snapshot = json.dumps(report, sort_keys=True, default=str)
    data = normalize_report_data(report)
    assert len(data["findings"]) == 13 == len(_ui_findings(report))
    assert {f["scanner"] for f in data["findings"]} == {"SQL Injection", "Security Misconfiguration"}
    assert data["scan_date"] == report["timestamp"]
    assert data["scanner_version"] == VERSION
    assert data["results"] == report["results"]                          # nested kept
    assert json.dumps(report, sort_keys=True, default=str) == snapshot   # input untouched


def test_existing_flat_findings_are_kept():
    flat = {"target": "t", "findings": [{"severity": "High", "type": "x"}],
            "scanner_version": "6.0.0", "scan_date": "d"}
    data = normalize_report_data(flat)
    assert data["findings"] == flat["findings"]
    assert (data["scanner_version"], data["scan_date"]) == ("6.0.0", "d")


def test_handles_missing_or_odd_results():
    assert normalize_report_data(None)["findings"] == []
    assert normalize_report_data({"results": {"a": None, "b": {"vulnerabilities": None}}})["findings"] == []
    listy = normalize_report_data({"results": [{"scanner": "s", "vulnerabilities": [{"severity": "Low"}]}]})
    assert listy["findings"] == [{"severity": "Low", "scanner": "s"}]


# --- reporter counts == UI counts ---------------------------------------------
def test_reporter_counts_match_ui_for_nested_report():
    report = _engine_report_dict()
    counts = ReportGenerator()._count_vulnerabilities(report)
    assert counts == _ui_counts(report)
    assert counts["Critical"] == 11 and sum(counts.values()) == 13


def test_html_report_shows_same_totals_findings_and_real_version():
    report = _engine_report_dict()
    html = ReportGenerator().generate_html_report(report)
    assert "identified 13 security vulnerabilities" in html
    assert "<strong>Findings Count:</strong> 13" in html
    for f in _ui_findings(report):
        assert f["type"] in html
    assert f"HydraX {VERSION}" in html and "HydraX Unknown" not in html


# --- report store (what the app actually writes to disk) ----------------------
def test_saved_json_and_html_match_ui(tmp_path):
    report = _engine_report_dict()
    store = ReportStore(directory=tmp_path)

    saved = json.loads(store.save(report, fmt="json").read_text(encoding="utf-8"))
    by_sev = {}
    for f in saved["findings"]:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    ui = {k: v for k, v in _ui_counts(report).items() if v}
    assert by_sev == ui
    assert saved["severity_counts"] == _ui_counts(report)
    assert saved["scanner_version"] == VERSION and saved["results"] == report["results"]

    html = store.save(report, fmt="html").read_text(encoding="utf-8")
    assert "identified 13 security vulnerabilities" in html
    assert "report_data" not in report and "findings" not in report   # caller's dict untouched


# --- Bug 1 regression locks -----------------------------------------------------
def test_no_function_level_theme_imports_in_ui_package():
    offenders = []
    for path in pathlib.Path("ui").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(fn):
                    if isinstance(node, ast.ImportFrom) and node.module == "ui.theme":
                        offenders.append(f"{path}:{node.lineno} in {fn.name}()")
    assert not offenders, "in-function `from ui.theme import` shadows module names: " + ", ".join(offenders)


def test_severity_badge_builds_for_every_severity():
    ctk = pytest.importorskip("customtkinter")
    try:
        root = ctk.CTk()
    except Exception as e:  # noqa: BLE001 — no display available (headless CI)
        pytest.skip(f"no Tk display: {e}")
    root.withdraw()
    try:
        from ui.widgets import SeverityBadge
        for sev in ("Critical", "High", "Medium", "Low", "Info", "Unknown"):
            SeverityBadge(root, sev)
    finally:
        root.destroy()
