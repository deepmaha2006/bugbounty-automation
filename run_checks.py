#!/usr/bin/env python3
"""
HydraX — compile/import health checks (Phase 1 deliverable).

Usage:
    python3 run_checks.py

Runs two layers of static verification over the installed packages, the
web platform, and the desktop GUI, without connecting to any live services:

  1. AST parse of every .py under webapp/, core/, scanners/, config/, utils/,
     ui/ — catches syntax errors that Python cannot import past.
  2. Import of every module the FastAPI app and the desktop GUI depend on
     (webapp.*/webapp.main and ui.*/main) under the interpreter this script
     runs with (system python by default, which has fastapi, uvicorn,
     psycopg2, pydantic, customtkinter). AST parsing alone (layer 1) cannot
     catch a name imported from a module that doesn't actually define it —
     only a real import does, which is how ui/dialogs/scope_editor.py's
     import of two nonexistent ui.theme constants (a stale rename that broke
     every desktop view importing it) went undetected until this check
     started importing ui.* too.

Exits non-zero if anything fails.
"""
import ast
import importlib
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
PACKAGES = ("webapp", "core", "scanners", "config", "utils", "ui", "connector", "scripts")

WEBAPP_MODULES = [
    "webapp.db", "webapp.config", "webapp.security", "webapp.schemas",
    "webapp.services.events", "webapp.services.web_scan_service",
    "webapp.services.system_scan_service",
    "webapp.services.report_service", "webapp.services.report_generator",
    "webapp.services.api_rate_limiter", "webapp.services.health",
    "webapp.logging_config", "webapp.services.discovery_service",
    "webapp.services.web_scan_tools", "webapp.services.kali_tools",
    "webapp.routers.auth", "webapp.routers.brain", "webapp.services.remediation_kb", "webapp.routers.organizations", "webapp.routers.assets",
    "webapp.routers.findings", "webapp.routers.alerts",
    "webapp.services.alert_engine",
    "webapp.routers.remediation", "webapp.services.remediation_service",
    "webapp.routers.connectors", "webapp.services.connector_crypto",
    "connector.agent",
    "webapp.routers.scans", "webapp.routers.reports",
    "webapp.routers.dashboard", "webapp.routers.settings", "webapp.routers.profile",
    "webapp.routers.verification", "webapp.routers.events", "webapp.main",
    "webapp.celery_app", "webapp.tasks",
]

UI_MODULES = [
    "ui.theme", "ui.widgets", "ui.main_window", "ui.dialogs.scope_editor",
    "ui.views.dashboard_view", "ui.views.website_scanner_view",
    "ui.views.company_scanner_view",
    "ui.views.results_view", "ui.views.reports_view", "ui.views.settings_view",
    "ui.views.profile_view",
]

ALL_MODULES = WEBAPP_MODULES + UI_MODULES


def syntax_errors() -> list:
    bad = []
    checked = 0
    for pkg in PACKAGES:
        base = PROJECT_ROOT / pkg
        if not base.is_dir():
            continue
        for py in base.rglob("*.py"):
            checked += 1
            try:
                ast.parse(py.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError as e:
                bad.append(f"{py}:{e.lineno}:{e.offset}: {e.msg}")
    print(f"[syntax] parsed {checked} source files")
    return bad


def import_errors() -> list:
    bad = []
    sys.path.insert(0, str(PROJECT_ROOT))
    for mod in ALL_MODULES:
        try:
            importlib.import_module(mod)
        except Exception as e:  # noqa: BLE001
            bad.append(f"{mod}: {type(e).__name__}: {e}")
    if bad:
        print(f"[import] failed {len(bad)}/{len(ALL_MODULES)} modules")
    else:
        print(f"[import] all {len(ALL_MODULES)} modules imported OK")
    return bad


def main() -> int:
    # coarse package-level compile first (fast fail on the obvious)
    import py_compile
    failed = False
    for pkg in PACKAGES:
        base = PROJECT_ROOT / pkg
        if base.is_dir():
            for py in base.rglob("*.py"):
                try:
                    py_compile.compile(str(py), doraise=True)
                except py_compile.PyCompileError as e:
                    print(f"[pyc] FAIL {py}  {e}")
                    failed = True
    if failed:
        print("[pyc] compileall-level errors present")

    syntax_bad = syntax_errors()
    for line in syntax_bad:
        print(f"[syntax] FAIL {line}")

    import_bad = import_errors()
    for line in import_bad:
        print(f"[import] FAIL {line}")

    total_bad = len(syntax_bad) + len(import_bad)
    if total_bad:
        print(f"\nCHECK FAILED: {total_bad} error(s)")
    else:
        print("\nCHECK PASSED: syntax + imports are clean.")
    return 1 if total_bad else 0


if __name__ == "__main__":
    raise SystemExit(main())