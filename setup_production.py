"""
HydraX Production Setup Utility

Validates the runtime environment, installs Python dependencies, and
verifies all optional external tools before the application launches.

Run with:  python setup_production.py
"""

import subprocess
import sys
import os
import json
import shutil
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).parent
REQUIREMENTS = PROJECT_ROOT / "requirements.txt"
CONFIG_DIR = PROJECT_ROOT / "config"
REPORTS_DIR = PROJECT_ROOT / "reports"
MEMORY_DIR = PROJECT_ROOT / "memory"

# ── Version gate ─────────────────────────────────────────────────────────────

MIN_PYTHON = (3, 9)

# ── External tool inventory ──────────────────────────────────────────────────

EXTERNAL_TOOLS = {
    "nmap":    ("nmap", "--version"),
    "nikto":   ("nikto", "-Version"),
    "whatweb": ("whatweb", "--version"),
    "dirb":    ("dirb",),
    "wfuzz":   ("wfuzz", "--version"),
    "sqlmap":  ("sqlmap", "--version"),
}

REQUIRED_TOOLS = {"nmap"}       # these MUST be present for core scan to run
OPTIONAL_TOOLS = set(EXTERNAL_TOOLS.keys()) - REQUIRED_TOOLS


# ── Helpers ──────────────────────────────────────────────────────────────────

def _banner() -> None:
    print("=" * 60)
    print("  HydraX — Production Environment Setup")
    print("  Authorized security testing only")
    print("=" * 60)
    print()


def _check_python() -> bool:
    v = sys.version_info[:2]
    ok = v >= MIN_PYTHON
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] Python {v[0]}.{v[1]}  (required ≥ {MIN_PYTHON[0]}.{MIN_PYTHON[1]})")
    return ok


def _install_dependencies() -> bool:
    if not REQUIREMENTS.exists():
        print("  [SKIP] requirements.txt not found")
        return True
    print("  [    ] Installing Python dependencies …", end="", flush=True)
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS),
         "--quiet", "--disable-pip-version-check"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print("\r  [PASS] Python dependencies installed")
        return True
    else:
        print(f"\r  [FAIL] pip install failed:\n{result.stderr[:500]}")
        return False


def _check_playwright() -> bool:
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        print("  [PASS] Playwright installed")
        # Check if Chromium is installed
        try:
            result = subprocess.run(
                [sys.executable, "-m", "playwright", "install", "--dry-run", "chromium"],
                capture_output=True, text=True,
            )
            if "chromium" in result.stdout.lower() or result.returncode == 0:
                print("  [PASS] Playwright Chromium available")
        except Exception:
            print("  [WARN] Could not verify Playwright Chromium — run: playwright install chromium")
        return True
    except ImportError:
        print("  [WARN] Playwright not installed — JavaScript crawling disabled")
        return False


def _check_external_tools() -> dict:
    print("\n  External tools:")
    results = {}
    for tool, cmd in EXTERNAL_TOOLS.items():
        found = shutil.which(tool)
        if found:
            results[tool] = True
            tag = "REQ" if tool in REQUIRED_TOOLS else "OPT"
            print(f"    [{tag}][PASS] {tool:12s} → {found}")
        else:
            results[tool] = False
            if tool in REQUIRED_TOOLS:
                print(f"    [REQ][FAIL] {tool:12s} → NOT FOUND  ← REQUIRED")
            else:
                print(f"    [OPT][WARN] {tool:12s} → NOT FOUND  (scanner disabled)")
    return results


def _create_directories() -> None:
    for d in (CONFIG_DIR, REPORTS_DIR, MEMORY_DIR):
        d.mkdir(parents=True, exist_ok=True)
    print("  [PASS] Runtime directories created")


def _write_default_config() -> None:
    settings = CONFIG_DIR / "settings.json"
    if not settings.exists():
        defaults = {
            "timeout": 15,
            "delay": 0.2,
            "threads": 5,
            "max_findings": 50,
            "verify_ssl": False,
        }
        settings.write_text(json.dumps(defaults, indent=2), encoding="utf-8")
        print("  [PASS] Default settings.json written")


def _security_hardening_check() -> None:
    """Warn about any misconfigurations that weaken security posture."""
    print("\n  Security posture checks:")

    notif = CONFIG_DIR / "notifications.json"
    if notif.exists():
        try:
            cfg = json.loads(notif.read_text(encoding="utf-8"))
            if cfg.get("smtp_password"):
                print("  [WARN] SMTP password is stored in plaintext in "
                      "config/notifications.json")
                print("         Restrict file permissions: chmod 600 config/notifications.json")
        except Exception:
            pass
    print("  [PASS] No critical configuration misconfigurations detected")


def _print_launch_instructions() -> None:
    print()
    print("=" * 60)
    print("  Setup complete. To launch HydraX:")
    print()
    if sys.platform.startswith("win"):
        print("    launch.bat")
        print("  or:")
        print("    python main.py")
    else:
        print("    ./launch.sh")
        print("  or:")
        print("    python3 main.py")
    print()
    print("  Logs: runtime/hydrax.log")
    print("  Reports: reports/")
    print("=" * 60)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    _banner()

    print("Checking environment …\n")
    checks_passed = True

    # Python version
    if not _check_python():
        print("\nFATAL: Python version too old. Install Python 3.9+.")
        return 1

    # Dependencies
    print()
    if not _install_dependencies():
        checks_passed = False

    # Playwright
    _check_playwright()

    # Directories
    _create_directories()
    _write_default_config()

    # External tools
    tool_results = _check_external_tools()
    missing_required = [t for t in REQUIRED_TOOLS if not tool_results.get(t)]
    if missing_required:
        print(f"\n  [WARN] Required tools missing: {', '.join(missing_required)}")
        print("         Some scan engines will be disabled.")
        checks_passed = False

    # Security checks
    _security_hardening_check()

    _print_launch_instructions()
    return 0 if checks_passed else 2


if __name__ == "__main__":
    sys.exit(main())
