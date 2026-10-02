"""
Attack-surface discovery for web scans.

Wraps the existing URLDiscovery crawler (real HTTP requests) and returns
DiscoveredTarget objects that feed the shared ScanContext so every selected
scanner tests the same real endpoints/parameters.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.discovery import URLDiscovery  # noqa: E402
from core.scan_context import ScanContext  # noqa: E402


def discover(target_url: str, max_pages: int = 60, max_depth: int = 3) -> dict:
    """Run real discovery and return targets plus a summary."""
    try:
        discovery = URLDiscovery(
            target=target_url,
            max_pages=max_pages,
            max_depth=max_depth,
            request_delay=0.02,
            request_timeout=15,
        )
        targets = discovery.discover()
    except Exception as exc:  # noqa: BLE001 - discovery must never crash the scan
        targets = []
        summary = {"error": str(exc), "urls": [target_url], "targets": []}
        return {"targets": targets, "summary": summary, "error": str(exc)}

    summary = {
        "urls": [t.url for t in targets][:50],
        "total": len(targets),
        "get_targets": sum(1 for t in targets if t.method == "get"),
        "post_targets": sum(1 for t in targets if t.method == "post"),
        "params_found": sum(len(t.params) for t in targets),
        "form_fields_found": sum(len(t.form_fields) for t in targets),
    }
    return {"targets": targets, "summary": summary, "error": None}


def build_context(target_url: str, options: dict = None) -> ScanContext:
    """Create a ScanContext populated with the discovered attack surface."""
    ctx = ScanContext(target=target_url, options=options or {})
    result = discover(target_url)
    ctx.discovered_targets = result["targets"]
    ctx.discovery_summary = result["summary"]
    return ctx
