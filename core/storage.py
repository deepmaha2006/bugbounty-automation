"""
Report persistence layer.

Handles saving scan results as HTML/JSON/SARIF files in the reports directory,
listing existing reports and deleting them. Keeps the UI free of any
file-system bookkeeping.
"""

import json
import datetime
import webbrowser
import os
from pathlib import Path
from typing import Dict, Any, List

from config.settings import REPORTS_DIR
from utils.reporter import ReportGenerator, normalize_report_data
from utils.sarif_export import save_sarif


class ReportStore:
    """Save, list and open generated reports."""

    def __init__(self, directory: Path = None):
        self.directory = Path(directory) if directory else REPORTS_DIR
        self.directory.mkdir(parents=True, exist_ok=True)
        self._reporter = ReportGenerator()

    # ------------------------------------------------------------------
    def timestamp_stamp(self) -> str:
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    def save(self, report_data: Dict[str, Any], fmt: str = "html") -> Path:
        """Persist a report and return the file path.

        HTML, JSON and SARIF are all written from the same normalized copy
        (flat findings + scan_date + scanner_version added, nested results
        kept), so every format shows the same counts as the Results screen.
        """
        report_data = normalize_report_data(report_data)
        stamp = self.timestamp_stamp()
        target = str(report_data.get("target", "unknown")).replace("https://", "").replace("http://", "")
        safe_target = "".join(c for c in target if c.isalnum() or c in ".-_")[:40] or "target"

        if fmt == "json":
            path = self.directory / f"report_{safe_target}_{stamp}.json"
            payload = report_data
        elif fmt == "sarif":
            path = self.directory / f"report_{safe_target}_{stamp}.sarif"
            payload = save_sarif(report_data, str(path))
            # save_sarif writes the file directly, so we just return the path
            return path
        else:
            path = self.directory / f"report_{safe_target}_{stamp}.html"
            payload = self._reporter.generate_html_report(report_data)

        path.write_text(payload if isinstance(payload, str) else json.dumps(payload, indent=2, default=str),
                        encoding="utf-8")
        return path

    def list_reports(self, limit: int = 50) -> List[Path]:
        """Return existing reports sorted by modification time (newest first)."""
        files = list(self.directory.glob("*.html")) + list(self.directory.glob("*.json")) + list(self.directory.glob("*.sarif"))
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return files[:limit]

    def open_report(self, path: Path) -> None:
        """Open a report in the default browser."""
        try:
            os.startfile(str(path))  # Windows
        except AttributeError:
            webbrowser.open(f"file:///{str(path).replace(os.sep, '/')}")

    def delete(self, path: Path) -> None:
        """Remove a report file if it exists."""
        try:
            path.unlink()
        except OSError:
            pass

    def format_size(self, path: Path) -> str:
        size = path.stat().st_size
        return f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.1f} MB"
