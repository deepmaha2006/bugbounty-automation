"""
Main application window: sidebar navigation + view router + event pump.

This is the single composition root of the UI. It owns the ScanEngine,
the ReportStore and the current report state, and routes engine events
to the active views.
"""

import os
import queue
import datetime
import subprocess

import customtkinter as ctk

from config.settings import (APP_NAME, VERSION, REPORTS_DIR,
                             DEFAULT_SCANNER_KEYS)

from core.scan_engine import ScanEngine
from core.storage import ReportStore
from ui.theme import (
    configure_app, resolve_fonts,
    SURFACE_BASE, SURFACE_MUTED, SURFACE_RAISED, SURFACE_STRONG,
    BORDER_HAIRLINE, BORDER_ACCENT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY, TEXT_INVERSE,
    FONTS,
    SPACE_1, SPACE_2, SPACE_3, SPACE_4, SPACE_5, SPACE_6, SPACE_7, SPACE_8,
    RADIUS_NONE, RADIUS_XS, RADIUS_SM,
    MOTION_INSTANT, MOTION_FAST,
    BTN_HEIGHT_MD,
    BORDER_WIDTH_HAIRLINE,
)
from ui.views.dashboard_view import ProfessionalDashboardView as DashboardView
from ui.views.website_scanner_view import ProfessionalScannerView as WebsiteScannerView
from ui.views.company_scanner_view import ProfessionalCompanyScannerView as CompanyScannerView
from ui.views.results_view import ResultsView
from ui.views.reports_view import ReportsView
from ui.views.settings_view import SettingsView, load_settings
from ui.views.profile_view import ProfileView
from ui.widgets import NavButton

NAV_ITEMS = [
    # (view_key, icon, label) — a distinct glyph per item instead of the
    # same "▣" repeated eight times, so the sidebar is actually scannable
    # at a glance rather than relying on label text alone.
    ("dashboard", "▦", "Dashboard"),
    ("website_scanner", "◎", "Website Scanner"),
    ("company_scanner", "◆", "Company Scanner"),
    ("results", "▤", "Results"),
    ("reports", "▥", "Reports"),
    ("settings", "⚙", "Settings"),
    ("profile", "◉", "Profile"),
]

QUICK_PRESETS = {
    "full": DEFAULT_SCANNER_KEYS,
    "xss_focus": ["xss", "sqli", "csrf", "ssrf"],
    "access_focus": ["bac", "sec_misconfig", "open_redirect", "clickjack"],
    "recon_focus": ["recon", "info_disclosure", "cloud", "sub_takeover"],
}


class PlaceholderView(ctk.CTkFrame):
    """Placeholder view for features not yet implemented."""

    def __init__(self, master, placeholder_text: str, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        label = ctk.CTkLabel(
            self,
            text=placeholder_text,
            font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_SECONDARY
        )
        label.grid(row=0, column=0, padx=20, pady=20)


class BugBountyApp(ctk.CTk):
    """Application shell."""

    def __init__(self):
        configure_app()
        super().__init__(fg_color=SURFACE_BASE)
        # Needs the root to exist; views build their fonts after this.
        resolve_fonts()

        self.title(f"{APP_NAME} — {VERSION}")
        self.geometry("1400x900")
        self.minsize(1200, 800)

        # Root grid: sidebar (col 0) is fixed-width, content (col 1) must
        # absorb all extra space on resize/maximize. Without weight on the
        # ROOT window's own grid, every child's sticky="nsew" is a no-op —
        # sticky only fills an already-expanded cell, it doesn't request the
        # expansion itself. This was missing entirely, which is why content
        # never grew past its natural minimum size on any page.
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.events = queue.Queue()
        self.scan_engine = ScanEngine(self.events)
        self.report_store = ReportStore()

        # Settings persisted from a previous session (config/settings.json)
        # were only ever applied when the user re-visited Settings and hit
        # Save in the current session — a fresh launch silently ignored
        # them and fell back to the hardcoded defaults in config/settings.py.
        self.apply_settings(load_settings())

        self.last_report_data = None
        self.scan_count = 0
        self._scan_start_time = None
        self._current_view = None
        self._pending_target = ""
        self._pending_keys = []

        self._build_sidebar()
        self._build_content()

        self._start_event_pump()

    def _build_sidebar(self):
        """Build the navigation sidebar — hard corners, lime accent."""
        self.sidebar_frame = ctk.CTkFrame(
            self,
            width=280,
            corner_radius=RADIUS_NONE,
            fg_color=SURFACE_MUTED,
            border_width=BORDER_WIDTH_HAIRLINE if 'BORDER_WIDTH_HAIRLINE' in globals() else 1,
            border_color=BORDER_HAIRLINE
        )
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_propagate(False)
        self.sidebar_frame.grid_rowconfigure(len(NAV_ITEMS), weight=1)

        # App logo/title — monospace, lime accent
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="HYDRAX\nPROFESSIONAL",
            font=ctk.CTkFont(*FONTS["brand"]),
            text_color=TEXT_PRIMARY,
            justify="left"
        )
        self.logo_label.grid(row=0, column=0, padx=SPACE_6, pady=(SPACE_6, SPACE_4), sticky="w")

        # Navigation buttons — fixed-width icon column guarantees consistent
        # icon/label alignment regardless of per-glyph font metrics.
        self.nav_buttons = {}
        for i, (name, icon, label) in enumerate(NAV_ITEMS, start=1):
            btn = NavButton(
                self.sidebar_frame,
                icon=icon,
                text=label,
                command=lambda n=name: self._switch_view(n),
            )
            btn.grid(row=i, column=0, padx=SPACE_4, pady=SPACE_2, sticky="ew")
            self.nav_buttons[name] = btn

        # Version info at bottom
        self.version_label = ctk.CTkLabel(
            self.sidebar_frame,
            text=f"v{VERSION}",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY
        )
        self.version_label.grid(row=len(NAV_ITEMS)+1, column=0, pady=(SPACE_4, SPACE_6))

    def _build_content(self):
        """Build the main content area."""
        self.content_frame = ctk.CTkFrame(self, fg_color=SURFACE_BASE, corner_radius=RADIUS_NONE)
        self.content_frame.grid(row=0, column=1, rowspan=4, sticky="nsew", padx=0, pady=0)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

        # Initialize views
        self.views = {
            "dashboard": DashboardView(self.content_frame, self),
            "website_scanner": WebsiteScannerView(self.content_frame, self.events),
            "company_scanner": CompanyScannerView(self.content_frame, self.events),
            "results": ResultsView(self.content_frame, self),
            "reports": ReportsView(self.content_frame, self),
            "settings": SettingsView(self.content_frame, self),
            "profile": ProfileView(self.content_frame, self)
        }

        # Show dashboard by default
        self._switch_view("dashboard")

    def _switch_view(self, view_name: str):
        """Switch to the specified view."""
        # Hide current view
        if self._current_view:
            self.views[self._current_view].grid_remove()

        # Show new view
        view = self.views[view_name]
        view.grid(row=0, column=0, sticky="nsew")
        # Views that load external state (Results/Reports) must repopulate
        # every time they're shown, not just once at construction — neither
        # ResultsView nor ReportsView called their own refresh() on initial
        # display, so both rendered as a permanently blank panel below the
        # header until something else happened to trigger it (Reports only
        # refreshed after a delete; Results never refreshed at all).
        if hasattr(view, "refresh"):
            view.refresh()
        self._current_view = view_name

        # Update navigation button states — active = lime text + surface fill
        for name, btn in self.nav_buttons.items():
            btn.set_active(name == view_name)

    def _start_event_pump(self):
        """Start the event processing loop."""
        self._process_events()
        self.after(100, self._start_event_pump)

    def _process_events(self):
        """Process events from the scan engine."""
        try:
            while not self.events.empty():
                event = self.events.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass

    def _handle_event(self, event):
        """Handle events from the scan engine."""
        if not event:
            return

        event_type = event[0]

        # Route events to active view
        if self._current_view and hasattr(self.views[self._current_view], 'handle_event'):
            self.views[self._current_view].handle_event(event)

        # Handle global events
        if event_type == "scan_complete":
            self.last_report_data = event[2] if len(event) > 2 else None
            self.scan_count += 1
            # Switch to results view automatically
            if self._current_view != "results":
                self._switch_view("results")
            else:
                # Already on Results — _switch_view's refresh() won't fire
                # for a page that's not being switched TO, so refresh it
                # explicitly or it keeps showing stale/empty data.
                self.views["results"].refresh()
        elif event_type == "scan_error":
            # Show error in current view or dashboard
            pass
        elif event_type == "threat_update":
            # Update threat feed in scanner view
            if self._current_view == "scanner":
                self.views["scanner"].handle_event(event)

    # ------------------------------------------------------------------
    # Report / folder helpers used by the views
    # ------------------------------------------------------------------
    def save_report(self, fmt: str = "html"):
        """Persist the current report data and return its path."""
        if not self.last_report_data:
            self.show_message("No report", "Run a scan first to generate a report.")
            return None
        try:
            path = self.report_store.save(self.last_report_data, fmt=fmt)
        except Exception as exc:
            self.show_message("Export failed", f"Could not save {fmt} report:\n{exc}")
            return None
        return path

    def open_reports_folder(self):
        """Open the reports directory in the system file manager."""
        from config.settings import REPORTS_DIR
        try:
            subprocess.Popen(["xdg-open", str(REPORTS_DIR)])
        except FileNotFoundError:
            print(f"Reports directory: {REPORTS_DIR}")

    def delete_report(self, path):
        """Delete a report file via the store, then refresh the reports view."""
        self.report_store.delete(path)
        if self._current_view == "reports":
            self.views["reports"].refresh()

    def show_message(self, title: str, message: str):
        """Show a modal info dialog."""
        import tkinter.messagebox as messagebox
        messagebox.showinfo(title, message, parent=self)

    def apply_settings(self, settings: dict):
        """Apply updated scan engine settings."""
        try:
            self.scan_engine.apply_settings(settings)
        except AttributeError:
            pass

    def run(self):
        """Start the application main loop."""
        self.mainloop()


def run():
    """Start the application main loop."""
    app = BugBountyApp()
    app.mainloop()


if __name__ == "__main__":
    run()