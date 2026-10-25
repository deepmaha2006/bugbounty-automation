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
from ui.views.company_scanner_view import init_company_scanner
from ui.views.results_view import ResultsView
from ui.views.reports_view import ReportsView
from ui.views.settings_view import SettingsView, load_settings
from ui.views.profile_view import ProfileView
from ui.widgets import NavButton

# Main navigation — fills the middle flex-1 area
NAV_ITEMS = [
    ("dashboard",       "▦", "Dashboard"),
    ("company_scanner", "◆", "Company Scanner"),
    ("website_scanner", "◎", "Website Scanner"),
    ("results",         "▤", "Results"),
    ("reports",         "▥", "Reports"),
]

# Footer navigation — sits above the profile card
NAV_FOOTER = [
    ("settings", "⚙", "Settings"),
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
        # absorb all extra space on resize/maximize. A single row with weight=1
        # means both the sidebar and content frame fill the full window height
        # without any gap or overflow. rowspan=1 on each child keeps them
        # anchored to row 0 only, avoiding ghost rows that push content down.
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.events = queue.Queue()
        self.scan_engine = ScanEngine(self.events)
        from brain.autonomous_brain import brain as autonomous_brain
        autonomous_brain.start(self.events)
        self._autonomous_brain = autonomous_brain
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
        self._setup_tray()
        self._setup_global_scroll()

    # ------------------------------------------------------------------
    # System tray (§7) — minimize to tray instead of quitting on close
    # ------------------------------------------------------------------

    def _setup_tray(self) -> None:
        """Wire the window-close button to minimize to tray (not quit).

        Uses pystray if available. If pystray or Pillow are absent, falls back
        to normal close behaviour so the app always starts cleanly.
        """
        try:
            import pystray
            from PIL import Image, ImageDraw
        except ImportError:
            # pystray / Pillow not installed — close button quits normally
            return

        self._tray_icon = None
        self._tray_running = False

        def _make_icon_image(size: int = 64) -> "Image.Image":
            img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            # Simple circle with "H" for HydraX
            draw.ellipse([4, 4, size - 4, size - 4], fill="#c41e3a")
            font_size = size // 2
            draw.text(
                (size // 2, size // 2),
                "H",
                fill="white",
                anchor="mm",
            )
            return img

        def _show_window() -> None:
            self.after(0, self.deiconify)
            self.after(0, self.lift)
            self.after(0, self.focus_force)

        def _quit_app() -> None:
            if self._tray_icon:
                self._tray_icon.stop()
            self.after(0, self.destroy)

        def _build_tray_icon() -> None:
            menu = pystray.Menu(
                pystray.MenuItem("Show HydraX", _show_window, default=True),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Quit", _quit_app),
            )
            img = _make_icon_image()
            self._tray_icon = pystray.Icon(
                "hydrax", img, "HydraX — running in background", menu
            )
            self._tray_running = True
            self._tray_icon.run()   # blocks until .stop() is called

        def _on_close() -> None:
            """Minimize to tray instead of destroying the window."""
            self.withdraw()
            if not self._tray_running:
                import threading as _threading
                _threading.Thread(
                    target=_build_tray_icon, daemon=True, name="hydrax-tray"
                ).start()

        self.protocol("WM_DELETE_WINDOW", _on_close)

    def _setup_global_scroll(self) -> None:
        """Route wheel events to the nearest CTkScrollableFrame ancestor.

        CTkScrollableFrame only captures wheel events when the scrollbar itself
        is hovered. This fix walks up the widget tree from whatever is under the
        cursor and delegates the scroll to the first CTkScrollableFrame found,
        letting every nested widget respond to two-finger / mouse-wheel scroll.

        Handles Windows (<MouseWheel>), Linux (<Button-4>/<Button-5>), and
        macOS (<MouseWheel> with different delta scaling) in one place.
        """
        import customtkinter as _ctk

        def _find_scrollable(widget):
            """Walk up the tree and return the first CTkScrollableFrame found."""
            seen = set()
            while widget is not None:
                wid = id(widget)
                if wid in seen:
                    break
                seen.add(wid)
                if isinstance(widget, _ctk.CTkScrollableFrame):
                    return widget
                if isinstance(widget, _ctk.CTkTextbox):
                    return None   # textbox handles its own scroll
                try:
                    widget = widget.master
                except AttributeError:
                    break
            return None

        def _on_wheel(event):
            sf = _find_scrollable(event.widget)
            if sf is None:
                return
            # Windows / macOS: event.delta in multiples of ±120
            # Linux Button-4 = scroll up, Button-5 = scroll down
            if event.num == 4:
                units = -3
            elif event.num == 5:
                units = 3
            else:
                units = int(-1 * (event.delta / 120)) * 3
            try:
                sf._parent_canvas.yview_scroll(units, "units")
            except Exception:
                pass

        self.bind_all("<MouseWheel>", _on_wheel, add="+")
        # Linux X11 scroll events come as Button-4 / Button-5
        self.bind_all("<Button-4>", _on_wheel, add="+")
        self.bind_all("<Button-5>", _on_wheel, add="+")

    def _build_sidebar(self):
        """Float-UI sidebar: logo (h-20) → main nav (flex-1) → footer nav → profile card."""
        sb = ctk.CTkFrame(
            self, width=280, corner_radius=RADIUS_NONE,
            fg_color=SURFACE_MUTED,
            border_width=BORDER_WIDTH_HAIRLINE,
            border_color=BORDER_HAIRLINE,
        )
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_columnconfigure(0, weight=1)
        # Row 1 (main nav) fills all available vertical space
        sb.grid_rowconfigure(1, weight=1)
        self.sidebar_frame = sb

        # ── Logo area  (h-20 = ~80 px) ───────────────────────────────────
        logo_row = ctk.CTkFrame(sb, fg_color="transparent", height=72, corner_radius=0)
        logo_row.grid(row=0, column=0, sticky="ew", padx=SPACE_5, pady=(SPACE_5, SPACE_3))
        logo_row.grid_propagate(False)
        logo_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            logo_row, text="HydraX",
            font=ctk.CTkFont(*FONTS["brand"]),
            text_color=BORDER_ACCENT, anchor="w",
        ).grid(row=0, column=0, sticky="sw")
        ctk.CTkLabel(
            logo_row, text="PROFESSIONAL EDITION",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY, anchor="w",
        ).grid(row=1, column=0, sticky="nw", pady=(SPACE_1, 0))

        # ── Main nav  (px-4, flex-1, scrollable) ─────────────────────────
        nav_scroll = ctk.CTkScrollableFrame(
            sb, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=SURFACE_STRONG,
            scrollbar_button_hover_color=BORDER_HAIRLINE,
        )
        nav_scroll.grid(row=1, column=0, sticky="nsew", padx=SPACE_4, pady=0)
        nav_scroll.grid_columnconfigure(0, weight=1)

        self.nav_buttons = {}
        for name, icon, label in NAV_ITEMS:
            btn = NavButton(
                nav_scroll, icon=icon, text=label,
                command=lambda n=name: self._switch_view(n),
            )
            btn.pack(fill="x", pady=SPACE_1)
            self.nav_buttons[name] = btn

        # ── Footer separator ──────────────────────────────────────────────
        ctk.CTkFrame(sb, height=1, fg_color=BORDER_HAIRLINE, corner_radius=0,
                     ).grid(row=2, column=0, sticky="ew", padx=0)

        # ── Footer nav items (Settings, …) ───────────────────────────────
        footer = ctk.CTkFrame(sb, fg_color="transparent", corner_radius=0)
        footer.grid(row=3, column=0, sticky="ew", padx=SPACE_4, pady=(SPACE_2, 0))
        footer.grid_columnconfigure(0, weight=1)

        for name, icon, label in NAV_FOOTER:
            btn = NavButton(
                footer, icon=icon, text=label,
                command=lambda n=name: self._switch_view(n),
            )
            btn.pack(fill="x", pady=SPACE_1)
            self.nav_buttons[name] = btn

        # ── Profile card separator ────────────────────────────────────────
        ctk.CTkFrame(sb, height=1, fg_color=BORDER_HAIRLINE, corner_radius=0,
                     ).grid(row=4, column=0, sticky="ew", padx=0)

        # ── Profile card  (py-4 px-4) ────────────────────────────────────
        profile_card = ctk.CTkFrame(sb, fg_color="transparent", corner_radius=0)
        profile_card.grid(row=5, column=0, sticky="ew", padx=SPACE_5, pady=SPACE_4)
        profile_card.grid_columnconfigure(1, weight=1)

        # Avatar circle — CTkLabel with fg_color + corner_radius renders as a circle badge
        ctk.CTkLabel(
            profile_card, text="HX",
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_INVERSE,
            fg_color=BORDER_ACCENT,
            corner_radius=22, width=44, height=44,
        ).grid(row=0, column=0, rowspan=2, padx=(0, SPACE_4), sticky="w")

        ctk.CTkLabel(
            profile_card, text="Security Analyst",
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=1, sticky="sw")

        view_profile_btn = ctk.CTkButton(
            profile_card, text="View profile",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            fg_color="transparent",
            hover_color=SURFACE_STRONG,
            corner_radius=RADIUS_XS,
            height=18, anchor="w",
            command=lambda: self._switch_view("profile"),
        )
        view_profile_btn.grid(row=1, column=1, sticky="nw")
        # Also track profile in nav_buttons so it highlights when active
        self.nav_buttons["profile"] = type(
            "_ProfileProxy", (),
            {"set_active": lambda self, a: view_profile_btn.configure(
                text_color=BORDER_ACCENT if a else TEXT_SECONDARY
            )}
        )()

    def _build_content(self):
        """Build the main content area."""
        self.content_frame = ctk.CTkFrame(self, fg_color=SURFACE_BASE, corner_radius=RADIUS_NONE)
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

        # Initialize views
        self.views = {
            "dashboard":       DashboardView(self.content_frame, self),
            "company_scanner": init_company_scanner(self.content_frame, self.events),
            "website_scanner": WebsiteScannerView(self.content_frame, self.events),
            "results":         ResultsView(self.content_frame, self),
            "reports":         ReportsView(self.content_frame, self),
            "settings":        SettingsView(self.content_frame, self),
            "profile":         ProfileView(self.content_frame, self),
        }

        # Show dashboard by default
        self._switch_view("dashboard")

    def _switch_view(self, view_name: str):
        """Switch to the specified view."""
        if view_name not in self.views:
            return

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
                # Feed brain (ignores non-scan_complete events internally)
                if hasattr(self, "_autonomous_brain"):
                    self._autonomous_brain.feed(event)
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
            # Don't steal focus from company scanner — it manages its own UI
            if self._current_view != "company_scanner":
                if self._current_view != "results":
                    self._switch_view("results")
                else:
                    self.views["results"].refresh()
        elif event_type == "scan_error":
            # Show error in current view or dashboard
            pass
        elif event_type == "brain_analysis_complete":
            # Route enriched findings to company scanner's brain tab
            if self._current_view == "company_scanner":
                view = self.views.get("company_scanner")
                if view and hasattr(view, "handle_brain_results"):
                    view.handle_brain_results(event[1], event[2])
        elif event_type == "threat_update":
            pass

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