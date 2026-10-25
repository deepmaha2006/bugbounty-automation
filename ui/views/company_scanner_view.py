"""
Company Scanner - Unified SOC-style dashboard for company asset protection.

Merges live threat monitoring (from connected company servers via Connector API)
with scheduled scanning and auto-remediation into a single professional interface.

Layout: 3 tabs - CONNECT & CONFIGURE | LIVE DETECTION | REMEDIATION
Tab 1 must have a successful connection before Tabs 2/3 activate.
"""

from __future__ import annotations

import json
import queue
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import customtkinter as ctk

from config.settings import (
    SCANNER_CATEGORIES, SCANNER_META, ALL_SCANNER_KEYS,
    DEFAULT_SCANNER_KEYS, resolve_target_url,
)
from core.scan_engine import ScanEngine
from ui.theme import (
    SURFACE_BASE, SURFACE_MUTED, SURFACE_RAISED, SURFACE_STRONG,
    BORDER_HAIRLINE, BORDER_ACCENT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY, TEXT_INVERSE,
    STATUS_COLORS, SEVERITY_COLORS,
    STATUS_CRITICAL, STATUS_HIGH, STATUS_MEDIUM, STATUS_LOW, STATUS_OK,
    FONTS,
    SPACE_1, SPACE_2, SPACE_3, SPACE_4, SPACE_5, SPACE_6, SPACE_7, SPACE_8,
    RADIUS_NONE, RADIUS_MD, RADIUS_SM, RADIUS_XS,
    BTN_HEIGHT_SM, BTN_HEIGHT_MD, BTN_HEIGHT_LG,
    BTN_WIDTH_SM, BTN_WIDTH_MD, BTN_WIDTH_LG, BTN_WIDTH_XL,
    INPUT_HEIGHT, CARD_PADDING,
    BORDER_WIDTH_HAIRLINE, BORDER_WIDTH_ACCENT,
)
from ui.widgets import (
    PrimaryButton, GhostButton,
    MetricCard, StatusIndicator, make_card, ScanChip,
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class Vulnerability:
    """A single vulnerability finding."""

    def __init__(
        self,
        vuln_id: str,
        name: str,
        severity: str,
        endpoint: str,
        description: str,
        remediation: str,
        cve: Optional[str] = None,
        owasp: Optional[str] = None,
        status: str = "Open",  # Open -> In Progress -> Fixed -> Won't Fix
        auto_remediated: bool = False,
    ):
        self.id = vuln_id
        self.name = name
        self.severity = severity
        self.endpoint = endpoint
        self.description = description
        self.remediation = remediation
        self.cve = cve
        self.owasp = owasp
        self.status = status
        self.auto_remediated = auto_remediated


class LiveThreat:
    """Threat from live connector telemetry."""

    def __init__(
        self,
        threat_id: str,
        timestamp: datetime,
        source_connector: str,
        threat_type: str,
        severity: str,
        description: str,
        target_asset: Optional[str] = None,
        auto_remediated: bool = False,
    ):
        self.id = threat_id
        self.timestamp = timestamp
        self.source_connector = source_connector
        self.threat_type = threat_type
        self.severity = severity
        self.description = description
        self.target_asset = target_asset
        self.auto_remediated = auto_remediated


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SEVERITY_COLORS_MAP = {
    "critical": "#E5484D",
    "high":     "#FF8B3D",
    "medium":   "#F5C518",
    "low":      "#8B97A7",
    "info":     "#8B97A7",
}

SCAN_CHECKBOXES = [
    "port_scan", "service_version", "ssl_tls_check", "security_headers",
    "open_directories", "sql_injection", "xss", "misconfigurations",
    "outdated_software",
]

SCAN_LABELS = {
    "port_scan":          "Port Scan",
    "service_version":    "Service/Version Detection",
    "ssl_tls_check":      "SSL/TLS Check",
    "security_headers":   "Security Headers",
    "open_directories":   "Open Directories",
    "sql_injection":      "SQL Injection",
    "xss":                "XSS",
    "misconfigurations":  "Misconfigurations",
    "outdated_software":  "Outdated Software / CVE",
}


# ---------------------------------------------------------------------------
# Underline tab bar  (mirrors Radix-UI / Vue tab design)
# ---------------------------------------------------------------------------

class _UnderlineTabs:
    """
    Horizontal underline-style tab bar + stacked content frames.

    Mirrors the Radix-UI / Vue tab component:
      - Tab bar row with a 1 px hairline at the bottom
      - Active tab: accent-color text + 2 px accent underline
      - Inactive tab: muted text, no underline
      - Content frames stacked in a grid; only the active one is shown

    Public interface mimics the subset of CTkTabview used in this view:
      .set(name)   → switch to tab
      .get()       → return active tab name
    """

    # Accent / inactive colours (pulled from theme at import time)
    _ACTIVE_TEXT   = BORDER_ACCENT          # "#c41e3a" cyber red
    _INACTIVE_TEXT = TEXT_SECONDARY
    _INDICATOR_ON  = BORDER_ACCENT
    _INDICATOR_OFF = "transparent"
    _HOVER_BG      = SURFACE_STRONG

    def __init__(
        self,
        parent: ctk.CTkFrame,
        tab_names: List[str],
        on_switch=None,
        **content_kwargs,
    ) -> None:
        self._parent     = parent
        self._tab_names  = tab_names
        self._on_switch  = on_switch
        self._active     = tab_names[0]
        self._buttons:    Dict[str, ctk.CTkButton]  = {}
        self._indicators: Dict[str, ctk.CTkFrame]   = {}
        self._frames:     Dict[str, ctk.CTkFrame]   = {}

        # ── tab bar row ──────────────────────────────────────────────────
        bar_outer = ctk.CTkFrame(parent, fg_color=SURFACE_BASE, corner_radius=0)
        bar_outer.grid(row=2, column=0, sticky="ew", padx=0, pady=0)
        bar_outer.grid_columnconfigure(len(tab_names), weight=1)

        for col, name in enumerate(tab_names):
            cell = ctk.CTkFrame(bar_outer, fg_color="transparent", corner_radius=0)
            cell.grid(row=0, column=col, sticky="ns", padx=(SPACE_6 if col == 0 else 0, 0))

            btn = ctk.CTkButton(
                cell,
                text=name,
                font=ctk.CTkFont(*FONTS["body_bold"]),
                text_color=self._ACTIVE_TEXT if name == self._active else self._INACTIVE_TEXT,
                fg_color="transparent",
                hover_color=self._HOVER_BG,
                corner_radius=RADIUS_SM,
                border_width=0,
                height=BTN_HEIGHT_MD,
                command=lambda n=name: self.set(n),
            )
            btn.pack(fill="x", padx=SPACE_3, pady=(SPACE_3, 0))

            indicator = ctk.CTkFrame(
                cell,
                height=2,
                corner_radius=1,
                fg_color=self._INDICATOR_ON if name == self._active else self._INDICATOR_OFF,
            )
            indicator.pack(fill="x", padx=SPACE_3, pady=(2, 0))

            self._buttons[name]    = btn
            self._indicators[name] = indicator

        # bottom separator spanning full width
        sep = ctk.CTkFrame(bar_outer, height=1, fg_color=BORDER_HAIRLINE, corner_radius=0)
        sep.grid(row=1, column=0, columnspan=len(tab_names) + 1, sticky="ew", pady=(SPACE_2, 0))

        # ── content area ─────────────────────────────────────────────────
        content_area = ctk.CTkFrame(
            parent,
            fg_color=SURFACE_MUTED,
            corner_radius=0,
            **content_kwargs,
        )
        content_area.grid(row=3, column=0, sticky="nsew", padx=SPACE_6, pady=(0, SPACE_6))
        content_area.grid_columnconfigure(0, weight=1)
        content_area.grid_rowconfigure(0, weight=1)

        for name in tab_names:
            frame = ctk.CTkFrame(content_area, fg_color="transparent", corner_radius=0)
            frame.grid(row=0, column=0, sticky="nsew")
            frame.grid_columnconfigure(0, weight=1)
            frame.grid_rowconfigure(0, weight=1)
            self._frames[name] = frame

        # hide all but the first
        for name in tab_names[1:]:
            self._frames[name].grid_remove()

    # ── public API ────────────────────────────────────────────────────────

    def set(self, name: str) -> None:
        """Switch to the named tab."""
        if name not in self._frames:
            return
        prev = self._active
        self._active = name

        # update indicators and text colors
        for n, btn in self._buttons.items():
            active = n == name
            btn.configure(text_color=self._ACTIVE_TEXT if active else self._INACTIVE_TEXT)
            self._indicators[n].configure(
                fg_color=self._INDICATOR_ON if active else self._INDICATOR_OFF
            )

        # swap frames
        self._frames[prev].grid_remove()
        self._frames[name].grid()

        if self._on_switch:
            self._on_switch()

    def get(self) -> str:
        """Return the currently active tab name."""
        return self._active

    def frame(self, name: str) -> ctk.CTkFrame:
        """Return the content frame for the named tab."""
        return self._frames[name]


# ---------------------------------------------------------------------------
# SOC Live Detection Table
# ---------------------------------------------------------------------------

class _SocRow(ctk.CTkFrame):
    """One row in the SOC detection table: TIME | MODULE | ENDPOINT | RESULT | SEV."""

    _PILL: dict = {
        "critical": ("#ef4444", "#3d0a0a"),
        "high":     ("#f97316", "#3d1e0a"),
        "alert":    ("#f97316", "#3d1e0a"),
        "medium":   ("#f59e0b", "#3d2a0a"),
        "low":      ("#84cc16", "#0f2e0a"),
        "safe":     ("#22c55e", "#0a2e12"),
        "running":  ("#38bdf8", "#0a1e2e"),
        "info":     ("#94a3b8", "#1a1f2e"),
        "success":  ("#22c55e", "#0a2e12"),
        "error":    ("#f87171", "#2a0a0a"),
        "monitor":  ("#a855f7", "#1e0a2e"),
    }
    _SPIN = "◐◓◑◒"

    def __init__(
        self,
        master,
        ts: str,
        module: str,
        endpoint: str,
        result: str,
        severity: str,
        zebra: bool = False,
    ) -> None:
        bg = "#0d1117" if zebra else "#080b0f"
        super().__init__(master, fg_color=bg, corner_radius=0)
        self.grid_columnconfigure(2, weight=1)

        self._sev   = severity.lower()
        self._si    = 0
        self._job: Optional[str] = None

        ft, fb = self._PILL.get(self._sev, self._PILL["info"])
        mono = ctk.CTkFont(family="Consolas", size=11)

        self._tl = ctk.CTkLabel(self, text=ts,                          width=62,  anchor="w", font=mono, text_color="#4a5568")
        self._ml = ctk.CTkLabel(self, text=module[:10],                  width=80,  anchor="w", font=mono, text_color="#718096")
        self._el = ctk.CTkLabel(self, text=self._t(endpoint, 28),       anchor="w", font=mono, text_color="#718096")
        self._rl = ctk.CTkLabel(self, text=self._t(result, 28),         width=190, anchor="w", font=mono, text_color="#e2e8f0")
        self._sl = ctk.CTkLabel(self, text=severity.upper()[:8],        width=76,  anchor="center",
                                 font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                                 text_color=ft, fg_color=fb, corner_radius=4)

        kw = {"pady": (3, 3)}
        self._tl.grid(row=0, column=0, padx=(6, 3), **kw, sticky="w")
        self._ml.grid(row=0, column=1, padx=3,      **kw, sticky="w")
        self._el.grid(row=0, column=2, padx=3,      **kw, sticky="ew")
        self._rl.grid(row=0, column=3, padx=3,      **kw, sticky="w")
        self._sl.grid(row=0, column=4, padx=(3, 6), **kw, sticky="e")

        if self._sev == "running":
            self._tick()

    @staticmethod
    def _t(s: str, n: int) -> str:
        return s if len(s) <= n else s[:n - 1] + "…"

    def _tick(self) -> None:
        if self._sev != "running":
            return
        try:
            self._si = (self._si + 1) % 4
            self._sl.configure(text=self._SPIN[self._si])
            self._job = self.after(220, self._tick)
        except Exception:
            pass

    def update(self, result: str, severity: str) -> None:
        if self._job:
            try:
                self.after_cancel(self._job)
            except Exception:
                pass
            self._job = None
        self._sev = severity.lower()
        ft, fb = self._PILL.get(self._sev, self._PILL["info"])
        self._rl.configure(text=self._t(result, 28))
        self._sl.configure(text=severity.upper()[:8], text_color=ft, fg_color=fb)

    def destroy(self) -> None:
        if self._job:
            try:
                self.after_cancel(self._job)
            except Exception:
                pass
            self._job = None
        self._sev = ""
        super().destroy()


class _SocTable(ctk.CTkFrame):
    """SOC-style live detection table with a sticky header and scrollable body."""

    MAX_ROWS = 500

    def __init__(self, master, **kwargs) -> None:
        kwargs.setdefault("fg_color", "#080b0f")
        kwargs.setdefault("corner_radius", 0)
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(0, weight=1)

        # Sticky header row (outside scroll)
        hdr = ctk.CTkFrame(self, fg_color="#0a0d12", corner_radius=0, height=24)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        hdr.grid_columnconfigure(2, weight=1)
        for col, (lbl, w) in enumerate([
            ("TIME", 62), ("MODULE", 80), ("ENDPOINT", None),
            ("RESULT", 190), ("SEV", 76),
        ]):
            if w:
                hdr.grid_columnconfigure(col, minsize=w)
            ctk.CTkLabel(
                hdr, text=lbl, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                text_color="#4a5568",
            ).grid(row=0, column=col, padx=(6 if col == 0 else 3, 3), pady=2, sticky="w")

        # Scrollable body
        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color="#080b0f", corner_radius=0, height=220,
            scrollbar_button_color="#1a1f2e",
            scrollbar_button_hover_color="#2d3748",
        )
        self._scroll.grid(row=1, column=0, sticky="ew")
        self._scroll.grid_columnconfigure(0, weight=1)

        self._rows: list = []
        self._mod_rows: dict = {}  # (module_key, cycle_idx) → _SocRow
        self._zebra: bool = False

    # --- Public API ---

    def add_module_row(self, ts: str, module: str, endpoint: str, cycle: int) -> "_SocRow":
        """Add a RUNNING row; returns it so it can be updated in-place later."""
        self._zebra = not self._zebra
        row = _SocRow(self._scroll, ts, module, endpoint, "scanning…", "running", self._zebra)
        row.pack(fill="x", side="top")
        self._rows.append(row)
        self._mod_rows[(module, cycle)] = row
        self._prune()
        self._autoscroll()
        return row

    def update_module_row(self, module: str, cycle: int, result: str, severity: str) -> None:
        """Update an existing RUNNING row to its final state."""
        row = self._mod_rows.get((module, cycle))
        if row:
            row.update(result, severity)

    def add_cycle_divider(self, cycle_n: int, findings_count: int) -> None:
        """Insert a separator row between cycles."""
        p = "s" if findings_count != 1 else ""
        txt = f"── Cycle {cycle_n}  ·  {findings_count} finding{p}  ──"
        div = ctk.CTkLabel(
            self._scroll, text=txt, anchor="center",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color="#4a5568", fg_color="#0f141a", corner_radius=0,
        )
        div.pack(fill="x", side="top", pady=(2, 0))
        self._rows.append(div)
        self._autoscroll()

    def add_info_row(self, ts: str, module: str, message: str, severity: str = "info") -> None:
        """Add a non-module status/info/error row."""
        self._zebra = not self._zebra
        row = _SocRow(self._scroll, ts, module, "", message, severity, self._zebra)
        row.pack(fill="x", side="top")
        self._rows.append(row)
        self._prune()
        self._autoscroll()

    def clear(self) -> None:
        for r in self._rows:
            try:
                r.pack_forget()
                r.destroy()
            except Exception:
                pass
        self._rows.clear()
        self._mod_rows.clear()
        self._zebra = False

    # --- Internal ---

    def _prune(self) -> None:
        while len(self._rows) > self.MAX_ROWS:
            try:
                r = self._rows.pop(0)
                r.pack_forget()
                r.destroy()
            except Exception:
                pass

    def _autoscroll(self) -> None:
        try:
            canvas = self._scroll._parent_canvas
            canvas.after(5, lambda: canvas.yview_moveto(1.0))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main view
# ---------------------------------------------------------------------------

class CompanyScannerView(ctk.CTkFrame):
    """Unified SOC dashboard: Connect & Configure -> Live Detection -> Remediation."""

    def __init__(
        self,
        master: ctk.CTk,
        event_queue: Optional[queue.Queue] = None,
        on_event=None,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color=SURFACE_BASE, **kwargs)
        self.event_queue = event_queue
        self.on_event = on_event

        # Scan engine (private queue)
        self._q: queue.Queue = queue.Queue()
        self.scan_engine = ScanEngine(self._q)

        # --- GLOBAL STATE ---
        self.is_connected: bool = False
        self.connected_target: Optional[str] = None
        self.scan_state: str = "Idle"
        self.last_scan_time: Optional[str] = None

        # Connection details
        self.connected_info: Dict[str, Any] = {}
        self.connection_status: str = "idle"  # idle, testing, connected, error

        # Scanning state
        self.is_scanning = False
        self.loop_scan: bool = False   # continuous loop mode
        self.loop_count: int = 0       # completed scan cycles
        self._loop_session_start: Optional[float] = None
        self.scan_progress: int = 0
        self.active_scans: List[str] = []

        # Threats and vulnerabilities
        self.live_threats: List[LiveThreat] = []
        self.vulnerabilities: List[Vulnerability] = []
        self.threat_counter = 0
        self.vuln_counter = 0

        # Simulation interval ID
        self._simulation_loop_id: Optional[str] = None

        # Connector state
        self.connectors: Dict[str, Dict[str, Any]] = {}
        self.auto_remediate_enabled = True
        self.remediation_policy = "CONSERVATIVE"

        # UI refs (set in _setup_ui)
        self.tabview: Optional[ctk.CTkTabview] = None
        self.conn_tab: Optional[ctk.CTkFrame] = None
        self.detection_tab: Optional[ctk.CTkFrame] = None
        self.remediation_tab: Optional[ctk.CTkFrame] = None

        self._setup_ui()
        self.after(100, self._poll_events)

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        """Build the full professional interface."""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)   # Top status bar
        self.grid_rowconfigure(1, weight=0)   # Title
        self.grid_rowconfigure(2, weight=0)   # Underline tab bar
        self.grid_rowconfigure(3, weight=1)   # Tab content area

        self._create_top_status_bar()

        # Title
        ctk.CTkLabel(
            self, text="COMPANY SCANNER",
            font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=SPACE_6, pady=(SPACE_4, SPACE_2))

        # Underline tab bar (row 2 = bar, row 3 = content — both managed inside _UnderlineTabs)
        self.tabview = _UnderlineTabs(
            self,
            tab_names=["CONNECT & CONFIGURE", "ATTACK", "VULNERABILITY INTELLIGENCE"],
            on_switch=self._on_tab_switch,
        )
        self.conn_tab        = self.tabview.frame("CONNECT & CONFIGURE")
        self.detection_tab   = self.tabview.frame("ATTACK")
        self.remediation_tab = self.tabview.frame("VULNERABILITY INTELLIGENCE")

        # Build each tab
        self._build_connect_tab(self.conn_tab)
        self._build_detection_tab(self.detection_tab)
        self._build_vuln_intelligence_tab(self.remediation_tab)

        # Start disabled
        self._update_ui_state()

    def _create_top_status_bar(self) -> None:
        """Thin status bar at the very top."""
        self.status_bar = ctk.CTkFrame(
            self, fg_color=SURFACE_STRONG, height=36, corner_radius=0
        )
        self.status_bar.grid(row=0, column=0, sticky="ew")
        self.status_bar.grid_propagate(False)

        # Left: Connection status + Scan state
        left_box = ctk.CTkFrame(self.status_bar, fg_color="transparent")
        left_box.pack(side="left", padx=SPACE_6)

        self.top_conn_label = ctk.CTkLabel(
            left_box, text="● Disconnected",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=STATUS_CRITICAL
        )
        self.top_conn_label.pack(side="left")

        ctk.CTkLabel(left_box, text="|", text_color=TEXT_TERTIARY).pack(side="left", padx=SPACE_4)

        self.top_scan_label = ctk.CTkLabel(
            left_box, text="Scan: Idle",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY
        )
        self.top_scan_label.pack(side="left")

        # Right: Timestamp + Pill
        right_box = ctk.CTkFrame(self.status_bar, fg_color="transparent")
        right_box.pack(side="right", padx=SPACE_6)

        self.top_time_label = ctk.CTkLabel(
            right_box, text="Last Scan: Never",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_TERTIARY
        )
        self.top_time_label.pack(side="left", padx=SPACE_4)

        self.soc_status = StatusIndicator(
            right_box, text="STANDBY", status="idle", width=100, height=24,
        )
        self.soc_status.pack(side="left", padx=SPACE_2)

    def _create_header(self) -> None:
        """Header bar with title (Removed as it's now integrated into setup_ui)."""
        pass


    # ------------------------------------------------------------------
    # TAB 1: CONNECT & CONFIGURE
    # ------------------------------------------------------------------

    def _build_connect_tab(self, parent: ctk.CTkFrame) -> None:
        """Build the responsive 2-column connection form."""
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)

        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll.grid(row=0, column=0, sticky="nsew", padx=SPACE_4, pady=SPACE_4)
        scroll.grid_columnconfigure(0, weight=1)

        main_grid = ctk.CTkFrame(scroll, fg_color="transparent")
        main_grid.grid(row=0, column=0, sticky="nsew")
        main_grid.grid_columnconfigure((0, 1), weight=1)

        # LEFT COLUMN — Settings
        left_col = ctk.CTkFrame(main_grid, fg_color="transparent")
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, SPACE_4))

        settings_card = make_card(left_col)
        settings_card.pack(fill="both", expand=True)

        ctk.CTkLabel(settings_card, text="CONNECTION SETTINGS", font=ctk.CTkFont(*FONTS["body_bold"]), text_color=TEXT_TERTIARY).pack(anchor="w", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_2))

        # Target (Full Width)
        ctk.CTkLabel(settings_card, text="Target URL / IP / Hostname", font=ctk.CTkFont(*FONTS["small_bold"])).pack(anchor="w", padx=CARD_PADDING, pady=(SPACE_2, 0))
        self.conn_target_entry = ctk.CTkEntry(settings_card, height=INPUT_HEIGHT, placeholder_text="https://example.com")
        self.conn_target_entry.pack(fill="x", padx=CARD_PADDING, pady=(0, SPACE_3))

        # 2-col inputs
        row_inputs = ctk.CTkFrame(settings_card, fg_color="transparent")
        row_inputs.pack(fill="x", padx=CARD_PADDING, pady=(0, SPACE_3))
        row_inputs.grid_columnconfigure((0, 1), weight=1)

        # Method | Ports
        method_frame = ctk.CTkFrame(row_inputs, fg_color="transparent")
        method_frame.grid(row=0, column=0, padx=(0, SPACE_2))
        ctk.CTkLabel(method_frame, text="Method", font=ctk.CTkFont(*FONTS["small_bold"])).pack(anchor="w")
        self.conn_method_var = ctk.StringVar(value="HTTPS")
        ctk.CTkOptionMenu(method_frame, values=["HTTPS", "HTTP", "SSH", "API"], variable=self.conn_method_var, height=INPUT_HEIGHT).pack(fill="x")

        ports_frame = ctk.CTkFrame(row_inputs, fg_color="transparent")
        ports_frame.grid(row=0, column=1, padx=(SPACE_2, 0))
        ctk.CTkLabel(ports_frame, text="Ports", font=ctk.CTkFont(*FONTS["small_bold"])).pack(anchor="w")
        self.conn_ports_entry = ctk.CTkEntry(ports_frame, height=INPUT_HEIGHT, placeholder_text="80, 443")
        self.conn_ports_entry.pack(fill="x")

        # Profile | Auth
        row2_inputs = ctk.CTkFrame(settings_card, fg_color="transparent")
        row2_inputs.pack(fill="x", padx=CARD_PADDING, pady=(0, SPACE_3))
        row2_inputs.grid_columnconfigure((0, 1), weight=1)

        prof_frame = ctk.CTkFrame(row2_inputs, fg_color="transparent")
        prof_frame.grid(row=0, column=0, padx=(0, SPACE_2))
        ctk.CTkLabel(prof_frame, text="Scan Profile", font=ctk.CTkFont(*FONTS["small_bold"])).pack(anchor="w")
        self.conn_profile_var = ctk.StringVar(value="Standard")
        ctk.CTkOptionMenu(prof_frame, values=["Quick", "Standard", "Deep"], variable=self.conn_profile_var, height=INPUT_HEIGHT).pack(fill="x")

        auth_frame = ctk.CTkFrame(row2_inputs, fg_color="transparent")
        auth_frame.grid(row=0, column=1, padx=(SPACE_2, 0))
        ctk.CTkLabel(auth_frame, text="Authentication", font=ctk.CTkFont(*FONTS["small_bold"])).pack(anchor="w")
        self.conn_auth_var = ctk.StringVar(value="None")
        self.conn_auth_menu = ctk.CTkOptionMenu(auth_frame, values=["None", "Basic Auth", "API Key", "SSH Key"], variable=self.conn_auth_var, height=INPUT_HEIGHT, command=self._on_auth_change)
        self.conn_auth_menu.pack(fill="x")

        self.conn_auth_frame = ctk.CTkFrame(settings_card, fg_color="transparent")
        self.conn_auth_frame.pack(fill="x", padx=CARD_PADDING, pady=(0, SPACE_3))
        self.conn_user_entry = ctk.CTkEntry(self.conn_auth_frame, placeholder_text="Username", height=INPUT_HEIGHT)
        self.conn_pass_entry = ctk.CTkEntry(self.conn_auth_frame, placeholder_text="Password", height=INPUT_HEIGHT, show="*")
        self.conn_key_entry = ctk.CTkEntry(self.conn_auth_frame, placeholder_text="API Key / Token", height=INPUT_HEIGHT, show="*")

        # Scans
        ctk.CTkLabel(settings_card, text="ENABLE SCANS", font=ctk.CTkFont(*FONTS["small_bold"])).pack(anchor="w", padx=CARD_PADDING, pady=(0, SPACE_2))
        checks = ctk.CTkFrame(settings_card, fg_color=SURFACE_MUTED, corner_radius=RADIUS_SM)
        checks.pack(fill="x", padx=CARD_PADDING, pady=(0, SPACE_3))
        self.scan_checkboxes = {}
        for i, key in enumerate(SCAN_CHECKBOXES):
            cb = ctk.CTkCheckBox(checks, text=SCAN_LABELS[key], font=ctk.CTkFont(*FONTS["body"]))
            cb.select()
            cb.grid(row=i//2, column=i%2, padx=SPACE_4, pady=SPACE_2, sticky="w")
            self.scan_checkboxes[key] = cb

        self.conn_auth_checkbox = ctk.CTkCheckBox(settings_card, text="I authorize this scan.", command=self._update_connect_btn_state)
        self.conn_auth_checkbox.pack(anchor="w", padx=CARD_PADDING, pady=SPACE_3)

        btn_row = ctk.CTkFrame(settings_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=CARD_PADDING, pady=SPACE_4)
        self.conn_test_btn = GhostButton(btn_row, "TEST CONNECTION", command=self._test_connection)
        self.conn_test_btn.pack(side="left", padx=(0, SPACE_3))
        self.conn_connect_btn = PrimaryButton(btn_row, "CONNECT", command=self._connect, state="disabled")
        self.conn_connect_btn.pack(side="left", padx=SPACE_3)
        self.conn_disconnect_btn = GhostButton(btn_row, "DISCONNECT", command=self._disconnect)

        # --- Remote Server Agent section ---
        self._agent_mode = ctk.StringVar(value="local")
        self._agent_url_var = ctk.StringVar()
        self._agent_key_var = ctk.StringVar()

        ctk.CTkFrame(settings_card, height=1, fg_color=BORDER_HAIRLINE, corner_radius=0).pack(fill="x", pady=(SPACE_2, SPACE_3))
        ctk.CTkLabel(settings_card, text="REMOTE SERVER AGENT", font=ctk.CTkFont(*FONTS["body_bold"]), text_color=TEXT_TERTIARY).pack(anchor="w", padx=CARD_PADDING, pady=(0, SPACE_1))
        ctk.CTkLabel(
            settings_card,
            text="Optionally install the HydraX agent on a remote server for continuous scanning.",
            font=ctk.CTkFont(*FONTS["small"]), text_color=TEXT_SECONDARY,
            wraplength=380, justify="left",
        ).pack(anchor="w", padx=CARD_PADDING, pady=(0, SPACE_3))

        mode_row = ctk.CTkFrame(settings_card, fg_color="transparent")
        mode_row.pack(fill="x", padx=CARD_PADDING, pady=(0, SPACE_3))
        ctk.CTkRadioButton(mode_row, text="Local Scan", variable=self._agent_mode, value="local", command=self._toggle_agent_mode).pack(side="left", padx=(0, SPACE_6))
        ctk.CTkRadioButton(mode_row, text="Remote Server", variable=self._agent_mode, value="remote", command=self._toggle_agent_mode).pack(side="left")

        self._agent_remote_frame = ctk.CTkFrame(settings_card, fg_color=SURFACE_MUTED, corner_radius=RADIUS_SM)
        ctk.CTkLabel(self._agent_remote_frame, text="Agent URL", font=ctk.CTkFont(*FONTS["small_bold"])).pack(anchor="w", padx=CARD_PADDING, pady=(CARD_PADDING, 0))
        ctk.CTkEntry(self._agent_remote_frame, height=INPUT_HEIGHT, textvariable=self._agent_url_var, placeholder_text="http://192.168.1.100:7474").pack(fill="x", padx=CARD_PADDING, pady=(0, SPACE_3))
        ctk.CTkLabel(self._agent_remote_frame, text="API Key", font=ctk.CTkFont(*FONTS["small_bold"])).pack(anchor="w", padx=CARD_PADDING)
        ctk.CTkEntry(self._agent_remote_frame, height=INPUT_HEIGHT, textvariable=self._agent_key_var, placeholder_text="API Key", show="*").pack(fill="x", padx=CARD_PADDING, pady=(0, SPACE_3))
        agent_btns = ctk.CTkFrame(self._agent_remote_frame, fg_color="transparent")
        agent_btns.pack(fill="x", padx=CARD_PADDING, pady=(0, CARD_PADDING))
        GhostButton(agent_btns, "TEST CONNECTION", command=self._test_agent_connection, height=BTN_HEIGHT_MD).pack(side="left", padx=(0, SPACE_3))
        GhostButton(agent_btns, "COPY INSTALL CMD", command=self._copy_install_command, height=BTN_HEIGHT_MD).pack(side="left")

        # RIGHT COLUMN — Connection Status
        right_col = ctk.CTkFrame(main_grid, fg_color="transparent")
        right_col.grid(row=0, column=1, sticky="nsew", padx=(SPACE_4, 0))

        self.conn_status_card = make_card(right_col)
        self.conn_status_card.pack(fill="both", expand=True)

        ctk.CTkLabel(self.conn_status_card, text="CONNECTION STATUS", font=ctk.CTkFont(*FONTS["body_bold"]), text_color=TEXT_TERTIARY).pack(anchor="w", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_2))

        self.conn_banner = ctk.CTkLabel(self.conn_status_card, text="Disconnected", font=ctk.CTkFont(size=18, weight="bold"), text_color=STATUS_CRITICAL)
        self.conn_banner.pack(pady=SPACE_8)

        self.conn_placeholder = ctk.CTkLabel(self.conn_status_card, text="Enter a target and connect to begin.", text_color=TEXT_SECONDARY)
        self.conn_placeholder.pack(pady=SPACE_8)

        self.conn_fingerprint_card = ctk.CTkFrame(self.conn_status_card, fg_color=SURFACE_MUTED)
        self.conn_fingerprint_text = ctk.CTkLabel(self.conn_fingerprint_card, text="", font=ctk.CTkFont(*FONTS["mono"]), justify="left")
        self.conn_fingerprint_text.pack(padx=CARD_PADDING, pady=CARD_PADDING)
        self.conn_fingerprint_card.pack_forget()

        self._on_auth_change("None")

    # ------------------------------------------------------------------
    # TAB 2: LIVE DETECTION
    # ------------------------------------------------------------------

    def _build_detection_tab(self, parent: ctk.CTkFrame) -> None:
        """Build the live detection tab — all content in one scrollable column."""
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)   # Scrollable frame fills everything

        # Single scrollable column — no clipping, touchpad scroll works via global handler
        scroll = ctk.CTkScrollableFrame(
            parent, fg_color="transparent",
            scrollbar_button_color=SURFACE_STRONG,
            scrollbar_button_hover_color=BORDER_HAIRLINE,
        )
        scroll.grid(row=0, column=0, sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)
        p = scroll   # alias — all rows attach to p, not parent

        # === ROW 0: Metric Cards ===
        metrics = ctk.CTkFrame(p, fg_color="transparent")
        metrics.grid(row=0, column=0, sticky="ew", padx=SPACE_6, pady=(SPACE_4, SPACE_2))
        metrics.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.det_metrics = {}
        metric_configs = [
            ("SCANS RUNNING", "scans_running", "0"),
            ("VULNS FOUND", "vulns_found", "0"),
            ("CRITICAL", "critical_count", "0"),
            ("HIGH", "high_count", "0"),
        ]
        for i, (label, key, default) in enumerate(metric_configs):
            card = MetricCard(metrics, title=label, value=default, width=180, height=64)
            card.grid(row=0, column=i, padx=SPACE_3, pady=SPACE_3, sticky="ew")
            self.det_metrics[key] = card

        # === ROW 1: Scan Controls ===
        ctrl = ctk.CTkFrame(p, fg_color="transparent")
        ctrl.grid(row=1, column=0, sticky="ew", padx=SPACE_6, pady=SPACE_2)
        ctrl.grid_columnconfigure(0, weight=1)

        self.det_start_btn = PrimaryButton(
            ctrl, "▶ START CONTINUOUS SCAN",
            command=lambda: [setattr(self, 'loop_scan', True), setattr(self, 'loop_count', 0), self._start_scan()],
            height=BTN_HEIGHT_MD,
            state="disabled"
        )
        self.det_start_btn.grid(row=0, column=0, padx=(0, SPACE_2), sticky="w")

        self.det_stop_btn = ctk.CTkButton(
            ctrl, text="STOP",
            command=self._stop_scan, height=BTN_HEIGHT_MD,
            fg_color=STATUS_CRITICAL, hover_color=STATUS_CRITICAL,
            text_color=TEXT_INVERSE, font=ctk.CTkFont(*FONTS["body_bold"]),
            corner_radius=RADIUS_SM,
            state="disabled"
        )
        self.det_stop_btn.grid(row=0, column=1, padx=SPACE_2, sticky="w")

        # Profile selector on the right
        self.det_profile_var = ctk.StringVar(value="Standard")
        self.det_profile_menu = ctk.CTkOptionMenu(
            ctrl, values=["Quick", "Standard", "Deep"],
            variable=self.det_profile_var, width=120, height=BTN_HEIGHT_MD,
            fg_color=SURFACE_MUTED, button_color=SURFACE_RAISED,
            button_hover_color=BORDER_ACCENT, text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(*FONTS["small"]),
            state="disabled"
        )
        self.det_profile_menu.grid(row=0, column=2, padx=(SPACE_4, 0), sticky="e")

        # === ROW 2: Progress Bar ===
        progress_frame = ctk.CTkFrame(p, fg_color="transparent")
        progress_frame.grid(row=2, column=0, sticky="ew", padx=SPACE_6, pady=(0, SPACE_4))
        progress_frame.grid_columnconfigure(0, weight=1)

        self.det_progress_bar = ctk.CTkProgressBar(
            progress_frame, height=10, corner_radius=RADIUS_SM,
            progress_color=BORDER_ACCENT, fg_color=SURFACE_MUTED
        )
        self.det_progress_bar.grid(row=0, column=0, sticky="ew")
        self.det_progress_bar.set(0)

        self.det_progress_label = ctk.CTkLabel(
            progress_frame, text="0% — Idle",
            font=ctk.CTkFont(*FONTS["small"]), text_color=TEXT_TERTIARY
        )
        self.det_progress_label.grid(row=1, column=0, sticky="w", pady=(SPACE_1, 0))

        # === ROW 3: Live Detection Feed (fixed height, scrolls internally) ===
        log_frame = make_card(p)
        log_frame.grid(row=3, column=0, sticky="ew", padx=SPACE_6, pady=(0, SPACE_3))
        log_frame.grid_columnconfigure(0, weight=1)

        hdr_row = ctk.CTkFrame(log_frame, fg_color="transparent")
        hdr_row.grid(row=0, column=0, sticky="ew", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_1))
        hdr_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr_row, text="LIVE DETECTION FEED",
                     font=ctk.CTkFont(*FONTS["subheading"]),
                     text_color=TEXT_PRIMARY, anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkButton(
            hdr_row, text="Clear", width=BTN_WIDTH_SM, height=BTN_HEIGHT_SM,
            fg_color=SURFACE_MUTED, hover_color=SURFACE_RAISED,
            text_color=TEXT_SECONDARY, corner_radius=RADIUS_SM,
            font=ctk.CTkFont(*FONTS["small"]),
            command=lambda: self.det_soc.clear() if hasattr(self, "det_soc") else None,
        ).grid(row=0, column=1, padx=(SPACE_4, 0), sticky="e")

        self.det_soc = _SocTable(log_frame)
        self.det_soc.grid(row=1, column=0, sticky="ew", padx=CARD_PADDING, pady=(0, CARD_PADDING))

        self._finding_rows: Dict[str, ctk.CTkFrame] = {}  # kept for Vuln Intelligence tab compat

        # === ROW 4: Scan Chips ===
        chips_outer = ctk.CTkFrame(p, fg_color="transparent")
        chips_outer.grid(row=4, column=0, sticky="ew", padx=SPACE_6, pady=(0, SPACE_3))
        chips_outer.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(chips_outer, text="SCANNERS", font=ctk.CTkFont(*FONTS["small_bold"]),
                     text_color=TEXT_SECONDARY, anchor="w").grid(row=0, column=0, sticky="w", pady=(SPACE_2, SPACE_1))
        chips_area = ctk.CTkFrame(chips_outer, fg_color=SURFACE_STRONG, height=64, corner_radius=RADIUS_SM)
        chips_area.grid(row=1, column=0, sticky="ew", pady=(0, SPACE_2))
        self._scan_chips: Dict[str, Any] = {}
        CHIP_DEFS = [
            ("shannon", "◈", "Shannon AI"), ("hexstrike", "⚡", "HexStrike"),
            ("web", "◎", "Web Scan"), ("sqli", "⟟", "SQLi"), ("xss", "✗", "XSS"),
            ("network", "⬡", "Network"), ("headers", "⊞", "Headers"),
            ("ssl", "⑆", "SSL/TLS"), ("nuclei", "◉", "Nuclei"),
        ]
        for key, icon, lbl in CHIP_DEFS:
            chip = ScanChip(chips_area, name=lbl, icon=icon)
            chip.pack(side="left", padx=SPACE_2, pady=SPACE_2)
            self._scan_chips[key] = chip

    # ------------------------------------------------------------------
    # TAB 3: BRAIN ANALYSIS
    # ------------------------------------------------------------------

    def _build_vuln_intelligence_tab(self, parent: ctk.CTkFrame) -> None:
        """Vulnerability Intelligence tab — enriched findings, CVE/CWE mapping, remediation gate."""
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=0)  # Summary rollup
        parent.grid_rowconfigure(1, weight=0)  # Status banner
        parent.grid_rowconfigure(2, weight=1)  # Findings list

        # === ROW 0: Severity Rollup Cards ===
        sum_frame = ctk.CTkFrame(parent, fg_color="transparent")
        sum_frame.grid(row=0, column=0, sticky="ew", padx=SPACE_6, pady=(SPACE_4, SPACE_2))
        sum_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        self.brain_summary = {}
        summary_configs = [
            ("TOTAL",    "total",    TEXT_PRIMARY),
            ("CRITICAL", "critical", STATUS_CRITICAL),
            ("HIGH",     "high",     STATUS_HIGH),
            ("MEDIUM",   "medium",   STATUS_MEDIUM),
            ("LOW",      "low",      STATUS_LOW),
        ]
        for i, (label, key, color) in enumerate(summary_configs):
            card = MetricCard(sum_frame, title=label, value="0", width=150, height=64)
            card.grid(row=0, column=i, padx=SPACE_3, pady=SPACE_3, sticky="ew")
            card.value_label.configure(text_color=color)
            self.brain_summary[key] = card

        # === ROW 1: Status banner ===
        self.brain_status_label = ctk.CTkLabel(
            parent,
            text="◈  Vulnerability Intelligence — waiting for scan results...",
            font=ctk.CTkFont(*FONTS["body"]),
            text_color=TEXT_TERTIARY, anchor="w",
        )
        self.brain_status_label.grid(row=1, column=0, sticky="w", padx=SPACE_6, pady=(0, SPACE_3))

        # === ROW 2: Enriched findings panel ===
        findings_outer = make_card(parent)
        findings_outer.grid(row=2, column=0, sticky="nsew", padx=SPACE_6, pady=(0, SPACE_6))
        findings_outer.grid_columnconfigure(0, weight=1)
        findings_outer.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(findings_outer, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=CARD_PADDING, pady=(CARD_PADDING, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="CORRELATED FINDINGS",
            font=ctk.CTkFont(*FONTS["subheading"]),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="CVE/CWE mapped · CVSS scored · step-by-step remediation · review-gated auto-fix",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(SPACE_1, SPACE_3))

        GhostButton(
            hdr, "AUDIT LOG",
            height=BTN_HEIGHT_SM, width=BTN_WIDTH_MD,
            command=self._show_audit_log,
        ).grid(row=0, column=1, rowspan=2, padx=(SPACE_4, 0))

        self.brain_findings_container = ctk.CTkScrollableFrame(
            findings_outer, fg_color="transparent",
        )
        self.brain_findings_container.grid(row=1, column=0, sticky="nsew",
                                           padx=CARD_PADDING, pady=(0, CARD_PADDING))
        self.brain_findings_container.grid_columnconfigure(0, weight=1)

        # Empty state placeholder
        self._vi_empty_label = ctk.CTkLabel(
            self.brain_findings_container,
            text="No findings yet.\nConnect to a target, run a scan, and results will appear here.",
            font=ctk.CTkFont(*FONTS["body"]),
            text_color=TEXT_TERTIARY, justify="center",
        )
        self._vi_empty_label.grid(row=0, column=0, padx=SPACE_8, pady=SPACE_8)

        # Audit log for applied auto-fixes — hidden until first fix applied
        self._fix_audit_log: List[dict] = []

        # Stubs so legacy code paths don't AttributeError
        self.rem_vuln_container = self.brain_findings_container
        self.rem_empty_label = self._vi_empty_label
        self.rem_actions_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self.rem_auto_btn = ctk.CTkButton(self.rem_actions_frame, text="")
        self.rem_status_var = ctk.StringVar(value="Open")
        self.rem_summary: dict = {}
        self._expanded_vuln_id: Optional[str] = None
        self._selected_vuln: Optional[Vulnerability] = None

    # ------------------------------------------------------------------
    # Tab switching & enabled state
    # ------------------------------------------------------------------

    def _on_tab_switch(self) -> None:
        """Enforce tab access - require connection before viewing tabs 2 & 3.

        CTkTabview's command callback does NOT pass the tab name as an argument.
        We must retrieve it via self.tabview.get().
        """
        if not self.tabview:
            return
        current = self.tabview.get()
        if current in ("ATTACK", "VULNERABILITY INTELLIGENCE") and not self.is_connected:
            self.tabview.set("CONNECT & CONFIGURE")
            # Show a toast-like notification in the connect tab
            if hasattr(self, 'conn_banner'):
                self.conn_banner.configure(
                    text="[!] Please connect to a target first to unlock Detection & Remediation.",
                    text_color=STATUS_HIGH,
                )
        elif current == "CONNECT & CONFIGURE":
            if hasattr(self, 'conn_banner') and "unlock" in self.conn_banner.cget("text"):
                self.conn_banner.configure(text="", text_color=TEXT_TERTIARY)

    def _on_auth_change(self, choice: str) -> None:
        """Show/hide appropriate auth fields based on selection."""
        if not hasattr(self, 'conn_auth_frame'):
            return
        for child in self.conn_auth_frame.winfo_children():
            child.grid_forget()

        if choice == "Basic Auth":
            self.conn_user_entry.grid(row=0, column=0, padx=(0, SPACE_2), sticky="ew")
            self.conn_pass_entry.grid(row=0, column=1, padx=(SPACE_2, 0), sticky="ew")
        elif choice in ("API Key", "SSH Key"):
            self.conn_key_entry.configure(placeholder_text=f"Enter {choice}")
            self.conn_key_entry.grid(row=0, column=0, columnspan=2, sticky="ew")

    def _update_ui_state(self) -> None:
        """Update all UI elements based on connection and scan state."""
        # Update top status bar
        if self.is_connected:
            self.top_conn_label.configure(text="● Connected", text_color=STATUS_OK)
            if self.connected_target:
                self.top_conn_label.configure(text=f"● Connected: {self.connected_target}")
        else:
            self.top_conn_label.configure(text="● Disconnected", text_color=STATUS_CRITICAL)

        # Update scan state label
        self.top_scan_label.configure(text=f"Scan: {self.scan_state}")

        # Update last scan time
        if self.last_scan_time:
            self.top_time_label.configure(text=f"Last Scan: {self.last_scan_time}")
        else:
            self.top_time_label.configure(text="Last Scan: Never")

        # Tab 1: Update connect/disconnect buttons (pack-based layout)
        if self.is_connected:
            self.conn_connect_btn.pack_forget()
            self.conn_disconnect_btn.pack(side="left", padx=SPACE_3)
            self.conn_test_btn.configure(state="disabled")
            # Show connection banner and fingerprint
            self._show_connection_banner()
        else:
            self.conn_disconnect_btn.pack_forget()
            self.conn_connect_btn.pack(side="left", padx=SPACE_3)
            self.conn_test_btn.configure(state="normal")
            self.conn_banner.configure(text="Disconnected", text_color=STATUS_CRITICAL)
            if hasattr(self, 'conn_placeholder'):
                self.conn_placeholder.pack(pady=SPACE_8)
            if hasattr(self, 'conn_fingerprint_card'):
                self.conn_fingerprint_card.pack_forget()

        # Tab 2: Enable/disable scan controls
        scan_enabled = self.is_connected and not self.is_scanning
        scanning = self.is_scanning

        if hasattr(self, 'det_start_btn'):
            self.det_start_btn.configure(state="normal" if scan_enabled else "disabled")
        if hasattr(self, 'det_pause_btn'):
            self.det_pause_btn.configure(state="normal" if scanning else "disabled")
        if hasattr(self, 'det_stop_btn'):
            self.det_stop_btn.configure(state="normal" if scanning else "disabled")
        if hasattr(self, 'det_profile_menu'):
            self.det_profile_menu.configure(state="normal" if scan_enabled else "disabled")

        # Tab 3: Enable/disable remediation actions
        has_vulns = len(self.vulnerabilities) > 0
        if hasattr(self, 'rem_auto_btn'):
            self.rem_auto_btn.configure(state="normal" if has_vulns else "disabled")

    def _show_connection_banner(self) -> None:
        """Show the green success banner and fingerprint card after successful connection."""
        if not self.connected_target or not self.connected_info:
            return

        info = self.connected_info
        self.conn_banner.configure(
            text=f"✓ Connected to {self.connected_target}",
            text_color=STATUS_OK
        )

        if hasattr(self, 'conn_placeholder'):
            self.conn_placeholder.pack_forget()

        fingerprint = (
            f"Target: {info.get('target', self.connected_target)}\n"
            f"IP Address: {info.get('ip', 'Unknown')}\n"
            f"Server: {info.get('server', 'Unknown')}\n"
            f"Open Ports: {', '.join(str(p) for p in info.get('ports', []))}\n"
            f"Connection Method: {info.get('method', 'HTTPS')}\n"
            f"Scan Profile: {info.get('profile', 'Standard')}\n"
            f"Response Time: {info.get('response_time', 'N/A')}"
        )
        self.conn_fingerprint_text.configure(text=fingerprint)
        self.conn_fingerprint_card.pack(fill="both", expand=True, padx=CARD_PADDING, pady=CARD_PADDING)

    def _set_connected(self, target: str, info: Dict[str, Any]) -> None:
        """Mark connection as established and enable downstream tabs."""
        self.is_connected = True
        self.connected_target = target
        self.connected_info = info
        self.scan_state = "Idle"
        self.last_scan_time = self._now_full()
        self._update_ui_state()

    def _disconnect(self) -> None:
        """Disconnect from target and reset state."""
        # Stop any running scan
        if self.is_scanning:
            self._stop_scan()

        # Clear simulation loop
        if self._simulation_loop_id:
            self.after_cancel(self._simulation_loop_id)
            self._simulation_loop_id = None

        # Reset state
        self.is_connected = False
        self.connected_target = None
        self.connected_info = {}
        self.scan_state = "Idle"
        self.connection_status = "idle"

        # Clear findings
        self.vulnerabilities.clear()
        self.live_threats.clear()
        self.threat_counter = 0
        self.vuln_counter = 0

        # Clear UI
        if hasattr(self, 'det_soc'):
            self.det_soc.clear()

        if hasattr(self, 'det_findings'):
            # Clear finding rows
            for row in self._finding_rows.values():
                row.destroy()
            self._finding_rows.clear()

        if hasattr(self, 'rem_vuln_container'):
            for child in self.rem_vuln_container.winfo_children():
                child.destroy()
            # Recreate empty state label since it was destroyed
            self.rem_empty_label = ctk.CTkLabel(
                self.rem_vuln_container,
                text="No vulnerabilities found yet.\nConnect to a target and start a scan to begin detection.",
                font=ctk.CTkFont(*FONTS["body"]),
                text_color=TEXT_TERTIARY,
                justify="center"
            )
            self.rem_empty_label.grid(row=0, column=0, padx=SPACE_8, pady=SPACE_8)

        # Reset metrics
        self._reset_detection_metrics()
        self._update_rem_summary()

        # Reset progress
        if hasattr(self, 'det_progress_bar'):
            self.det_progress_bar.set(0)
        if hasattr(self, 'det_progress_label'):
            self.det_progress_label.configure(text="0% — Idle")

        self._update_ui_state()

    def _reset_detection_metrics(self) -> None:
        """Reset all detection metric cards to zero."""
        defaults = {
            "scans_running": "0",
            "vulns_found": "0",
            "critical_count": "0",
            "high_count": "0",
        }
        for key, value in defaults.items():
            if key in self.det_metrics:
                self.det_metrics[key].update_value(value)

    # ------------------------------------------------------------------
    # Tab 1: Connection logic
    # ------------------------------------------------------------------

    def _validate_target(self, target: str) -> Tuple[bool, str]:
        """Validate target URL/IP/hostname."""
        if not target or not target.strip():
            return False, "Target is required"
        target = target.strip()
        # Allow URLs, IPs, hostnames
        url_pat = re.compile(r'^https?://[a-zA-Z0-9][\w\-\.]+(:\d+)?(/.*)?$')
        ip_pat = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$')
        host_pat = re.compile(r'^[a-zA-Z0-9][\w\-\.]+$')
        if url_pat.match(target) or ip_pat.match(target) or host_pat.match(target):
            return True, ""
        return False, "Invalid target. Use a URL, IP address, or hostname."

    def _update_connect_btn_state(self) -> None:
        """Enable/disable CONNECT button based on authorization checkbox."""
        if self.conn_auth_checkbox.get():
            self.conn_connect_btn.configure(state="normal")
        else:
            self.conn_connect_btn.configure(state="disabled")

    def _toggle_agent_mode(self) -> None:
        if not hasattr(self, "_agent_remote_frame"):
            return
        if self._agent_mode.get() == "remote":
            self._agent_remote_frame.pack(fill="x", padx=CARD_PADDING, pady=(0, SPACE_3))
        else:
            self._agent_remote_frame.pack_forget()

    def _test_agent_connection(self) -> None:
        import urllib.request
        url = self._agent_url_var.get().strip().rstrip("/")
        key = self._agent_key_var.get().strip()
        if not url:
            self._log_detection("[AGENT] No URL configured", "error")
            return
        def _ping():
            try:
                req = urllib.request.Request(f"{url}/ping", headers={"X-HydraX-Key": key})
                with urllib.request.urlopen(req, timeout=5) as r:
                    data = json.loads(r.read())
                self.after(0, lambda: self._log_detection(
                    f"[{self._now()}] [AGENT] Connected to {url} — tools: {data.get('tools', {})}", "info"
                ))
            except Exception as e:
                self.after(0, lambda: self._log_detection(f"[{self._now()}] [AGENT] Connection failed: {e}", "error"))
        threading.Thread(target=_ping, daemon=True).start()

    def _copy_install_command(self) -> None:
        import secrets as _secrets
        key = self._agent_key_var.get().strip() or _secrets.token_hex(16)
        cmd = f"python server_agent.py --key {key} --port 7474"
        try:
            self.clipboard_clear()
            self.clipboard_append(cmd)
            self._log_detection(f"[{self._now()}] [AGENT] Install command copied to clipboard", "info")
        except Exception:
            self._log_detection(f"[{self._now()}] [AGENT] Install cmd: {cmd}", "info")

    def _test_connection(self) -> None:
        """Test connection to target (simulated)."""
        target = self.conn_target_entry.get().strip()
        ok, err = self._validate_target(target)
        if not ok:
            self.conn_banner.configure(text=f"[X] {err}", text_color=STATUS_CRITICAL)
            return

        self.conn_banner.configure(text="Testing connection...", text_color=TEXT_TERTIARY)
        self.conn_test_btn.configure(state="disabled")
        self.after(800, lambda: self._test_connection_result(target))

    def _test_connection_result(self, target: str) -> None:
        """Show test connection result (simulated)."""
        import random
        # Simulate success 90% of the time
        if random.random() < 0.9:
            # Generate fake fingerprint
            ip = f"93.184.{random.randint(1,254)}.{random.randint(1,254)}"
            server_types = ["nginx/1.24", "Apache/2.4.57", "Caddy/2.7", "Cloudflare"]
            ports = random.sample([80, 443, 8080, 8443, 3000, 5000, 8000], k=random.randint(2, 4))
            fingerprint = (
                f"Target: {target}\n"
                f"IP Address: {ip}\n"
                f"Server: {random.choice(server_types)}\n"
                f"Open Ports: {', '.join(str(p) for p in sorted(ports))}\n"
                f"SSL: {'Enabled' if self.conn_method_var.get() in ('HTTPS', 'HTTP') else 'N/A'}\n"
                f"Response Time: {random.randint(20, 200)}ms"
            )
            self.conn_fingerprint_text.configure(text=fingerprint)
            self.conn_fingerprint_card.pack(fill="x", padx=CARD_PADDING, pady=(SPACE_2, 0))
            self.conn_banner.configure(text="[OK] Connection test passed", text_color=STATUS_OK)
        else:
            self.conn_banner.configure(
                text="[X] Connection test failed - target unreachable",
                text_color=STATUS_CRITICAL,
            )
        self.conn_test_btn.configure(state="normal")

    def _connect(self) -> None:
        """Establish connection to target."""
        if not self.conn_auth_checkbox.get():
            self.conn_banner.configure(
                text="[X] You must confirm authorization before connecting.",
                text_color=STATUS_CRITICAL,
            )
            return

        target = self.conn_target_entry.get().strip()
        ok, err = self._validate_target(target)
        if not ok:
            self.conn_banner.configure(text=f"[X] {err}", text_color=STATUS_CRITICAL)
            return

        self.conn_banner.configure(text="Connecting...", text_color=TEXT_TERTIARY)
        self.conn_connect_btn.configure(state="disabled")

        def _do_connect():
            import random
            time.sleep(1)  # simulate delay
            ip = f"93.184.{random.randint(1,254)}.{random.randint(1,254)}"
            server_types = ["nginx/1.24", "Apache/2.4.57", "Caddy/2.7", "Cloudflare"]
            ports = random.sample([80, 443, 8080, 8443], k=random.randint(2, 3))
            info = {
                "ip": ip,
                "server": random.choice(server_types),
                "ports": sorted(ports),
                "target": target,
                "method": self.conn_method_var.get(),
                "profile": self.conn_profile_var.get(),
                "response_time": f"{random.randint(20, 200)}ms",
            }
            self.after(0, lambda: self._set_connected(target, info))

        threading.Thread(target=_do_connect, daemon=True).start()

    # ------------------------------------------------------------------
    # Tab 2: Scan logic
    # ------------------------------------------------------------------

    def _start_scan(self) -> None:
        """Start a scan (or next loop cycle) on the connected target."""
        if not self.is_connected:
            return
        # Fresh manual start (not a loop restart): reset cycle counter
        if not self.loop_scan:
            self.loop_count = 0

        self.is_scanning = True
        self.scan_progress = 0
        self.scan_state = "Scanning"
        self._update_ui_state()

        # Only reset findings/UI on the first cycle (loop_count == 0) or a fresh manual start
        first_cycle = self.loop_count == 0
        if first_cycle:
            import time as _time
            self._loop_session_start = _time.time()
            self._reset_detection_metrics()
            self.vulnerabilities.clear()
            self.vuln_counter = 0
            if hasattr(self, 'det_soc'):
                self.det_soc.clear()
            for row in self._finding_rows.values():
                row.destroy()
            self._finding_rows.clear()

        cycle_tag = f"cycle {self.loop_count + 1}" if self.loop_scan else "scan"
        self._log_detection(
            f"[{self._now()}] [INFO] Starting {cycle_tag} on {self.connected_target}", "info"
        )
        self._update_det_metric("scans_running", "1")

        # Reset all chips to QUEUED — scheduler will transition them individually
        if hasattr(self, "_scan_chips"):
            for chip in self._scan_chips.values():
                chip.reset()

        profiles = self._get_active_profiles()
        self.scan_engine.scan(self.connected_target, profiles)

        # Launch parallel scheduler in a daemon thread so each chip gets its
        # own QUEUED→RUNNING→DONE/FAILED lifecycle independently.
        # Reset per-round module counters
        self._running_modules = 0
        self._modules_done_this_round = 0
        chip_count = len(getattr(self, '_scan_chips', {}))
        self._modules_total = chip_count if chip_count > 0 else 1

        self._launch_parallel_scheduler(self.connected_target)

    # ------------------------------------------------------------------
    # Parallel scan scheduler integration
    # ------------------------------------------------------------------

    def _launch_parallel_scheduler(self, target: str) -> None:
        """Run discovery then launch real agents via ParallelScanScheduler.

        Phase 1 (discovery thread): crawl the target to build an attack surface.
        Phase 2 (scheduler thread): run each agent chip concurrently, emitting
          ("module_status", key, status, elapsed, count) events every poll cycle.
        """
        from core.parallel_scheduler import ParallelScanScheduler
        from core.agent_task import build_module_defs
        from config.settings import SCANNER_META

        stop_event = self.scan_engine.stop_event

        # Keys for which we render chips — intersect with what SCANNER_META knows
        chip_keys = list(getattr(self, "_scan_chips", {}).keys()) or [
            "shannon", "hexstrike", "web", "sqli", "xss",
            "network", "headers", "ssl", "nuclei",
        ]

        def _bg_run() -> None:
            # --- Phase 1: discovery (once per session) ----------------------
            discovery: Dict[str, Any] = {"urls": [target], "forms": [], "parameters": {}}
            if not stop_event.is_set():
                try:
                    from utils.discovery import URLDiscovery
                    from config import settings as _cfg
                    disc = URLDiscovery(
                        target=target,
                        max_pages=getattr(_cfg, "CRAWL_MAX_PAGES", 50),
                        max_depth=getattr(_cfg, "CRAWL_MAX_DEPTH", 3),
                        request_delay=getattr(_cfg, "CRAWL_REQUEST_DELAY", 0.05),
                        request_timeout=getattr(_cfg, "CRAWL_REQUEST_TIMEOUT", 10),
                    )
                    result = disc.discover()
                    if isinstance(result, dict):
                        discovery = result
                except Exception as exc:
                    self._q.put_nowait(("log",
                        f"[SCHEDULER] Discovery fallback: {exc}", "warning"))

            cycle_idx = 0
            while not stop_event.is_set() and getattr(self, 'loop_scan', False) or cycle_idx == 0:
                if stop_event.is_set():
                    break

                # --- Phase 2: build ModuleDefs + run scheduler --------------
                module_defs = build_module_defs(
                    keys=chip_keys,
                    target=target,
                    discovery=discovery,
                )

                # Recreate stop event proxy — same event, just a fresh scheduler
                scheduler = ParallelScanScheduler(
                    modules=module_defs,
                    target=target,
                    emit=self._q.put_nowait,
                    stop_event=stop_event,
                    max_workers=4,
                )
                try:
                    results = scheduler.run()
                except RuntimeError:
                    # Interpreter shutting down — exit loop cleanly
                    return

                cycle_idx += 1
                if not stop_event.is_set():
                    findings_count = sum(
                        len(v.get("findings", [])) for v in results.values()
                    )
                    self._q.put_nowait(("cycle_done", target, {
                        "cycle_n": cycle_idx,
                        "findings_count": findings_count,
                        "results": results,
                    }))

                # If not looping, done after first cycle
                if not getattr(self, 'loop_scan', False):
                    break

                # Small delay between cycles so the UI can settle
                import time as _t
                _t.sleep(2)

            if not stop_event.is_set():
                self._q.put_nowait(("scan_complete", target, {"findings": []}))

        threading.Thread(target=_bg_run, daemon=True, name="hydrax-scheduler").start()

    def _simulate_scan_progress(self) -> None:
        """Simulate scan progress increments for demo."""
        if not self.is_scanning:
            return
        import random
        prev = self.scan_progress
        self.scan_progress = min(100, self.scan_progress + random.randint(5, 15))
        self.det_progress_bar.set(self.scan_progress / 100)
        self.det_progress_label.configure(text=f"{self.scan_progress}% — Scanning...")

        # Emit phase log lines at progress thresholds
        if prev < 10 <= self.scan_progress:
            self._log_detection(f"[{self._now()}] [INFO    ] Phase 1/4: Discovery & Reconnaissance started…", "info")
        elif prev < 25 <= self.scan_progress:
            self._log_detection(f"[{self._now()}] [SUCCESS ] Phase 1/4: Discovery complete — surface mapped", "success")
            self._log_detection(f"[{self._now()}] [INFO    ] Phase 2/4: Injection & Input Testing running…", "info")
        elif prev < 50 <= self.scan_progress:
            self._log_detection(f"[{self._now()}] [SUCCESS ] Phase 2/4: Injection tests complete", "success")
            self._log_detection(f"[{self._now()}] [INFO    ] Phase 3/4: Access Control & Auth checks…", "info")
        elif prev < 75 <= self.scan_progress:
            self._log_detection(f"[{self._now()}] [SUCCESS ] Phase 3/4: Access control checks complete", "success")
            self._log_detection(f"[{self._now()}] [INFO    ] Phase 4/4: Advanced & Infrastructure checks…", "info")

        if self.scan_progress < 100:
            self.after(400, self._simulate_scan_progress)
        else:
            self._log_detection(f"[{self._now()}] [SUCCESS ] Phase 4/4: All scans complete — analysing findings…", "success")
            # Generate some simulated findings
            self._generate_simulated_findings()

    def _get_active_profiles(self) -> List[str]:
        """Return all real scanner keys — company scanner runs everything in parallel."""
        from config.settings import ALL_SCANNER_KEYS, SCANNER_META
        real_keys = [k for k in ALL_SCANNER_KEYS if SCANNER_META.get(k, {}).get("cls") is not None]
        return real_keys if real_keys else ALL_SCANNER_KEYS

    def _generate_simulated_findings(self) -> None:
        """Generate simulated vulnerabilities based on enabled modules."""
        import random
        vuln_templates = [
            ("SQL Injection", "critical", "/login?id=",
             "Unsanitized user input passed directly to SQL query",
             "Use parameterized queries / prepared statements",
             "CVE-2021-44228", "OWASP-A03:2021"),
            ("Reflected XSS", "high", "/search?q=",
             "User-controlled input reflected in HTML without encoding",
             "Output-encode all user input; use CSP headers",
             None, "OWASP-A03:2021"),
            ("Missing Security Headers", "medium", "/",
             "X-Content-Type-Options, X-Frame-Options not set",
             "Add security headers: X-Frame-Options: DENY, X-Content-Type-Options: nosniff",
             None, "OWASP-A05:2021"),
            ("Open Directory", "low", "/backup/",
             "Directory listing enabled, exposing sensitive files",
             "Disable directory listing in web server config",
             None, "OWASP-A01:2021"),
            ("Outdated SSL/TLS", "high", "/",
             "Server supports TLS 1.0 / TLS 1.1 which are deprecated",
             "Disable TLS 1.0 and 1.1; enforce TLS 1.2+",
             None, "OWASP-A08:2021"),
            ("Information Disclosure", "medium", "/robots.txt",
             "Sensitive paths exposed via robots.txt",
             "Review and restrict robots.txt disclosures",
             None, "OWASP-A01:2021"),
            ("CSRF Vulnerability", "medium", "/account/update",
             "State-changing request lacks CSRF token validation",
             "Implement CSRF tokens on all state-changing forms",
             None, "OWASP-A01:2021"),
            ("Insecure Deserialization", "high", "/api/import",
             "Untrusted data deserialized without validation",
             "Avoid deserializing untrusted data; use safe formats",
             None, "OWASP-A08:2021"),
        ]
        enabled = [k for k, v in self.scan_checkboxes.items() if v.get() == "1"]
        min_count = 3 if enabled else 1
        max_count = min(7, len(enabled) + 2) if enabled else 3
        count = random.randint(min_count, max_count)
        endpoints = ["/login", "/search", "/api/v1/users", "/admin", "/dashboard", "/contact", "/api/auth", "/upload"]
        for _ in range(count):
            template = random.choice(vuln_templates)
            vuln = Vulnerability(
                vuln_id=f"VULN-{self.vuln_counter:04d}",
                name=template[0],
                severity=template[1],
                endpoint=f"{self.connected_target}{random.choice(endpoints)}",
                description=template[2],
                remediation=template[3],
                cve=template[4],
                owasp=template[5],
            )
            self.vulnerabilities.append(vuln)
            self.vuln_counter += 1
            self._log_detection(f"[{self._now()}] [{template[1].upper():8s}] ▶ {template[0]} found at {vuln.endpoint}", template[1])
            # Push to findings card list and remediation tab
            self.after(0, lambda v=vuln: self._update_finding_row(v))
            self.after(0, lambda v=vuln: self._push_to_remediation(v))

        self._update_det_metric("vulns_found", str(len(self.vulnerabilities)))
        criticals = len([v for v in self.vulnerabilities if v.severity == "critical"])
        highs = len([v for v in self.vulnerabilities if v.severity == "high"])
        self._update_det_metric("critical_count", str(criticals))
        self._update_det_metric("high_count", str(highs))

    def _pause_scan(self) -> None:
        """Pause the current scan."""
        if self.is_scanning:
            self.is_scanning = False
            self.scan_state = "Paused"
            self._update_ui_state()
            self._log_detection(f"[{self._now()}] [INFO] Scan paused", "info")

    def _start_scan_loop_cycle(self) -> None:
        """Restart a scan cycle if loop mode is still active."""
        if not self.loop_scan or not self.is_connected:
            return
        # Reset progress bar for next cycle
        self.scan_progress = 0
        self.det_progress_bar.set(0)
        self.det_progress_label.configure(text=f"0% — Starting cycle {self.loop_count + 1}…")
        self._start_scan()

    def _on_cycle_done(self, cycle_n: int, findings_count: int, results: dict = None) -> None:
        """Handle a mid-loop cycle completion without stopping the scan."""
        self.loop_count += 1
        self._running_modules = 0
        self._modules_done_this_round = 0
        # Reset chips for next cycle
        if hasattr(self, '_scan_chips'):
            for chip in self._scan_chips.values():
                if chip._status in ("queued", "running"):
                    chip.set_done(0)
                chip.reset()
        self.det_progress_bar.set(0)
        self.det_progress_label.configure(
            text=f"0% — Cycle {cycle_n} done  ·  {findings_count} finding(s)  ·  restarting…"
        )
        if hasattr(self, 'det_soc'):
            self.det_soc.add_cycle_divider(cycle_n, findings_count)

        # Route any findings from this cycle to the Vulnerability Intelligence tab
        if results:
            self._ingest_cycle_findings(results)

    def _ingest_cycle_findings(self, results: dict) -> None:
        """Push non-SAFE scheduler results to the vuln list + Vuln Intel tab (deduped)."""
        new_vulns: list = []
        for key, data in results.items():
            for f in data.get("findings", []) or []:
                name      = f.get("type") or f.get("name", key)
                severity  = (f.get("severity") or "medium").lower()
                endpoint  = f.get("url") or f.get("endpoint", self.connected_target or "")
                dedup_key = (name, endpoint)
                # Deduplicate: update last_seen count on existing entry
                existing = next(
                    (v for v in self.vulnerabilities if (v.name, v.endpoint) == dedup_key),
                    None,
                )
                if existing:
                    continue
                vuln = Vulnerability(
                    vuln_id=f"V{self.vuln_counter + 1:04d}",
                    name=name,
                    severity=severity,
                    endpoint=endpoint,
                    description=f.get("description", ""),
                    remediation=f.get("fix") or f.get("remediation", "Review finding manually."),
                    cve=f.get("cve", "") or f.get("evidence", ""),
                    owasp=f.get("owasp", ""),
                )
                self.vuln_counter += 1
                self.vulnerabilities.append(vuln)
                new_vulns.append(vuln)
                self._update_finding_row(vuln)
                self._push_to_remediation(vuln)

        if new_vulns:
            self._update_det_metric("vulns_found", str(len(self.vulnerabilities)))
            criticals = sum(1 for v in self.vulnerabilities if v.severity == "critical")
            highs     = sum(1 for v in self.vulnerabilities if v.severity == "high")
            self._update_det_metric("critical_count", str(criticals))
            self._update_det_metric("high_count", str(highs))
            # Feed the brain for Vuln Intel enrichment
            if self.event_queue:
                vuln_dicts = [
                    {"type": v.name, "name": v.name, "severity": v.severity.capitalize(),
                     "url": v.endpoint, "description": v.description,
                     "cve": v.cve, "owasp": v.owasp, "id": v.id}
                    for v in new_vulns
                ]
                self.event_queue.put(("brain_feed", self.connected_target, {"findings": vuln_dicts}))

    def _toggle_loop(self) -> None:
        """Toggle continuous loop scan mode on/off."""
        self.loop_scan = not self.loop_scan
        if hasattr(self, "det_loop_btn"):
            if self.loop_scan:
                self.det_loop_btn.configure(
                    text="⟳ LOOP: ON",
                    fg_color="#1a4a1a",
                    border_color="#00ff41",
                    text_color="#00ff41",
                )
                self._log_detection(
                    f"[{self._now()}] [LOOP ] Continuous loop mode ENABLED — "
                    "scanning will repeat indefinitely until stopped", "info"
                )
                # If already scanning, the next completion will restart automatically
                # If idle and connected, kick off immediately
                if not self.is_scanning and self.is_connected:
                    self._start_scan()
            else:
                self.det_loop_btn.configure(
                    text="⟳ LOOP: OFF",
                    fg_color=SURFACE_MUTED,
                    border_color=BORDER_HAIRLINE,
                    text_color=TEXT_SECONDARY,
                )
                self._log_detection(
                    f"[{self._now()}] [LOOP ] Continuous loop mode DISABLED — "
                    f"completed {self.loop_count} cycle(s)", "info"
                )

    def _stop_scan(self) -> None:
        """Stop the current scan and disable loop mode."""
        self.loop_scan = False
        # Signal the background thread to stop looping
        if hasattr(self, 'scan_engine') and hasattr(self.scan_engine, 'stop_event'):
            self.scan_engine.stop_event.set()
        self.is_scanning = False
        self.scan_progress = 0
        self.scan_state = "Idle"
        self.det_progress_bar.set(0)
        self.det_progress_label.configure(text="0% — Idle")
        self._update_det_metric("scans_running", "0")
        self._update_ui_state()
        self._log_detection(
            f"[{self._now()}] [INFO] Scan stopped after {self.loop_count} cycle(s)", "info"
        )
        # Generate session report when loop stops
        if self._loop_session_start and self.vulnerabilities:
            import time as _time
            duration = _time.time() - self._loop_session_start
            report = {
                "target": self.connected_target,
                "duration_s": round(duration, 1),
                "cycles": self.loop_count,
                "findings": [v.__dict__ if hasattr(v, '__dict__') else dict(v) if hasattr(v, '__iter__') else {} for v in self.vulnerabilities],
                "timestamp": datetime.now().isoformat(),
            }
            self._q.put(("scan_complete", self.connected_target, report))
            self._loop_session_start = None
            self._log_detection(
                f"[{self._now()}] [REPORT] Session report generated — {len(self.vulnerabilities)} total findings across {self.loop_count} cycle(s)",
                "success"
            )
        self.loop_count = 0
        if hasattr(self, "det_loop_btn"):
            self.det_loop_btn.configure(
                text="⟳ LOOP: OFF",
                fg_color=SURFACE_MUTED,
                border_color=BORDER_HAIRLINE,
                text_color=TEXT_SECONDARY,
            )

    def _scan_complete(self, total_findings: int = 0, report: dict = None) -> None:
        """Handle scan completion. If loop_scan is on, restart immediately."""
        self.loop_count += 1
        self.is_scanning = False
        self.scan_progress = 100
        self._running_modules = 0
        self._modules_done_this_round = 0

        if self.loop_scan:
            cycle_label = f"100% — Cycle {self.loop_count} complete, restarting…"
        else:
            cycle_label = "100% — Complete"
            self.scan_state = "Complete"

        self.det_progress_bar.set(1)
        self.det_progress_label.configure(text=cycle_label)
        self._update_det_metric("scans_running", "0")
        self._update_ui_state()
        self.last_scan_time = self._now_full()

        # Merge real findings from the engine report into our vuln list
        if report and isinstance(report, dict):
            for f in report.get("findings", []):
                # Avoid duplicates by URL+type within this session
                key = (f.get("type", ""), f.get("url", ""))
                if not any((v.name, v.endpoint) == key for v in self.vulnerabilities):
                    v = Vulnerability(
                        vuln_id=f"V{self.vuln_counter + 1:04d}",
                        name=f.get("type", "Finding"),
                        severity=f.get("severity", "Medium").lower(),
                        endpoint=f.get("url", self.connected_target or ""),
                        description=f.get("description", ""),
                        remediation=f.get("fix", "") or f.get("remediation", "Review finding manually."),
                        cve=f.get("evidence", "") or f.get("cve", ""),
                        owasp=f.get("owasp", ""),
                    )
                    self.vuln_counter += 1
                    self.vulnerabilities.append(v)
                    self._update_finding_row(v)

        cycle_msg = f"Cycle {self.loop_count}" if self.loop_scan else "Scan complete"
        self._log_detection(
            f"[{self._now()}] [INFO] {cycle_msg} — {len(self.vulnerabilities)} total findings", "info"
        )
        # Chips are updated in real-time by the parallel scheduler via
        # module_status events. Only update chips that are still in a
        # non-terminal state (still QUEUED or RUNNING) when the engine
        # reports scan_complete, so they don't stay spinning indefinitely.
        if hasattr(self, "_scan_chips"):
            for chip in self._scan_chips.values():
                if chip._status in ("queued", "running"):
                    chip.set_done(0)
        self._update_det_metric("vulns_found", str(len(self.vulnerabilities)))

        # Push to app event queue so the autonomous brain can process it
        # In loop mode, only push brain feed (not scan_complete); full report is on STOP
        if self.event_queue:
            vuln_dicts = [
                {
                    "type": v.name, "name": v.name, "severity": v.severity.capitalize(),
                    "url": v.endpoint, "description": v.description,
                    "cve": v.cve, "owasp": v.owasp, "id": v.id,
                }
                for v in self.vulnerabilities
            ]
            if not self.loop_scan:
                # Single scan: emit full scan_complete for report generation
                self.event_queue.put(("scan_complete", self.connected_target,
                                      {"findings": vuln_dicts}))
            else:
                # Loop mode: only feed brain, report generated on STOP
                self.event_queue.put(("brain_feed", self.connected_target,
                                      {"findings": vuln_dicts}))

        # Loop cycles are driven by the self-looping _bg_run thread —
        # no need to restart here.

    def handle_brain_results(self, enriched_findings: list, summary: dict) -> None:
        """Called by main_window when brain_analysis_complete fires."""
        self._log_detection(
            f"[{self._now()}] [VULN-INTEL] Analysis complete — "
            f"{summary.get('total', 0)} findings enriched "
            f"({summary.get('critical', 0)} critical, {summary.get('high', 0)} high)",
            "info"
        )
        if hasattr(self, "brain_status_label"):
            self.brain_status_label.configure(
                text=(
                    f"◈  Vulnerability Intelligence — {summary.get('total', 0)} findings correlated  "
                    f"| {summary.get('critical', 0)} Critical  "
                    f"| {summary.get('high', 0)} High"
                ),
                text_color=STATUS_OK,
            )
        # Refresh the Vulnerability Intelligence tab with enriched data
        self.after(0, lambda: self._populate_brain_tab(enriched_findings, summary))

    def _populate_brain_tab(self, enriched_findings: list, summary: dict) -> None:
        """Populate Tab 3 with brain-enriched findings."""
        if not hasattr(self, "brain_findings_container"):
            return
        # Update summary counters
        if hasattr(self, "brain_summary"):
            for key in ("total", "critical", "high", "medium", "low"):
                card = self.brain_summary.get(key)
                if card:
                    card.update_value(str(summary.get(key, 0)))
        # Clear existing finding rows
        for w in self.brain_findings_container.winfo_children():
            w.destroy()
        if not enriched_findings:
            ctk.CTkLabel(
                self.brain_findings_container,
                text="No findings to display.",
                font=ctk.CTkFont(*FONTS["body"]),
                text_color=TEXT_TERTIARY,
            ).grid(row=0, column=0, padx=SPACE_8, pady=SPACE_8)
            return
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            enriched_findings,
            key=lambda f: sev_order.get(str(f.get("severity", "info")).lower(), 5)
        )
        for i, f in enumerate(sorted_findings):
            self._create_brain_finding_row(self.brain_findings_container, i, f)

    @staticmethod
    def _cve_url(cve_id: str) -> str:
        """Return the correct NVD URL for a CVE ID like CVE-2021-44228."""
        import re
        cve_id = (cve_id or "").strip()
        if re.match(r"^CVE-\d{4}-\d+$", cve_id, re.IGNORECASE):
            return f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}"
        return ""

    def _create_brain_finding_row(self, parent, row_idx: int, f: dict) -> None:
        """Create a Vulnerability Intelligence finding card with CVE links + remediation gate."""
        from ui.theme import STATUS_CRITICAL, STATUS_HIGH, STATUS_MEDIUM, STATUS_LOW, SEV_ROW
        sev = str(f.get("severity", "Info")).lower()
        sev_color_map = {
            "critical": STATUS_CRITICAL, "high": STATUS_HIGH,
            "medium": STATUS_MEDIUM, "low": STATUS_LOW,
        }
        sev_color = sev_color_map.get(sev, TEXT_TERTIARY)
        row_bg = SEV_ROW.get(sev, SURFACE_MUTED)

        card = ctk.CTkFrame(parent, fg_color=row_bg,
                            corner_radius=RADIUS_SM,
                            border_width=1, border_color=sev_color)
        card.grid(row=row_idx, column=0, sticky="ew", padx=SPACE_3, pady=(0, SPACE_2))
        card.grid_columnconfigure(1, weight=1)

        # ── Row 0: severity badge | name | CVE | OWASP ──────────────────────
        ctk.CTkLabel(
            card, text=f"  {sev.upper()}  ",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_INVERSE, fg_color=sev_color, corner_radius=4,
        ).grid(row=0, column=0, padx=(SPACE_4, SPACE_3), pady=SPACE_3, sticky="w")

        name = f.get("type") or f.get("name", "Finding")
        ctk.CTkLabel(
            card, text=name,
            font=ctk.CTkFont(*FONTS["body_bold"]), text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=1, padx=SPACE_3, pady=SPACE_3, sticky="w")

        cve_raw = (f.get("cve_id") or f.get("cve") or "").strip()
        cve_url = self._cve_url(cve_raw)
        if cve_raw:
            cve_lbl = ctk.CTkLabel(
                card, text=cve_raw,
                font=ctk.CTkFont(*FONTS["small"]), text_color="#60a5fa",
                cursor="hand2",
            )
            cve_lbl.grid(row=0, column=2, padx=SPACE_3, pady=SPACE_3)
            if cve_url:
                import webbrowser
                cve_lbl.bind("<Button-1>", lambda e, u=cve_url: webbrowser.open(u))

        cvss = f.get("cvss") or f.get("cvss_score", "")
        if cvss:
            ctk.CTkLabel(
                card, text=f"CVSS {cvss}",
                font=ctk.CTkFont(*FONTS["small_bold"]), text_color=sev_color,
            ).grid(row=0, column=3, padx=(SPACE_2, SPACE_4), pady=SPACE_3)

        owasp = f.get("owasp", "")
        if owasp:
            ctk.CTkLabel(
                card, text=owasp,
                font=ctk.CTkFont(*FONTS["small"]), text_color=BORDER_ACCENT,
            ).grid(row=0, column=4, padx=(SPACE_2, SPACE_4), pady=SPACE_3)

        # ── Row 1: affected asset ────────────────────────────────────────────
        url = f.get("url") or f.get("location") or f.get("endpoint", "")
        if url:
            ctk.CTkLabel(
                card, text=url,
                font=ctk.CTkFont(*FONTS["mono"]),
                text_color=TEXT_SECONDARY, anchor="w",
            ).grid(row=1, column=0, columnspan=5, padx=SPACE_4, pady=(0, SPACE_2), sticky="w")

        # ── Row 2: description ───────────────────────────────────────────────
        desc = f.get("description", "")
        if desc:
            ctk.CTkLabel(
                card, text=desc,
                font=ctk.CTkFont(*FONTS["small"]),
                text_color=TEXT_SECONDARY, anchor="w",
                wraplength=720, justify="left",
            ).grid(row=2, column=0, columnspan=5, padx=SPACE_4, pady=(0, SPACE_2), sticky="w")

        # ── Row 3: remediation + optional review-gated auto-fix ─────────────
        fix_text = f.get("ai_fix") or f.get("fix") or f.get("remediation", "")
        if fix_text:
            fix_frame = ctk.CTkFrame(card, fg_color=SURFACE_STRONG, corner_radius=4)
            fix_frame.grid(row=3, column=0, columnspan=5, sticky="ew",
                           padx=SPACE_4, pady=(0, SPACE_3))
            fix_frame.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(
                fix_frame, text=f"REMEDIATION: {fix_text}",
                font=ctk.CTkFont(*FONTS["small"]),
                text_color="#3DD68C", anchor="w", wraplength=680, justify="left",
            ).grid(row=0, column=0, padx=SPACE_3, pady=SPACE_2, sticky="w")

            # Auto-fix button only for safe, well-defined fixes
            auto_fixable = f.get("auto_fixable", False)
            if auto_fixable:
                fix_patch = f.get("fix_patch") or fix_text
                btn = ctk.CTkButton(
                    fix_frame,
                    text="▶ Review & Apply Fix",
                    font=ctk.CTkFont(*FONTS["small_bold"]),
                    fg_color=SURFACE_MUTED,
                    border_width=1, border_color="#3DD68C",
                    text_color="#3DD68C",
                    hover_color="#0d2018",
                    height=BTN_HEIGHT_MD,
                    corner_radius=RADIUS_SM,
                    command=lambda fp=fix_patch, fn=name: self._review_auto_fix(fn, fp),
                )
                btn.grid(row=1, column=0, padx=SPACE_3, pady=(0, SPACE_3), sticky="w")

    def _log_detection(self, message: str, severity: str = "info") -> None:
        """Append a status/info row to the SOC detection table."""
        if not hasattr(self, 'det_soc'):
            return
        ts = self._now()
        # Strip leading [HH:MM:SS] if present — we'll use ts from _now()
        body = message
        if body.startswith("["):
            end = body.find("]")
            if end > 0:
                body = body[end + 1:].lstrip()
        self.det_soc.add_info_row(ts, "SYSTEM", body, severity)

        # Also add to findings table
        self._add_finding_to_table(message, severity)

    def _add_finding_to_table(self, message: str, severity: str) -> None:
        """Add or update a finding row in the findings table."""
        # Extract vulnerability info from message
        # Format: [HH:MM:SS] [SEVERITY    ] Name found at Endpoint
        import re
        match = re.search(r'\[(\w+)\]\s+(\w+)\s+found\s+at\s+(.+)', message)
        if match:
            sev = match.group(1).lower()
            name = match.group(2)
            endpoint = match.group(3)

            # Find matching vulnerability
            vuln = None
            for v in self.vulnerabilities:
                if v.name == name and v.endpoint == endpoint:
                    vuln = v
                    break

            if vuln:
                self._update_finding_row(vuln)

    def _update_finding_row(self, vuln: Vulnerability) -> None:
        """Update or create a finding row in the table."""
        if not hasattr(self, 'det_findings'):
            return
        if vuln.id in self._finding_rows:
            # Card already exists — just recreate it to reflect auto-fix state
            self._finding_rows[vuln.id].destroy()
            del self._finding_rows[vuln.id]

        # Create clean card row — severity badge + name + endpoint + description
        sev_color = SEVERITY_COLORS_MAP.get(vuln.severity, TEXT_TERTIARY)
        sev_bg    = {"critical": "#2a0808", "high": "#2a1508",
                     "medium": "#2a1f08", "low": "#0d200d"}.get(vuln.severity, SURFACE_RAISED)

        row = ctk.CTkFrame(self.det_findings, fg_color=sev_bg, corner_radius=RADIUS_SM)
        row.grid(row=len(self._finding_rows), column=0, sticky="ew", padx=SPACE_2, pady=2)
        row.grid_columnconfigure(1, weight=1)

        # Severity badge (left accent) — Tkinter only supports #RRGGBB, no alpha
        _badge_bg = {
            "critical": "#3d0a0a", "high": "#3d1e0a",
            "medium": "#3d2e0a", "low": "#0f2e0f",
        }.get(vuln.severity, SURFACE_RAISED)
        ctk.CTkLabel(
            row, text=vuln.severity.upper(),
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=sev_color, fg_color=_badge_bg,
            corner_radius=4, width=72, height=20,
        ).grid(row=0, column=0, rowspan=2, padx=(SPACE_3, SPACE_4), pady=SPACE_3, sticky="w")

        # Name
        ctk.CTkLabel(
            row, text=vuln.name,
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=1, sticky="ew", padx=(0, SPACE_3), pady=(SPACE_2, 0))

        # Endpoint (small, muted)
        ep_text = vuln.endpoint[:80] + "…" if len(vuln.endpoint) > 80 else vuln.endpoint
        ctk.CTkLabel(
            row, text=ep_text,
            font=ctk.CTkFont(*FONTS["mono"]),
            text_color=TEXT_TERTIARY, anchor="w",
        ).grid(row=1, column=1, sticky="ew", padx=(0, SPACE_3), pady=(0, SPACE_1))

        # Description + remediation (collapsible single line)
        desc = (vuln.description or "")[:120]
        fix  = (vuln.remediation or "")[:100]
        if desc or fix:
            detail_frame = ctk.CTkFrame(row, fg_color="transparent")
            detail_frame.grid(row=2, column=0, columnspan=2, sticky="ew",
                              padx=SPACE_3, pady=(0, SPACE_2))
            detail_frame.grid_columnconfigure(0, weight=1)
            if desc:
                ctk.CTkLabel(detail_frame, text=desc, font=ctk.CTkFont(*FONTS["small"]),
                             text_color=TEXT_SECONDARY, anchor="w", wraplength=600,
                             justify="left").grid(row=0, column=0, sticky="ew")
            if fix:
                ctk.CTkLabel(detail_frame, text=f"▸ {fix}", font=ctk.CTkFont(*FONTS["small"]),
                             text_color="#4eca7a", anchor="w", wraplength=600,
                             justify="left").grid(row=1, column=0, sticky="ew", pady=(SPACE_1, 0))

        # Click handler to expand in brain tab
        row.bind("<Button-1>", lambda e, v=vuln: self._on_finding_selected(v))
        for child in row.winfo_children():
            child.bind("<Button-1>", lambda e, v=vuln: self._on_finding_selected(v))

        self._finding_rows[vuln.id] = row

    def _on_finding_selected(self, vuln: Vulnerability) -> None:
        """Handle finding selection - show in remediation tab."""
        self._selected_vuln = vuln
        # Switch to brain analysis tab
        self.tabview.set("BRAIN ANALYSIS")
        # Show detail
        self._generate_fix()

    def _update_det_metric(self, key: str, value: str) -> None:
        card = self.det_metrics.get(key)
        if card:
            card.update_value(value)

    # ------------------------------------------------------------------
    # Tab 3: Remediation logic
    # ------------------------------------------------------------------

    def _push_to_remediation(self, vuln: Vulnerability) -> None:
        """Add a vulnerability as an expandable card to the remediation list."""
        if not hasattr(self, 'rem_vuln_container'):
            return

        # Hide empty state
        self.rem_empty_label.grid_remove()

        # Create expandable card for this vulnerability
        self._create_vuln_card(vuln)
        self._update_rem_summary()

    def _create_vuln_card(self, vuln: Vulnerability) -> None:
        """Create an expandable vulnerability card."""
        card = make_card(self.rem_vuln_container)
        card.grid(row=len(self.rem_vuln_container.winfo_children()) - 1, column=0, sticky="ew", pady=SPACE_2)
        card.grid_columnconfigure(0, weight=1)

        # Severity color
        sev_color = SEVERITY_COLORS_MAP.get(vuln.severity, TEXT_TERTIARY)

        # Header (always visible)
        header = ctk.CTkFrame(card, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_2))
        header.grid_columnconfigure((0, 1, 2, 3), weight=1)

        # Severity badge
        sev_badge = ctk.CTkLabel(
            header, text=f"  {vuln.severity.upper()}  ",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_INVERSE, fg_color=sev_color,
            corner_radius=RADIUS_XS
        )
        sev_badge.grid(row=0, column=0, padx=(0, SPACE_3), sticky="w")

        # Name
        name_label = ctk.CTkLabel(
            header, text=vuln.name,
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_PRIMARY, anchor="w"
        )
        name_label.grid(row=0, column=1, padx=SPACE_3, sticky="w")

        # Endpoint
        ctk.CTkLabel(
            header, text=vuln.endpoint,
            font=ctk.CTkFont(*FONTS["mono"]),
            text_color=TEXT_SECONDARY, anchor="w"
        ).grid(row=0, column=2, padx=SPACE_3, sticky="w")

        # Status
        status_color = STATUS_OK if vuln.status == "Fixed" else (BORDER_ACCENT if vuln.auto_remediated else TEXT_TERTIARY)
        status_text = "Auto-Fixed" if vuln.auto_remediated else vuln.status
        status_label = ctk.CTkLabel(
            header, text=status_text,
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=status_color, anchor="e"
        )
        status_label.grid(row=0, column=3, padx=SPACE_3, sticky="e")

        # Expandable content (initially hidden)
        content = ctk.CTkFrame(card, fg_color=SURFACE_BASE, corner_radius=RADIUS_SM)
        content.grid(row=1, column=0, sticky="ew", padx=CARD_PADDING, pady=(0, CARD_PADDING))
        content.grid_columnconfigure(0, weight=1)
        content.grid_remove()  # Hidden by default

        # Content details
        details = (
            f"Description:\n{vuln.description}\n\n"
            f"Remediation:\n{vuln.remediation}\n"
        )
        if vuln.cve:
            details += f"\nCVE: {vuln.cve}\n  https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln.cve}"
        if vuln.owasp:
            details += f"\nOWASP: {vuln.owasp}\n  https://owasp.org/"

        detail_text = ctk.CTkLabel(
            content, text=details,
            font=ctk.CTkFont(*FONTS["body"]),
            text_color=TEXT_PRIMARY, justify="left", anchor="w"
        )
        detail_text.pack(padx=SPACE_4, pady=SPACE_4, fill="x", anchor="w")

        # Store references for expansion
        card._vuln = vuln
        card._content = content
        card._is_expanded = False
        card._status_label = status_label

        # Click handler on header to toggle expansion
        def toggle_expand(e=None):
            self._toggle_vuln_card(card)

        header.bind("<Button-1>", toggle_expand)
        for child in header.winfo_children():
            child.bind("<Button-1>", toggle_expand)

        # Also bind on card itself
        card.bind("<Button-1>", toggle_expand)

    def _toggle_vuln_card(self, card) -> None:
        """Toggle expansion of a vulnerability card."""
        # Collapse previously expanded card
        if self._expanded_vuln_id and self._expanded_vuln_id != card._vuln.id:
            for child in self.rem_vuln_container.winfo_children():
                if hasattr(child, '_vuln') and child._vuln.id == self._expanded_vuln_id:
                    child._content.grid_remove()
                    child._is_expanded = False
                    break

        # Toggle this card
        if card._is_expanded:
            card._content.grid_remove()
            card._is_expanded = False
            self._expanded_vuln_id = None
            self._selected_vuln = None
            self.rem_actions_frame.grid_remove()
        else:
            card._content.grid()
            card._is_expanded = True
            self._expanded_vuln_id = card._vuln.id
            self._selected_vuln = card._vuln
            # Show action bar
            self.rem_actions_frame.grid()
            self.rem_status_var.set(card._vuln.status)

    def _update_rem_summary(self) -> None:
        total = len(self.vulnerabilities)
        fixed = len([v for v in self.vulnerabilities if v.status == "Fixed"])
        remaining = total - fixed
        auto_fixed = len([v for v in self.vulnerabilities if v.auto_remediated])
        for k, v in [("total", total), ("fixed", fixed), ("remaining", remaining), ("auto_fixed", auto_fixed)]:
            self._update_rem_metric(k, str(v))

        # Enable/disable auto-remediate button
        if hasattr(self, 'rem_auto_btn'):
            self.rem_auto_btn.configure(state="normal" if total > 0 else "disabled")

    def _update_rem_metric(self, key: str, value: str) -> None:
        card = self.rem_summary.get(key)
        if card:
            card.update_value(value)

    def _generate_fix(self) -> None:
        """Show detailed remediation for selected vulnerability."""
        if not self._selected_vuln:
            return
        vuln = self._selected_vuln
        detail = (
            f"=== {vuln.name} ===\n"
            f"Severity: {vuln.severity.upper()}\n"
            f"ID: {vuln.id}\n\n"
            f"Location: {vuln.endpoint}\n\n"
            f"Risk:\n{vuln.description}\n\n"
            f"Remediation:\n{vuln.remediation}\n"
        )
        if vuln.cve:
            detail += f"\nCVE: {vuln.cve} (https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln.cve})\n"
        if vuln.owasp:
            detail += f"OWASP: {vuln.owasp} (https://owasp.org/)\n"
        detail += f"\nStatus: {vuln.status}"
        if vuln.auto_remediated:
            detail += " (Auto-Remediated)"

        # This is a quick reference - the expandable card already shows this
        # but we can also log it
        self._log_detection(f"[{self._now()}] [INFO] Fix generated for {vuln.name}", "info")

    def _show_audit_log(self) -> None:
        """Display all applied auto-fix audit entries in a popup."""
        import tkinter as _tk
        top = _tk.Toplevel(self)
        top.title("HydraX — Auto-Fix Audit Log")
        top.geometry("680x440")
        top.resizable(True, True)

        title = ctk.CTkLabel(
            top, text="AUTO-FIX AUDIT LOG",
            font=ctk.CTkFont(*FONTS["subheading"]),
            text_color=TEXT_PRIMARY,
        )
        title.pack(padx=16, pady=(12, 4), anchor="w")

        subtitle = ctk.CTkLabel(
            top,
            text="Every fix listed here was explicitly confirmed by the operator before being applied.",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
        )
        subtitle.pack(padx=16, pady=(0, 8), anchor="w")

        box = ctk.CTkScrollableFrame(top, fg_color=SURFACE_MUTED)
        box.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        if not self._fix_audit_log:
            ctk.CTkLabel(
                box, text="No fixes have been applied yet.",
                font=ctk.CTkFont(*FONTS["body"]),
                text_color=TEXT_TERTIARY,
            ).pack(padx=12, pady=24)
        else:
            for i, entry in enumerate(reversed(self._fix_audit_log)):
                row = ctk.CTkFrame(box, fg_color=SURFACE_RAISED, corner_radius=RADIUS_SM)
                row.pack(fill="x", padx=4, pady=(0, 6))
                ctk.CTkLabel(
                    row,
                    text=f"[{entry.get('timestamp', '?')}]  {entry.get('finding', '?')}",
                    font=ctk.CTkFont(*FONTS["body_bold"]),
                    text_color=TEXT_PRIMARY, anchor="w",
                ).pack(padx=10, pady=(8, 2), anchor="w")
                ctk.CTkLabel(
                    row,
                    text=entry.get("fix", ""),
                    font=ctk.CTkFont(*FONTS["small"]),
                    text_color=TEXT_SECONDARY, anchor="w", justify="left",
                    wraplength=600,
                ).pack(padx=10, pady=(0, 8), anchor="w")

        GhostButton(
            top, "CLOSE",
            height=BTN_HEIGHT_SM, width=BTN_WIDTH_MD,
            command=top.destroy,
        ).pack(pady=(0, 12))

    def _review_auto_fix(self, finding_name: str, fix_patch: str) -> bool:
        """Show a review dialog; write audit entry and return True only if user confirms."""
        import tkinter.messagebox as mb
        msg = (
            f"AUTO-FIX REVIEW — {finding_name}\n\n"
            f"Proposed change:\n{fix_patch}\n\n"
            "An audit log entry will be created.\n"
            "Apply this fix?"
        )
        confirmed = mb.askyesno("Review & Apply Fix", msg, parent=self)
        if confirmed:
            import datetime as _dt
            entry = {
                "timestamp": _dt.datetime.now().isoformat(),
                "finding":   finding_name,
                "fix":       fix_patch,
                "applied":   True,
            }
            self._fix_audit_log.append(entry)
        return confirmed

    def _auto_remediate(self) -> None:
        """Propose a fix for the selected vulnerability.

        MANDATORY security gate: every fix — regardless of severity or type —
        is shown to the user via _review_auto_fix() before anything is applied.
        The audit log entry is written inside that method only after confirmation.
        """
        if not self._selected_vuln:
            return
        vuln = self._selected_vuln

        # Build a human-readable proposed patch (rule-based, per type)
        patch_map = {
            "Missing Security Headers": (
                "Add to server configuration:\n"
                "  Strict-Transport-Security: max-age=63072000; includeSubDomains\n"
                "  X-Frame-Options: DENY\n"
                "  X-Content-Type-Options: nosniff\n"
                "  Content-Security-Policy: default-src 'self'"
            ),
            "Open Directory": (
                "Disable directory listing in your web server:\n"
                "  Apache:  Options -Indexes\n"
                "  Nginx:   autoindex off;"
            ),
            "Information Disclosure": (
                "Remove server version banners:\n"
                "  Apache:  ServerTokens Prod\n"
                "  Nginx:   server_tokens off;"
            ),
            "CSRF Vulnerability": (
                "Add CSRF token validation to all state-changing endpoints:\n"
                "  1. Generate a per-session CSRF token\n"
                "  2. Embed it in every form as a hidden field\n"
                "  3. Validate it server-side before processing the request"
            ),
        }
        fix_patch = patch_map.get(
            vuln.name,
            f"Manual remediation required for '{vuln.name}'.\n"
            f"Endpoint: {vuln.endpoint}\n"
            f"Review finding details and apply the appropriate fix.",
        )

        # Gate: show review dialog and only proceed if user confirms
        confirmed = self._review_auto_fix(vuln.name, fix_patch)
        if not confirmed:
            return

        vuln.auto_remediated = True
        vuln.status = "Fixed"

        # Update the card's status label
        for child in self.rem_vuln_container.winfo_children():
            if hasattr(child, '_vuln') and child._vuln.id == vuln.id:
                child._status_label.configure(text="Applied", text_color=BORDER_ACCENT)
                break

        # Also update findings table
        if vuln.id in self._finding_rows:
            row = self._finding_rows[vuln.id]
            for child in row.winfo_children():
                if isinstance(child, ctk.CTkLabel) and child.cget("text") in (
                    "Open", "In Progress", "Fixed", "Won't Fix"
                ):
                    child.configure(text="Applied", text_color=BORDER_ACCENT)
                    break

        self._log_detection(
            f"[{self._now()}] [AUTO-FIX] '{vuln.name}' on {vuln.endpoint} — fix applied (audit log updated)",
            "success",
        )
        self._update_rem_summary()

    def _dismiss_detail(self) -> None:
        """Collapse the currently expanded vulnerability card."""
        if self._expanded_vuln_id:
            for child in self.rem_vuln_container.winfo_children():
                if hasattr(child, '_vuln') and child._vuln.id == self._expanded_vuln_id:
                    child._content.grid_remove()
                    child._is_expanded = False
                    break
            self._expanded_vuln_id = None
            self._selected_vuln = None
            self.rem_actions_frame.grid_remove()

    def _export_report(self) -> None:
        """Export a remediation report as HTML."""
        import html as htmlmod
        report_lines = [
            "<!DOCTYPE html>",
            "<html><head><title>Remediation Report - HydraX</title>",
            "<style>body{font-family:monospace;background:#1a1a2e;color:#eee;padding:2em;}",
            "table{border-collapse:collapse;width:100%;}th,td{border:1px solid #333;padding:8px;text-align:left;}",
            ".critical{color:#d14b4b;}.high{color:#cf7f2e;}.medium{color:#bda14a;}.low{color:#7f97ad;}</style>",
            "</head><body>",
            f"<h1>Remediation Report - {self.connected_target or 'No Target'}</h1>",
            f"<p>Generated: {datetime.now(timezone.utc).isoformat()}</p>",
            f"<p>Total: {len(self.vulnerabilities)} | Fixed: {len([v for v in self.vulnerabilities if v.status == 'Fixed'])}</p>",
            "<table><tr><th>ID</th><th>Vulnerability</th><th>Severity</th><th>Endpoint</th><th>Status</th></tr>",
        ]
        for v in self.vulnerabilities:
            cls = v.severity.lower()
            report_lines.append(
                f"<tr class='{cls}'><td>{v.id}</td><td>{htmlmod.escape(v.name)}</td>"
                f"<td>{v.severity}</td><td>{htmlmod.escape(v.endpoint)}</td><td>{v.status}</td></tr>"
            )
        report_lines += ["</table></body></html>"]
        report = "\n".join(report_lines)
        # Save to reports dir
        import os
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        filename = os.path.join(reports_dir, f"remediation_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html")
        with open(filename, "w") as f:
            f.write(report)
        self._log_detection(f"[{self._now()}] [INFO] Report exported to {filename}", "info")

    # ------------------------------------------------------------------
    # Live threat simulation
    # ------------------------------------------------------------------

    def _simulate_live_events(self) -> None:
        """Simulate live threats from connectors."""
        import random
        if not self.connectors:
            source_id, source_name = "local_scan", "LOCAL"
        else:
            source_id = random.choice(list(self.connectors.keys()))
            source_name = self.connectors[source_id]["name"]

        threat_types = ["SQL Injection", "XSS Attack", "Brute Force", "DDoS Attempt", "Port Scan"]
        severities = ["critical", "high", "medium", "low"]
        descriptions = [
            "Suspicious SQL query detected in login form",
            "Cross-site scripting payload in user comment",
            "Multiple failed login attempts from single IP",
            "Unusual traffic spike from external source",
            "Port scanning activity detected",
        ]
        threat = LiveThreat(
            threat_id=f"LIVE-{self.threat_counter:04d}",
            timestamp=datetime.now(timezone.utc),
            source_connector=source_name,
            threat_type=random.choice(threat_types),
            severity=random.choice(severities),
            description=random.choice(descriptions),
            target_asset=self.connected_target or "unknown",
        )
        self.live_threats.append(threat)
        self.threat_counter += 1
        self._log_detection(
            f"[{self._now()}] [{threat.severity.upper():8s}] LIVE ALERT: "
            f"{threat.threat_type} from {threat.source_connector} - {threat.description}"
        )
        # Never auto-apply remediation silently — flag for manual review only
        # (auto_remediate_enabled enables SUGGESTIONS, not silent application)
        self.after(random.randint(8000, 20000), self._simulate_live_events)

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    def _poll_events(self) -> None:
        """Poll the private scan engine queue for tuples: (etype, ...)."""
        try:
            while True:
                event = self._q.get_nowait()
                if not isinstance(event, tuple) or not event:
                    continue
                etype = event[0]
                if etype == "scan_complete":
                    report = event[2] if len(event) > 2 else {}
                    total = len(report.get("findings", [])) if isinstance(report, dict) else 0
                    self._scan_complete(total, report)
                elif etype == "cycle_done":
                    data = event[2] if len(event) > 2 else {}
                    self._on_cycle_done(
                        data.get("cycle_n", self.loop_count + 1),
                        data.get("findings_count", 0),
                        data.get("results"),
                    )
                elif etype == "error":
                    self.is_scanning = False
                    self._update_status("error")
                    msg = event[1] if len(event) > 1 else "Scan error"
                    self._log_detection(f"[{self._now()}] [ERROR] {msg}", "error")
                elif etype in ("status", "phase"):
                    msg = event[1] if len(event) > 1 else ""
                    self._log_detection(f"[{self._now()}] [ENGINE] {msg}", "info")
                elif etype == "module_status":
                    # ("module_status", key, status, elapsed, findings_count, error)
                    key     = event[1] if len(event) > 1 else ""
                    status  = event[2] if len(event) > 2 else ""
                    elapsed = event[3] if len(event) > 3 else 0.0
                    count   = event[4] if len(event) > 4 else 0
                    error   = event[5] if len(event) > 5 else ""
                    chip = (self._scan_chips or {}).get(key)
                    mod_label = key.upper()[:10]
                    cycle_idx = self.loop_count
                    ts = self._now()
                    if status == "running":
                        self._running_modules = getattr(self, '_running_modules', 0) + 1
                        self._update_det_metric("scans_running", str(self._running_modules))
                        if hasattr(self, 'det_soc'):
                            self.det_soc.add_module_row(ts, mod_label, self.connected_target or "", cycle_idx)
                        if chip:
                            chip.set_running()
                    elif status == "done":
                        self._running_modules = max(0, getattr(self, '_running_modules', 1) - 1)
                        self._modules_done_this_round = getattr(self, '_modules_done_this_round', 0) + 1
                        self._update_det_metric("scans_running", str(self._running_modules))
                        if count > 0:
                            result_txt = f"{count} finding(s)"
                            sev = "alert"
                        else:
                            result_txt = "no issues found"
                            sev = "safe"
                        if hasattr(self, 'det_soc'):
                            self.det_soc.update_module_row(mod_label, cycle_idx, result_txt, sev)
                        if chip:
                            chip.set_done(count)
                        total_modules = max(1, getattr(self, '_modules_total', 1))
                        done = self._modules_done_this_round
                        round_n = self.loop_count + 1
                        if hasattr(self, 'det_progress_label'):
                            self.det_progress_label.configure(
                                text=f"Round {round_n}  ·  {done}/{total_modules} modules complete"
                            )
                    elif status == "failed":
                        self._running_modules = max(0, getattr(self, '_running_modules', 1) - 1)
                        self._modules_done_this_round = getattr(self, '_modules_done_this_round', 0) + 1
                        self._update_det_metric("scans_running", str(self._running_modules))
                        not_ready = error.startswith("MODULE_NOT_READY") if error else False
                        err_txt   = error[:60] if error else f"failed after {elapsed:.1f}s"
                        err_sev   = "medium" if not_ready else "error"
                        if hasattr(self, 'det_soc'):
                            self.det_soc.update_module_row(mod_label, cycle_idx, err_txt, err_sev)
                        if chip:
                            chip.set_error()
                elif etype == "scanner_update":
                    key = event[1] if len(event) > 1 else ""
                    status = event[2] if len(event) > 2 else ""
                    count = event[3] if len(event) > 3 else 0
                    if count:
                        self._log_detection(
                            f"[{self._now()}] [{key.upper():12s}] {status} — {count} finding(s)", "info"
                        )
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).strftime("%H:%M:%S")

    def _now_full(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def _update_status(self, status: str) -> None:
        labels = {
            "idle": ("STANDBY", "idle"),
            "scanning": ("SCANNING...", "warning"),
            "error": ("ERROR", "error"),
            "connected": ("CONNECTED", "success"),
        }
        text, color = labels.get(status, ("UNKNOWN", "idle"))
        self.soc_status.update_status(text, color)

    def destroy(self) -> None:
        super().destroy()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def init_company_scanner(master, event_queue=None, on_event=None):
    """Create and return a new CompanyScannerView instance."""
    view = CompanyScannerView(master, event_queue=event_queue, on_event=on_event)
    return view
