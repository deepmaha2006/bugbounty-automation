"""
Professional Company Scanner View for Enterprise Security Assessment — HydraX Hashcats Design System.
Dark, monospace, hard-edged, terminal/pixel aesthetic.
"""

import customtkinter as ctk
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from config.settings import (SCANNER_CATEGORIES, SCANNER_META,
                             ALL_SCANNER_KEYS, DEFAULT_SCANNER_KEYS,
                             resolve_target_url)
from config.profiles import ScanProfile, load_profile, save_profile, list_profiles, get_profile_manager
from config.scope import ScopeConfig, create_api_scope, create_web_scope, create_authenticated_scope
from ui.theme import (
    # Surfaces
    SURFACE_BASE, SURFACE_MUTED, SURFACE_RAISED, SURFACE_STRONG,
    # Borders
    BORDER_HAIRLINE, BORDER_ACCENT,
    # Text
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY, TEXT_INVERSE,
    # Status / Severity
    STATUS_COLORS, SEVERITY_COLORS,
    STATUS_CRITICAL, STATUS_HIGH, STATUS_MEDIUM, STATUS_LOW, STATUS_OK,
    # Typography
    FONTS,
    # Spacing
    SPACE_1, SPACE_2, SPACE_3, SPACE_4, SPACE_5, SPACE_6, SPACE_7, SPACE_8,
    # Radius
    RADIUS_NONE, RADIUS_MD, RADIUS_SM,
    # Motion
    MOTION_INSTANT, MOTION_FAST,
    # Component tokens
    BTN_HEIGHT_MD, BTN_HEIGHT_LG,
    BTN_WIDTH_MD, BTN_WIDTH_LG, BTN_WIDTH_XL,
    INPUT_HEIGHT, CARD_PADDING,
    BORDER_WIDTH_HAIRLINE, BORDER_WIDTH_ACCENT,
)
from ui.widgets import (SectionHeader, PrimaryButton, GhostButton,
                        Tag, MetricCard, StatusIndicator, ThreatFeedWidget,
                        make_card)
from ui.dialogs.scope_editor import ScopeEditorDialog
from ui.dialogs.scan_config_dialog import ScanConfigDialog, short_scanner_label
from core.scan_engine import ScanEngine


class ProfessionalCompanyScannerView(ctk.CTkFrame):
    """Professional company scanner view designed for enterprise security analysts — Hashcats style."""

    def __init__(self, master, event_queue: ctk.Queue, **kwargs):
        super().__init__(master, fg_color=SURFACE_BASE, corner_radius=RADIUS_NONE, **kwargs)

        self.event_queue = event_queue
        self.scan_engine = ScanEngine(event_queue)
        self.is_scanning = False
        self.scan_start_time = None
        self.current_target = ""
        self.scan_thread = None

        # Live activity feed — populated only from real events on this scan
        # engine (see _add_threat_feed_item); starts empty, not fabricated.
        self.threat_feed = [
            {"time": "--:--", "threat": "No activity yet — start a scan to populate this feed.", "severity": "Info"},
        ]

        self._setup_ui()
        self._start_event_listener()

    def _setup_ui(self):
        """Setup the professional SOC analyst interface — Hashcats layout."""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)  # Header
        self.grid_rowconfigure(1, weight=0)  # Target input
        self.grid_rowconfigure(2, weight=0)  # Metrics row
        self.grid_rowconfigure(3, weight=1)  # Main content
        self.grid_rowconfigure(4, weight=0)  # Threat feed

        # Header
        self._create_header()

        # Target input section
        self._create_target_section()

        # Metrics dashboard
        self._create_metrics_dashboard()

        # Main content: Scanner panels and controls
        self._create_main_content()

        # Threat intelligence feed
        self._create_threat_feed()

    def _create_header(self):
        """Create header — Hashcats topbar style."""
        header_frame = ctk.CTkFrame(
            self,
            fg_color=SURFACE_MUTED,
            corner_radius=RADIUS_NONE,
            border_width=BORDER_WIDTH_HAIRLINE,
            border_color=BORDER_HAIRLINE,
            height=56
        )
        header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header_frame.grid_propagate(False)
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="COMPANY SCANNER",
            font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_TERTIARY,  # Lime
            wraplength=480,  # wrap instead of overlapping the status badge if squeezed
            justify="left",
            anchor="w",
        )
        title_label.grid(row=0, column=0, padx=SPACE_6, pady=SPACE_4, sticky="w")

        # Status indicator
        self.status_indicator = StatusIndicator(
            header_frame,
            text="READY TO SCAN",
            status="idle",
            width=160,
            height=32
        )
        self.status_indicator.grid(row=0, column=1, padx=SPACE_6, pady=SPACE_4, sticky="e")

    def _create_target_section(self):
        """Create target input section — Hashcats card style."""
        target_frame = make_card(self)
        target_frame.grid(row=1, column=0, sticky="ew", padx=SPACE_6, pady=(SPACE_4, SPACE_4))
        target_frame.grid_columnconfigure(1, weight=1)

        # Target label
        target_label = ctk.CTkLabel(
            target_frame,
            text="ENTERPRISE TARGET",
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_SECONDARY
        )
        target_label.grid(row=0, column=0, columnspan=4, padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_3), sticky="w")

        # Target entry
        self.target_entry = ctk.CTkEntry(
            target_frame,
            placeholder_text="Network range (e.g., 192.168.1.0/24) or domain",
            height=INPUT_HEIGHT,
            font=ctk.CTkFont(*FONTS["body"]),
            corner_radius=RADIUS_SM,
            border_width=BORDER_WIDTH_HAIRLINE,
            border_color=BORDER_HAIRLINE,
            fg_color=SURFACE_BASE,
            text_color=TEXT_PRIMARY,
            placeholder_text_color=TEXT_SECONDARY
        )
        self.target_entry.grid(row=1, column=0, columnspan=2, padx=(CARD_PADDING, SPACE_3), pady=(0, SPACE_3), sticky="ew")
        self.target_entry.bind("<Return>", lambda e: self._start_scan())
        self.target_entry.bind("<FocusIn>", lambda e: self.target_entry.configure(border_color=BORDER_ACCENT, border_width=BORDER_WIDTH_ACCENT))
        self.target_entry.bind("<FocusOut>", lambda e: self.target_entry.configure(border_color=BORDER_HAIRLINE, border_width=BORDER_WIDTH_HAIRLINE))

        # Scan profile selector
        profile_label = ctk.CTkLabel(
            target_frame,
            text="PROFILE:",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_SECONDARY
        )
        profile_label.grid(row=2, column=0, padx=(CARD_PADDING, SPACE_3), pady=(0, CARD_PADDING), sticky="w")

        self.profile_var = ctk.StringVar(value="cloud")
        self.profile_menu = ctk.CTkOptionMenu(
            target_frame,
            values=list_profiles(),
            variable=self.profile_var,
            command=self._on_profile_change,
            width=BTN_WIDTH_LG,
            height=INPUT_HEIGHT,
            font=ctk.CTkFont(*FONTS["small"]),
            corner_radius=RADIUS_SM,
            fg_color=SURFACE_BASE,
            text_color=TEXT_PRIMARY,
            button_color=SURFACE_STRONG,
            button_hover_color=SURFACE_RAISED,
            dropdown_fg_color=SURFACE_MUTED,
            dropdown_text_color=TEXT_PRIMARY,
            dropdown_hover_color=SURFACE_STRONG
        )
        self.profile_menu.grid(row=2, column=1, padx=(0, SPACE_3), pady=(0, CARD_PADDING), sticky="w")

        # Scanner selection state — the actual list handed to the scan
        # engine at scan time; seeded from the initially selected profile.
        self.enabled_scanners: List[str] = self._load_enabled_scanners_from_profile(self.profile_var.get())

        self.configure_scans_button = GhostButton(
            target_frame,
            text="CONFIGURE SCANS",
            command=self._open_scan_config_dialog,
            width=BTN_WIDTH_XL,
            height=INPUT_HEIGHT,
        )
        self.configure_scans_button.grid(row=2, column=2, padx=(0, SPACE_3), pady=(0, CARD_PADDING), sticky="e")

        # Scan control buttons
        button_frame = ctk.CTkFrame(target_frame, fg_color="transparent")
        button_frame.grid(row=2, column=3, padx=(0, CARD_PADDING), pady=(0, CARD_PADDING), sticky="e")

        self.scan_button = PrimaryButton(
            button_frame,
            text="START SCAN",
            command=self._start_scan,
            width=BTN_WIDTH_MD,
            height=BTN_HEIGHT_MD
        )
        self.scan_button.grid(row=0, column=0, padx=(0, SPACE_3))

        self.stop_button = GhostButton(
            button_frame,
            text="STOP SCAN",
            command=self._stop_scan,
            width=BTN_WIDTH_MD,
            height=BTN_HEIGHT_MD,
            state="disabled"
        )
        self.stop_button.grid(row=0, column=1)

    def _create_metrics_dashboard(self):
        """Create real-time metrics dashboard — 4 severity cards."""
        metrics_frame = ctk.CTkFrame(self, fg_color="transparent")
        metrics_frame.grid(row=2, column=0, sticky="ew", padx=SPACE_6, pady=(0, SPACE_4))
        metrics_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.vulns_critical = MetricCard(
            metrics_frame,
            title="CRITICAL",
            value="0",
            icon="▣",
            color=STATUS_CRITICAL
        )
        self.vulns_critical.grid(row=0, column=0, padx=(0, SPACE_3), sticky="ew")

        self.vulns_high = MetricCard(
            metrics_frame,
            title="HIGH",
            value="0",
            icon="▣",
            color=STATUS_HIGH
        )
        self.vulns_high.grid(row=0, column=1, padx=SPACE_3, sticky="ew")

        self.vulns_medium = MetricCard(
            metrics_frame,
            title="MEDIUM",
            value="0",
            icon="▣",
            color=STATUS_MEDIUM
        )
        self.vulns_medium.grid(row=0, column=2, padx=SPACE_3, sticky="ew")

        self.vulns_low = MetricCard(
            metrics_frame,
            title="LOW/INFO",
            value="0",
            icon="▣",
            color=STATUS_LOW
        )
        self.vulns_low.grid(row=0, column=3, padx=(SPACE_3, 0), sticky="ew")

    def _create_main_content(self):
        """Create main content area: scanner summary row + action buttons.

        The old inline scanner-toggle card grid lived here, but overflowed
        and clipped once the catalog grew past ~2-3 modules per row — see
        ScanConfigDialog for the replacement modal, opened via the
        CONFIGURE SCANS button next to the profile selector above.
        """
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.grid(row=3, column=0, sticky="nsew", padx=SPACE_6, pady=(0, SPACE_4))
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_rowconfigure(0, weight=0)
        main_container.grid_rowconfigure(1, weight=1)
        main_container.grid_rowconfigure(2, weight=0)

        # Compact summary of which scanners are currently enabled.
        summary_frame = make_card(main_container)
        summary_frame.grid(row=0, column=0, sticky="ew", pady=(0, SPACE_4))
        summary_frame.grid_columnconfigure(0, weight=1)

        self.scanner_summary_label = ctk.CTkLabel(
            summary_frame,
            text="",
            font=ctk.CTkFont(*FONTS["body"]),
            text_color=TEXT_PRIMARY,
            anchor="w",
            justify="left",
        )
        self.scanner_summary_label.grid(row=0, column=0, sticky="ew", padx=CARD_PADDING, pady=CARD_PADDING)

        def _sync_summary_wrap(event):
            new_width = max(200, event.width - 2 * CARD_PADDING)
            if self.scanner_summary_label.cget("wraplength") != new_width:
                self.scanner_summary_label.configure(wraplength=new_width)
        summary_frame.bind("<Configure>", _sync_summary_wrap)

        self._update_scanner_summary()

        # Live per-scanner activity: which scanner is running, how long
        # it's taken so far, and how many findings it turned up — so a
        # long-running scan isn't a black box.
        self._create_scanner_activity_panel(main_container)

        # Action buttons at bottom
        action_frame = ctk.CTkFrame(main_container, fg_color="transparent", height=60)
        action_frame.grid(row=2, column=0, sticky="sew", pady=(SPACE_4, 0))
        action_frame.grid_propagate(False)

        self.export_button = PrimaryButton(
            action_frame,
            text="EXPORT REPORT",
            command=self._export_report,
            width=BTN_WIDTH_LG,
            height=BTN_HEIGHT_MD,
            state="disabled"
        )
        self.export_button.grid(row=0, column=0, padx=(0, SPACE_3), pady=SPACE_4)

        self.clear_button = GhostButton(
            action_frame,
            text="CLEAR RESULTS",
            command=self._clear_results,
            width=BTN_WIDTH_LG,
            height=BTN_HEIGHT_MD
        )
        self.clear_button.grid(row=0, column=1, pady=SPACE_4)

    def _create_scanner_activity_panel(self, main_container):
        """Live roster of the scanners in this run — status, elapsed time
        and findings-so-far for each, updated from scanner_start/
        scanner_done/scanner_error engine events plus a 1s ticker."""
        activity_frame = make_card(main_container)
        activity_frame.grid(row=1, column=0, sticky="nsew", pady=(0, SPACE_4))
        activity_frame.grid_columnconfigure(0, weight=1)
        activity_frame.grid_rowconfigure(1, weight=1)

        activity_label = ctk.CTkLabel(
            activity_frame,
            text="SCANNER ACTIVITY",
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_SECONDARY,
        )
        activity_label.grid(row=0, column=0, sticky="w", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_2))

        self.scanner_activity_scroll = ctk.CTkScrollableFrame(
            activity_frame,
            fg_color="transparent",
            scrollbar_button_color=SURFACE_STRONG,
            scrollbar_button_hover_color=SURFACE_MUTED,
        )
        self.scanner_activity_scroll.grid(row=1, column=0, sticky="nsew", padx=CARD_PADDING, pady=(0, CARD_PADDING))
        self.scanner_activity_scroll.grid_columnconfigure(0, weight=1)

        self.scanner_rows: Dict[str, dict] = {}
        self._render_scanner_activity_empty()

    def _render_scanner_activity_empty(self):
        for widget in self.scanner_activity_scroll.winfo_children():
            widget.destroy()
        self.scanner_rows = {}
        ctk.CTkLabel(
            self.scanner_activity_scroll,
            text="No scan running yet — click START SCAN to see live per-scanner progress here.",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
        ).grid(row=0, column=0, pady=SPACE_4)

    def _init_scanner_activity(self, roster: List[tuple]):
        """Rebuild the activity panel with one QUEUED row per scanner about
        to run — called from the 'scanners_queued' engine event."""
        for widget in self.scanner_activity_scroll.winfo_children():
            widget.destroy()
        self.scanner_rows = {}
        for i, (key, name) in enumerate(roster):
            row = self._build_scanner_row(key, name)
            row["frame"].grid(row=i, column=0, sticky="ew", pady=(0, SPACE_2))
            self.scanner_rows[key] = row

    def _build_scanner_row(self, key: str, name: str) -> dict:
        frame = ctk.CTkFrame(
            self.scanner_activity_scroll,
            fg_color=SURFACE_MUTED,
            corner_radius=RADIUS_MD,
            border_width=BORDER_WIDTH_HAIRLINE,
            border_color=BORDER_HAIRLINE,
        )
        frame.grid_columnconfigure(0, weight=1)

        name_label = ctk.CTkLabel(
            frame, text=name, font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_PRIMARY, anchor="w",
        )
        name_label.grid(row=0, column=0, sticky="w", padx=(SPACE_3, SPACE_2), pady=SPACE_2)

        status_label = ctk.CTkLabel(
            frame, text="QUEUED", font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_SECONDARY, width=80, anchor="w",
        )
        status_label.grid(row=0, column=1, padx=SPACE_2, pady=SPACE_2)

        time_label = ctk.CTkLabel(
            frame, text="--", font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY, width=60, anchor="e",
        )
        time_label.grid(row=0, column=2, padx=SPACE_2, pady=SPACE_2)

        findings_label = ctk.CTkLabel(
            frame, text="-- findings", font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY, width=90, anchor="e",
        )
        findings_label.grid(row=0, column=3, padx=(SPACE_2, SPACE_3), pady=SPACE_2)

        return {
            "frame": frame, "status_label": status_label,
            "time_label": time_label, "findings_label": findings_label,
            "status": "queued", "start": None,
        }

    def _set_scanner_status(self, key: str, status: str,
                            findings: Optional[int] = None, duration: Optional[float] = None):
        row = self.scanner_rows.get(key)
        if not row:
            return
        row["status"] = status
        color_map = {
            "queued": TEXT_SECONDARY, "running": TEXT_TERTIARY,
            "done": STATUS_OK, "error": STATUS_CRITICAL,
        }
        row["status_label"].configure(text=status.upper(), text_color=color_map.get(status, TEXT_SECONDARY))
        if status == "running":
            row["start"] = time.time()
            row["time_label"].configure(text="0.0s")
        elif duration is not None:
            row["time_label"].configure(text=f"{duration:.1f}s")
        if findings is not None:
            row["findings_label"].configure(text=f"{findings} finding{'s' if findings != 1 else ''}")

    def _tick_scanner_rows(self):
        """Advance the elapsed-time label of every still-RUNNING row every
        second while a scan is in progress."""
        if not self.is_scanning:
            return
        for row in self.scanner_rows.values():
            if row["status"] == "running" and row["start"] is not None:
                row["time_label"].configure(text=f"{time.time() - row['start']:.1f}s")
        self.after(1000, self._tick_scanner_rows)

    def _create_threat_feed(self):
        """Create real-time threat intelligence feed — Hashcats card."""
        threat_frame = make_card(self)
        threat_frame.grid(row=4, column=0, sticky="ew", padx=SPACE_6, pady=(0, SPACE_6))
        threat_frame.grid_columnconfigure(0, weight=1)
        threat_frame.grid_rowconfigure(1, weight=1)

        threat_label = ctk.CTkLabel(
            threat_frame,
            text="THREAT INTELLIGENCE FEED",
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_SECONDARY
        )
        threat_label.grid(row=0, column=0, padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_3), sticky="w")

        self.threat_widget = ThreatFeedWidget(threat_frame, threats=self.threat_feed)
        self.threat_widget.grid(row=1, column=0, padx=CARD_PADDING, pady=(0, CARD_PADDING), sticky="ew")

    def _load_enabled_scanners_from_profile(self, profile_name: str) -> List[str]:
        """Resolve the enabled-scanner set for a profile, in catalog order."""
        try:
            profile = load_profile(profile_name)
            keys = profile.enabled_scanners if profile.enabled_scanners else DEFAULT_SCANNER_KEYS
        except Exception:
            keys = DEFAULT_SCANNER_KEYS
        return [k for k in ALL_SCANNER_KEYS if k in keys]

    def _on_profile_change(self, _value=None):
        """Reload the enabled-scanner state when the user switches profiles."""
        self.enabled_scanners = self._load_enabled_scanners_from_profile(self.profile_var.get())
        self._update_scanner_summary()

    def _open_scan_config_dialog(self):
        """Open the Configure Scans modal for this page's scanner catalog."""
        ScanConfigDialog(
            self.winfo_toplevel(),
            categories=SCANNER_CATEGORIES,
            enabled_keys=self.enabled_scanners,
            on_apply=self._apply_scanner_selection,
        )

    def _apply_scanner_selection(self, new_enabled: List[str]):
        """Commit the modal's selection — same list the scan engine reads."""
        self.enabled_scanners = new_enabled
        self._persist_enabled_scanners(new_enabled)
        self._update_scanner_summary()

    def _persist_enabled_scanners(self, enabled: List[str]):
        """Write the selection back into the currently selected profile —
        the exact same enabled_scanners/disabled_scanners fields
        _run_scan_worker already reads to decide what runs."""
        profile_name = self.profile_var.get()
        try:
            profile = load_profile(profile_name)
            profile.enabled_scanners = list(enabled)
            profile.disabled_scanners = [k for k in ALL_SCANNER_KEYS if k not in enabled]
            save_profile(profile)
        except Exception as e:
            self._show_error(f"Could not save scanner selection to profile '{profile_name}': {e}")

    def _update_scanner_summary(self):
        """Refresh the CONFIGURE SCANS button count and main-page summary row."""
        n = len(self.enabled_scanners)
        total = len(ALL_SCANNER_KEYS)
        self.configure_scans_button.configure(text=f"CONFIGURE SCANS ({n} selected)")

        if not self.enabled_scanners:
            text = "No scanners enabled — click CONFIGURE SCANS to select modules."
        else:
            labels = [short_scanner_label(SCANNER_META[k]["name"]) for k in self.enabled_scanners if k in SCANNER_META]
            shown = " · ".join(labels[:3])
            more = f" · +{len(labels) - 3} more" if len(labels) > 3 else ""
            text = f"Active: {shown}{more}  ({n}/{total})"
        self.scanner_summary_label.configure(text=text)

    def _start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            self._show_error("Please enter a target (network range, IP, or domain)")
            return

        self.current_target = target
        profile_name = self.profile_var.get()

        self.is_scanning = True
        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.export_button.configure(state="disabled")
        self.clear_button.configure(state="disabled")
        self.status_indicator.update_status("SCANNING...", "active")

        self._reset_metrics()
        self._render_scanner_activity_empty()

        self.scan_start_time = datetime.now()
        self.scan_thread = threading.Thread(
            target=self._run_scan_worker,
            args=(target, profile_name),
            daemon=True
        )
        self.scan_thread.start()
        self.after(1000, self._tick_scanner_rows)

        self._add_threat_feed_item(f"Started security assessment on {target}")

    def _stop_scan(self):
        if self.is_scanning:
            self.is_scanning = False
            self.scan_engine.stop()
            self.scan_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            self.status_indicator.update_status("SCAN STOPPED", "warning")
            self._add_threat_feed_item("Security assessment stopped by user")

    def _run_scan_worker(self, target: str, profile_name: str):
        try:
            # Load selected profile (scope/rate-limit settings)
            profile = load_profile(profile_name)

            # Scanner selection comes from the Configure Scans modal state,
            # which is also persisted into this same profile's
            # enabled_scanners field — see _persist_enabled_scanners.
            scanner_keys = list(self.enabled_scanners)

            self.scan_engine.scan(target, scanner_keys, profile.scope)
        except Exception as e:
            self._scan_error(str(e))

    def _scan_complete(self, total_findings: Optional[int] = None):
        self.is_scanning = False
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_indicator.update_status("SCAN COMPLETE", "success")
        self.export_button.configure(state="normal")
        self.clear_button.configure(state="normal")

        scan_duration = datetime.now() - self.scan_start_time
        duration_text = f"{scan_duration.seconds//60}m {scan_duration.seconds%60}s"
        if total_findings is not None:
            self._add_threat_feed_item(
                f"Security assessment completed in {duration_text} — {total_findings} vulnerabilities found"
            )
        else:
            self._add_threat_feed_item(f"Security assessment completed in {duration_text}")

    def _scan_error(self, error_msg: str):
        self.is_scanning = False
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_indicator.update_status("SCAN ERROR", "error")
        self._show_error(f"Scan failed: {error_msg}")
        self._add_threat_feed_item(f"Scan error: {error_msg}")

    def _add_threat_feed_item(self, threat_text: str):
        from datetime import datetime
        new_threat = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "threat": threat_text,
            "severity": "Info"
        }
        self.threat_feed.insert(0, new_threat)
        if len(self.threat_feed) > 10:
            self.threat_feed = self.threat_feed[:10]
        self.threat_widget.update_threats(self.threat_feed)

    def _reset_metrics(self):
        self.vulns_critical.update_value("0")
        self.vulns_high.update_value("0")
        self.vulns_medium.update_value("0")
        self.vulns_low.update_value("0")

    def _update_metrics(self, findings: List[Dict]):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for finding in findings:
            severity = finding.get("severity", "Info")
            if severity in counts:
                counts[severity] += 1
        self.vulns_critical.update_value(str(counts["Critical"]))
        self.vulns_high.update_value(str(counts["High"]))
        self.vulns_medium.update_value(str(counts["Medium"]))
        self.vulns_low.update_value(str(counts["Low"] + counts["Info"]))

    def _export_report(self):
        self._show_info("Report export functionality would be implemented here")

    def _clear_results(self):
        self._reset_metrics()
        self._render_scanner_activity_empty()
        self._show_info("Results cleared")

    def _show_error(self, message: str):
        print(f"ERROR: {message}")

    def _show_info(self, message: str):
        print(f"INFO: {message}")

    def _start_event_listener(self):
        def listen_for_events():
            while True:
                try:
                    if not self.event_queue.empty():
                        event = self.event_queue.get_nowait()
                        # _handle_scan_event touches CTk widgets — calling it
                        # directly from this background thread intermittently
                        # raises _tkinter.TclError from inside CTk's redraw
                        # internals. Marshal it onto the main loop.
                        self.after(0, lambda e=event: self._handle_scan_event(e))
                    time.sleep(0.1)
                except:
                    break

        threading.Thread(target=listen_for_events, daemon=True).start()

    def _handle_scan_event(self, event):
        event_type = event[0] if event else None

        if event_type == "status":
            self.status_indicator.update_status(event[1] if len(event) > 1 else "", "active")
        elif event_type == "error":
            self._scan_error(event[1] if len(event) > 1 else "Unknown error")
        elif event_type == "scanners_queued":
            self._init_scanner_activity(event[1])
        elif event_type == "scanner_start":
            _, key, name = event
            self._set_scanner_status(key, "running")
            # Pushed for every scanner that starts — since scanners run
            # concurrently, several "Running ... scan..." lines land in the
            # feed close together, which is the visible proof concurrency
            # is real.
            self._add_threat_feed_item(f"Running {name} scan...")
        elif event_type == "scanner_done":
            _, key, name, count, duration = event
            self._set_scanner_status(key, "done", findings=count, duration=duration)
            self._add_threat_feed_item(
                f"{name} scan completed in {duration:.1f}s — {count} finding{'s' if count != 1 else ''}"
            )
        elif event_type == "scanner_error":
            _, key, name, err, duration = event
            self._set_scanner_status(key, "error", findings=0, duration=duration)
            self._add_threat_feed_item(f"{name} scan failed after {duration:.1f}s: {err}")
        elif event_type == "scan_complete":
            report_dict = event[2] if len(event) > 2 else {}
            findings = []
            for result in (report_dict.get("results") or {}).values():
                findings.extend(result.get("vulnerabilities") or [])
            self._update_metrics(findings)
            self._scan_complete(len(findings))
        elif event_type == "report_saved":
            pass
        elif event_type == "discovery":
            pass
        elif event_type == "progress":
            pass