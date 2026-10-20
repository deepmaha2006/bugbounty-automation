"""
Company Scanner View — HydraX Hashcats Design System.
Enterprise-wide scanning: network ranges, domains, cloud targets.

Event-queue architecture
------------------------
The view owns a PRIVATE queue (_q) that its ScanEngine writes to.
Events are polled every 100 ms via widget.after() — never a background
thread — so Tk widget calls are always on the main thread.

`scan_complete` is forwarded to the app-level `event_queue` so the main
window can update its scan count, save last_report_data, and switch to
the Results view — the same side effects it performs for all scan views.

The view does NOT define `handle_event`; the main window only routes
its own queue's events to views via that method and would double-route
any event the view forwards back.
"""

import queue
import time
from datetime import datetime
from typing import Dict, List, Optional

import customtkinter as ctk

from config.settings import (SCANNER_CATEGORIES, SCANNER_META,
                             ALL_SCANNER_KEYS, DEFAULT_SCANNER_KEYS,
                             resolve_target_url)
from config.profiles import load_profile, save_profile, list_profiles
from config.scope import ScopeConfig
from ui.theme import (
    SURFACE_BASE, SURFACE_MUTED, SURFACE_RAISED, SURFACE_STRONG,
    BORDER_HAIRLINE, BORDER_ACCENT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY, TEXT_INVERSE,
    STATUS_COLORS, SEVERITY_COLORS,
    STATUS_CRITICAL, STATUS_HIGH, STATUS_MEDIUM, STATUS_LOW, STATUS_OK,
    FONTS,
    SPACE_1, SPACE_2, SPACE_3, SPACE_4, SPACE_5, SPACE_6, SPACE_7, SPACE_8,
    RADIUS_NONE, RADIUS_MD, RADIUS_SM,
    MOTION_INSTANT, MOTION_FAST,
    BTN_HEIGHT_MD, BTN_HEIGHT_LG,
    BTN_WIDTH_MD, BTN_WIDTH_LG, BTN_WIDTH_XL,
    INPUT_HEIGHT, CARD_PADDING,
    BORDER_WIDTH_HAIRLINE, BORDER_WIDTH_ACCENT,
)
from ui.widgets import (SectionHeader, PrimaryButton, GhostButton,
                        Tag, MetricCard, StatusIndicator, make_card)
from ui.agent_status_card import AgentStatusCard
from ui.radar_ring import RadarRing
from ui.xp_bar import XPBar
from ui.animated_threat_feed import AnimatedThreatFeed
from ui.dialogs.scope_editor import ScopeEditorDialog
from ui.dialogs.scan_config_dialog import ScanConfigDialog, short_scanner_label
from core.scan_engine import ScanEngine


class ProfessionalCompanyScannerView(ctk.CTkFrame):
    """Enterprise-target scanner view — Hashcats style."""

    def __init__(self, master, event_queue: ctk.Queue, **kwargs):
        super().__init__(master, fg_color=SURFACE_BASE,
                         corner_radius=RADIUS_NONE, **kwargs)

        # App-level queue — we only WRITE to it (forward scan_complete).
        self.event_queue = event_queue

        # Private queue: our ScanEngine pushes here; we poll on Tk thread.
        self._q: queue.Queue = queue.Queue()
        self.scan_engine = ScanEngine(self._q)

        self.is_scanning = False          # read by dashboard_view
        self.scan_start_time = None
        self.current_target = ""

        self._agents_done = 0             # tracks done/error/skipped for radar
        self._live_finding_counts: Dict[str, int] = {}

        self._setup_ui()
        self.after(100, self._poll_events)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)   # header
        self.grid_rowconfigure(1, weight=0)   # target input
        self.grid_rowconfigure(2, weight=0)   # metrics
        self.grid_rowconfigure(3, weight=1)   # main content
        self.grid_rowconfigure(4, weight=0)   # threat feed

        self._create_header()
        self._create_target_section()
        self._create_metrics_dashboard()
        self._create_main_content()
        self._create_threat_feed()

    def _create_header(self):
        hdr = ctk.CTkFrame(
            self, fg_color=SURFACE_MUTED, corner_radius=RADIUS_NONE,
            border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE,
            height=56,
        )
        hdr.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        hdr.grid_propagate(False)
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr, text="COMPANY SCANNER",
            font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_TERTIARY,
            wraplength=480, justify="left", anchor="w",
        ).grid(row=0, column=0, padx=SPACE_6, pady=SPACE_4, sticky="w")

        self.status_indicator = StatusIndicator(
            hdr, text="READY TO SCAN", status="idle", width=160, height=32,
        )
        self.status_indicator.grid(row=0, column=1, padx=SPACE_6,
                                   pady=SPACE_4, sticky="e")

    def _create_target_section(self):
        frm = make_card(self)
        frm.grid(row=1, column=0, sticky="ew", padx=SPACE_6,
                 pady=(SPACE_4, SPACE_4))
        frm.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            frm, text="ENTERPRISE TARGET",
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_SECONDARY,
        ).grid(row=0, column=0, columnspan=4, padx=CARD_PADDING,
               pady=(CARD_PADDING, SPACE_3), sticky="w")

        self.target_entry = ctk.CTkEntry(
            frm,
            placeholder_text="Network range (e.g. 192.168.1.0/24), domain, or URL",
            height=INPUT_HEIGHT,
            font=ctk.CTkFont(*FONTS["body"]),
            corner_radius=RADIUS_SM,
            border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE,
            fg_color=SURFACE_BASE, text_color=TEXT_PRIMARY,
            placeholder_text_color=TEXT_SECONDARY,
        )
        self.target_entry.grid(row=1, column=0, columnspan=2,
                               padx=(CARD_PADDING, SPACE_3),
                               pady=(0, SPACE_3), sticky="ew")
        self.target_entry.bind("<Return>", lambda e: self._start_scan())
        self.target_entry.bind(
            "<FocusIn>",
            lambda e: self.target_entry.configure(
                border_color=BORDER_ACCENT, border_width=BORDER_WIDTH_ACCENT))
        self.target_entry.bind(
            "<FocusOut>",
            lambda e: self.target_entry.configure(
                border_color=BORDER_HAIRLINE,
                border_width=BORDER_WIDTH_HAIRLINE))

        ctk.CTkLabel(
            frm, text="PROFILE:",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_SECONDARY,
        ).grid(row=2, column=0, padx=(CARD_PADDING, SPACE_3),
               pady=(0, CARD_PADDING), sticky="w")

        self.profile_var = ctk.StringVar(value="cloud")
        self.profile_menu = ctk.CTkOptionMenu(
            frm, values=list_profiles(), variable=self.profile_var,
            command=self._on_profile_change,
            width=BTN_WIDTH_LG, height=INPUT_HEIGHT,
            font=ctk.CTkFont(*FONTS["small"]),
            corner_radius=RADIUS_SM,
            fg_color=SURFACE_BASE, text_color=TEXT_PRIMARY,
            button_color=SURFACE_STRONG, button_hover_color=SURFACE_RAISED,
            dropdown_fg_color=SURFACE_MUTED, dropdown_text_color=TEXT_PRIMARY,
            dropdown_hover_color=SURFACE_STRONG,
        )
        self.profile_menu.grid(row=2, column=1, padx=(0, SPACE_3),
                               pady=(0, CARD_PADDING), sticky="w")

        self.enabled_scanners: List[str] = \
            self._load_enabled_scanners_from_profile(self.profile_var.get())

        self.configure_scans_button = GhostButton(
            frm, text="CONFIGURE SCANS",
            command=self._open_scan_config_dialog,
            width=BTN_WIDTH_XL, height=INPUT_HEIGHT,
        )
        self.configure_scans_button.grid(row=2, column=2,
                                         padx=(0, SPACE_3),
                                         pady=(0, CARD_PADDING), sticky="e")

        btn_frame = ctk.CTkFrame(frm, fg_color="transparent")
        btn_frame.grid(row=2, column=3, padx=(0, CARD_PADDING),
                       pady=(0, CARD_PADDING), sticky="e")

        self.scan_button = PrimaryButton(
            btn_frame, text="START SCAN", command=self._start_scan,
            width=BTN_WIDTH_MD, height=BTN_HEIGHT_MD,
        )
        self.scan_button.grid(row=0, column=0, padx=(0, SPACE_3))

        self.stop_button = GhostButton(
            btn_frame, text="STOP SCAN", command=self._stop_scan,
            width=BTN_WIDTH_MD, height=BTN_HEIGHT_MD, state="disabled",
        )
        self.stop_button.grid(row=0, column=1)

    def _create_metrics_dashboard(self):
        mf = ctk.CTkFrame(self, fg_color="transparent")
        mf.grid(row=2, column=0, sticky="ew", padx=SPACE_6, pady=(0, SPACE_4))
        mf.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.vulns_critical = MetricCard(mf, title="CRITICAL", value="0",
                                         icon="▣", color=STATUS_CRITICAL)
        self.vulns_critical.grid(row=0, column=0, padx=(0, SPACE_3),
                                 sticky="ew")

        self.vulns_high = MetricCard(mf, title="HIGH", value="0",
                                     icon="▣", color=STATUS_HIGH)
        self.vulns_high.grid(row=0, column=1, padx=SPACE_3, sticky="ew")

        self.vulns_medium = MetricCard(mf, title="MEDIUM", value="0",
                                       icon="▣", color=STATUS_MEDIUM)
        self.vulns_medium.grid(row=0, column=2, padx=SPACE_3, sticky="ew")

        self.vulns_low = MetricCard(mf, title="LOW/INFO", value="0",
                                    icon="▣", color=STATUS_LOW)
        self.vulns_low.grid(row=0, column=3, padx=(SPACE_3, 0), sticky="ew")

    def _create_main_content(self):
        mc = ctk.CTkFrame(self, fg_color="transparent")
        mc.grid(row=3, column=0, sticky="nsew", padx=SPACE_6,
                pady=(0, SPACE_4))
        mc.grid_columnconfigure(0, weight=1)
        mc.grid_rowconfigure(0, weight=0)
        mc.grid_rowconfigure(1, weight=1)
        mc.grid_rowconfigure(2, weight=0)
        mc.grid_rowconfigure(3, weight=0)

        # Scanner summary row
        summary_frame = make_card(mc)
        summary_frame.grid(row=0, column=0, sticky="ew", pady=(0, SPACE_4))
        summary_frame.grid_columnconfigure(0, weight=1)

        self.scanner_summary_label = ctk.CTkLabel(
            summary_frame, text="",
            font=ctk.CTkFont(*FONTS["body"]),
            text_color=TEXT_PRIMARY,
            anchor="w", justify="left",
        )
        self.scanner_summary_label.grid(row=0, column=0, sticky="ew",
                                        padx=CARD_PADDING, pady=CARD_PADDING)

        def _sync_wrap(event):
            w = max(200, event.width - 2 * CARD_PADDING)
            if self.scanner_summary_label.cget("wraplength") != w:
                self.scanner_summary_label.configure(wraplength=w)
        summary_frame.bind("<Configure>", _sync_wrap)
        self._update_scanner_summary()

        # AgentStatusCard activity panel
        self._create_scanner_activity_panel(mc)

        # HUD strip — RadarRing + XPBar
        hud = ctk.CTkFrame(mc, fg_color="transparent")
        hud.grid(row=2, column=0, sticky="ew", pady=(0, SPACE_4))
        hud.grid_columnconfigure(1, weight=1)

        self._radar = RadarRing(hud, size=96, bg="#0b0b0b")
        self._radar.grid(row=0, column=0, padx=(0, SPACE_4), pady=SPACE_2)

        self._xp_bar = XPBar(hud)
        self._xp_bar.grid(row=0, column=1, sticky="ew", pady=SPACE_2)

        # Action buttons
        af = ctk.CTkFrame(mc, fg_color="transparent", height=60)
        af.grid(row=3, column=0, sticky="sew", pady=(SPACE_4, 0))
        af.grid_propagate(False)

        self.export_button = PrimaryButton(
            af, text="EXPORT REPORT", command=self._export_report,
            width=BTN_WIDTH_LG, height=BTN_HEIGHT_MD, state="disabled",
        )
        self.export_button.grid(row=0, column=0, padx=(0, SPACE_3),
                                pady=SPACE_4)

        self.clear_button = GhostButton(
            af, text="CLEAR RESULTS", command=self._clear_results,
            width=BTN_WIDTH_LG, height=BTN_HEIGHT_MD,
        )
        self.clear_button.grid(row=0, column=1, pady=SPACE_4)

    def _create_scanner_activity_panel(self, mc):
        af = make_card(mc)
        af.grid(row=1, column=0, sticky="nsew", pady=(0, SPACE_4))
        af.grid_columnconfigure(0, weight=1)
        af.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            af, text="SCANNER ACTIVITY",
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_SECONDARY,
        ).grid(row=0, column=0, sticky="w", padx=CARD_PADDING,
               pady=(CARD_PADDING, SPACE_2))

        self.scanner_activity_scroll = ctk.CTkScrollableFrame(
            af, fg_color="transparent",
            scrollbar_button_color=SURFACE_STRONG,
            scrollbar_button_hover_color=SURFACE_MUTED,
        )
        self.scanner_activity_scroll.grid(row=1, column=0, sticky="nsew",
                                          padx=CARD_PADDING,
                                          pady=(0, CARD_PADDING))
        self.scanner_activity_scroll.grid_columnconfigure(0, weight=1)

        self.scanner_rows: Dict[str, AgentStatusCard] = {}
        self._render_scanner_activity_empty()

    def _create_threat_feed(self):
        tf = make_card(self)
        tf.grid(row=4, column=0, sticky="ew", padx=SPACE_6,
                pady=(0, SPACE_6))
        tf.grid_columnconfigure(0, weight=1)
        tf.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            tf, text="THREAT INTELLIGENCE FEED",
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_SECONDARY,
        ).grid(row=0, column=0, padx=CARD_PADDING,
               pady=(CARD_PADDING, SPACE_3), sticky="w")

        self.threat_widget = AnimatedThreatFeed(tf, height=160)
        self.threat_widget.grid(row=1, column=0, padx=CARD_PADDING,
                                pady=(0, CARD_PADDING), sticky="ew")

    # ------------------------------------------------------------------
    # Activity panel helpers
    # ------------------------------------------------------------------

    def _render_scanner_activity_empty(self):
        for w in self.scanner_activity_scroll.winfo_children():
            w.destroy()
        self.scanner_rows = {}
        ctk.CTkLabel(
            self.scanner_activity_scroll,
            text="No scan running yet — click START SCAN to see live per-scanner progress here.",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
        ).grid(row=0, column=0, pady=SPACE_4)

    def _init_scanner_activity(self, roster: List[tuple]):
        for w in self.scanner_activity_scroll.winfo_children():
            w.destroy()
        self.scanner_rows = {}
        for i, (key, name) in enumerate(roster):
            card = AgentStatusCard(self.scanner_activity_scroll,
                                   key=key, name=name)
            card.grid(row=i, column=0, sticky="ew", pady=(0, SPACE_2))
            self.scanner_rows[key] = card

    def _set_scanner_status(self, key: str, status: str,
                            findings: Optional[int] = None,
                            duration: Optional[float] = None):
        card = self.scanner_rows.get(key)
        if card is not None:
            card.update_status(status, findings=findings, duration=duration)

    # ------------------------------------------------------------------
    # Scan control
    # ------------------------------------------------------------------

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
        self._agents_done = 0
        self._live_finding_counts.clear()
        self._radar.reset()
        self._xp_bar.reset()
        self.threat_widget.clear()

        self.scan_start_time = datetime.now()

        import threading
        threading.Thread(
            target=self._run_scan_worker,
            args=(target, profile_name),
            daemon=True,
        ).start()

        self._add_threat_feed_item(f"Started enterprise assessment on {target}")

    def _stop_scan(self):
        if self.is_scanning:
            self.is_scanning = False
            self.scan_engine.stop()
            self.scan_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            self.status_indicator.update_status("SCAN STOPPED", "warning")
            self._radar.stop_sweep()
            self._add_threat_feed_item("Enterprise assessment stopped by user")

    def _run_scan_worker(self, target: str, profile_name: str):
        try:
            profile = load_profile(profile_name)
            scanner_keys = list(self.enabled_scanners)
            self.scan_engine.scan(target, scanner_keys, profile.scope)
        except Exception as e:
            self._q.put(("error", str(e), ""))

    def _scan_complete(self, total_findings: Optional[int] = None):
        self.is_scanning = False
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_indicator.update_status("SCAN COMPLETE", "success")
        self.export_button.configure(state="normal")
        self.clear_button.configure(state="normal")
        self._radar.stop_sweep()

        scan_duration = datetime.now() - self.scan_start_time
        mins, secs = divmod(scan_duration.seconds, 60)
        duration_text = f"{mins}m {secs}s"
        if total_findings is not None:
            self._add_threat_feed_item(
                f"Assessment completed in {duration_text} — "
                f"{total_findings} vulnerabilit{'y' if total_findings == 1 else 'ies'} found"
            )
        else:
            self._add_threat_feed_item(
                f"Assessment completed in {duration_text}")

    def _scan_error(self, error_msg: str):
        self.is_scanning = False
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_indicator.update_status("SCAN ERROR", "error")
        self._radar.stop_sweep()
        self._show_error(f"Scan failed: {error_msg}")
        self._add_threat_feed_item(f"Scan error: {error_msg}", severity="high")

    # ------------------------------------------------------------------
    # Event polling (private queue, Tk main thread)
    # ------------------------------------------------------------------

    def _poll_events(self):
        """Drain the private scan-engine queue on the Tk main thread."""
        try:
            while not self._q.empty():
                event = self._q.get_nowait()
                self._handle_scan_event(event)
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _handle_scan_event(self, event):
        if not event:
            return
        event_type = event[0]

        if event_type == "status":
            self.status_indicator.update_status(
                event[1] if len(event) > 1 else "", "active")
        elif event_type == "error":
            self._scan_error(event[1] if len(event) > 1 else "Unknown error")
        elif event_type == "scanners_queued":
            roster = event[1]
            self._init_scanner_activity(roster)
            self._radar.update_progress(0, len(roster))
            self._radar.start_sweep()
        elif event_type == "scanner_start":
            _, key, name = event
            self._set_scanner_status(key, "running")
            self._add_threat_feed_item(f"Running {name} scan...")
        elif event_type == "scanner_done":
            _, key, name, count, duration = event
            self._set_scanner_status(key, "done",
                                     findings=count, duration=duration)
            self._add_threat_feed_item(
                f"{name} completed in {duration:.1f}s — "
                f"{count} finding{'s' if count != 1 else ''}"
            )
        elif event_type == "scanner_error":
            _, key, name, err, duration = event
            self._set_scanner_status(key, "error",
                                     findings=0, duration=duration)
            self._add_threat_feed_item(
                f"{name} failed after {duration:.1f}s: {err}",
                severity="medium")
        elif event_type == "scan_complete":
            report_dict = event[2] if len(event) > 2 else {}
            findings = []
            for result in (report_dict.get("results") or {}).values():
                findings.extend(result.get("vulnerabilities") or [])
            self._update_metrics(findings)
            self._scan_complete(len(findings))
            # Forward to app queue so main window handles results switch
            try:
                self.event_queue.put_nowait(event)
            except Exception:
                pass
        elif event_type == "agent_lifecycle":
            self._handle_lifecycle_event(event)
        # discovery / progress / report_saved: no-op

    def _handle_lifecycle_event(self, event):
        if len(event) < 3:
            return
        key, phase = event[1], event[2]
        card = self.scanner_rows.get(key)
        if card is None or not isinstance(card, AgentStatusCard):
            return

        if phase == "skipped":
            card.update_status("skipped")
            self._agents_done += 1
            self._radar.update_progress(self._agents_done,
                                        max(1, len(self.scanner_rows)))
        elif phase in ("done", "error"):
            self._agents_done += 1
            self._radar.update_progress(self._agents_done,
                                        max(1, len(self.scanner_rows)))
        elif phase == "finding" and len(event) > 3:
            finding = event[3]
            self._live_finding_counts[key] = \
                self._live_finding_counts.get(key, 0) + 1
            card.update_findings(self._live_finding_counts[key])
            # finding may be a Finding dataclass or a plain dict
            if isinstance(finding, dict):
                title = finding.get("title", finding.get("type", "Finding"))
                severity = finding.get("severity", "info")
            else:
                title = getattr(finding, "title", None) or getattr(finding, "type", "Finding")
                severity = getattr(finding, "severity", "info")
            severity = (severity or "info").lower()
            self.threat_widget.add_finding(key=key, title=title,
                                           severity=severity)
            self._xp_bar.add_xp(XPBar.xp_for_severity(severity))

    # ------------------------------------------------------------------
    # Threat feed helper
    # ------------------------------------------------------------------

    def _add_threat_feed_item(self, text: str,
                              severity: str = "info") -> None:
        self.threat_widget.add_finding(key="sys", title=text,
                                       severity=severity)

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def _reset_metrics(self):
        self.vulns_critical.update_value("0")
        self.vulns_high.update_value("0")
        self.vulns_medium.update_value("0")
        self.vulns_low.update_value("0")

    def _update_metrics(self, findings: List[dict]):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.get("severity", "Info")
            if sev in counts:
                counts[sev] += 1
        self.vulns_critical.update_value(str(counts["Critical"]))
        self.vulns_high.update_value(str(counts["High"]))
        self.vulns_medium.update_value(str(counts["Medium"]))
        self.vulns_low.update_value(str(counts["Low"] + counts["Info"]))

    # ------------------------------------------------------------------
    # Profile / scanner selection
    # ------------------------------------------------------------------

    def _load_enabled_scanners_from_profile(self,
                                            profile_name: str) -> List[str]:
        try:
            profile = load_profile(profile_name)
            keys = (profile.enabled_scanners
                    if profile.enabled_scanners else DEFAULT_SCANNER_KEYS)
        except Exception:
            keys = DEFAULT_SCANNER_KEYS
        return [k for k in ALL_SCANNER_KEYS if k in keys]

    def _on_profile_change(self, _value=None):
        self.enabled_scanners = \
            self._load_enabled_scanners_from_profile(self.profile_var.get())
        self._update_scanner_summary()

    def _open_scan_config_dialog(self):
        ScanConfigDialog(
            self.winfo_toplevel(),
            categories=SCANNER_CATEGORIES,
            enabled_keys=self.enabled_scanners,
            on_apply=self._apply_scanner_selection,
        )

    def _apply_scanner_selection(self, new_enabled: List[str]):
        self.enabled_scanners = new_enabled
        self._persist_enabled_scanners(new_enabled)
        self._update_scanner_summary()

    def _persist_enabled_scanners(self, enabled: List[str]):
        profile_name = self.profile_var.get()
        try:
            profile = load_profile(profile_name)
            profile.enabled_scanners = list(enabled)
            profile.disabled_scanners = [k for k in ALL_SCANNER_KEYS
                                         if k not in enabled]
            save_profile(profile)
        except Exception as e:
            self._show_error(
                f"Could not save scanner selection to "
                f"profile '{profile_name}': {e}")

    def _update_scanner_summary(self):
        n = len(self.enabled_scanners)
        total = len(ALL_SCANNER_KEYS)
        self.configure_scans_button.configure(
            text=f"CONFIGURE SCANS ({n} selected)")
        if not self.enabled_scanners:
            text = "No scanners enabled — click CONFIGURE SCANS to select modules."
        else:
            labels = [short_scanner_label(SCANNER_META[k]["name"])
                      for k in self.enabled_scanners if k in SCANNER_META]
            shown = " · ".join(labels[:3])
            more = f" · +{len(labels) - 3} more" if len(labels) > 3 else ""
            text = f"Active: {shown}{more}  ({n}/{total})"
        self.scanner_summary_label.configure(text=text)

    # ------------------------------------------------------------------
    # Action buttons
    # ------------------------------------------------------------------

    def _export_report(self):
        self._show_info("Report export functionality would be implemented here")

    def _clear_results(self):
        self._reset_metrics()
        self._render_scanner_activity_empty()
        self._radar.reset()
        self._xp_bar.reset()
        self.threat_widget.clear()
        self._show_info("Results cleared")

    def _show_error(self, message: str):
        print(f"ERROR: {message}")

    def _show_info(self, message: str):
        print(f"INFO: {message}")

    # ------------------------------------------------------------------
    # Public alias expected by main_window.py
    # ------------------------------------------------------------------

    def refresh(self):
        """Called by main_window when navigating to this view."""
        pass
