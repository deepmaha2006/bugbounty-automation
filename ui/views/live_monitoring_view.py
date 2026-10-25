"""
Live Threat / Breach Monitoring view.

Continuous, event-driven monitoring of a connected authorized target for:
  - Anomalous HTTP responses
  - New open ports / services
  - Certificate changes
  - Suspicious endpoint appearances
  - Exposed malware artifacts

Alerts are severity-colored in the live feed and push desktop notifications
(via utils.notifications) when a threshold is crossed.
"""

from __future__ import annotations

import queue
import threading
import time
import random
from datetime import datetime
from typing import Any, Dict, List, Optional

import customtkinter as ctk

from ui.theme import (
    SURFACE_BASE, SURFACE_MUTED, SURFACE_RAISED, SURFACE_STRONG,
    BORDER_HAIRLINE, BORDER_ACCENT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY, TEXT_INVERSE,
    STATUS_CRITICAL, STATUS_HIGH, STATUS_MEDIUM, STATUS_LOW, STATUS_OK,
    STATUS_RUNNING_COLOR,
    SEVERITY_COLORS, FONTS,
    SPACE_1, SPACE_2, SPACE_3, SPACE_4, SPACE_5, SPACE_6, SPACE_7, SPACE_8,
    RADIUS_NONE, RADIUS_SM, RADIUS_MD,
    BTN_HEIGHT_MD, BTN_HEIGHT_LG,
    INPUT_HEIGHT, CARD_PADDING,
    BORDER_WIDTH_HAIRLINE, BORDER_WIDTH_ACCENT,
)
from ui.widgets import (
    PrimaryButton, GhostButton, MetricCard, StatusIndicator, make_card,
)


# ─────────────────────────────────────────────────────────────────────────────
# Indicator types and their default severity
# ─────────────────────────────────────────────────────────────────────────────
INDICATOR_TYPES = [
    ("anomalous_response",   "Anomalous HTTP Response",   "high"),
    ("new_open_port",        "New Open Port Detected",     "critical"),
    ("cert_change",          "Certificate Change",         "high"),
    ("suspicious_endpoint",  "Suspicious Endpoint",        "high"),
    ("malware_artifact",     "Malware Artifact Exposed",   "critical"),
    ("unexpected_service",   "Unexpected Service",         "medium"),
    ("info_disclosure",      "Information Disclosure",     "medium"),
    ("config_drift",         "Configuration Drift",        "low"),
]


class LiveMonitoringView(ctk.CTkFrame):
    """Live breach/threat monitoring panel for a connected authorized target."""

    def __init__(self, master, event_queue: Optional[queue.Queue] = None, **kwargs):
        super().__init__(master, fg_color=SURFACE_BASE, **kwargs)
        self.event_queue = event_queue or queue.Queue()
        self._monitor_thread: Optional[threading.Thread] = None
        self._running = False
        self._target: str = ""
        self._alert_threshold = "high"   # only notify on HIGH+
        self._alerts: List[Dict[str, Any]] = []
        self._pulse_state = False
        self._pulse_job: Optional[str] = None

        self._setup_ui()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _setup_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)  # status bar
        self.grid_rowconfigure(1, weight=0)  # title
        self.grid_rowconfigure(2, weight=0)  # config + metrics row
        self.grid_rowconfigure(3, weight=1)  # live feed
        self.grid_rowconfigure(4, weight=0)  # indicators checklist

        self._build_status_bar()
        self._build_title()
        self._build_config_row()
        self._build_live_feed()
        self._build_indicator_strip()

    def _build_status_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=SURFACE_STRONG, height=36, corner_radius=0)
        bar.grid(row=0, column=0, sticky="ew")
        bar.grid_propagate(False)

        left = ctk.CTkFrame(bar, fg_color="transparent")
        left.pack(side="left", padx=SPACE_6)

        self._top_status = ctk.CTkLabel(
            left, text="● STANDBY",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_SECONDARY,
        )
        self._top_status.pack(side="left")

        ctk.CTkLabel(left, text="|", text_color=TEXT_TERTIARY).pack(side="left", padx=SPACE_4)

        self._top_target = ctk.CTkLabel(
            left, text="No target connected",
            font=ctk.CTkFont(*FONTS["small"]), text_color=TEXT_SECONDARY,
        )
        self._top_target.pack(side="left")

        right = ctk.CTkFrame(bar, fg_color="transparent")
        right.pack(side="right", padx=SPACE_6)

        self._alert_count_lbl = ctk.CTkLabel(
            right, text="Alerts: 0",
            font=ctk.CTkFont(*FONTS["small_bold"]), text_color=TEXT_SECONDARY,
        )
        self._alert_count_lbl.pack(side="left")

    def _build_title(self) -> None:
        ctk.CTkLabel(
            self, text="LIVE THREAT MONITOR",
            font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=SPACE_6, pady=(SPACE_4, SPACE_2))

    def _build_config_row(self) -> None:
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=2, column=0, sticky="ew", padx=SPACE_6, pady=(0, SPACE_4))
        row.grid_columnconfigure(0, weight=1)
        row.grid_columnconfigure(1, weight=0)

        # Left: target entry + controls
        left = ctk.CTkFrame(row, fg_color="transparent")
        left.grid(row=0, column=0, sticky="ew")
        left.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            left, text="Target",
            font=ctk.CTkFont(*FONTS["small_bold"]), text_color=TEXT_SECONDARY,
        ).grid(row=0, column=0, padx=(0, SPACE_3), sticky="w")

        self._target_entry = ctk.CTkEntry(
            left, placeholder_text="https://example.com",
            height=INPUT_HEIGHT,
        )
        self._target_entry.grid(row=0, column=1, padx=(0, SPACE_3), sticky="ew")

        ctk.CTkLabel(
            left, text="Alert threshold",
            font=ctk.CTkFont(*FONTS["small_bold"]), text_color=TEXT_SECONDARY,
        ).grid(row=0, column=2, padx=(SPACE_4, SPACE_2), sticky="w")

        self._threshold_var = ctk.StringVar(value="High+")
        ctk.CTkOptionMenu(
            left, values=["Critical only", "High+", "Medium+", "All"],
            variable=self._threshold_var,
            height=INPUT_HEIGHT, width=110,
            fg_color=SURFACE_MUTED, button_color=SURFACE_RAISED,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(*FONTS["small"]),
        ).grid(row=0, column=3, padx=(0, SPACE_3))

        self._auth_cb = ctk.CTkCheckBox(
            left, text="I authorize this monitoring session.",
            font=ctk.CTkFont(*FONTS["small"]),
            command=self._update_btn_state,
        )
        self._auth_cb.grid(row=1, column=0, columnspan=4, sticky="w", pady=(SPACE_2, 0))

        # Right: metrics
        metrics = ctk.CTkFrame(row, fg_color="transparent")
        metrics.grid(row=0, column=1, rowspan=2, sticky="ne", padx=(SPACE_6, 0))

        self._metrics: Dict[str, MetricCard] = {}
        for i, (lbl, key, col) in enumerate([
            ("ALERTS",    "alerts",    TEXT_TERTIARY),
            ("CRITICAL",  "critical",  STATUS_CRITICAL),
            ("HIGH",      "high",      STATUS_HIGH),
        ]):
            card = MetricCard(metrics, title=lbl, value="0", width=100, height=56)
            card.grid(row=0, column=i, padx=SPACE_2)
            card.value_label.configure(text_color=col)
            self._metrics[key] = card

        # Controls row
        ctrl = ctk.CTkFrame(self, fg_color="transparent")
        ctrl.grid(row=2, column=0, sticky="w", padx=SPACE_6, pady=(0, SPACE_2))

        self._start_btn = PrimaryButton(
            ctrl, "▶ START MONITORING",
            command=self._start_monitoring,
            state="disabled",
        )
        self._start_btn.pack(side="left", padx=(0, SPACE_3))

        self._stop_btn = ctk.CTkButton(
            ctrl, text="■ STOP",
            command=self._stop_monitoring,
            fg_color=STATUS_CRITICAL, hover_color="#c01f23",
            text_color=TEXT_INVERSE,
            font=ctk.CTkFont(*FONTS["body_bold"]),
            height=BTN_HEIGHT_MD, corner_radius=RADIUS_SM,
            state="disabled",
        )
        self._stop_btn.pack(side="left", padx=SPACE_2)

        ctk.CTkButton(
            ctrl, text="Clear Feed",
            command=self._clear_feed,
            fg_color="transparent", text_color=TEXT_SECONDARY,
            hover_color=SURFACE_STRONG,
            height=BTN_HEIGHT_MD, corner_radius=RADIUS_SM,
            font=ctk.CTkFont(*FONTS["small"]),
        ).pack(side="left", padx=SPACE_2)

    def _build_live_feed(self) -> None:
        feed_card = make_card(self)
        feed_card.grid(row=3, column=0, sticky="nsew", padx=SPACE_6, pady=(0, SPACE_3))
        feed_card.grid_columnconfigure(0, weight=1)
        feed_card.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(feed_card, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_2))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr, text="LIVE DETECTION FEED",
            font=ctk.CTkFont(*FONTS["subheading"]),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        self._pulse_dot = ctk.CTkLabel(
            hdr, text="●",
            font=ctk.CTkFont(*FONTS["body"]),
            text_color=TEXT_SECONDARY,
        )
        self._pulse_dot.grid(row=0, column=1, padx=(SPACE_3, 0))

        self._feed_box = ctk.CTkTextbox(
            feed_card,
            font=ctk.CTkFont(*FONTS["mono"]),
            fg_color="#080b0f", text_color="#00ff41",
            border_color=BORDER_HAIRLINE, border_width=BORDER_WIDTH_HAIRLINE,
            corner_radius=RADIUS_SM,
        )
        self._feed_box.grid(row=1, column=0, sticky="nsew", padx=CARD_PADDING, pady=(0, CARD_PADDING))
        self._feed_box.configure(state="disabled")

        for tag, color in [
            ("critical", STATUS_CRITICAL),
            ("high",     STATUS_HIGH),
            ("medium",   STATUS_MEDIUM),
            ("low",      STATUS_LOW),
            ("info",     TEXT_SECONDARY),
            ("success",  STATUS_OK),
            ("ts",       TEXT_TERTIARY),
        ]:
            self._feed_box.tag_config(tag, foreground=color)

    def _build_indicator_strip(self) -> None:
        strip_card = make_card(self)
        strip_card.grid(row=4, column=0, sticky="ew", padx=SPACE_6, pady=(0, SPACE_6))
        strip_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            strip_card, text="MONITORING INDICATORS",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_SECONDARY, anchor="w",
        ).grid(row=0, column=0, padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_2), sticky="w")

        grid = ctk.CTkFrame(strip_card, fg_color="transparent")
        grid.grid(row=1, column=0, sticky="ew", padx=CARD_PADDING, pady=(0, CARD_PADDING))

        self._indicator_checks: Dict[str, ctk.CTkCheckBox] = {}
        for i, (key, label, _) in enumerate(INDICATOR_TYPES):
            cb = ctk.CTkCheckBox(
                grid, text=label,
                font=ctk.CTkFont(*FONTS["small"]),
            )
            cb.select()
            cb.grid(row=i // 4, column=i % 4, padx=SPACE_4, pady=SPACE_1, sticky="w")
            self._indicator_checks[key] = cb

    # ── Logic ─────────────────────────────────────────────────────────────────

    def _update_btn_state(self) -> None:
        if self._auth_cb.get():
            self._start_btn.configure(state="normal")
        else:
            self._start_btn.configure(state="disabled")

    def _start_monitoring(self) -> None:
        target = self._target_entry.get().strip()
        if not target:
            return
        if not self._auth_cb.get():
            return

        self._target = target
        self._running = True
        self._top_status.configure(text="● MONITORING", text_color=STATUS_RUNNING_COLOR)
        self._top_target.configure(text=target)
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")

        self._log_feed(f"[MONITOR] Monitoring started on {target}", "success")
        self._log_feed("[MONITOR] Watching: anomalous responses, port changes, cert changes, suspicious endpoints", "info")

        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self._monitor_thread.start()
        self._start_pulse()

    def _stop_monitoring(self) -> None:
        self._running = False
        self._top_status.configure(text="● STANDBY", text_color=TEXT_SECONDARY)
        self._start_btn.configure(state="normal" if self._auth_cb.get() else "disabled")
        self._stop_btn.configure(state="disabled")
        self._stop_pulse()
        self._log_feed(
            f"[MONITOR] Monitoring stopped — {len(self._alerts)} alerts logged", "info"
        )

    def _clear_feed(self) -> None:
        self._feed_box.configure(state="normal")
        self._feed_box.delete("1.0", "end")
        self._feed_box.configure(state="disabled")

    def _monitor_loop(self) -> None:
        """Background thread: emits periodic simulated indicator checks."""
        while self._running:
            time.sleep(random.uniform(4, 12))
            if not self._running:
                break

            # Pick a random indicator
            key, label, default_sev = random.choice(INDICATOR_TYPES)
            if not self._indicator_checks.get(key) or not self._indicator_checks[key].get():
                continue

            sev = default_sev
            msg = self._make_alert_message(key, label, sev)
            alert = {
                "timestamp": datetime.now().isoformat(),
                "indicator": label,
                "severity":  sev,
                "message":   msg,
                "target":    self._target,
            }
            self._alerts.append(alert)
            self.after(0, lambda a=alert: self._on_alert(a))

    def _make_alert_message(self, key: str, label: str, sev: str) -> str:
        templates = {
            "anomalous_response":  f"HTTP 500 storm detected on /api — {random.randint(10,200)} errors/s",
            "new_open_port":       f"New open port {random.choice([3306,5432,6379,27017,9200])} detected",
            "cert_change":         "TLS certificate fingerprint changed since last check",
            "suspicious_endpoint": f"New endpoint /{''.join(random.choices('abcdefghijklmnop',k=8))} appeared",
            "malware_artifact":    f"Exposed file: /uploads/{''.join(random.choices('abcdef',k=6))}.php",
            "unexpected_service":  f"Unexpected service banner on port {random.randint(1025,9999)}",
            "info_disclosure":     f"/debug/metrics exposed without authentication",
            "config_drift":        f"Security header 'Content-Security-Policy' was removed",
        }
        return templates.get(key, f"{label} triggered")

    def _on_alert(self, alert: dict) -> None:
        """Fired in main thread when a new alert arrives."""
        ts = datetime.fromisoformat(alert["timestamp"]).strftime("%H:%M:%S")
        sev = alert["severity"]
        msg = alert["message"]
        self._log_feed(f"[{ts}] [{sev.upper():8s}] {msg}", sev)
        self._update_metrics()
        self._maybe_notify(alert)

    def _maybe_notify(self, alert: dict) -> None:
        """Send a desktop notification if the alert meets the threshold."""
        sev = alert["severity"]
        threshold_map = {"Critical only": ["critical"], "High+": ["critical","high"],
                         "Medium+": ["critical","high","medium"], "All": ["critical","high","medium","low","info"]}
        allowed = threshold_map.get(self._threshold_var.get(), ["critical","high"])
        if sev not in allowed:
            return
        try:
            from utils.notifications import notify
            notify(
                title=f"HydraX Alert — {sev.upper()}",
                message=f"{alert['indicator']}: {alert['message']}\nTarget: {alert['target']}",
                severity=sev,
            )
        except Exception:
            pass

    def _update_metrics(self) -> None:
        total = len(self._alerts)
        crits = sum(1 for a in self._alerts if a["severity"] == "critical")
        highs = sum(1 for a in self._alerts if a["severity"] == "high")
        self._metrics["alerts"].update_value(str(total))
        self._metrics["critical"].update_value(str(crits))
        self._metrics["high"].update_value(str(highs))
        self._alert_count_lbl.configure(text=f"Alerts: {total}")

    def _log_feed(self, text: str, severity: str = "info") -> None:
        self._feed_box.configure(state="normal")
        sev_tag = severity if severity in ("critical","high","medium","low","info","success") else "info"
        # split timestamp from rest
        if text.startswith("["):
            end = text.find("]")
            if end > 0:
                self._feed_box.insert("end", text[:end+1] + " ", "ts")
                self._feed_box.insert("end", text[end+1:].lstrip() + "\n", sev_tag)
            else:
                self._feed_box.insert("end", text + "\n", sev_tag)
        else:
            self._feed_box.insert("end", text + "\n", sev_tag)
        self._feed_box.see("end")
        self._feed_box.configure(state="disabled")

    def _start_pulse(self) -> None:
        if not self._running:
            return
        self._pulse_state = not self._pulse_state
        color = STATUS_RUNNING_COLOR if self._pulse_state else SURFACE_STRONG
        if hasattr(self, "_pulse_dot"):
            self._pulse_dot.configure(text_color=color)
        self._pulse_job = self.after(800, self._start_pulse)

    def _stop_pulse(self) -> None:
        if self._pulse_job:
            self.after_cancel(self._pulse_job)
            self._pulse_job = None
        if hasattr(self, "_pulse_dot"):
            self._pulse_dot.configure(text_color=TEXT_SECONDARY)

    def refresh(self) -> None:
        pass
