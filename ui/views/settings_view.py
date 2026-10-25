"""
Settings view: scan engine parameters persisted to config/settings.json,
plus an About panel — HydraX Hashcats Design System.
"""

import json
from pathlib import Path
from typing import Dict

import customtkinter as ctk

from config.settings import (APP_NAME, VERSION, PROJECT_ROOT, REPORTS_DIR,
                             DEFAULT_TIMEOUT, DEFAULT_REQUEST_DELAY,
                             DEFAULT_THREADS, VERIFY_SSL)
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
    RADIUS_NONE, RADIUS_SM,
    # Motion
    MOTION_INSTANT, MOTION_FAST,
    # Component tokens
    BTN_HEIGHT_MD, BTN_HEIGHT_LG,
    BTN_WIDTH_MD, BTN_WIDTH_LG, BTN_WIDTH_XL,
    INPUT_HEIGHT, CARD_PADDING,
    BORDER_WIDTH_HAIRLINE, BORDER_WIDTH_ACCENT,
)
from ui.widgets import (SectionHeader, PrimaryButton, GhostButton, make_card)
from ui.tool_readiness_panel import ToolReadinessPanel
from ui.signature_widget import SignatureWidget


SETTINGS_FILE = PROJECT_ROOT / "config" / "settings.json"

DEFAULTS = {
    "timeout": DEFAULT_TIMEOUT,
    "delay": DEFAULT_REQUEST_DELAY,
    "threads": DEFAULT_THREADS,
    "verify_ssl": VERIFY_SSL,
    "max_findings": 50,
}


def load_settings() -> dict:
    try:
        if SETTINGS_FILE.exists():
            data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            merged = dict(DEFAULTS)
            merged.update(data)
            return merged
    except (OSError, json.JSONDecodeError):
        pass
    return dict(DEFAULTS)


def save_settings(data: dict) -> None:
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


class SettingsView(ctk.CTkFrame):
    """Configuration page for scan engine behaviour — Hashcats style."""

    def __init__(self, master, app):
        super().__init__(master, fg_color=SURFACE_BASE, corner_radius=RADIUS_NONE)
        self.app = app
        self.settings = load_settings()
        self.build()

    def build(self):
        self.grid_columnconfigure(0, weight=1)

        # Top bar
        top = ctk.CTkFrame(self, fg_color=SURFACE_MUTED, corner_radius=RADIUS_NONE,
                           border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE,
                           height=76)
        top.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        top.grid_propagate(False)
        top.grid_columnconfigure(0, weight=1)

        SectionHeader(
            top,
            "SETTINGS",
            subtitle="Configure scan engine behaviour and application options",
            action_text="OPEN FOLDER",
            action_command=self.app.open_reports_folder
        ).grid(row=0, column=0, sticky="ew", padx=SPACE_6, pady=SPACE_4)

        # Scrollable body
        body = ctk.CTkScrollableFrame(
            self,
            fg_color=SURFACE_BASE,
            corner_radius=RADIUS_NONE,
            scrollbar_button_color=SURFACE_STRONG,
            scrollbar_button_hover_color=SURFACE_MUTED
        )
        body.grid(row=1, column=0, sticky="nsew", padx=SPACE_6, pady=(SPACE_4, SPACE_6))
        body.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Scan Engine card
        engine = make_card(body)
        engine.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, SPACE_4))
        engine.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            engine,
            text="⚙  SCAN ENGINE",
            font=ctk.CTkFont(*FONTS["subheading"]),
            text_color=TEXT_PRIMARY,
            anchor="w"
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_3))

        self.timeout_var = ctk.StringVar(value=str(self.settings.get("timeout", 15)))
        self.delay_var = ctk.StringVar(value=str(self.settings.get("delay", 0.2)))
        self.threads_var = ctk.StringVar(value=str(self.settings.get("threads", 5)))
        self.findings_var = ctk.StringVar(value=str(self.settings.get("max_findings", 50)))
        self.ssl_var = ctk.BooleanVar(value=bool(self.settings.get("verify_ssl", False)))

        fields = [
            ("Request timeout (seconds)", self.timeout_var),
            ("Delay between requests", self.delay_var),
            ("Concurrent threads", self.threads_var),
            ("Max findings per scanner", self.findings_var),
        ]
        for i, (label, var) in enumerate(fields, start=1):
            ctk.CTkLabel(
                engine,
                text=label,
                font=ctk.CTkFont(*FONTS["body"]),
                text_color=TEXT_PRIMARY,
                anchor="w"
            ).grid(row=i, column=0, sticky="w", padx=CARD_PADDING, pady=SPACE_3)

            entry = ctk.CTkEntry(
                engine,
                textvariable=var,
                font=ctk.CTkFont(*FONTS["body"]),
                width=BTN_WIDTH_MD,
                height=INPUT_HEIGHT,
                corner_radius=RADIUS_SM,
                border_width=BORDER_WIDTH_HAIRLINE,
                border_color=BORDER_HAIRLINE,
                fg_color=SURFACE_BASE,
                text_color=TEXT_PRIMARY,
                placeholder_text_color=TEXT_SECONDARY
            )
            entry.grid(row=i, column=1, sticky="w", padx=(0, CARD_PADDING), pady=SPACE_3)
            entry.bind("<FocusIn>", lambda e, w=entry: w.configure(border_color=BORDER_ACCENT, border_width=BORDER_WIDTH_ACCENT))
            entry.bind("<FocusOut>", lambda e, w=entry: w.configure(border_color=BORDER_HAIRLINE, border_width=BORDER_WIDTH_HAIRLINE))

        ctk.CTkLabel(
            engine,
            text="Verify SSL certificates",
            font=ctk.CTkFont(*FONTS["body"]),
            text_color=TEXT_PRIMARY,
            anchor="w"
        ).grid(row=len(fields) + 1, column=0, sticky="w", padx=CARD_PADDING, pady=SPACE_3)

        ctk.CTkSwitch(
            engine,
            text="",
            variable=self.ssl_var,
            button_color=SURFACE_RAISED,
            button_hover_color=SURFACE_STRONG,
            progress_color=SURFACE_RAISED,
            fg_color=SURFACE_STRONG
        ).grid(row=len(fields) + 1, column=1, sticky="w", padx=(0, CARD_PADDING), pady=SPACE_3)

        # Reduce Motion toggle
        ctk.CTkLabel(
            engine,
            text="Reduce motion (accessibility)",
            font=ctk.CTkFont(*FONTS["body"]),
            text_color=TEXT_PRIMARY,
            anchor="w"
        ).grid(row=len(fields) + 2, column=0, sticky="w", padx=CARD_PADDING, pady=SPACE_3)

        import ui.motion as _motion
        self._reduce_motion_var = ctk.BooleanVar(value=_motion.REDUCE_MOTION)

        def _on_reduce_motion_toggle():
            import ui.motion as m
            m.REDUCE_MOTION = bool(self._reduce_motion_var.get())

        ctk.CTkSwitch(
            engine,
            text="",
            variable=self._reduce_motion_var,
            command=_on_reduce_motion_toggle,
            button_color=SURFACE_RAISED,
            button_hover_color=SURFACE_STRONG,
            progress_color=SURFACE_RAISED,
            fg_color=SURFACE_STRONG
        ).grid(row=len(fields) + 2, column=1, sticky="w", padx=(0, CARD_PADDING), pady=SPACE_3)

        save_btn = PrimaryButton(
            engine,
            "SAVE SETTINGS",
            command=self._save,
            height=BTN_HEIGHT_MD,
            width=BTN_WIDTH_MD
        )
        save_btn.grid(row=len(fields) + 3, column=0, columnspan=2, sticky="w",
                      padx=CARD_PADDING, pady=(SPACE_3, CARD_PADDING))

        # Tool Readiness card
        self._tool_panel = ToolReadinessPanel(body)
        self._tool_panel.grid(row=1, column=0, sticky="ew", padx=0, pady=(SPACE_4, 0))

        # Notifications card
        self._build_notifications_card(body, row=2)

        # About card
        info = make_card(body)
        info.grid(row=3, column=0, sticky="ew", padx=0, pady=(SPACE_4, 0))
        info.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            info,
            text="ℹ  ABOUT",
            font=ctk.CTkFont(*FONTS["subheading"]),
            text_color=TEXT_PRIMARY,
            anchor="w"
        ).grid(row=0, column=0, sticky="w", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_3))

        ctk.CTkLabel(
            info,
            text=(
                f"{APP_NAME} v{VERSION}\n"
                "Professional bug bounty automation suite.\n"
                "Authorized security testing only — always obtain written "
                "permission before scanning a target you do not own."
            ),
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            anchor="w",
            justify="left",
            wraplength=640
        ).grid(row=1, column=0, sticky="w", padx=CARD_PADDING, pady=(0, SPACE_3))

        ctk.CTkLabel(
            info,
            text=f"Reports directory: {REPORTS_DIR}",
            font=ctk.CTkFont(*FONTS["mono"]),
            text_color=TEXT_TERTIARY,
            anchor="w"
        ).grid(row=2, column=0, sticky="w", padx=CARD_PADDING, pady=(0, CARD_PADDING))

        # ── Signature card — immutable authorship seal ─────────────────────
        sig_card = make_card(body)
        sig_card.grid(row=4, column=0, sticky="ew", padx=0, pady=(SPACE_4, SPACE_6))
        sig_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            sig_card,
            text="CREATOR",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_SECONDARY,
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_2))

        ctk.CTkLabel(
            sig_card,
            text=(
                "HydraX is designed, architected, and developed by its creator.\n"
                "This signature is an immutable platform seal — it cannot be altered\n"
                "or removed from any deployed instance of this software."
            ),
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            anchor="w",
            justify="left",
            wraplength=580,
        ).grid(row=1, column=0, sticky="w", padx=CARD_PADDING, pady=(0, SPACE_3))

        self._signature = SignatureWidget(sig_card)
        self._signature.grid(
            row=2, column=0, sticky="ew",
            padx=CARD_PADDING, pady=(0, CARD_PADDING)
        )

        # Replay button — triggers the animation again without modifying anything
        ctk.CTkButton(
            sig_card,
            text="↺  Replay Signature",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            fg_color="transparent",
            hover_color=SURFACE_STRONG,
            corner_radius=RADIUS_SM,
            height=24,
            anchor="w",
            command=self._signature.replay,
        ).grid(row=3, column=0, sticky="w", padx=CARD_PADDING, pady=(0, CARD_PADDING))

    def _build_notifications_card(self, parent, row: int) -> None:
        from utils.notifications import _load_config as _load_notif, save_config as _save_notif
        cfg = _load_notif()

        card = make_card(parent)
        card.grid(row=row, column=0, sticky="ew", padx=0, pady=(SPACE_4, 0))
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            card, text="🔔  NOTIFICATIONS",
            font=ctk.CTkFont(*FONTS["subheading"]),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_3))

        ctk.CTkLabel(
            card, text="Desktop notifications, email alerts, and webhook messages when vulnerabilities are found.",
            font=ctk.CTkFont(*FONTS["small"]), text_color=TEXT_SECONDARY, anchor="w",
            wraplength=600, justify="left",
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=CARD_PADDING, pady=(0, SPACE_3))

        # Enable toggle
        self._notif_enabled = ctk.BooleanVar(value=cfg.get("enabled", True))
        ctk.CTkLabel(card, text="Enable notifications", font=ctk.CTkFont(*FONTS["body"]),
                     text_color=TEXT_PRIMARY, anchor="w").grid(
            row=2, column=0, sticky="w", padx=CARD_PADDING, pady=SPACE_2)
        ctk.CTkSwitch(card, text="", variable=self._notif_enabled,
                      button_color=SURFACE_RAISED, progress_color=STATUS_OK,
                      fg_color=SURFACE_STRONG).grid(
            row=2, column=1, sticky="w", padx=(0, CARD_PADDING), pady=SPACE_2)

        # Alert threshold
        ctk.CTkLabel(card, text="Alert threshold", font=ctk.CTkFont(*FONTS["body"]),
                     text_color=TEXT_PRIMARY, anchor="w").grid(
            row=3, column=0, sticky="w", padx=CARD_PADDING, pady=SPACE_2)
        self._notif_threshold = ctk.StringVar(value=cfg.get("threshold", "high"))
        ctk.CTkOptionMenu(card, values=["critical", "high", "medium", "all"],
                          variable=self._notif_threshold,
                          height=INPUT_HEIGHT, width=120,
                          fg_color=SURFACE_MUTED, button_color=SURFACE_RAISED,
                          text_color=TEXT_PRIMARY, font=ctk.CTkFont(*FONTS["small"])).grid(
            row=3, column=1, sticky="w", padx=(0, CARD_PADDING), pady=SPACE_2)

        # Quiet hours
        ctk.CTkLabel(card, text="Quiet hours (start / end)", font=ctk.CTkFont(*FONTS["body"]),
                     text_color=TEXT_PRIMARY, anchor="w").grid(
            row=4, column=0, sticky="w", padx=CARD_PADDING, pady=SPACE_2)
        qrow = ctk.CTkFrame(card, fg_color="transparent")
        qrow.grid(row=4, column=1, sticky="w", padx=(0, CARD_PADDING), pady=SPACE_2)
        self._notif_qstart = ctk.CTkEntry(qrow, placeholder_text="22:00", width=70, height=INPUT_HEIGHT)
        self._notif_qstart.insert(0, cfg.get("quiet_hours_start", ""))
        self._notif_qstart.pack(side="left", padx=(0, SPACE_2))
        self._notif_qend = ctk.CTkEntry(qrow, placeholder_text="08:00", width=70, height=INPUT_HEIGHT)
        self._notif_qend.insert(0, cfg.get("quiet_hours_end", ""))
        self._notif_qend.pack(side="left")

        # Email section
        ctk.CTkFrame(card, height=1, fg_color=BORDER_HAIRLINE, corner_radius=0).grid(
            row=5, column=0, columnspan=2, sticky="ew", padx=CARD_PADDING, pady=SPACE_3)
        ctk.CTkLabel(card, text="EMAIL ALERTS", font=ctk.CTkFont(*FONTS["small_bold"]),
                     text_color=TEXT_TERTIARY, anchor="w").grid(
            row=6, column=0, columnspan=2, sticky="w", padx=CARD_PADDING, pady=(0, SPACE_2))

        self._notif_email_enabled = ctk.BooleanVar(value=cfg.get("email_enabled", False))
        ctk.CTkCheckBox(card, text="Send email on alert", variable=self._notif_email_enabled,
                        font=ctk.CTkFont(*FONTS["small"])).grid(
            row=7, column=0, columnspan=2, sticky="w", padx=CARD_PADDING, pady=SPACE_1)

        email_fields = [
            ("SMTP Host",  "smtp_host",     cfg.get("smtp_host", ""),     "mail.example.com"),
            ("SMTP Port",  "smtp_port",     str(cfg.get("smtp_port", 587)), "587"),
            ("SMTP User",  "smtp_user",     cfg.get("smtp_user", ""),     "user@example.com"),
            ("SMTP Pass",  "smtp_password", "",                            "••••••••"),
            ("Send to",    "email_to",      cfg.get("email_to", ""),      "security@example.com"),
        ]
        self._notif_email_vars: Dict[str, ctk.CTkEntry] = {}
        for j, (lbl, key, val, ph) in enumerate(email_fields):
            ctk.CTkLabel(card, text=lbl, font=ctk.CTkFont(*FONTS["small"]),
                         text_color=TEXT_SECONDARY, anchor="w").grid(
                row=8 + j, column=0, sticky="w", padx=(CARD_PADDING * 2, 0), pady=SPACE_1)
            show = "*" if key == "smtp_password" else ""
            e = ctk.CTkEntry(card, placeholder_text=ph, height=INPUT_HEIGHT, show=show)
            if val:
                e.insert(0, val)
            e.grid(row=8 + j, column=1, sticky="ew", padx=(0, CARD_PADDING), pady=SPACE_1)
            self._notif_email_vars[key] = e

        # Webhook section
        ctk.CTkFrame(card, height=1, fg_color=BORDER_HAIRLINE, corner_radius=0).grid(
            row=13, column=0, columnspan=2, sticky="ew", padx=CARD_PADDING, pady=SPACE_3)
        ctk.CTkLabel(card, text="WEBHOOK (Slack / Telegram / generic POST)", font=ctk.CTkFont(*FONTS["small_bold"]),
                     text_color=TEXT_TERTIARY, anchor="w").grid(
            row=14, column=0, columnspan=2, sticky="w", padx=CARD_PADDING, pady=(0, SPACE_2))
        self._notif_webhook_enabled = ctk.BooleanVar(value=cfg.get("webhook_enabled", False))
        ctk.CTkCheckBox(card, text="Send webhook on alert", variable=self._notif_webhook_enabled,
                        font=ctk.CTkFont(*FONTS["small"])).grid(
            row=15, column=0, columnspan=2, sticky="w", padx=CARD_PADDING, pady=SPACE_1)
        ctk.CTkLabel(card, text="Webhook URL", font=ctk.CTkFont(*FONTS["small"]),
                     text_color=TEXT_SECONDARY, anchor="w").grid(
            row=16, column=0, sticky="w", padx=(CARD_PADDING * 2, 0), pady=SPACE_1)
        self._notif_webhook_url = ctk.CTkEntry(card, placeholder_text="https://hooks.slack.com/…",
                                               height=INPUT_HEIGHT)
        if cfg.get("webhook_url"):
            self._notif_webhook_url.insert(0, cfg["webhook_url"])
        self._notif_webhook_url.grid(row=16, column=1, sticky="ew",
                                     padx=(0, CARD_PADDING), pady=SPACE_1)

        # Save
        GhostButton(card, "SAVE NOTIFICATIONS", command=self._save_notifications,
                    height=BTN_HEIGHT_MD).grid(
            row=17, column=0, columnspan=2, sticky="w",
            padx=CARD_PADDING, pady=(SPACE_3, CARD_PADDING))

    def _save_notifications(self) -> None:
        from utils.notifications import save_config as _save_notif
        cfg = {
            "enabled":           bool(self._notif_enabled.get()),
            "threshold":         self._notif_threshold.get(),
            "quiet_hours_start": self._notif_qstart.get().strip(),
            "quiet_hours_end":   self._notif_qend.get().strip(),
            "email_enabled":     bool(self._notif_email_enabled.get()),
            "smtp_host":         self._notif_email_vars["smtp_host"].get().strip(),
            "smtp_port":         int(self._notif_email_vars["smtp_port"].get().strip() or "587"),
            "smtp_user":         self._notif_email_vars["smtp_user"].get().strip(),
            "smtp_password":     self._notif_email_vars["smtp_password"].get(),
            "email_to":          self._notif_email_vars["email_to"].get().strip(),
            "webhook_enabled":   bool(self._notif_webhook_enabled.get()),
            "webhook_url":       self._notif_webhook_url.get().strip(),
        }
        _save_notif(cfg)
        self.app.show_message("Notifications saved", "Notification settings updated.")

    def _save(self):
        try:
            self.settings.update({
                "timeout": max(1, float(self.timeout_var.get())),
                "delay": max(0.0, float(self.delay_var.get())),
                "threads": max(1, int(self.threads_var.get())),
                "max_findings": max(5, int(self.findings_var.get())),
                "verify_ssl": bool(self.ssl_var.get()),
            })
        except ValueError:
            self.app.show_message("Invalid value",
                                  "Please enter valid numbers for all fields.")
            return
        save_settings(self.settings)
        self.app.apply_settings(self.settings)
        self.app.show_message("Settings saved",
                              "Scan engine settings updated successfully.")

    def refresh(self):
        # Kick off tool-readiness preflight whenever the Settings page is opened.
        self._tool_panel.run_preflight()
        # Replay the signature animation each time Settings is visited
        if hasattr(self, "_signature"):
            self._signature.replay()