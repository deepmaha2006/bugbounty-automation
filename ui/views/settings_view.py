"""
Settings view: scan engine parameters persisted to config/settings.json,
plus an About panel — HydraX Hashcats Design System.
"""

import json
from pathlib import Path

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

        save_btn = PrimaryButton(
            engine,
            "SAVE SETTINGS",
            command=self._save,
            height=BTN_HEIGHT_MD,
            width=BTN_WIDTH_MD
        )
        save_btn.grid(row=len(fields) + 2, column=0, columnspan=2, sticky="w",
                      padx=CARD_PADDING, pady=(SPACE_3, CARD_PADDING))

        # About card
        info = make_card(body)
        info.grid(row=1, column=0, sticky="ew", padx=0, pady=0)
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
        pass