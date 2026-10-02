"""
Reports view: gallery of saved HTML/JSON reports with open/delete actions — HydraX Hashcats Design System.
"""

import customtkinter as ctk
from pathlib import Path

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
    RADIUS_NONE, RADIUS_MD,
    # Motion
    MOTION_INSTANT, MOTION_FAST,
    # Component tokens
    BTN_HEIGHT_SM, BTN_HEIGHT_MD, BTN_HEIGHT_LG,
    BTN_WIDTH_MD, BTN_WIDTH_LG, BTN_WIDTH_XL,
    CARD_PADDING,
    BORDER_WIDTH_HAIRLINE, BORDER_WIDTH_ACCENT,
)
from ui.widgets import (SectionHeader, make_card, PrimaryButton, GhostButton,
                        EmptyState, Badge, Tag)


class ReportRow(ctk.CTkFrame):
    """One saved report file: name, size, age, actions — Hashcats style."""

    def __init__(self, master, path: Path, store, on_delete):
        super().__init__(
            master,
            fg_color=SURFACE_MUTED,
            corner_radius=RADIUS_MD,
            border_width=BORDER_WIDTH_HAIRLINE,
            border_color=BORDER_HAIRLINE
        )
        self.path = path
        self.store = store
        self.on_delete = on_delete
        self.grid_columnconfigure(1, weight=1)

        kind = "HTML" if path.suffix == ".html" else "JSON"
        color = SEVERITY_COLORS.get("Critical") if kind == "HTML" else STATUS_MEDIUM
        Tag(self, kind, color=color).grid(row=0, column=0, rowspan=2,
                                          padx=(CARD_PADDING, SPACE_3), pady=CARD_PADDING)

        ctk.CTkLabel(
            self,
            text=path.name,
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_PRIMARY,
            anchor="w"
        ).grid(row=0, column=1, sticky="w", pady=(CARD_PADDING, 0))

        ctk.CTkLabel(
            self,
            text=f"{store.format_size(path)}   ▣   {self._age()}",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            anchor="w"
        ).grid(row=1, column=1, sticky="w", pady=(SPACE_2, CARD_PADDING))

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=0, column=2, rowspan=2, padx=(0, CARD_PADDING))
        GhostButton(actions, "OPEN", height=BTN_HEIGHT_SM, width=BTN_WIDTH_MD,
                    command=lambda: store.open_report(path)).pack(side="left", padx=(0, SPACE_2))
        GhostButton(actions, "DELETE", height=BTN_HEIGHT_SM, width=BTN_WIDTH_MD,
                    command=self._confirm_delete).pack(side="left")

    def _age(self) -> str:
        import datetime
        mtime = datetime.datetime.fromtimestamp(self.path.stat().st_mtime)
        delta = datetime.datetime.now() - mtime
        if delta.days > 0:
            return f"{delta.days}d ago"
        if delta.seconds // 3600 > 0:
            return f"{delta.seconds // 3600}h ago"
        return f"{max(1, delta.seconds // 60)}m ago"

    def _confirm_delete(self):
        self.on_delete(self.path)


class ReportsView(ctk.CTkFrame):
    """Gallery of previously saved reports — Hashcats style."""

    def __init__(self, master, app):
        super().__init__(master, fg_color=SURFACE_BASE, corner_radius=RADIUS_NONE)
        self.app = app
        self.build()

    def build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Top bar
        top = ctk.CTkFrame(self, fg_color=SURFACE_MUTED, corner_radius=RADIUS_NONE,
                           border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE,
                           height=76)
        top.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        top.grid_propagate(False)
        top.grid_columnconfigure(0, weight=1)

        SectionHeader(
            top,
            "REPORTS",
            subtitle="HTML & JSON reports generated from your scans",
            action_text="OPEN FOLDER",
            action_command=self.app.open_reports_folder
        ).grid(row=0, column=0, sticky="ew", padx=SPACE_6, pady=SPACE_4)

        # Body scrollable
        self.body = ctk.CTkScrollableFrame(
            self,
            fg_color=SURFACE_BASE,
            corner_radius=RADIUS_NONE,
            scrollbar_button_color=SURFACE_STRONG,
            scrollbar_button_hover_color=SURFACE_MUTED
        )
        self.body.grid(row=1, column=0, sticky="nsew", padx=SPACE_6, pady=(SPACE_4, SPACE_6))
        self.body.grid_columnconfigure(0, weight=1)

    def refresh(self):
        for child in self.body.winfo_children():
            child.destroy()

        reports = self.app.report_store.list_reports(limit=100)
        if not reports:
            EmptyState(
                self.body,
                "▣",
                "NO REPORTS YET",
                "Run a scan, then use 'EXPORT REPORT' to generate one."
            ).grid(row=0, column=0, pady=SPACE_8)
            return

        for i, path in enumerate(reports):
            row = ReportRow(self.body, path, self.app.report_store,
                            on_delete=self.app.delete_report)
            row.grid(row=i, column=0, sticky="ew", padx=0, pady=(0, SPACE_3))