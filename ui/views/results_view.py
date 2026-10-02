"""
Results view: per-scanner breakdown of findings with severity badges,
evidence and remediation, plus report export actions — HydraX Hashcats Design System.
"""

import customtkinter as ctk

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
                        SeverityBadge, EmptyState, Badge)


class FindingRow(ctk.CTkFrame):
    """One finding: severity badge, type, description, evidence, fix — Hashcats style."""

    def __init__(self, master, finding: dict):
        super().__init__(
            master,
            fg_color=SURFACE_MUTED,
            corner_radius=RADIUS_MD,
            border_width=BORDER_WIDTH_HAIRLINE,
            border_color=BORDER_HAIRLINE
        )
        self.grid_columnconfigure(1, weight=1)

        sev = finding.get("severity", "Info")
        color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["Info"])

        badge = SeverityBadge(self, sev)
        badge.grid(row=0, column=0, rowspan=2, padx=(CARD_PADDING, SPACE_3), pady=CARD_PADDING)

        type_lbl = ctk.CTkLabel(
            self,
            text=finding.get("type", "Unknown"),
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=color,
            anchor="w"
        )
        type_lbl.grid(row=0, column=1, sticky="w", pady=(CARD_PADDING, 0))

        desc_lbl = ctk.CTkLabel(
            self,
            text=finding.get("description", ""),
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_PRIMARY,
            anchor="w",
            justify="left",
            wraplength=700
        )
        desc_lbl.grid(row=1, column=1, sticky="w", padx=(0, CARD_PADDING), pady=(SPACE_2, SPACE_2))

        if finding.get("url"):
            url_lbl = ctk.CTkLabel(
                self,
                text=finding["url"],
                font=ctk.CTkFont(*FONTS["mono"]),
                text_color=TEXT_TERTIARY,  # Lime for URLs
                anchor="w",
                justify="left",
                wraplength=700
            )
            url_lbl.grid(row=2, column=1, sticky="w", padx=(0, CARD_PADDING))

        if finding.get("evidence"):
            ev_card = ctk.CTkFrame(self, fg_color=SURFACE_BASE, corner_radius=RADIUS_MD,
                                   border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE)
            ev_card.grid(row=3, column=1, sticky="ew", padx=(0, CARD_PADDING), pady=(SPACE_2, 0))
            ev_card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(
                ev_card,
                text=finding["evidence"],
                font=ctk.CTkFont(*FONTS["mono"]),
                text_color=TEXT_SECONDARY,
                anchor="w",
                justify="left",
                wraplength=680
            ).grid(row=0, column=0, sticky="w", padx=SPACE_3, pady=SPACE_3)

        if finding.get("remediation"):
            fix_lbl = ctk.CTkLabel(
                self,
                text="FIX: " + finding["remediation"],
                font=ctk.CTkFont(*FONTS["small"]),
                text_color=STATUS_MEDIUM,  # Blue for remediation
                anchor="w",
                justify="left",
                wraplength=700
            )
            fix_lbl.grid(row=4, column=1, sticky="w", padx=(0, CARD_PADDING), pady=(SPACE_3, CARD_PADDING))


class ScannerSection(ctk.CTkFrame):
    """One scanner's results: header with counts + finding rows — Hashcats style."""

    def __init__(self, master, key: str, result: dict):
        super().__init__(master, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)

        header = make_card(self)
        header.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header.grid_columnconfigure(0, weight=1)

        name = result.get("scanner", key.replace("_", " ").title())
        total = result.get("total_findings", 0)
        status = result.get("status", "done")

        ctk.CTkLabel(
            header,
            text=name,
            font=ctk.CTkFont(*FONTS["subheading"]),
            text_color=TEXT_PRIMARY,
            anchor="w"
        ).grid(row=0, column=0, sticky="w", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_2))

        stat_row = ctk.CTkFrame(header, fg_color="transparent")
        stat_row.grid(row=1, column=0, sticky="w", padx=CARD_PADDING, pady=(0, CARD_PADDING))
        for sev in ["Critical", "High", "Medium", "Low"]:
            n = sum(1 for f in result.get("vulnerabilities", [])
                    if f.get("severity") == sev)
            if n:
                Badge(stat_row, f"{sev}: {n}",
                      SEVERITY_COLORS.get(sev)).pack(side="left", padx=(0, SPACE_2))

        if status == "error":
            ctk.CTkLabel(
                header,
                text="▣ ERROR: " + result.get("error", "scanner error"),
                font=ctk.CTkFont(*FONTS["small"]),
                text_color=STATUS_CRITICAL,
                anchor="w"
            ).grid(row=2, column=0, sticky="w", padx=CARD_PADDING, pady=(0, CARD_PADDING))
        elif not result.get("vulnerabilities"):
            ctk.CTkLabel(
                header,
                text="▣ No vulnerabilities detected",
                font=ctk.CTkFont(*FONTS["small"]),
                text_color=STATUS_OK,
                anchor="w"
            ).grid(row=2, column=0, sticky="w", padx=CARD_PADDING, pady=(0, CARD_PADDING))

        for i, finding in enumerate(result.get("vulnerabilities", [])):
            FindingRow(self, finding).grid(row=i + 1, column=0, sticky="ew", pady=(SPACE_2, 0))


class ResultsView(ctk.CTkFrame):
    """Full report page for the most recent scan — Hashcats style."""

    def __init__(self, master, app):
        super().__init__(master, fg_color=SURFACE_BASE, corner_radius=RADIUS_NONE)
        self.app = app
        self.build()

    # ------------------------------------------------------------------
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
            "SCAN RESULTS",
            subtitle="Detailed findings grouped by scanner module",
        ).grid(row=0, column=0, sticky="ew", padx=SPACE_6, pady=SPACE_4)

        # All three export actions in one aligned group on the right.
        self.actions = ctk.CTkFrame(top, fg_color="transparent")
        self.actions.grid(row=0, column=1, sticky="e", padx=SPACE_6)
        GhostButton(self.actions, "DOWNLOAD HTML", command=self.save_html,
                    width=BTN_WIDTH_MD, height=BTN_HEIGHT_SM).pack(side="left", padx=(0, SPACE_3))
        GhostButton(self.actions, "DOWNLOAD JSON", command=self.save_json,
                    width=BTN_WIDTH_MD, height=BTN_HEIGHT_SM).pack(side="left", padx=(0, SPACE_3))
        GhostButton(self.actions, "OPEN REPORTS", command=self.app.open_reports_folder,
                    width=BTN_WIDTH_MD, height=BTN_HEIGHT_SM).pack(side="left")

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

    # ------------------------------------------------------------------
    def refresh(self):
        """Rebuild from app.last_report_data."""
        for child in self.body.winfo_children():
            child.destroy()

        report = self.app.last_report_data
        if not report:
            EmptyState(
                self.body,
                "▣",
                "NO RESULTS YET",
                "Run a scan to see the detailed findings here."
            ).grid(row=0, column=0, pady=SPACE_8)
            return

        # --- Summary strip ---
        summary = make_card(self.body)
        summary.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, SPACE_4))
        summary.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1, uniform="sum")

        score = report.get("security_score", 0)
        counts = report.get("severity_counts", {})

        # Security score card
        score_card = ctk.CTkFrame(summary, fg_color="transparent")
        score_card.grid(row=0, column=0, rowspan=2, sticky="ew", padx=CARD_PADDING)
        ctk.CTkLabel(
            score_card,
            text=str(score),
            font=ctk.CTkFont(*FONTS["score"]),
            text_color=TEXT_TERTIARY  # Lime
        ).pack()
        ctk.CTkLabel(
            score_card,
            text="SECURITY SCORE",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY
        ).pack()

        # Severity counts
        sev_titles = [
            ("CRITICAL", counts.get("Critical", 0), STATUS_CRITICAL),
            ("HIGH", counts.get("High", 0), STATUS_HIGH),
            ("MEDIUM", counts.get("Medium", 0), STATUS_MEDIUM),
            ("LOW", counts.get("Low", 0), STATUS_LOW),
            ("INFO", counts.get("Info", 0), STATUS_LOW),
        ]
        for i, (sev, n, color) in enumerate(sev_titles, start=1):
            cell = ctk.CTkFrame(summary, fg_color="transparent")
            cell.grid(row=0, column=i, rowspan=2, sticky="ew", padx=CARD_PADDING)
            ctk.CTkLabel(
                cell,
                text=str(n),
                font=ctk.CTkFont(*FONTS["stat_number"]),
                text_color=color
            ).pack()
            ctk.CTkLabel(
                cell,
                text=sev,
                font=ctk.CTkFont(*FONTS["small"]),
                text_color=TEXT_SECONDARY
            ).pack()

        # Meta info
        meta_lbl = ctk.CTkLabel(
            summary,
            text=(
                f"TARGET: {report.get('target', '-')}"
                f"    DURATION: {report.get('duration', '-')}"
                f"    TIME: {str(report.get('timestamp', '-')).replace('T', ' ')[:19]}"
            ),
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            anchor="w"
        )
        meta_lbl.grid(row=2, column=0, columnspan=6, sticky="w", padx=CARD_PADDING, pady=(SPACE_2, CARD_PADDING))

        # --- Per-scanner sections ---
        results = report.get("results", {})
        if not results:
            ctk.CTkLabel(
                self.body,
                text="No scanner produced output.",
                font=ctk.CTkFont(*FONTS["small"]),
                text_color=TEXT_SECONDARY
            ).grid(row=1, column=0, pady=SPACE_4)
            return

        row = 1
        for key, result in results.items():
            section = ScannerSection(self.body, key, result)
            section.grid(row=row, column=0, sticky="ew", padx=0, pady=(0, SPACE_3))
            row += 1

    # ------------------------------------------------------------------
    def save_html(self):
        path = self.app.save_report(fmt="html")
        if path:
            self.app.show_message("Report Downloaded", f"HTML report saved to:\n{path}")

    def save_json(self):
        path = self.app.save_report(fmt="json")
        if path:
            self.app.show_message("Report Downloaded", f"JSON report saved to:\n{path}")