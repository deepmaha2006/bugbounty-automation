"""
Shared UI widgets for the HydraX desktop interface.
Styled to match the web frontend: dark panels, soft corners, gold accent,
fixed severity palette.
"""

import customtkinter as ctk
from typing import Optional, Callable, List, Dict
from ui.theme import (
    # Surfaces
    SURFACE_BASE, SURFACE_MUTED, SURFACE_RAISED, SURFACE_STRONG,
    ACCENT_HOVER,
    # Borders
    BORDER_HAIRLINE, BORDER_ACCENT,
    # Text
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY, TEXT_INVERSE,
    # Status / Severity
    STATUS_COLORS, SEVERITY_COLORS,
    STATUS_CRITICAL, STATUS_HIGH, STATUS_MEDIUM, STATUS_LOW, STATUS_INFO,
    # Typography
    FONTS,
    # Spacing
    SPACE_1, SPACE_2, SPACE_3, SPACE_4, SPACE_5, SPACE_6, SPACE_7, SPACE_8,
    # Radius
    RADIUS_NONE, RADIUS_XS, RADIUS_SM, RADIUS_MD,
    # Motion
    MOTION_INSTANT, MOTION_FAST,
    # Component tokens
    BTN_HEIGHT_SM, BTN_HEIGHT_MD, BTN_HEIGHT_LG,
    BTN_WIDTH_SM, BTN_WIDTH_MD, BTN_WIDTH_LG, BTN_WIDTH_XL,
    INPUT_HEIGHT, CARD_PADDING,
    BORDER_WIDTH_HAIRLINE, BORDER_WIDTH_ACCENT,
    FOCUS_RING_WIDTH, FOCUS_RING_COLOR, FOCUS_RING_OFFSET,
)


class MetricCard(ctk.CTkFrame):
    """Professional metric card — rounded, hairline border."""

    def __init__(
        self,
        master,
        title: str,
        value: str,
        icon: str = "",
        color: str = TEXT_TERTIARY,  # Default accent
        command: Optional[Callable] = None,
        **kwargs
    ):
        super().__init__(
            master,
            fg_color=SURFACE_MUTED,
            corner_radius=RADIUS_MD,
            border_width=BORDER_WIDTH_HAIRLINE,
            border_color=BORDER_HAIRLINE,
            **kwargs
        )

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure((0, 1), weight=1)

        # Icon and title row
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_2))
        header_frame.grid_columnconfigure(0, weight=1)

        if icon:
            icon_label = ctk.CTkLabel(
                header_frame,
                text=icon,
                font=ctk.CTkFont(*FONTS["subheading"]),
                text_color=color
            )
            icon_label.grid(row=0, column=0, padx=(0, SPACE_2), sticky="w")

        title_label = ctk.CTkLabel(
            header_frame,
            text=title,
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_SECONDARY,
            anchor="w"
        )
        title_label.grid(row=0, column=1, sticky="ew")

        # Value display
        self.value_label = ctk.CTkLabel(
            self,
            text=value,
            font=ctk.CTkFont(*FONTS["score"]),
            text_color=TEXT_PRIMARY
        )
        self.value_label.grid(row=1, column=0, pady=(0, CARD_PADDING), sticky="")

        # Optional click handler — give clickable cards the same hover
        # affordance as scanner cards (accent border), so it's visually
        # obvious the card is interactive before the user clicks it.
        if command:
            self.configure(cursor="hand2")
            self.bind("<Button-1>", lambda e: command())
            self.value_label.bind("<Button-1>", lambda e: command())
            self.bind("<Enter>", lambda e: self.configure(
                border_color=BORDER_ACCENT, border_width=BORDER_WIDTH_ACCENT))
            self.bind("<Leave>", lambda e: self.configure(
                border_color=BORDER_HAIRLINE, border_width=BORDER_WIDTH_HAIRLINE))

    def update_value(self, value: str):
        """Update the metric value."""
        self.value_label.configure(text=value)


class StatusIndicator(ctk.CTkFrame):
    """Professional status indicator — rounded, gold/amber/red states."""

    def __init__(
        self,
        master,
        text: str = "Ready",
        status: str = "idle",
        width: int = 140,
        height: int = 32,
        **kwargs
    ):
        super().__init__(
            master,
            fg_color=SURFACE_MUTED,
            corner_radius=RADIUS_SM,
            border_width=BORDER_WIDTH_HAIRLINE,
            border_color=BORDER_HAIRLINE,
            width=width,
            height=height,
            **kwargs
        )
        self.grid_propagate(False)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(
            self,
            text=text,
            font=ctk.CTkFont(*FONTS["body_bold"]),
            text_color=TEXT_PRIMARY
        )
        self.status_label.grid(row=0, column=0)

        self.update_status(text, status)

    def update_status(self, text: str, status: str = "idle"):
        """Update status text and border color."""
        self.status_label.configure(text=text)

        # Border color based on status (hard-corner indicator)
        color_map = {
            "idle": BORDER_HAIRLINE,
            "active": TEXT_TERTIARY,       # gold
            "success": STATUS_COLORS["success"],  # green
            "warning": STATUS_COLORS["warning"],  # amber
            "error": STATUS_COLORS["error"],      # red
        }
        border_color = color_map.get(status, BORDER_HAIRLINE)
        self.configure(border_color=border_color)

        # Text color for active states
        text_color_map = {
            "idle": TEXT_SECONDARY,
            "active": TEXT_TERTIARY,
            "success": STATUS_COLORS["success"],
            "warning": STATUS_COLORS["warning"],
            "error": STATUS_COLORS["error"],
        }
        self.status_label.configure(text_color=text_color_map.get(status, TEXT_SECONDARY))


class PrimaryButton(ctk.CTkButton):
    """Primary button — filled gold, rounded, focus ring on focus."""

    def __init__(
        self,
        master,
        text: str,
        command: Optional[Callable] = None,
        width: int = BTN_WIDTH_MD,
        height: int = BTN_HEIGHT_MD,
        **kwargs
    ):
        # Use token-based sizing directly
        kwargs.setdefault("font", ctk.CTkFont(*FONTS["body_bold"]))
        kwargs.setdefault("fg_color", self._fill_for(kwargs.get("state")))
        super().__init__(
            master,
            text=text,
            command=command,
            width=width,
            height=height,
            corner_radius=RADIUS_SM,
            border_width=0,
            text_color=TEXT_INVERSE,           # Dark text on gold
            text_color_disabled=TEXT_SECONDARY,
            hover_color=ACCENT_HOVER,           # Lighter gold hover
            **kwargs
        )

        # Focus ring via border (CustomTkinter limitation workaround)
        self.bind("<FocusIn>", lambda e: self.configure(border_width=FOCUS_RING_WIDTH, border_color=FOCUS_RING_COLOR))
        self.bind("<FocusOut>", lambda e: self.configure(border_width=0))

    @staticmethod
    def _fill_for(state) -> str:
        # CTkButton keeps its fill when disabled, which left dark-on-gold
        # buttons looking live (and gold-on-gold unreadable). Dim the fill.
        return SURFACE_STRONG if state == "disabled" else SURFACE_RAISED

    def configure(self, require_redraw=False, **kwargs):
        if "state" in kwargs and "fg_color" not in kwargs:
            kwargs["fg_color"] = self._fill_for(kwargs["state"])
        super().configure(require_redraw, **kwargs)


class GhostButton(ctk.CTkButton):
    """Ghost button — transparent, hairline border, rounded, gold ring on focus."""

    def __init__(
        self,
        master,
        text: str,
        command: Optional[Callable] = None,
        width: int = BTN_WIDTH_MD,
        height: int = BTN_HEIGHT_MD,
        **kwargs
    ):
        kwargs.setdefault("font", ctk.CTkFont(*FONTS["body"]))
        super().__init__(
            master,
            text=text,
            command=command,
            width=width,
            height=height,
            corner_radius=RADIUS_SM,
            border_width=BORDER_WIDTH_HAIRLINE,
            border_color=BORDER_HAIRLINE,
            fg_color="transparent",
            text_color=TEXT_PRIMARY,
            hover_color=SURFACE_STRONG,         # Subtle surface on hover
            **kwargs
        )

        # Focus ring
        self.bind("<FocusIn>", lambda e: self.configure(border_width=BORDER_WIDTH_ACCENT, border_color=FOCUS_RING_COLOR))
        self.bind("<FocusOut>", lambda e: self.configure(border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE))


class SectionHeader(ctk.CTkFrame):
    """Section header — monospace heading, optional subtitle, optional action button.

    Every call site in the app was passing a full descriptive sentence as the
    positional `icon` argument (meant for a single glyph), which rendered a
    whole sentence in the icon slot at subheading size instead of as a proper
    subtitle line — that's now a real `subtitle` parameter instead.
    """

    def __init__(
        self,
        master,
        text: str,
        subtitle: str = "",
        icon: str = "",
        action_text: Optional[str] = None,
        action_command: Optional[Callable] = None,
        **kwargs
    ):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew")
        header_frame.grid_columnconfigure(1, weight=1)

        if icon:
            icon_label = ctk.CTkLabel(
                header_frame,
                text=icon,
                font=ctk.CTkFont(*FONTS["subheading"]),
                text_color=TEXT_TERTIARY  # Accent
            )
            icon_label.grid(row=0, column=0, padx=(0, SPACE_2), sticky="w")

        title_label = ctk.CTkLabel(
            header_frame,
            text=text,
            font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_PRIMARY,
            anchor="w"
        )
        title_label.grid(row=0, column=1, sticky="ew")

        if action_text and action_command:
            action_btn = GhostButton(
                header_frame,
                text=action_text,
                command=action_command,
                width=BTN_WIDTH_SM,
                height=BTN_HEIGHT_SM,
            )
            action_btn.grid(row=0, column=2, padx=(SPACE_2, 0), sticky="e")

        if subtitle:
            subtitle_label = ctk.CTkLabel(
                self,
                text=subtitle,
                font=ctk.CTkFont(*FONTS["small"]),
                text_color=TEXT_SECONDARY,
                anchor="w",
                justify="left",
            )
            subtitle_label.grid(row=1, column=0, sticky="ew", pady=(SPACE_1, 0))


class Tag(ctk.CTkLabel):
    """Tag label — rounded, gold bg, dark text."""

    def __init__(self, master, text: str, color: str = SURFACE_RAISED, **kwargs):
        super().__init__(
            master,
            text=text,
            font=ctk.CTkFont(*FONTS["small_bold"]),
            corner_radius=RADIUS_XS,
            fg_color=color,
            text_color=TEXT_INVERSE if color == SURFACE_RAISED else TEXT_PRIMARY,
            padx=SPACE_2,
            pady=SPACE_1,
            **kwargs
        )


class Badge(ctk.CTkLabel):
    """Small badge — rounded, for counts/categories."""

    def __init__(self, master, text: str, color: str = SURFACE_RAISED, **kwargs):
        super().__init__(
            master,
            text=text,
            font=ctk.CTkFont(*FONTS["small_bold"]),
            corner_radius=RADIUS_XS,
            fg_color=color,
            text_color=TEXT_INVERSE if color == SURFACE_RAISED else TEXT_PRIMARY,
            padx=SPACE_2,
            pady=SPACE_1,
            **kwargs
        )


class SeverityBadge(ctk.CTkLabel):
    """Severity badge — rounded, severity-specific colors."""

    def __init__(self, master, severity: str, **kwargs):
        color_map = {
            "Critical": STATUS_CRITICAL,
            "High": STATUS_HIGH,
            "Medium": STATUS_MEDIUM,
            "Low": STATUS_LOW,
            "Info": STATUS_INFO,
        }
        color = color_map.get(severity, STATUS_LOW)
        super().__init__(
            master,
            text=severity,
            font=ctk.CTkFont(*FONTS["small_bold"]),
            corner_radius=RADIUS_XS,
            fg_color=color,
            text_color=TEXT_INVERSE,  # dark text on every severity chip, as on the web
            width=70,
            height=24,
            **kwargs
        )


class EmptyState(ctk.CTkFrame):
    """Empty state — terminal-style with blinking cursor indicator."""

    def __init__(self, master, icon: str, title: str, subtitle: str = "", **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)

        icon_lbl = ctk.CTkLabel(self, text=icon, font=ctk.CTkFont(*FONTS["score"]))
        icon_lbl.grid(row=0, column=0, pady=(SPACE_6, SPACE_3))

        title_lbl = ctk.CTkLabel(
            self,
            text=title,
            font=ctk.CTkFont(*FONTS["subheading"]),
            text_color=TEXT_PRIMARY
        )
        title_lbl.grid(row=1, column=0, pady=(0, SPACE_2))

        if subtitle:
            sub_lbl = ctk.CTkLabel(
                self,
                text=subtitle,
                font=ctk.CTkFont(*FONTS["body"]),
                text_color=TEXT_SECONDARY
            )
            sub_lbl.grid(row=2, column=0, pady=(0, SPACE_6))


def make_card(master, **kwargs) -> ctk.CTkFrame:
    """Create a styled card frame — rounded, hairline border."""
    frame = ctk.CTkFrame(
        master,
        fg_color=SURFACE_MUTED,
        corner_radius=RADIUS_MD,
        border_width=BORDER_WIDTH_HAIRLINE,
        border_color=BORDER_HAIRLINE,
        **kwargs
    )
    return frame


class ThreatFeedWidget(ctk.CTkFrame):
    """Real-time threat intelligence feed — terminal-style list."""

    def __init__(self, master, threats: List[Dict] = None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.threats = threats or []
        self.grid_columnconfigure(0, weight=1)

        # Create scrollable frame for threats
        self.threat_frame = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            height=100,
            scrollbar_button_color=SURFACE_STRONG,
            scrollbar_button_hover_color=SURFACE_MUTED
        )
        self.threat_frame.grid(row=0, column=0, sticky="ew", padx=SPACE_1, pady=SPACE_1)
        self.threat_frame.grid_columnconfigure(0, weight=1)

        self._render_threats()

    def _render_threats(self):
        """Render threat intelligence items — terminal rows."""
        # Clear existing widgets
        for widget in self.threat_frame.winfo_children():
            widget.destroy()

        # Render each threat
        for i, threat in enumerate(self.threats[:10]):  # Show max 10 threats
            threat_frame = ctk.CTkFrame(
                self.threat_frame,
                fg_color=SURFACE_MUTED,
                corner_radius=RADIUS_SM,
                border_width=BORDER_WIDTH_HAIRLINE,
                border_color=BORDER_HAIRLINE,
                height=28
            )
            threat_frame.grid(row=i, column=0, sticky="ew", pady=SPACE_1)
            threat_frame.grid_propagate(False)
            threat_frame.grid_columnconfigure((0, 1, 2), weight=1)

            # Time badge
            time_label = ctk.CTkLabel(
                threat_frame,
                text=threat.get("time", ""),
                font=ctk.CTkFont(*FONTS["small"]),
                text_color=TEXT_SECONDARY,
                width=50
            )
            time_label.grid(row=0, column=0, padx=(SPACE_2, 0), pady=SPACE_1, sticky="w")

            # Threat text
            threat_label = ctk.CTkLabel(
                threat_frame,
                text=threat.get("threat", ""),
                font=ctk.CTkFont(*FONTS["small"]),
                text_color=TEXT_PRIMARY,
                anchor="w"
            )
            threat_label.grid(row=0, column=1, padx=SPACE_2, pady=SPACE_1, sticky="ew")

            # Severity badge
            severity = threat.get("severity", "Info")
            color = SEVERITY_COLORS.get(severity, TEXT_SECONDARY)

            severity_badge = ctk.CTkLabel(
                threat_frame,
                text=severity,
                font=ctk.CTkFont(*FONTS["small_bold"]),
                corner_radius=RADIUS_XS,
                fg_color=color,
                text_color=TEXT_INVERSE,
                width=72,
                height=20
            )
            severity_badge.grid(row=0, column=2, padx=(0, SPACE_2), pady=SPACE_1, sticky="e")

    def update_threats(self, threats: List[Dict]):
        """Update the threat feed with new threats."""
        self.threats = threats
        self._render_threats()


class NavButton(ctk.CTkFrame):
    """Sidebar navigation item — icon + label in a fixed-width icon column.

    A plain CTkButton with text=f"{icon}  {label}" was used previously, but
    that only aligns correctly if every icon glyph happens to render at the
    same width in whatever font the button falls back to for each specific
    character — not guaranteed for arbitrary Unicode symbols in a pixel font
    (theme.py's FONT_STACK starts with DotGothic16). A fixed-width icon
    column in its own grid cell guarantees alignment regardless of glyph
    metrics.
    """

    def __init__(self, master, icon: str, text: str, command: Callable, **kwargs):
        super().__init__(
            master, fg_color="transparent", corner_radius=RADIUS_SM,
            height=BTN_HEIGHT_MD, **kwargs
        )
        self.grid_propagate(False)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._command = command
        self._active = False

        self.icon_label = ctk.CTkLabel(
            self, text=icon, width=24, font=ctk.CTkFont(*FONTS["body"]),
            text_color=TEXT_SECONDARY, anchor="center"
        )
        self.icon_label.grid(row=0, column=0, padx=(SPACE_3, SPACE_2), sticky="ns")

        self.text_label = ctk.CTkLabel(
            self, text=text, font=ctk.CTkFont(*FONTS["body"]),
            text_color=TEXT_SECONDARY, anchor="w"
        )
        self.text_label.grid(row=0, column=1, sticky="nsew")

        for widget in (self, self.icon_label, self.text_label):
            widget.bind("<Button-1>", lambda e: self._command())
            widget.bind("<Enter>", lambda e: self._on_enter())
            widget.bind("<Leave>", lambda e: self._on_leave())

    def _on_enter(self):
        if not self._active:
            self.configure(fg_color=SURFACE_STRONG)

    def _on_leave(self):
        if not self._active:
            self.configure(fg_color="transparent")

    def set_active(self, active: bool) -> None:
        self._active = active
        color = TEXT_TERTIARY if active else TEXT_SECONDARY
        self.configure(fg_color=SURFACE_STRONG if active else "transparent")
        self.icon_label.configure(text_color=color)
        self.text_label.configure(text_color=color)


# Export the enhanced widgets
__all__ = [
    "MetricCard", "StatusIndicator", "PrimaryButton", "GhostButton",
    "SectionHeader", "Tag", "ThreatFeedWidget",
    "Badge", "SeverityBadge", "EmptyState", "make_card", "NavButton"
]