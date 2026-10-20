"""
ui/animated_threat_feed.py — animated per-finding threat feed.

Displays findings as they arrive from agent_lifecycle events.  Each row
has a severity dot, scanner key badge, finding title, and elapsed time
since the feed was last cleared.  The dot fades in via a ColorTweener
when each row is appended.

Public API
----------
AnimatedThreatFeed(master, **kwargs)
    .add_finding(key, title, severity)  — append a row; call from main thread
    .clear()                             — remove all rows and reset timer
"""

import time
from typing import List

import customtkinter as ctk

from ui.motion import ColorTweener
from ui.theme import (
    SURFACE_BASE, SURFACE_MUTED, SURFACE_STRONG,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY,
    STATUS_CRITICAL, STATUS_HIGH, STATUS_MEDIUM, STATUS_LOW, STATUS_INFO,
    FONTS, SPACE_1, SPACE_2, SPACE_3,
    RADIUS_SM, RADIUS_MD,
)

_SEV_COLORS = {
    "critical": STATUS_CRITICAL,
    "high":     STATUS_HIGH,
    "medium":   STATUS_MEDIUM,
    "low":      STATUS_LOW,
    "info":     STATUS_INFO,
}
_DOT = "●"
_MAX_ROWS = 100


class AnimatedThreatFeed(ctk.CTkScrollableFrame):
    """Scrollable live feed of findings; newest at the bottom.

    Each new row's severity dot fades in from the background colour,
    providing a non-distracting visual cue that an item was just added.
    When REDUCE_MOTION is True the dot appears at full colour immediately.
    """

    def __init__(self, master, **kwargs):
        kwargs.setdefault("fg_color", SURFACE_MUTED)
        kwargs.setdefault("corner_radius", RADIUS_MD)
        kwargs.setdefault("scrollbar_button_color", SURFACE_STRONG)
        kwargs.setdefault("scrollbar_button_hover_color", SURFACE_MUTED)
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self._rows: List[ctk.CTkFrame] = []
        self._scan_start: float = time.time()
        self._empty_lbl: ctk.CTkLabel = self._make_empty_label()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_finding(self, key: str, title: str,
                    severity: str = "info") -> None:
        """Append one finding row (call from Tk main thread)."""
        if self._empty_lbl.winfo_exists():
            self._empty_lbl.grid_forget()

        if len(self._rows) >= _MAX_ROWS:
            oldest = self._rows.pop(0)
            oldest.destroy()
            for i, row in enumerate(self._rows):
                row.grid(row=i, column=0, sticky="ew",
                         padx=SPACE_2, pady=(0, 1))

        row_idx = len(self._rows)
        row = self._make_row(key, title, severity)
        row.grid(row=row_idx, column=0, sticky="ew",
                 padx=SPACE_2, pady=(0, 1))
        self._rows.append(row)

        # Dot fade-in from background to severity color
        dot_lbl = row.winfo_children()[0]
        sev_color = _SEV_COLORS.get(severity.lower(), STATUS_INFO)
        ColorTweener(
            row,
            lambda c, lbl=dot_lbl: lbl.configure(text_color=c),
            start=SURFACE_MUTED,
            end=sev_color,
            duration_ms=300,
        ).start()

        try:
            self._parent_canvas.yview_moveto(1.0)
        except Exception:
            pass

    def clear(self) -> None:
        """Remove all rows and reset the elapsed-time reference (main thread)."""
        for row in self._rows:
            row.destroy()
        self._rows.clear()
        self._scan_start = time.time()
        if not self._empty_lbl.winfo_exists():
            self._empty_lbl = self._make_empty_label()
        self._empty_lbl.grid(row=0, column=0, pady=SPACE_3)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_empty_label(self) -> ctk.CTkLabel:
        lbl = ctk.CTkLabel(
            self,
            text="No findings yet.",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
        )
        lbl.grid(row=0, column=0, pady=SPACE_3)
        return lbl

    def _make_row(self, key: str, title: str,
                  severity: str) -> ctk.CTkFrame:
        elapsed = time.time() - self._scan_start

        row = ctk.CTkFrame(
            self,
            fg_color=SURFACE_BASE,
            corner_radius=RADIUS_SM,
            border_width=0,
        )
        row.grid_columnconfigure(2, weight=1)

        # Severity dot — initially invisible; tween animates it in
        dot = ctk.CTkLabel(
            row,
            text=_DOT,
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=SURFACE_MUTED,
            width=14,
            anchor="center",
        )
        dot.grid(row=0, column=0, padx=(SPACE_2, SPACE_1), pady=SPACE_1)

        # Scanner key badge
        ctk.CTkLabel(
            row,
            text=key.upper()[:8],
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_TERTIARY,
            width=52,
            anchor="w",
        ).grid(row=0, column=1, padx=(0, SPACE_2), pady=SPACE_1)

        # Finding title (truncated to avoid wrapping)
        ctk.CTkLabel(
            row,
            text=title[:80],
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_PRIMARY,
            anchor="w",
        ).grid(row=0, column=2, sticky="ew", padx=(0, SPACE_2), pady=SPACE_1)

        # Elapsed time stamp
        ctk.CTkLabel(
            row,
            text=f"+{elapsed:.0f}s",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            width=40,
            anchor="e",
        ).grid(row=0, column=3, padx=(0, SPACE_2), pady=SPACE_1)

        return row
