"""
ui/xp_bar.py — gamer-style XP bar driven by real findings.

Each severity level awards a fixed XP amount.  The bar levels up at
XP_PER_LEVEL; the level label flashes green on level-up then fades back
to gold.

Public API
----------
XPBar(master, **kwargs)
    .add_xp(amount)               — award XP and animate; call from main thread
    .reset()                       — return to LVL 1, 0 XP
    XPBar.xp_for_severity(str)    — class-level helper: severity → int
"""

from typing import Optional

import customtkinter as ctk

from ui.motion import ColorTweener
from ui.theme import (
    SURFACE_MUTED, SURFACE_STRONG,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY,
    STATUS_OK,
    FONTS, SPACE_2, SPACE_3,
    RADIUS_SM,
)

XP_PER_LEVEL: int = 10

_XP_BY_SEVERITY = {
    "critical": 5,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
}


class XPBar(ctk.CTkFrame):
    """Gamer-style XP bar driven by real scan findings.

    Fills left-to-right as XP accumulates.  On level-up the bar
    resets and the level label flashes green before settling back
    to gold.
    """

    def __init__(self, master, **kwargs):
        kwargs.setdefault("fg_color", SURFACE_MUTED)
        kwargs.setdefault("corner_radius", RADIUS_SM)
        super().__init__(master, **kwargs)
        self._level = 1
        self._xp = 0
        self._color_tween: Optional[ColorTweener] = None
        self._build()

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self) -> None:
        self.grid_columnconfigure(1, weight=1)

        self._level_lbl = ctk.CTkLabel(
            self,
            text="LVL 1",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_TERTIARY,
            width=44,
            anchor="w",
        )
        self._level_lbl.grid(row=0, column=0, padx=(SPACE_3, SPACE_2), pady=SPACE_2)

        self._bar = ctk.CTkProgressBar(
            self,
            height=8,
            corner_radius=RADIUS_SM,
            fg_color=SURFACE_STRONG,
            progress_color=TEXT_TERTIARY,
            border_width=0,
        )
        self._bar.set(0.0)
        self._bar.grid(row=0, column=1, sticky="ew", padx=(0, SPACE_2), pady=SPACE_2)

        self._xp_lbl = ctk.CTkLabel(
            self,
            text="0 XP",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            width=44,
            anchor="e",
        )
        self._xp_lbl.grid(row=0, column=2, padx=(0, SPACE_3), pady=SPACE_2)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_xp(self, amount: int) -> None:
        """Award *amount* XP and update the bar (main thread only)."""
        if amount <= 0:
            return
        self._xp += amount
        while self._xp >= XP_PER_LEVEL:
            self._xp -= XP_PER_LEVEL
            self._level += 1
            self._level_lbl.configure(text=f"LVL {self._level}",
                                      text_color=STATUS_OK)
            if self._color_tween:
                self._color_tween.cancel()
            self._color_tween = ColorTweener(
                self,
                lambda c: self._level_lbl.configure(text_color=c),
                start=STATUS_OK,
                end=TEXT_TERTIARY,
                duration_ms=600,
            )
            self._color_tween.start()

        frac = self._xp / XP_PER_LEVEL
        self._bar.set(frac)
        self._xp_lbl.configure(text=f"{self._xp} XP")

    def reset(self) -> None:
        """Return to LVL 1 with 0 XP (main thread only)."""
        if self._color_tween:
            self._color_tween.cancel()
            self._color_tween = None
        self._level = 1
        self._xp = 0
        self._level_lbl.configure(text="LVL 1", text_color=TEXT_TERTIARY)
        self._bar.set(0.0)
        self._xp_lbl.configure(text="0 XP")

    @classmethod
    def xp_for_severity(cls, severity: str) -> int:
        """Return the XP award for *severity* (case-insensitive)."""
        return _XP_BY_SEVERITY.get(severity.lower(), 0)
