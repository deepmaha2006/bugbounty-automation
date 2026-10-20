"""
AgentStatusCard — animated per-agent status widget.

Displays agent name, an animated status dot, live elapsed time, and
finding count.  Status transitions use ColorTweener for smooth colour
changes; the dot pulses while the agent is running.

All animation guards against REDUCE_MOTION via ui.motion.
Only real events (update_status, update_findings, update_elapsed) drive
the display — nothing is fabricated.

Typical lifecycle driven by the scanner view:
    card = AgentStatusCard(parent, key="xss", name="Cross-Site Scripting")
    card.grid(...)
    # On scanner_start event:
    card.update_status("running")
    # On 1-second tick:
    card.update_elapsed(elapsed_seconds)
    # On scanner_done event:
    card.update_status("done", findings=3, duration=4.2)
"""

import time
from typing import Optional

import customtkinter as ctk

from ui.motion import ColorTweener, PulseTweener
from ui.theme import (
    SURFACE_MUTED, SURFACE_STRONG,
    BORDER_HAIRLINE, BORDER_WIDTH_HAIRLINE,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY, TEXT_INVERSE,
    STATUS_OK, STATUS_CRITICAL, STATUS_HIGH, STATUS_INFO,
    FONTS, SPACE_1, SPACE_2, SPACE_3, SPACE_4,
    RADIUS_MD, RADIUS_SM,
)

# ---------------------------------------------------------------------------
# Status palette
# ---------------------------------------------------------------------------

_DOT_COLORS = {
    "queued":  TEXT_SECONDARY,     # grey
    "running": TEXT_TERTIARY,      # gold — pulsed
    "done":    STATUS_OK,          # green
    "error":   STATUS_CRITICAL,    # red
    "skipped": STATUS_INFO,        # dim grey
}

_STATUS_LABELS = {
    "queued":  "QUEUED",
    "running": "RUNNING",
    "done":    "DONE",
    "error":   "ERROR",
    "skipped": "SKIPPED",
}

_DOT_CHAR = "●"


class AgentStatusCard(ctk.CTkFrame):
    """One animated card for one agent in the scanner activity roster.

    Parameters
    ----------
    master : Tk widget
    key    : agent registry key (e.g. ``"xss"``)
    name   : human-readable name for the agent
    """

    def __init__(self, master, key: str, name: str, **kwargs):
        super().__init__(
            master,
            fg_color=SURFACE_MUTED,
            corner_radius=RADIUS_MD,
            border_width=BORDER_WIDTH_HAIRLINE,
            border_color=BORDER_HAIRLINE,
            **kwargs,
        )
        self.key = key
        self.name = name
        self._status = "queued"
        self._start_time: Optional[float] = None
        self._ticker_active = False

        # Active tweens/pulse — cancel before starting a new one
        self._color_tween: Optional[ColorTweener] = None
        self._pulse: Optional[PulseTweener] = None

        self._build()

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self):
        self.grid_columnconfigure(1, weight=1)

        # ── Status dot ─────────────────────────────────────────────────
        self._dot = ctk.CTkLabel(
            self,
            text=_DOT_CHAR,
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=_DOT_COLORS["queued"],
            width=18,
            anchor="center",
        )
        self._dot.grid(row=0, column=0, padx=(SPACE_3, SPACE_2), pady=SPACE_2)

        # ── Agent name ─────────────────────────────────────────────────
        self._name_lbl = ctk.CTkLabel(
            self,
            text=self.name,
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_PRIMARY,
            anchor="w",
        )
        self._name_lbl.grid(row=0, column=1, sticky="w", pady=SPACE_2)

        # ── Status text ────────────────────────────────────────────────
        self._status_lbl = ctk.CTkLabel(
            self,
            text=_STATUS_LABELS["queued"],
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_SECONDARY,
            width=72,
            anchor="w",
        )
        self._status_lbl.grid(row=0, column=2, padx=SPACE_2, pady=SPACE_2)

        # ── Elapsed time ───────────────────────────────────────────────
        self._time_lbl = ctk.CTkLabel(
            self,
            text="--",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            width=56,
            anchor="e",
        )
        self._time_lbl.grid(row=0, column=3, padx=SPACE_2, pady=SPACE_2)

        # ── Finding count ──────────────────────────────────────────────
        self._findings_lbl = ctk.CTkLabel(
            self,
            text="-- findings",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            width=90,
            anchor="e",
        )
        self._findings_lbl.grid(row=0, column=4,
                                padx=(SPACE_2, SPACE_3), pady=SPACE_2)

    # ------------------------------------------------------------------
    # Public update API
    # ------------------------------------------------------------------

    def update_status(self, status: str,
                      findings: Optional[int] = None,
                      duration: Optional[float] = None) -> None:
        """Transition the card to *status*.  Call from the main thread only
        (router via widget.after if coming from an event thread).

        Parameters
        ----------
        status   : "queued" | "running" | "done" | "error" | "skipped"
        findings : finding count (set on done/error)
        duration : elapsed seconds (set on done/error)
        """
        old_status = self._status
        self._status = status

        target_color = _DOT_COLORS.get(status, TEXT_SECONDARY)
        old_color    = _DOT_COLORS.get(old_status, TEXT_SECONDARY)

        # Stop current pulse / tween
        if self._pulse:
            self._pulse.cancel()
            self._pulse = None
        if self._color_tween:
            self._color_tween.cancel()
            self._color_tween = None

        # Update status label
        self._status_lbl.configure(
            text=_STATUS_LABELS.get(status, status.upper()),
            text_color=target_color,
        )

        if status == "running":
            self._start_time = time.time()
            self._time_lbl.configure(text="0.0s")
            self._ticker_active = True
            self.after(1000, self._tick_elapsed)
            # Animate dot colour to gold then start pulsing
            def _begin_pulse():
                self._pulse = PulseTweener(
                    self, lambda c: self._dot.configure(text_color=c),
                    lo=TEXT_SECONDARY, hi=TEXT_TERTIARY,
                    half_period_ms=700,
                )
                self._pulse.start()
            self._color_tween = ColorTweener(
                self,
                lambda c: self._dot.configure(text_color=c),
                start=old_color, end=TEXT_TERTIARY,
                duration_ms=200,
                on_done=_begin_pulse,
            )
            self._color_tween.start()

        else:
            # One-shot colour transition to the terminal state colour
            self._ticker_active = False
            if duration is not None:
                self._time_lbl.configure(text=f"{duration:.1f}s")
            self._color_tween = ColorTweener(
                self,
                lambda c: self._dot.configure(text_color=c),
                start=old_color, end=target_color,
                duration_ms=300,
            )
            self._color_tween.start()

        if findings is not None:
            self.update_findings(findings)

    def update_findings(self, count: int) -> None:
        """Update the finding-count label. Call from the main thread."""
        text = f"{count} finding{'s' if count != 1 else ''}"
        color = TEXT_TERTIARY if count > 0 else TEXT_SECONDARY
        self._findings_lbl.configure(text=text, text_color=color)

    def update_elapsed(self, seconds: float) -> None:
        """Set the elapsed-time label directly (e.g. on scan_done)."""
        self._time_lbl.configure(text=f"{seconds:.1f}s")

    # ------------------------------------------------------------------
    # Internal ticker
    # ------------------------------------------------------------------

    def _tick_elapsed(self):
        """Advance the elapsed-time label while running."""
        if not self._ticker_active or self._start_time is None:
            return
        elapsed = time.time() - self._start_time
        try:
            self._time_lbl.configure(text=f"{elapsed:.1f}s")
        except Exception:
            self._ticker_active = False
            return
        self.after(1000, self._tick_elapsed)
