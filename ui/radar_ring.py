"""
ui/radar_ring.py — animated circular scan progress ring.

Uses tkinter.Canvas (fully compatible with the CTk root window).
Displays a filled arc tracking how many agents have finished and a
rotating sweep line while any agent is still running.

Public API
----------
RadarRing(master, size=120, bg=SURFACE_BASE, **kwargs)
    .update_progress(done, total)  — advance the filled arc
    .start_sweep()                 — begin rotating sweep animation
    .stop_sweep()                  — stop sweep, redraw arc at rest
    .reset()                       — clear back to idle state
"""

import math
import tkinter as tk
from typing import Optional

from ui.theme import (
    SURFACE_BASE, SURFACE_STRONG,
    STATUS_OK, STATUS_HIGH,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY,
)
import ui.motion as _motion

_TRACK_COLOR    = SURFACE_STRONG
_DONE_COLOR     = STATUS_OK           # green when all done
_PARTIAL_COLOR  = STATUS_HIGH         # orange while in progress
_SWEEP_COLOR    = TEXT_TERTIARY       # gold sweep line
_SWEEP_FPS      = 30
_SWEEP_MS       = int(1000 / _SWEEP_FPS)
_DEG_PER_FRAME  = 6                   # 360° in 2 s at 30fps


class RadarRing(tk.Canvas):
    """Circular scan-progress widget drawn on a tk.Canvas.

    The ring arc fills as agents complete.  A sweep line rotates while
    agents are running; it stops when ``stop_sweep()`` is called.
    When ``REDUCE_MOTION`` is True the sweep is skipped entirely.
    """

    def __init__(self, master, size: int = 120,
                 bg: str = SURFACE_BASE, **kwargs):
        kwargs.setdefault("width", size)
        kwargs.setdefault("height", size)
        kwargs.setdefault("highlightthickness", 0)
        kwargs.setdefault("bd", 0)
        super().__init__(master, bg=bg, **kwargs)
        self._size = size
        self._margin = max(6, int(size * 0.09))
        self._done = 0
        self._total = 0
        self._sweep_angle: float = 90.0     # start pointing up
        self._sweeping = False
        self._draw()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_progress(self, done: int, total: int) -> None:
        self._done = max(0, done)
        self._total = max(1, total)
        self._draw()

    def start_sweep(self) -> None:
        if self._sweeping:
            return
        self._sweeping = True
        if not _motion.REDUCE_MOTION:
            self.after(_SWEEP_MS, self._tick_sweep)
        else:
            self._draw()

    def stop_sweep(self) -> None:
        self._sweeping = False
        self._sweep_angle = 90.0
        self._draw()

    def reset(self) -> None:
        self._done = 0
        self._total = 0
        self._sweep_angle = 90.0
        self._sweeping = False
        self._draw()

    # ------------------------------------------------------------------
    # Drawing
    # ------------------------------------------------------------------

    def _draw(self) -> None:
        self.delete("all")
        s = self._size
        m = self._margin
        x0, y0 = m, m
        x1, y1 = s - m, s - m
        cx, cy = s / 2.0, s / 2.0

        # Track ring (full circle, dim)
        self.create_arc(x0, y0, x1, y1,
                        start=0, extent=359.9,
                        style=tk.ARC, outline=_TRACK_COLOR, width=5)

        # Progress arc — clockwise from 12 o'clock (start=90, extent<0)
        if self._total > 0 and self._done > 0:
            frac = min(self._done / self._total, 1.0)
            extent = frac * -359.9
            color = _DONE_COLOR if frac >= 1.0 else _PARTIAL_COLOR
            self.create_arc(x0, y0, x1, y1,
                            start=90, extent=extent,
                            style=tk.ARC, outline=color, width=5)

        # Sweep line (only when sweeping and motion enabled)
        if self._sweeping and not _motion.REDUCE_MOTION:
            r = (s / 2.0 - m) * 0.75
            rad = math.radians(self._sweep_angle)
            x2 = cx + r * math.cos(rad)
            y2 = cy - r * math.sin(rad)
            self.create_line(cx, cy, x2, y2,
                             fill=_SWEEP_COLOR, width=2, capstyle=tk.ROUND)

        # Centre label
        if self._total > 0:
            frac = self._done / self._total
            if frac >= 1.0:
                label, color = "✓", _DONE_COLOR
            else:
                label, color = f"{self._done}/{self._total}", TEXT_PRIMARY
        else:
            label, color = "—", TEXT_SECONDARY

        font_size = max(8, s // 10)
        self.create_text(cx, cy, text=label, fill=color,
                         font=("Courier New", font_size, "bold"))

    # ------------------------------------------------------------------
    # Sweep animation tick
    # ------------------------------------------------------------------

    def _tick_sweep(self) -> None:
        if not self._sweeping:
            return
        self._sweep_angle = (self._sweep_angle - _DEG_PER_FRAME) % 360
        self._draw()
        self.after(_SWEEP_MS, self._tick_sweep)
