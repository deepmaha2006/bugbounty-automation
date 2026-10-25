"""
SignatureWidget — animated handwriting canvas widget for HydraX.

Renders "Deepesh Kumar Mahawar" as an animated cursive signature on a
Tkinter Canvas, letter by letter, then sweeps an underline beneath it.
Read-only: no user interaction modifies the display.

Used in Settings as an immutable authorship seal — cannot be edited or
removed after the application ships.
"""

from __future__ import annotations

import tkinter as tk
import customtkinter as ctk
from typing import List, Tuple, Optional

from ui.theme import (
    SURFACE_MUTED,
    BORDER_HAIRLINE,
    BORDER_ACCENT,
    TEXT_SECONDARY,
    FONTS,
)

# ── Constants ────────────────────────────────────────────────────────────────

AUTHOR = "Deepesh Kumar Mahawar"
STROKE_COLOR = "#c41e3a"          # cyber red — matches BORDER_ACCENT
UNDERLINE_COLOR = "#c41e3a"
GHOST_COLOR = "#1c2530"           # extremely subtle pre-ghost
CHAR_DELAY_MS = 80                # ms between each character appearing
UNDERLINE_STEPS = 30              # number of animation frames for the underline
UNDERLINE_DELAY_MS = 20           # ms per underline step

# Try to find the best cursive / italic font available on the system.
# resolve() is called once so we only pay for font enumeration once.
_CURSIVE_FONT: Optional[Tuple[str, int, str]] = None


def _resolve_cursive(size: int = 26) -> Tuple[str, int, str]:
    """Pick the best available cursive-like font."""
    global _CURSIVE_FONT
    if _CURSIVE_FONT and _CURSIVE_FONT[1] == size:
        return _CURSIVE_FONT

    preference = [
        "Segoe Script",
        "Brush Script MT",
        "Kunstler Script",
        "Lucida Handwriting",
        "Comic Sans MS",   # fallback — universally available
        "Times New Roman",
    ]
    try:
        import tkinter.font as tkfont
        available = set(tkfont.families())
        for name in preference:
            if name in available:
                _CURSIVE_FONT = (name, size, "italic")
                return _CURSIVE_FONT
    except Exception:
        pass

    _CURSIVE_FONT = ("Times New Roman", size, "italic")
    return _CURSIVE_FONT


# ── Widget ───────────────────────────────────────────────────────────────────

class SignatureWidget(ctk.CTkFrame):
    """An animated, read-only cursive signature display widget.

    The name is drawn character-by-character then underlined.
    Replay is triggered by calling animate() again.
    """

    HEIGHT = 90   # canvas height in px

    def __init__(
        self,
        master,
        text: str = AUTHOR,
        font_size: int = 26,
        **kwargs,
    ) -> None:
        super().__init__(
            master,
            fg_color=SURFACE_MUTED,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_HAIRLINE,
            **kwargs,
        )
        self._text = text
        self._font_size = font_size
        self._font = _resolve_cursive(font_size)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Label above the signature
        ctk.CTkLabel(
            self,
            text="PLATFORM SIGNATURE",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=TEXT_SECONDARY,
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 2))

        # Canvas for the animated signature
        self._canvas = tk.Canvas(
            self,
            height=self.HEIGHT,
            bg=SURFACE_MUTED,
            highlightthickness=0,
            cursor="arrow",
        )
        self._canvas.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))

        # Bind resize so the canvas re-centres the signature
        self._canvas.bind("<Configure>", self._on_resize)

        # Internal state
        self._char_ids: List[int] = []
        self._underline_id: Optional[int] = None
        self._anim_job: Optional[str] = None
        self._width: int = 400

        # Delayed first render — canvas geometry isn't settled at init time
        self.after(120, self.animate)

    # ── Private helpers ──────────────────────────────────────────────────────

    def _on_resize(self, event) -> None:
        self._width = event.width
        # Re-run animation on first layout or re-layout
        if self._anim_job:
            self._canvas.after_cancel(self._anim_job)
            self._anim_job = None
        self._canvas.delete("all")
        self._char_ids.clear()
        self._underline_id = None
        self.after(50, self.animate)

    def _cancel(self) -> None:
        if self._anim_job:
            try:
                self._canvas.after_cancel(self._anim_job)
            except Exception:
                pass
            self._anim_job = None

    def _measure_text(self) -> int:
        """Estimate pixel width of the full signature string."""
        # ctk.CTkFont can't measure; use tkinter.font directly
        try:
            import tkinter.font as tkfont
            f = tkfont.Font(family=self._font[0], size=self._font[1],
                            slant="italic")
            return f.measure(self._text)
        except Exception:
            # Rough estimate: 0.6× font-size per character
            return int(len(self._text) * self._font_size * 0.6)

    # ── Public API ───────────────────────────────────────────────────────────

    def animate(self) -> None:
        """Start (or restart) the signature animation from scratch."""
        self._cancel()
        self._canvas.delete("all")
        self._char_ids.clear()
        self._underline_id = None

        canvas_w = self._canvas.winfo_width() or self._width
        text_w = self._measure_text()
        x_start = max(8, (canvas_w - text_w) // 2)
        y_centre = self.HEIGHT // 2 + self._font_size // 4

        # Draw the ghost placeholder (full text, very dim)
        self._canvas.create_text(
            x_start, y_centre,
            text=self._text,
            font=self._font,
            fill=GHOST_COLOR,
            anchor="w",
        )

        # Schedule character-by-character reveal
        self._schedule_chars(x_start, y_centre, canvas_w, text_w)

    def _schedule_chars(
        self,
        x_start: int,
        y_centre: int,
        canvas_w: int,
        text_w: int,
    ) -> None:
        visible = [""]   # mutable closure cell

        def _step(idx: int) -> None:
            if idx > len(self._text):
                # All chars drawn — start underline animation
                self._schedule_underline(x_start, y_centre + self._font_size // 2 + 4,
                                         x_start + text_w, canvas_w)
                return

            visible[0] = self._text[:idx]

            # Remove previous partial text, add updated version
            for cid in self._char_ids:
                self._canvas.delete(cid)
            self._char_ids.clear()

            cid = self._canvas.create_text(
                x_start, y_centre,
                text=visible[0],
                font=self._font,
                fill=STROKE_COLOR,
                anchor="w",
            )
            self._char_ids.append(cid)

            self._anim_job = self._canvas.after(CHAR_DELAY_MS, _step, idx + 1)

        _step(1)

    def _schedule_underline(
        self,
        x0: int,
        y: int,
        x1: int,
        canvas_w: int,
    ) -> None:
        """Animate a sweeping underline beneath the completed signature."""
        total_w = x1 - x0
        step_w = total_w / UNDERLINE_STEPS

        def _step(frame: int) -> None:
            if self._underline_id is not None:
                self._canvas.delete(self._underline_id)

            curr_x1 = x0 + int(step_w * frame)
            self._underline_id = self._canvas.create_line(
                x0, y, curr_x1, y,
                fill=UNDERLINE_COLOR,
                width=2,
                capstyle=tk.ROUND,
            )
            if frame < UNDERLINE_STEPS:
                self._anim_job = self._canvas.after(UNDERLINE_DELAY_MS, _step, frame + 1)
            else:
                # Add a small decorative flourish dot at the end
                r = 3
                self._canvas.create_oval(
                    curr_x1 - r, y - r,
                    curr_x1 + r, y + r,
                    fill=UNDERLINE_COLOR, outline="",
                )
                self._anim_job = None

        _step(1)

    def replay(self) -> None:
        """Re-run the animation (e.g. on click or when Settings page opens)."""
        self.animate()
