"""
ui/motion.py — lightweight tween engine for HydraX animated UI.

Designed for CustomTkinter: all frame callbacks run via widget.after()
so they are always dispatched on the Tk main thread.

Public API
----------
REDUCE_MOTION : bool
    Module-level flag. When True every tween snaps to its end value
    immediately — no animation fires.  Toggle at runtime from Settings.

lerp(a, b, t)          Linear interpolation (float).
ease_out_quad(t)       Quadratic ease-out curve.
hex_lerp(c1, c2, t)    Interpolate between two #rrggbb hex colours.

Tweener       — float a→b over duration_ms, calls apply(value) per frame.
ColorTweener  — same but for #rrggbb hex values, using hex_lerp.
PulseTweener  — oscillates lo↔hi continuously; cancel() snaps to lo.

Frame rate is capped at 30 FPS (≈33 ms / frame).
"""

import os
import time

from ui import perf_guard as _pg

# ---------------------------------------------------------------------------
# Global reduce-motion flag
# ---------------------------------------------------------------------------

REDUCE_MOTION: bool = os.environ.get(
    "HYDRAX_REDUCE_MOTION", ""
).lower() in ("1", "true", "yes")

# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------

_TARGET_FPS = 30
_FRAME_MS = int(1000 / _TARGET_FPS)   # 33 ms per frame


# ---------------------------------------------------------------------------
# Pure math helpers
# ---------------------------------------------------------------------------

def lerp(a: float, b: float, t: float) -> float:
    """Linear interpolation from *a* to *b* by fraction *t* (0..1)."""
    return a + (b - a) * max(0.0, min(1.0, t))


def ease_out_quad(t: float) -> float:
    """Quadratic ease-out — fast start, decelerates to end."""
    t = max(0.0, min(1.0, t))
    return 1.0 - (1.0 - t) ** 2


def hex_lerp(c1: str, c2: str, t: float) -> str:
    """Interpolate between two ``#rrggbb`` colour strings.

    Returns a valid ``#rrggbb`` string at fraction *t* (0..1).
    """
    t = max(0.0, min(1.0, t))
    try:
        r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
        r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
    except (ValueError, IndexError):
        return c2
    r = round(r1 + (r2 - r1) * t)
    g = round(g1 + (g2 - g1) * t)
    b = round(b1 + (b2 - b1) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


# ---------------------------------------------------------------------------
# Tweener — float a → b
# ---------------------------------------------------------------------------

class Tweener:
    """Animate a float from *start* to *end* over *duration_ms* milliseconds.

    *apply_fn* is called with the current interpolated value on every frame.
    Frame scheduling uses ``widget.after()`` so the callback is always on the
    Tk main thread.

    When :data:`REDUCE_MOTION` is ``True`` the tween snaps to *end*
    immediately and *on_done* is called synchronously.
    """

    def __init__(self, widget, apply_fn, start: float, end: float,
                 duration_ms: int = 200, ease=ease_out_quad, on_done=None):
        self._w = widget
        self._apply = apply_fn
        self._start = float(start)
        self._end = float(end)
        self._duration = max(1, duration_ms)
        self._ease = ease
        self._on_done = on_done
        self._running = False
        self._t0: float = 0.0

    def start(self):
        if REDUCE_MOTION:
            self._snap()
            return
        if not _pg.acquire():
            self._snap()
            return
        self._running = True
        self._t0 = time.monotonic()
        self._w.after(0, self._tick)

    def cancel(self):
        if self._running:
            self._running = False
            _pg.release()

    def _snap(self):
        try:
            self._apply(self._end)
        except Exception:
            pass
        if self._on_done:
            try:
                self._on_done()
            except Exception:
                pass

    def _tick(self):
        if not self._running:
            return
        try:
            elapsed_ms = (time.monotonic() - self._t0) * 1000.0
            t = min(elapsed_ms / self._duration, 1.0)
            self._apply(lerp(self._start, self._end, self._ease(t)))
            if t < 1.0:
                self._w.after(_FRAME_MS, self._tick)
            else:
                self._running = False
                _pg.release()
                if self._on_done:
                    self._on_done()
        except Exception:
            self._running = False
            _pg.release()


# ---------------------------------------------------------------------------
# ColorTweener — #rrggbb c1 → c2
# ---------------------------------------------------------------------------

class ColorTweener:
    """Animate a ``#rrggbb`` colour value from *start* to *end*.

    *apply_fn* is called with the current hex string on every frame.
    Uses :func:`hex_lerp`; otherwise identical to :class:`Tweener`.
    """

    def __init__(self, widget, apply_fn, start: str, end: str,
                 duration_ms: int = 200, ease=ease_out_quad, on_done=None):
        self._w = widget
        self._apply = apply_fn
        self._start = start
        self._end = end
        self._duration = max(1, duration_ms)
        self._ease = ease
        self._on_done = on_done
        self._running = False
        self._t0: float = 0.0

    def start(self):
        if REDUCE_MOTION:
            self._snap()
            return
        if not _pg.acquire():
            self._snap()
            return
        self._running = True
        self._t0 = time.monotonic()
        self._w.after(0, self._tick)

    def cancel(self):
        if self._running:
            self._running = False
            _pg.release()

    def _snap(self):
        try:
            self._apply(self._end)
        except Exception:
            pass
        if self._on_done:
            try:
                self._on_done()
            except Exception:
                pass

    def _tick(self):
        if not self._running:
            return
        try:
            elapsed_ms = (time.monotonic() - self._t0) * 1000.0
            t = min(elapsed_ms / self._duration, 1.0)
            self._apply(hex_lerp(self._start, self._end, self._ease(t)))
            if t < 1.0:
                self._w.after(_FRAME_MS, self._tick)
            else:
                self._running = False
                _pg.release()
                if self._on_done:
                    self._on_done()
        except Exception:
            self._running = False
            _pg.release()


# ---------------------------------------------------------------------------
# PulseTweener — continuous lo ↔ hi oscillation
# ---------------------------------------------------------------------------

class PulseTweener:
    """Oscillate a value between *lo* and *hi* continuously until stopped.

    Uses a triangle wave so the transition is smooth in both directions.
    Designed for status-dot pulse animations while an agent is running.

    ``cancel()`` stops the animation and calls ``apply_fn(lo)`` to return
    the dot to its rest colour.

    When :data:`REDUCE_MOTION` is ``True``, ``start()`` applies *hi* once
    and stops (static highlight, no oscillation).
    """

    def __init__(self, widget, apply_fn, lo, hi, half_period_ms: int = 700):
        self._w = widget
        self._apply = apply_fn
        self._lo = lo
        self._hi = hi
        self._half = max(1, half_period_ms)
        self._running = False
        self._t0: float = 0.0

    def start(self):
        if REDUCE_MOTION:
            try:
                self._apply(self._hi)
            except Exception:
                pass
            return
        if not _pg.acquire():
            try:
                self._apply(self._hi)
            except Exception:
                pass
            return
        self._running = True
        self._t0 = time.monotonic()
        self._w.after(0, self._tick)

    def cancel(self):
        if self._running:
            self._running = False
            _pg.release()
        try:
            self._apply(self._lo)
        except Exception:
            pass

    def _tick(self):
        if not self._running:
            return
        try:
            elapsed_ms = (time.monotonic() - self._t0) * 1000.0
            phase = (elapsed_ms % (2 * self._half)) / self._half  # 0..2
            t = phase if phase <= 1.0 else 2.0 - phase            # triangle 0→1→0
            if isinstance(self._lo, str):
                value = hex_lerp(self._lo, self._hi, ease_out_quad(t))
            else:
                value = lerp(self._lo, self._hi, ease_out_quad(t))
            self._apply(value)
            self._w.after(_FRAME_MS, self._tick)
        except Exception:
            self._running = False
            _pg.release()
