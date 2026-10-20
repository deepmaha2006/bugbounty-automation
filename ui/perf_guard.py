"""
ui/perf_guard.py — performance guardrails for the tween engine.

Caps concurrent running tweens at MAX_ACTIVE_TWEENS.  When the cap is
reached, new tweens snap to their end value instead of animating, which
prevents animation stacking and Tk callback pile-ups during rapid-fire
scan events (e.g., 100 findings arriving within a second).

ui/motion.py imports this module; nothing here imports motion.
"""

import threading

MAX_ACTIVE_TWEENS: int = 16

_lock = threading.Lock()
_active: int = 0


def acquire() -> bool:
    """Claim a tween slot.  Returns True if the animation should run;
    False if the cap is reached and the tween should snap instead."""
    global _active
    with _lock:
        if _active >= MAX_ACTIVE_TWEENS:
            return False
        _active += 1
        return True


def release() -> None:
    """Release a previously acquired tween slot."""
    global _active
    with _lock:
        _active = max(0, _active - 1)


def reset() -> None:
    """Reset the counter to zero — call after a scan completes."""
    global _active
    with _lock:
        _active = 0


def active_count() -> int:
    """Return the number of currently running tween slots."""
    with _lock:
        return _active
