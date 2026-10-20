"""
Phase 5 tests — ui/motion.py tween engine + AgentStatusCard.

All hermetic — no network, no Postgres, no Tk display required.

Covers:
  - lerp / ease_out_quad / hex_lerp math
  - Tweener / ColorTweener / PulseTweener with REDUCE_MOTION=True snap
  - REDUCE_MOTION module flag can be toggled at runtime
  - ui.motion imports cleanly
  - ui.agent_status_card imports cleanly (headless — no CTk widget created)
"""

import pytest
import ui.motion as motion


# ---------------------------------------------------------------------------
# lerp
# ---------------------------------------------------------------------------

class TestLerp:
    def test_lerp_at_zero(self):
        assert motion.lerp(0.0, 10.0, 0.0) == pytest.approx(0.0)

    def test_lerp_at_one(self):
        assert motion.lerp(0.0, 10.0, 1.0) == pytest.approx(10.0)

    def test_lerp_midpoint(self):
        assert motion.lerp(0.0, 10.0, 0.5) == pytest.approx(5.0)

    def test_lerp_clamps_below_zero(self):
        assert motion.lerp(0.0, 10.0, -1.0) == pytest.approx(0.0)

    def test_lerp_clamps_above_one(self):
        assert motion.lerp(0.0, 10.0, 2.0) == pytest.approx(10.0)

    def test_lerp_reverse(self):
        assert motion.lerp(10.0, 0.0, 0.5) == pytest.approx(5.0)


# ---------------------------------------------------------------------------
# ease_out_quad
# ---------------------------------------------------------------------------

class TestEaseOutQuad:
    def test_starts_at_zero(self):
        assert motion.ease_out_quad(0.0) == pytest.approx(0.0)

    def test_ends_at_one(self):
        assert motion.ease_out_quad(1.0) == pytest.approx(1.0)

    def test_midpoint_more_than_half(self):
        # Ease-out means it covers more than half the range by t=0.5
        assert motion.ease_out_quad(0.5) > 0.5

    def test_clamps_negative(self):
        assert motion.ease_out_quad(-0.5) == pytest.approx(0.0)

    def test_clamps_over_one(self):
        assert motion.ease_out_quad(1.5) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# hex_lerp
# ---------------------------------------------------------------------------

class TestHexLerp:
    def test_at_zero_returns_first_colour(self):
        result = motion.hex_lerp("#000000", "#ffffff", 0.0)
        assert result == "#000000"

    def test_at_one_returns_second_colour(self):
        result = motion.hex_lerp("#000000", "#ffffff", 1.0)
        assert result == "#ffffff"

    def test_midpoint_is_grey(self):
        result = motion.hex_lerp("#000000", "#ffffff", 0.5)
        # Each channel should be ~128 (0x80)
        r = int(result[1:3], 16)
        g = int(result[3:5], 16)
        b = int(result[5:7], 16)
        assert 126 <= r <= 128
        assert 126 <= g <= 128
        assert 126 <= b <= 128

    def test_returns_valid_hex_string(self):
        result = motion.hex_lerp("#ff0000", "#0000ff", 0.3)
        assert result.startswith("#")
        assert len(result) == 7
        int(result[1:], 16)  # raises ValueError if not valid hex

    def test_clamps_above_one(self):
        assert motion.hex_lerp("#000000", "#ffffff", 2.0) == "#ffffff"

    def test_bad_colour_returns_end(self):
        # Gracefully handles malformed input
        result = motion.hex_lerp("notacolor", "#ffffff", 0.5)
        assert result == "#ffffff"


# ---------------------------------------------------------------------------
# REDUCE_MOTION flag
# ---------------------------------------------------------------------------

class TestReduceMotion:
    def test_flag_is_bool(self):
        assert isinstance(motion.REDUCE_MOTION, bool)

    def test_flag_can_be_set_at_runtime(self):
        original = motion.REDUCE_MOTION
        try:
            motion.REDUCE_MOTION = True
            assert motion.REDUCE_MOTION is True
            motion.REDUCE_MOTION = False
            assert motion.REDUCE_MOTION is False
        finally:
            motion.REDUCE_MOTION = original

    def test_env_var_respected(self, monkeypatch):
        # Re-importing after env change is not trivially testable here, but
        # we can verify the default value logic by examining the module.
        import importlib, os
        orig = os.environ.get("HYDRAX_REDUCE_MOTION")
        try:
            os.environ["HYDRAX_REDUCE_MOTION"] = "1"
            import ui.motion as m2
            importlib.reload(m2)
            assert m2.REDUCE_MOTION is True
        finally:
            if orig is None:
                os.environ.pop("HYDRAX_REDUCE_MOTION", None)
            else:
                os.environ["HYDRAX_REDUCE_MOTION"] = orig
            importlib.reload(motion)


# ---------------------------------------------------------------------------
# Tweener — REDUCE_MOTION=True snap path (no Tk widget needed)
# ---------------------------------------------------------------------------

class _FakeWidget:
    """Minimal stand-in so Tweener doesn't need a real CTk widget."""
    def after(self, ms, fn):
        fn()   # execute immediately for tests


class TestTweenerReduceMotion:
    def test_snaps_to_end_when_reduce_motion(self):
        original = motion.REDUCE_MOTION
        motion.REDUCE_MOTION = True
        try:
            results = []
            t = motion.Tweener(
                _FakeWidget(), lambda v: results.append(v),
                start=0.0, end=100.0, duration_ms=500,
            )
            t.start()
            assert results == [100.0]
        finally:
            motion.REDUCE_MOTION = original

    def test_on_done_called_when_reduce_motion(self):
        original = motion.REDUCE_MOTION
        motion.REDUCE_MOTION = True
        try:
            done = []
            t = motion.Tweener(
                _FakeWidget(), lambda v: None,
                start=0.0, end=1.0, duration_ms=100,
                on_done=lambda: done.append(True),
            )
            t.start()
            assert done == [True]
        finally:
            motion.REDUCE_MOTION = original

    def test_cancel_stops_tween(self):
        original = motion.REDUCE_MOTION
        motion.REDUCE_MOTION = False
        try:
            t = motion.Tweener(
                _FakeWidget(), lambda v: None,
                start=0.0, end=1.0, duration_ms=200,
            )
            t.cancel()
            assert not t._running
        finally:
            motion.REDUCE_MOTION = original


class TestColorTweenerReduceMotion:
    def test_snaps_to_end_colour_when_reduce_motion(self):
        original = motion.REDUCE_MOTION
        motion.REDUCE_MOTION = True
        try:
            results = []
            t = motion.ColorTweener(
                _FakeWidget(), lambda c: results.append(c),
                start="#000000", end="#ffffff", duration_ms=200,
            )
            t.start()
            assert results == ["#ffffff"]
        finally:
            motion.REDUCE_MOTION = original


class TestPulseTweenerReduceMotion:
    def test_applies_hi_and_stops_when_reduce_motion(self):
        original = motion.REDUCE_MOTION
        motion.REDUCE_MOTION = True
        try:
            results = []
            p = motion.PulseTweener(
                _FakeWidget(), lambda v: results.append(v),
                lo="#111111", hi="#ffffff",
            )
            p.start()
            # When reduce motion, should apply hi immediately and not loop
            assert results == ["#ffffff"]
            assert not p._running
        finally:
            motion.REDUCE_MOTION = original

    def test_cancel_stops_and_applies_lo(self):
        original = motion.REDUCE_MOTION
        motion.REDUCE_MOTION = True
        try:
            results = []
            p = motion.PulseTweener(
                _FakeWidget(), lambda v: results.append(v),
                lo="#000000", hi="#ffffff",
            )
            p.cancel()
            assert "#000000" in results
        finally:
            motion.REDUCE_MOTION = original


# ---------------------------------------------------------------------------
# AgentStatusCard — import + static properties (no Tk widget created)
# ---------------------------------------------------------------------------

class TestAgentStatusCardModule:
    def test_import_succeeds(self):
        import ui.agent_status_card  # noqa: F401

    def test_dot_colors_cover_all_statuses(self):
        from ui.agent_status_card import _DOT_COLORS, _STATUS_LABELS
        for status in ("queued", "running", "done", "error", "skipped"):
            assert status in _DOT_COLORS, f"Missing dot color for {status}"
            assert status in _STATUS_LABELS, f"Missing status label for {status}"

    def test_dot_colors_are_valid_hex(self):
        from ui.agent_status_card import _DOT_COLORS
        for status, color in _DOT_COLORS.items():
            assert color.startswith("#"), f"{status}: color {color!r} must start with #"

    def test_frame_ms_is_positive(self):
        assert motion._FRAME_MS > 0

    def test_target_fps_is_30(self):
        assert motion._TARGET_FPS == 30
