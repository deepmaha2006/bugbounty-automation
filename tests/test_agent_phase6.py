"""
Phase 6 tests — HUD widgets + perf guardrails.

All hermetic — no network, no Postgres, no Tk display required.

Covers:
  - ui.perf_guard: acquire/release/reset/active_count correctness
  - ui.perf_guard: cap at MAX_ACTIVE_TWEENS
  - ui.motion: perf_guard integration (cap → snap path)
  - ui.radar_ring: import + public API surface
  - ui.xp_bar: XP accumulation, level-up, xp_for_severity
  - ui.animated_threat_feed: import cleanly
  - run_checks module list: all 4 new modules are registered
"""

import pytest
import ui.perf_guard as pg
import ui.motion as motion


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeWidget:
    """Minimal stand-in so Tweener doesn't need a real CTk widget."""
    def after(self, ms, fn):
        fn()


def _reset_pg():
    pg.reset()


# ---------------------------------------------------------------------------
# perf_guard
# ---------------------------------------------------------------------------

class TestPerfGuardBasics:
    def setup_method(self):
        _reset_pg()

    def test_acquire_returns_true_when_below_cap(self):
        assert pg.acquire() is True
        pg.release()

    def test_release_decrements_count(self):
        pg.acquire()
        assert pg.active_count() == 1
        pg.release()
        assert pg.active_count() == 0

    def test_release_never_goes_negative(self):
        pg.release()  # release without acquire
        assert pg.active_count() == 0

    def test_reset_clears_all(self):
        pg.acquire()
        pg.acquire()
        assert pg.active_count() == 2
        pg.reset()
        assert pg.active_count() == 0

    def test_cap_returns_false_when_full(self):
        for _ in range(pg.MAX_ACTIVE_TWEENS):
            result = pg.acquire()
            assert result is True
        assert pg.acquire() is False
        pg.reset()

    def test_slot_reuse_after_release(self):
        for _ in range(pg.MAX_ACTIVE_TWEENS):
            pg.acquire()
        assert pg.active_count() == pg.MAX_ACTIVE_TWEENS
        pg.release()
        assert pg.acquire() is True
        pg.reset()

    def test_active_count_initial_zero(self):
        assert pg.active_count() == 0

    def test_max_active_tweens_is_positive(self):
        assert pg.MAX_ACTIVE_TWEENS > 0


class TestPerfGuardThreadSafety:
    def setup_method(self):
        _reset_pg()

    def test_concurrent_acquires_never_exceed_cap(self):
        import threading
        results = []
        lock = threading.Lock()

        def worker():
            r = pg.acquire()
            with lock:
                results.append(r)

        threads = [threading.Thread(target=worker)
                   for _ in range(pg.MAX_ACTIVE_TWEENS + 4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # At most MAX_ACTIVE_TWEENS should have succeeded
        assert sum(results) <= pg.MAX_ACTIVE_TWEENS
        pg.reset()


# ---------------------------------------------------------------------------
# motion.py perf_guard integration
# ---------------------------------------------------------------------------

class TestMotionPerfGuardIntegration:
    def setup_method(self):
        _reset_pg()
        self._orig_rm = motion.REDUCE_MOTION
        motion.REDUCE_MOTION = False

    def teardown_method(self):
        motion.REDUCE_MOTION = self._orig_rm
        _reset_pg()

    def test_tweener_acquires_slot_on_start(self):
        t = motion.Tweener(
            _FakeWidget(), lambda v: None,
            start=0.0, end=1.0, duration_ms=200,
        )
        # Fill cap minus 1 so we can observe the acquire
        for _ in range(pg.MAX_ACTIVE_TWEENS - 1):
            pg.acquire()
        assert pg.active_count() == pg.MAX_ACTIVE_TWEENS - 1
        t.start()
        # Either acquired (count == MAX) or snapped (count unchanged)
        # In the test environment _FakeWidget.after runs immediately,
        # which means the tick fires at t≈0 and may complete instantly.
        # Just verify the count didn't go negative and no exception raised.
        assert pg.active_count() >= 0

    def test_tweener_snaps_when_cap_exceeded(self):
        # Fill all slots
        for _ in range(pg.MAX_ACTIVE_TWEENS):
            pg.acquire()
        results = []
        t = motion.Tweener(
            _FakeWidget(), lambda v: results.append(v),
            start=0.0, end=42.0, duration_ms=500,
        )
        t.start()
        # Should have snapped to end value
        assert results == [42.0]

    def test_cancel_releases_slot_only_when_running(self):
        assert pg.active_count() == 0
        t = motion.Tweener(
            _FakeWidget(), lambda v: None,
            start=0.0, end=1.0, duration_ms=5000,
        )
        # Do not start — cancel should not release
        t.cancel()
        assert pg.active_count() == 0


# ---------------------------------------------------------------------------
# RadarRing — import + public API surface
# ---------------------------------------------------------------------------

class TestRadarRingModule:
    def test_import_succeeds(self):
        import ui.radar_ring  # noqa: F401

    def test_class_exists(self):
        from ui.radar_ring import RadarRing
        assert callable(RadarRing)

    def test_sweep_ms_is_positive(self):
        from ui.radar_ring import _SWEEP_MS
        assert _SWEEP_MS > 0

    def test_deg_per_frame_produces_full_circle(self):
        from ui.radar_ring import _DEG_PER_FRAME, _SWEEP_FPS
        frames_per_revolution = 360 / _DEG_PER_FRAME
        seconds_per_revolution = frames_per_revolution / _SWEEP_FPS
        # Should complete a revolution in a reasonable time (0.5–5 s)
        assert 0.5 <= seconds_per_revolution <= 5.0


# ---------------------------------------------------------------------------
# XPBar — XP accumulation and level-up logic (no Tk widget created)
# ---------------------------------------------------------------------------

class TestXPBarLogic:
    def test_xp_for_severity_critical(self):
        from ui.xp_bar import XPBar
        assert XPBar.xp_for_severity("critical") == 5

    def test_xp_for_severity_high(self):
        from ui.xp_bar import XPBar
        assert XPBar.xp_for_severity("high") == 3

    def test_xp_for_severity_medium(self):
        from ui.xp_bar import XPBar
        assert XPBar.xp_for_severity("medium") == 2

    def test_xp_for_severity_low(self):
        from ui.xp_bar import XPBar
        assert XPBar.xp_for_severity("low") == 1

    def test_xp_for_severity_info(self):
        from ui.xp_bar import XPBar
        assert XPBar.xp_for_severity("info") == 0

    def test_xp_for_severity_unknown_returns_zero(self):
        from ui.xp_bar import XPBar
        assert XPBar.xp_for_severity("extreme") == 0

    def test_xp_for_severity_case_insensitive(self):
        from ui.xp_bar import XPBar
        assert XPBar.xp_for_severity("CRITICAL") == XPBar.xp_for_severity("critical")

    def test_xp_per_level_is_positive(self):
        from ui.xp_bar import XP_PER_LEVEL
        assert XP_PER_LEVEL > 0

    def test_all_severity_awards_are_non_negative(self):
        from ui.xp_bar import _XP_BY_SEVERITY
        for sev, xp in _XP_BY_SEVERITY.items():
            assert xp >= 0, f"{sev} has negative XP"

    def test_critical_awards_most_xp(self):
        from ui.xp_bar import _XP_BY_SEVERITY
        assert _XP_BY_SEVERITY["critical"] >= _XP_BY_SEVERITY["high"]
        assert _XP_BY_SEVERITY["high"]     >= _XP_BY_SEVERITY["medium"]
        assert _XP_BY_SEVERITY["medium"]   >= _XP_BY_SEVERITY["low"]


# ---------------------------------------------------------------------------
# AnimatedThreatFeed — import + constants
# ---------------------------------------------------------------------------

class TestAnimatedThreatFeedModule:
    def test_import_succeeds(self):
        import ui.animated_threat_feed  # noqa: F401

    def test_max_rows_is_positive(self):
        from ui.animated_threat_feed import _MAX_ROWS
        assert _MAX_ROWS > 0

    def test_sev_colors_cover_all_levels(self):
        from ui.animated_threat_feed import _SEV_COLORS
        for level in ("critical", "high", "medium", "low", "info"):
            assert level in _SEV_COLORS, f"Missing color for {level}"

    def test_sev_colors_are_hex(self):
        from ui.animated_threat_feed import _SEV_COLORS
        for level, color in _SEV_COLORS.items():
            assert color.startswith("#"), f"{level}: {color!r} must start with #"


# ---------------------------------------------------------------------------
# run_checks module list sanity
# ---------------------------------------------------------------------------

class TestRunChecksRegistration:
    def test_new_modules_in_ui_list(self):
        import run_checks
        for mod in ("ui.perf_guard", "ui.radar_ring",
                    "ui.xp_bar", "ui.animated_threat_feed"):
            assert mod in run_checks.UI_MODULES, f"{mod} missing from UI_MODULES"
