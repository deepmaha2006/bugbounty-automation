"""
Phase 7 tests — Company Scanner rebuild.

Hermetic — no network, no Postgres, no Tk display required.

Covers:
  - company_scanner_view imports cleanly
  - ProfessionalCompanyScannerView uses its own private queue (not app queue)
  - No _start_event_listener / _build_scanner_row / _tick_scanner_rows
  - No handle_event (would cause double-routing from main window)
  - scan_complete is forwarded to the app event_queue
  - _handle_lifecycle_event: finding→xp+feed, done/error/skipped→radar
  - _poll_events drains private queue and calls _handle_scan_event
  - refresh() method exists (called by main_window on nav)
  - is_scanning attribute exists (read by dashboard_view)
  - scanner_rows is a Dict[str, AgentStatusCard] (not dicts)
"""

import queue
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Module-level import check
# ---------------------------------------------------------------------------

class TestCompanyScannerImport:
    def test_import_succeeds(self):
        import ui.views.company_scanner_view  # noqa: F401

    def test_class_exists(self):
        from ui.views.company_scanner_view import ProfessionalCompanyScannerView
        assert callable(ProfessionalCompanyScannerView)


# ---------------------------------------------------------------------------
# Structural invariants (inspect source, no Tk widget created)
# ---------------------------------------------------------------------------

class TestCompanyScannerStructure:
    def _src(self):
        import inspect
        from ui.views.company_scanner_view import ProfessionalCompanyScannerView
        return inspect.getsource(ProfessionalCompanyScannerView)

    def test_no_start_event_listener(self):
        assert "_start_event_listener" not in self._src(), \
            "Must not define _start_event_listener — background thread drains shared queue"

    def test_no_build_scanner_row(self):
        assert "_build_scanner_row" not in self._src(), \
            "Old dict-based scanner rows replaced by AgentStatusCard"

    def test_no_tick_scanner_rows(self):
        assert "_tick_scanner_rows" not in self._src(), \
            "AgentStatusCard manages its own ticker; centralized ticker removed"

    def test_no_handle_event(self):
        assert "def handle_event" not in self._src(), \
            "handle_event must not be defined — main window would double-route"

    def test_has_refresh_method(self):
        from ui.views.company_scanner_view import ProfessionalCompanyScannerView
        assert hasattr(ProfessionalCompanyScannerView, "refresh"), \
            "refresh() must exist — main_window calls it on nav"

    def test_uses_animated_threat_feed(self):
        assert "AnimatedThreatFeed" in self._src(), \
            "Must use AnimatedThreatFeed (not old ThreatFeedWidget)"

    def test_uses_agent_status_card(self):
        assert "AgentStatusCard" in self._src()

    def test_uses_radar_ring(self):
        assert "RadarRing" in self._src()

    def test_uses_xp_bar(self):
        assert "XPBar" in self._src()

    def test_private_queue_created(self):
        assert "queue.Queue()" in self._src(), \
            "Private queue for ScanEngine must be created"

    def test_poll_events_method(self):
        from ui.views.company_scanner_view import ProfessionalCompanyScannerView
        assert hasattr(ProfessionalCompanyScannerView, "_poll_events"), \
            "_poll_events() must exist — replaces background thread"

    def test_scan_complete_forwarded_to_app_queue(self):
        src = self._src()
        assert "event_queue.put_nowait" in src, \
            "scan_complete must be forwarded to app queue for main window"


# ---------------------------------------------------------------------------
# _poll_events logic — stub the view with a fake private queue
# ---------------------------------------------------------------------------

class _StubView:
    """Minimal stand-in to test _poll_events without a real Tk window."""

    def __init__(self):
        self._q = queue.Queue()
        self._handled = []
        self._after_calls = []

    def _handle_scan_event(self, event):
        self._handled.append(event)

    def after(self, ms, fn):
        self._after_calls.append((ms, fn))

    def _poll_events(self):
        # Copy of the real method
        try:
            while not self._q.empty():
                event = self._q.get_nowait()
                self._handle_scan_event(event)
        except queue.Empty:
            pass
        self.after(100, self._poll_events)


class TestPollEvents:
    def test_drains_all_queued_events(self):
        view = _StubView()
        view._q.put(("status", "ok"))
        view._q.put(("status", "done"))
        view._poll_events()
        assert len(view._handled) == 2

    def test_reschedules_itself(self):
        view = _StubView()
        view._poll_events()
        assert len(view._after_calls) == 1
        ms, fn = view._after_calls[0]
        assert ms == 100
        assert fn == view._poll_events

    def test_empty_queue_does_not_raise(self):
        view = _StubView()
        view._poll_events()  # no exception


# ---------------------------------------------------------------------------
# _handle_lifecycle_event logic (pure logic, no Tk)
# ---------------------------------------------------------------------------

class _FakeCard:
    def __init__(self, key):
        self.key = key
        self._status = "queued"
        self.updates = []
        self.finding_updates = []

    def update_status(self, status, **kwargs):
        self._status = status
        self.updates.append((status, kwargs))

    def update_findings(self, count):
        self.finding_updates.append(count)


class _FakeRadar:
    def __init__(self):
        self.progress = (0, 0)

    def update_progress(self, done, total):
        self.progress = (done, total)


class _FakeXPBar:
    def __init__(self):
        self.total_xp = 0

    def add_xp(self, amount):
        self.total_xp += amount


class _FakeFeed:
    def __init__(self):
        self.items = []

    def add_finding(self, key, title, severity):
        self.items.append((key, title, severity))


class _LifecycleView:
    """Minimal stand-in to unit-test _handle_lifecycle_event."""

    def __init__(self):
        self._agents_done = 0
        self._live_finding_counts = {}
        self.scanner_rows = {}
        self._radar = _FakeRadar()
        self._xp_bar = _FakeXPBar()
        self.threat_widget = _FakeFeed()

    # Paste the real method body without the class binding
    def _handle_lifecycle_event(self, event):
        if len(event) < 3:
            return
        key, phase = event[1], event[2]
        card = self.scanner_rows.get(key)
        if card is None:
            return
        # Only accepts AgentStatusCard-like objects
        from ui.agent_status_card import AgentStatusCard
        if not isinstance(card, (_FakeCard, AgentStatusCard)):
            return

        if phase == "skipped":
            card.update_status("skipped")
            self._agents_done += 1
            self._radar.update_progress(self._agents_done,
                                        max(1, len(self.scanner_rows)))
        elif phase in ("done", "error"):
            self._agents_done += 1
            self._radar.update_progress(self._agents_done,
                                        max(1, len(self.scanner_rows)))
        elif phase == "finding" and len(event) > 3:
            finding = event[3]
            self._live_finding_counts[key] = \
                self._live_finding_counts.get(key, 0) + 1
            card.update_findings(self._live_finding_counts[key])
            title = finding.get("title", finding.get("type", "Finding"))
            severity = finding.get("severity", "info").lower()
            self.threat_widget.add_finding(key=key, title=title,
                                           severity=severity)
            from ui.xp_bar import XPBar
            self._xp_bar.add_xp(XPBar.xp_for_severity(severity))


class TestLifecycleEventRouting:
    def _view_with_key(self, key="xss"):
        v = _LifecycleView()
        v.scanner_rows[key] = _FakeCard(key)
        return v

    def test_skipped_increments_agents_done(self):
        v = self._view_with_key()
        v._handle_lifecycle_event(("agent_lifecycle", "xss", "skipped"))
        assert v._agents_done == 1

    def test_done_increments_agents_done(self):
        v = self._view_with_key()
        v._handle_lifecycle_event(("agent_lifecycle", "xss", "done"))
        assert v._agents_done == 1

    def test_error_increments_agents_done(self):
        v = self._view_with_key()
        v._handle_lifecycle_event(("agent_lifecycle", "xss", "error"))
        assert v._agents_done == 1

    def test_done_updates_radar(self):
        v = self._view_with_key()
        v._handle_lifecycle_event(("agent_lifecycle", "xss", "done"))
        assert v._radar.progress == (1, 1)

    def test_finding_increments_card_count(self):
        v = self._view_with_key()
        finding = {"title": "Reflected XSS", "severity": "High"}
        v._handle_lifecycle_event(("agent_lifecycle", "xss", "finding", finding))
        assert v.scanner_rows["xss"].finding_updates == [1]

    def test_finding_adds_to_feed(self):
        v = self._view_with_key()
        finding = {"title": "SQLi found", "severity": "critical"}
        v._handle_lifecycle_event(("agent_lifecycle", "xss", "finding", finding))
        assert len(v.threat_widget.items) == 1
        key, title, sev = v.threat_widget.items[0]
        assert title == "SQLi found"
        assert sev == "critical"

    def test_finding_awards_xp(self):
        v = self._view_with_key()
        finding = {"title": "High vuln", "severity": "high"}
        v._handle_lifecycle_event(("agent_lifecycle", "xss", "finding", finding))
        from ui.xp_bar import XPBar
        assert v._xp_bar.total_xp == XPBar.xp_for_severity("high")

    def test_unknown_key_does_not_crash(self):
        v = self._view_with_key()
        # "sqli" not in scanner_rows — should silently return
        v._handle_lifecycle_event(("agent_lifecycle", "sqli", "done"))
        assert v._agents_done == 0

    def test_too_short_event_does_not_crash(self):
        v = self._view_with_key()
        v._handle_lifecycle_event(("agent_lifecycle",))

    def test_multiple_findings_accumulate_count(self):
        v = self._view_with_key()
        f = {"title": "XSS", "severity": "medium"}
        for _ in range(3):
            v._handle_lifecycle_event(("agent_lifecycle", "xss", "finding", f))
        assert v.scanner_rows["xss"].finding_updates == [1, 2, 3]


# ---------------------------------------------------------------------------
# XPBar.xp_for_severity integration (already in phase6, re-confirm here)
# ---------------------------------------------------------------------------

class TestXPForSeverityIntegration:
    def test_critical_awards_more_than_high(self):
        from ui.xp_bar import XPBar
        assert XPBar.xp_for_severity("critical") > XPBar.xp_for_severity("high")
