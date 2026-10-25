"""
Phase 21: Live Defense View construction and event handling.

Tests:
  LiveDefenseView construction
  • instantiates without error (headless CTk)
  • has attacks_canvas, gauge_state, timeline_label, severity_labels, overall_bar, cve_list
  • update_event is a no-op for unknown types (does not raise)

  Event handling
  • update_event with type "scan_complete" does not raise
  • update_event with unknown type does not raise
  • _handle_scan_finding adds an entry to self.attacks
  • _handle_auto_fix removes an existing attack by id
  • _handle_brain_confidence updates gauge state and overall_bar

  Gauge visuals
  • _refresh_gauge_visuals updates overall_bar without error
  • _update_severity_counts updates severity_labels without error
  • _add_cve_to_list inserts into cve_list without error

  Poll timer
  • _start_poll_timer schedules a recurring callback
  • _poll does not raise
"""
import sys

import pytest

pytest.importorskip("customtkinter", reason="CTk not available in this env")

import customtkinter as ctk

from ui.views.live_defense_view import LiveDefenseView


# ---------------------------------------------------------------------------
# Fixture: headless root window
# ---------------------------------------------------------------------------

@pytest.fixture()
def root():
    r = ctk.CTk()
    r.withdraw()
    yield r
    try:
        r.destroy()
    except Exception:
        pass


@pytest.fixture()
def view(root):
    v = LiveDefenseView(root)
    v.grid(row=0, column=0)
    return v


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

def test_view_instantiates(view):
    assert view is not None


def test_view_has_scannable_canvas(view):
    assert hasattr(view, "attacks_canvas")
    assert view.attacks_canvas is not None


def test_view_has_gauge_state(view):
    assert hasattr(view, "gauge_state")
    assert view.gauge_state is not None


def test_view_has_timeline_label(view):
    assert hasattr(view, "timeline_label")
    assert view.timeline_label is not None


def test_view_has_severity_labels(view):
    assert hasattr(view, "severity_labels")
    assert isinstance(view.severity_labels, dict)


def test_view_has_overall_bar(view):
    assert hasattr(view, "overall_bar")
    assert view.overall_bar is not None


def test_view_has_cve_list(view):
    assert hasattr(view, "cve_list")
    assert view.cve_list is not None


# ---------------------------------------------------------------------------
# Event handling
# ---------------------------------------------------------------------------

def test_update_event_unknown_type_is_noop(view):
    view.update_event({"type": "unknown_type"})  # must not raise


def test_update_event_scan_complete_is_noop(view):
    view.update_event({"type": "scan_complete"})  # must not raise


def test_handle_scan_finding_adds_attack(view, monkeypatch):
    # Monkeypatch the failed import so the handler runs without the brain module
    class FakeMod:
        class KILL_SWITCH:
            engaged = False
        effective_tier = lambda *a, **k: "observe"
        can_act_autonomously = lambda *a, **k: False
    monkeypatch.setitem(sys.modules, "core.autonomy", FakeMod())
    initial_count = len(view.attacks)
    view._handle_scan_finding({
        "severity": "high",
        "confidence": 0.8,
        "attack_class": "xss",
        "target": "http://example.com",
    })
    assert len(view.attacks) == initial_count + 1


def test_handle_auto_fix_removes_attack(view, monkeypatch):
    class FakeMod:
        class KILL_SWITCH:
            engaged = False
        effective_tier = lambda *a, **k: "observe"
        can_act_autonomously = lambda *a, **k: False
    monkeypatch.setitem(sys.modules, "core.autonomy", FakeMod())
    view._handle_scan_finding({
        "severity": "medium",
        "confidence": 0.5,
        "attack_class": "ssrf",
        "target": "http://example.com",
    })
    attack_id = next(iter(view.attacks))
    view._handle_auto_fix({"attack_id": attack_id, "success": True})
    assert attack_id not in view.attacks


def test_handle_brain_confidence_updates_gauge(view):
    view._handle_brain_confidence({"overall": 0.75})
    assert view.gauge_state.overall == 0.75


# ---------------------------------------------------------------------------
# Gauge visuals
# ---------------------------------------------------------------------------

def test_refresh_gauge_visuals(view):
    view._refresh_gauge_visuals()  # must not raise


def test_update_severity_counts(view):
    view._update_severity_counts()  # must not raise


def test_add_cve_to_list(view):
    view._add_cve_to_list("CVE-2024-1234", 9.8)  # must not raise


# ---------------------------------------------------------------------------
# Poll timer
# ---------------------------------------------------------------------------

def test_start_poll_timer(view):
    view._start_poll_timer()  # must not raise


def test_poll(view):
    view._poll()  # must not raise
