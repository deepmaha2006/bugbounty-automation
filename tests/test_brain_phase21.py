"""
Phase 21: Live Defense View full control panel.

Tests:
  LiveDefenseView construction
  • instantiates without error (headless CTk)
  • has _scroll_incidents / _scroll_events / _scroll_knowledge / _scroll_actions
  • has _ks_btn (kill switch button) and _tier_menu (tier selector)
  • has _hunt_btn (run hunt button)
  • handle_event is a no-op (does not raise)

  Kill-switch UI
  • _update_kill_switch_ui reflects KILL_SWITCH.engaged=False → label "disengaged"
  • _update_kill_switch_ui reflects KILL_SWITCH.engaged=True → label contains "ENGAGED"
  • _toggle_kill_switch engages when disengaged
  • _toggle_kill_switch disengages when engaged

  Tier control
  • _load_tier sets _tier_var to the stored policy tier
  • _on_tier_changed stores the policy via set_policy

  Hunt
  • _run_hunt sets hunt_running guard
  • _run_hunt rejects call when asset/org not set

  Rendering helpers
  • _render_incidents empty → EmptyState child
  • _render_incidents non-empty → row count matches
  • _render_events empty → EmptyState child
  • _render_events non-empty → row count matches
  • _render_knowledge empty → EmptyState child
  • _render_knowledge non-empty → row count matches
  • _render_actions empty → EmptyState child
  • _render_actions non-empty → row count matches

  Row widgets
  • _IncidentRow builds without error
  • _EventRow builds without error
  • _KnowledgeRow builds without error
  • _ActionRow builds without error

  _fmt_ts helper
  • None → "—"
  • datetime → HH:MM:SS format
  • ISO string → truncated at 19 chars with T→space
  • exception-safe (bad input → "—")
"""
import pytest

pytest.importorskip("customtkinter", reason="CTk not available in this env")

import customtkinter as ctk

from ui.views.live_defense_view import (
    LiveDefenseView,
    _IncidentRow,
    _EventRow,
    _KnowledgeRow,
    _ActionRow,
    _fmt_ts,
    _BRAIN_OK,
)


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


def test_view_has_scroll_frames(view):
    assert hasattr(view, "_scroll_incidents")
    assert hasattr(view, "_scroll_events")
    assert hasattr(view, "_scroll_knowledge")
    assert hasattr(view, "_scroll_actions")


def test_view_has_kill_switch_btn(view):
    assert hasattr(view, "_ks_btn")


def test_view_has_tier_menu(view):
    assert hasattr(view, "_tier_menu")


def test_view_has_hunt_btn(view):
    assert hasattr(view, "_hunt_btn")


def test_handle_event_is_noop(view):
    view.handle_event({"type": "scan_complete"})  # must not raise


# ---------------------------------------------------------------------------
# Kill-switch UI
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _BRAIN_OK, reason="brain modules unavailable")
def test_ks_ui_disengaged(view):
    from brain.autonomy import KILL_SWITCH
    KILL_SWITCH.disengage()
    view._update_kill_switch_ui()
    label_text = view._ks_state_lbl.cget("text")
    assert "disengaged" in label_text.lower()


@pytest.mark.skipif(not _BRAIN_OK, reason="brain modules unavailable")
def test_ks_ui_engaged(view):
    from brain.autonomy import KILL_SWITCH
    KILL_SWITCH.engage()
    try:
        view._update_kill_switch_ui()
        label_text = view._ks_state_lbl.cget("text")
        assert "ENGAGED" in label_text.upper()
    finally:
        KILL_SWITCH.disengage()


@pytest.mark.skipif(not _BRAIN_OK, reason="brain modules unavailable")
def test_toggle_engages(view):
    from brain.autonomy import KILL_SWITCH
    KILL_SWITCH.disengage()
    view._toggle_kill_switch()
    try:
        assert KILL_SWITCH.engaged
    finally:
        KILL_SWITCH.disengage()


@pytest.mark.skipif(not _BRAIN_OK, reason="brain modules unavailable")
def test_toggle_disengages(view):
    from brain.autonomy import KILL_SWITCH
    KILL_SWITCH.engage()
    try:
        view._toggle_kill_switch()
        assert not KILL_SWITCH.engaged
    finally:
        KILL_SWITCH.disengage()


# ---------------------------------------------------------------------------
# Tier control
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _BRAIN_OK, reason="brain modules unavailable")
def test_load_tier_sets_var(view, fake):
    from brain.autonomy import AutonomyPolicy, AutonomyTier, set_policy
    view._asset_id = 1
    view._org_id = 1
    set_policy(AutonomyPolicy(asset_id=1, org_id=1, tier=AutonomyTier.RECOMMEND))
    view._load_tier()
    assert view._tier_var.get() == "recommend"


@pytest.mark.skipif(not _BRAIN_OK, reason="brain modules unavailable")
def test_on_tier_changed_stores_policy(view, fake):
    view._asset_id = 1
    view._org_id = 1
    view._on_tier_changed("auto_contain")
    from brain.autonomy import get_policy
    assert get_policy(1, 1).tier.value == "auto_contain"


# ---------------------------------------------------------------------------
# Hunt guard
# ---------------------------------------------------------------------------

def test_run_hunt_rejects_without_ids(view):
    view._asset_id = None
    view._org_id = None
    view._run_hunt()
    status = view._status_lbl.cget("text")
    assert "asset" in status.lower() or "org" in status.lower()


def test_run_hunt_sets_running_guard(view, monkeypatch):
    view._hunt_running = True
    called = []
    monkeypatch.setattr(view, "_do_hunt", lambda: called.append(1))
    view._asset_id = 1
    view._org_id = 1
    view._run_hunt()
    assert called == []


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def test_render_incidents_empty(view):
    view._render_incidents([])
    children = view._scroll_incidents.winfo_children()
    assert len(children) == 1  # EmptyState


def test_render_incidents_rows(view):
    rows = [
        {"severity": "high", "attack_class": "xss", "summary": "test", "first_seen": None},
        {"severity": "medium", "attack_class": "sqli", "summary": "test2", "last_seen": None},
    ]
    view._render_incidents(rows)
    children = view._scroll_incidents.winfo_children()
    assert len(children) == 2


def test_render_events_empty(view):
    view._render_events([])
    assert len(view._scroll_events.winfo_children()) == 1


def test_render_events_rows(view):
    rows = [{"ts": None, "method": "GET", "path": "/x", "signals": {"xss_hint": True}}]
    view._render_events(rows)
    assert len(view._scroll_events.winfo_children()) == 1


def test_render_knowledge_empty(view):
    view._render_knowledge([])
    assert len(view._scroll_knowledge.winfo_children()) == 1


def test_render_knowledge_rows(view):
    rows = [{"attack_class": "sqli", "confidence": 0.8, "times_seen": 3,
             "signature_fingerprint": "fp1"}]
    view._render_knowledge(rows)
    assert len(view._scroll_knowledge.winfo_children()) == 1


def test_render_actions_empty(view):
    view._render_actions([])
    assert len(view._scroll_actions.winfo_children()) == 1


def test_render_actions_rows(view):
    rows = [{"status": "applied", "action_type": "block_ip",
             "detail": "1.2.3.4", "created_at": None}]
    view._render_actions(rows)
    assert len(view._scroll_actions.winfo_children()) == 1


# ---------------------------------------------------------------------------
# Row widgets
# ---------------------------------------------------------------------------

def test_incident_row_builds(root):
    inc = {"severity": "critical", "attack_class": "rce",
           "summary": "payload detected", "first_seen": None, "last_seen": None}
    row = _IncidentRow(root, inc)
    assert row is not None


def test_event_row_builds(root):
    ev = {"ts": "2026-10-19T12:00:00", "method": "POST", "path": "/login",
          "signals": {"sqli_hint": True}}
    row = _EventRow(root, ev)
    assert row is not None


def test_knowledge_row_builds(root):
    kb = {"attack_class": "xss", "confidence": 0.9, "times_seen": 5,
          "signature_fingerprint": "abc123"}
    row = _KnowledgeRow(root, kb)
    assert row is not None


def test_action_row_builds(root):
    action = {"status": "pending", "action_type": "rate_limit",
              "detail": "1.2.3.4", "created_at": None}
    row = _ActionRow(root, action)
    assert row is not None


# ---------------------------------------------------------------------------
# _fmt_ts helper
# ---------------------------------------------------------------------------

def test_fmt_ts_none():
    assert _fmt_ts(None) == "—"


def test_fmt_ts_datetime():
    from datetime import datetime
    dt = datetime(2026, 10, 19, 12, 34, 56)
    assert _fmt_ts(dt) == "12:34:56"


def test_fmt_ts_iso_string():
    result = _fmt_ts("2026-10-19T12:34:56.000Z")
    assert result == "2026-10-19 12:34:56"


def test_fmt_ts_bad_input():
    result = _fmt_ts(object())
    assert isinstance(result, str)
