"""
Live Defense view — full WAF+IDS+SOAR control panel (Phase 21).

Sections:
  • Kill Switch bar — engage/disengage the global brain kill switch.
  • Controls row   — asset/org IDs, autonomy-tier selector, Refresh, Run Hunt.
  • Status line    — last refresh timestamp and hunt result.
  • Tabbed feeds   — Incidents | Events | Knowledge | Actions.

All DB/brain calls run in daemon threads; UI updates via after().
Auto-polls every 5 s while the view is on screen.
"""
from __future__ import annotations

import threading
from datetime import datetime
from typing import List, Optional

import customtkinter as ctk

from ui.theme import (
    SURFACE_BASE, SURFACE_MUTED, SURFACE_RAISED,
    BORDER_HAIRLINE, BORDER_ACCENT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY,
    SEVERITY_COLORS, STATUS_HIGH, STATUS_MEDIUM, STATUS_LOW,
    FONTS, SPACE_1, SPACE_2, SPACE_3, SPACE_4, SPACE_5, SPACE_6,
    RADIUS_NONE, RADIUS_MD, BORDER_WIDTH_HAIRLINE,
    BTN_HEIGHT_SM,
)
from ui.widgets import SectionHeader, GhostButton, EmptyState

POLL_INTERVAL_MS = 5000

try:
    from brain.autonomy import (
        KILL_SWITCH, AutonomyPolicy, AutonomyTier,
        get_policy, set_policy,
    )
    _BRAIN_OK = True
except Exception:
    _BRAIN_OK = False
    KILL_SWITCH = None  # type: ignore[assignment]

_TIERS = ["observe", "recommend", "auto_contain", "auto_remediate"]

# ── small helper rows ──────────────────────────────────────────────────────────

class _IncidentRow(ctk.CTkFrame):
    _SEV = {"critical": "#FF2D55", "high": STATUS_HIGH,
            "medium": STATUS_MEDIUM, "low": STATUS_LOW}

    def __init__(self, master, inc: dict):
        super().__init__(master, fg_color=SURFACE_MUTED, corner_radius=RADIUS_MD,
                         border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE)
        self.grid_columnconfigure(2, weight=1)
        sev = (inc.get("severity") or "low").lower()
        color = self._SEV.get(sev, STATUS_LOW)
        ctk.CTkLabel(self, text=sev.upper(), font=ctk.CTkFont(*FONTS["small_bold"]),
                     text_color=color, width=70).grid(
            row=0, column=0, padx=(SPACE_3, SPACE_2), pady=SPACE_2, sticky="w")
        attack = inc.get("attack_class") or inc.get("summary", "unknown")
        ctk.CTkLabel(self, text=attack, font=ctk.CTkFont(*FONTS["body"]),
                     text_color=TEXT_PRIMARY, anchor="w").grid(
            row=0, column=1, padx=SPACE_2, pady=SPACE_2, sticky="w")
        ctk.CTkLabel(self, text=inc.get("summary", ""), font=ctk.CTkFont(*FONTS["small"]),
                     text_color=TEXT_SECONDARY, anchor="w").grid(
            row=0, column=2, padx=SPACE_2, pady=SPACE_2, sticky="ew")
        ts = _fmt_ts(inc.get("first_seen")) + " → " + _fmt_ts(inc.get("last_seen"))
        ctk.CTkLabel(self, text=ts, font=ctk.CTkFont(*FONTS["small"]),
                     text_color=TEXT_TERTIARY, anchor="e").grid(
            row=0, column=3, padx=(SPACE_2, SPACE_3), pady=SPACE_2, sticky="e")


class _EventRow(ctk.CTkFrame):
    def __init__(self, master, ev: dict):
        super().__init__(master, fg_color=SURFACE_MUTED, corner_radius=RADIUS_MD,
                         border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE)
        self.grid_columnconfigure(1, weight=1)
        ts = _fmt_ts(ev.get("ts"))
        ctk.CTkLabel(self, text=ts, font=ctk.CTkFont(*FONTS["small"]),
                     text_color=TEXT_TERTIARY, width=80).grid(
            row=0, column=0, padx=(SPACE_3, SPACE_2), pady=SPACE_2, sticky="w")
        method = ev.get("method") or "?"
        path = ev.get("path") or ""
        ctk.CTkLabel(self, text=f"{method} {path}",
                     font=ctk.CTkFont(*FONTS["body"]), text_color=TEXT_PRIMARY,
                     anchor="w").grid(row=0, column=1, padx=SPACE_2, pady=SPACE_2, sticky="ew")
        sigs = ", ".join(k for k, v in (ev.get("signals") or {}).items() if v)
        ctk.CTkLabel(self, text=sigs, font=ctk.CTkFont(*FONTS["small"]),
                     text_color=TEXT_SECONDARY, anchor="e").grid(
            row=0, column=2, padx=(SPACE_2, SPACE_3), pady=SPACE_2, sticky="e")


class _KnowledgeRow(ctk.CTkFrame):
    def __init__(self, master, kb: dict):
        super().__init__(master, fg_color=SURFACE_MUTED, corner_radius=RADIUS_MD,
                         border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE)
        self.grid_columnconfigure(1, weight=1)
        ac = kb.get("attack_class") or "?"
        conf = kb.get("confidence", 0.0)
        seen = kb.get("times_seen", 0)
        ctk.CTkLabel(self, text=ac, font=ctk.CTkFont(*FONTS["body"]),
                     text_color=TEXT_PRIMARY, anchor="w", width=130).grid(
            row=0, column=0, padx=(SPACE_3, SPACE_2), pady=SPACE_2, sticky="w")
        fp = kb.get("signature_fingerprint") or ""
        ctk.CTkLabel(self, text=fp[:60], font=ctk.CTkFont(*FONTS["small"]),
                     text_color=TEXT_SECONDARY, anchor="w").grid(
            row=0, column=1, padx=SPACE_2, pady=SPACE_2, sticky="ew")
        stats = f"conf {conf:.2f}  ×{seen}"
        ctk.CTkLabel(self, text=stats, font=ctk.CTkFont(*FONTS["small"]),
                     text_color=TEXT_TERTIARY, anchor="e", width=90).grid(
            row=0, column=2, padx=(SPACE_2, SPACE_3), pady=SPACE_2, sticky="e")


class _ActionRow(ctk.CTkFrame):
    _STATUS_COLORS = {"pending": TEXT_TERTIARY, "applied": STATUS_MEDIUM,
                      "rolled_back": STATUS_HIGH, "expired": TEXT_TERTIARY}

    def __init__(self, master, action: dict):
        super().__init__(master, fg_color=SURFACE_MUTED, corner_radius=RADIUS_MD,
                         border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE)
        self.grid_columnconfigure(1, weight=1)
        status = (action.get("status") or "pending").lower()
        color = self._STATUS_COLORS.get(status, TEXT_TERTIARY)
        ctk.CTkLabel(self, text=status.upper(), font=ctk.CTkFont(*FONTS["small_bold"]),
                     text_color=color, width=90).grid(
            row=0, column=0, padx=(SPACE_3, SPACE_2), pady=SPACE_2, sticky="w")
        action_type = action.get("action_type") or "?"
        detail = str(action.get("detail") or "")[:80]
        ctk.CTkLabel(self, text=f"{action_type}: {detail}",
                     font=ctk.CTkFont(*FONTS["body"]), text_color=TEXT_PRIMARY,
                     anchor="w").grid(row=0, column=1, padx=SPACE_2, pady=SPACE_2, sticky="ew")
        ts = _fmt_ts(action.get("created_at"))
        ctk.CTkLabel(self, text=ts, font=ctk.CTkFont(*FONTS["small"]),
                     text_color=TEXT_TERTIARY, anchor="e").grid(
            row=0, column=2, padx=(SPACE_2, SPACE_3), pady=SPACE_2, sticky="e")


def _fmt_ts(raw) -> str:
    if not raw:
        return "—"
    if isinstance(raw, datetime):
        return raw.strftime("%H:%M:%S")
    try:
        return str(raw)[:19].replace("T", " ")
    except Exception:
        return "—"


# ── main view ─────────────────────────────────────────────────────────────────

class LiveDefenseView(ctk.CTkFrame):
    """Live Defense: kill-switch + tier control + tabbed incident/event/knowledge/action feeds."""

    def __init__(self, master, app=None):
        super().__init__(master, fg_color=SURFACE_BASE, corner_radius=RADIUS_NONE)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        self._app = app
        self._asset_id: Optional[int] = None
        self._org_id: Optional[int] = None
        self._poll_job = None
        self._hunt_running = False

        self._build()

    # ── construction ──────────────────────────────────────────────────────────

    def _build(self):
        # Row 0: section header
        SectionHeader(self, "Live Defense",
                      subtitle="WAF · IDS · SOAR — autonomous threat response").grid(
            row=0, column=0, sticky="ew", padx=SPACE_4, pady=(SPACE_4, 0))

        # Row 1: kill switch bar
        self._ks_bar = ctk.CTkFrame(self, fg_color=SURFACE_RAISED, corner_radius=RADIUS_MD)
        self._ks_bar.grid(row=1, column=0, sticky="ew", padx=SPACE_4, pady=(SPACE_2, 0))
        self._ks_bar.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(self._ks_bar, text="KILL SWITCH", font=ctk.CTkFont(*FONTS["small_bold"]),
                     text_color=TEXT_TERTIARY).grid(
            row=0, column=0, padx=(SPACE_4, SPACE_2), pady=SPACE_2)
        self._ks_state_lbl = ctk.CTkLabel(
            self._ks_bar, text="—", font=ctk.CTkFont(*FONTS["small_bold"]), text_color=TEXT_TERTIARY)
        self._ks_state_lbl.grid(row=0, column=1, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self._ks_btn = GhostButton(self._ks_bar, text="Engage", height=BTN_HEIGHT_SM,
                                   command=self._toggle_kill_switch)
        self._ks_btn.grid(row=0, column=2, padx=(SPACE_2, SPACE_4), pady=SPACE_2)
        self._update_kill_switch_ui()

        # Row 2: controls (asset/org IDs + tier + buttons)
        ctrl = ctk.CTkFrame(self, fg_color="transparent")
        ctrl.grid(row=2, column=0, sticky="ew", padx=SPACE_4, pady=SPACE_2)

        ctk.CTkLabel(ctrl, text="Asset:", font=ctk.CTkFont(*FONTS["small_bold"]),
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(0, SPACE_1))
        self._asset_entry = ctk.CTkEntry(ctrl, width=60, placeholder_text="1")
        self._asset_entry.pack(side="left", padx=(0, SPACE_3))

        ctk.CTkLabel(ctrl, text="Org:", font=ctk.CTkFont(*FONTS["small_bold"]),
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(0, SPACE_1))
        self._org_entry = ctk.CTkEntry(ctrl, width=60, placeholder_text="1")
        self._org_entry.pack(side="left", padx=(0, SPACE_3))

        ctk.CTkLabel(ctrl, text="Tier:", font=ctk.CTkFont(*FONTS["small_bold"]),
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(0, SPACE_1))
        self._tier_var = ctk.StringVar(value="observe")
        self._tier_menu = ctk.CTkOptionMenu(ctrl, variable=self._tier_var,
                                            values=_TIERS, width=140, height=BTN_HEIGHT_SM,
                                            command=self._on_tier_changed)
        self._tier_menu.pack(side="left", padx=(0, SPACE_3))

        GhostButton(ctrl, text="Refresh", height=BTN_HEIGHT_SM,
                    command=self.refresh).pack(side="left", padx=(0, SPACE_2))
        self._hunt_btn = GhostButton(ctrl, text="Run Hunt", height=BTN_HEIGHT_SM,
                                     command=self._run_hunt)
        self._hunt_btn.pack(side="left")

        # Row 3: status label
        self._status_lbl = ctk.CTkLabel(
            self, text="Enter asset/org IDs and click Refresh.",
            font=ctk.CTkFont(*FONTS["small"]), text_color=TEXT_TERTIARY)
        self._status_lbl.grid(row=3, column=0, sticky="w", padx=SPACE_4, pady=(0, SPACE_2))

        # Row 4: tab view
        self._tabs = ctk.CTkTabview(self, fg_color=SURFACE_BASE)
        self._tabs.grid(row=4, column=0, sticky="nsew", padx=SPACE_4, pady=(0, SPACE_4))
        self._tabs.grid_columnconfigure(0, weight=1)

        for name in ("Incidents", "Events", "Knowledge", "Actions"):
            tab = self._tabs.add(name)
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)
            scroll = ctk.CTkScrollableFrame(tab, fg_color=SURFACE_BASE)
            scroll.grid(row=0, column=0, sticky="nsew")
            scroll.grid_columnconfigure(0, weight=1)
            setattr(self, f"_scroll_{name.lower()}", scroll)

        self._render_incidents([])
        self._render_events([])
        self._render_knowledge([])
        self._render_actions([])

    # ── public / event pump ───────────────────────────────────────────────────

    def refresh(self):
        """Parse entries, fetch all feeds, update tier display."""
        try:
            asset_id = int(self._asset_entry.get() or "0")
            org_id = int(self._org_entry.get() or "0")
        except ValueError:
            self._set_status("Invalid asset/org ID.")
            return
        if asset_id <= 0 or org_id <= 0:
            self._set_status("Enter valid asset and org IDs.")
            return
        self._asset_id = asset_id
        self._org_id = org_id
        self._load_tier()
        threading.Thread(target=self._fetch_all, daemon=True).start()

    def handle_event(self, event: dict):
        pass  # brain events arrive via polling, not the app queue

    # ── kill switch ───────────────────────────────────────────────────────────

    def _toggle_kill_switch(self):
        if not _BRAIN_OK or KILL_SWITCH is None:
            return
        try:
            if KILL_SWITCH.engaged:
                KILL_SWITCH.disengage()
            else:
                KILL_SWITCH.engage()
        except Exception:
            pass
        self._update_kill_switch_ui()

    def _update_kill_switch_ui(self):
        if not _BRAIN_OK or KILL_SWITCH is None:
            self._ks_state_lbl.configure(text="unavailable", text_color=TEXT_TERTIARY)
            self._ks_btn.configure(state="disabled")
            return
        engaged = bool(KILL_SWITCH.engaged)
        if engaged:
            self._ks_state_lbl.configure(text="ENGAGED — observe only, all actions rolled back",
                                         text_color=STATUS_HIGH)
            self._ks_btn.configure(text="Disengage")
        else:
            self._ks_state_lbl.configure(text="disengaged", text_color=STATUS_LOW)
            self._ks_btn.configure(text="Engage")

    # ── tier ──────────────────────────────────────────────────────────────────

    def _load_tier(self):
        if not _BRAIN_OK or not self._asset_id:
            return
        try:
            policy = get_policy(self._asset_id, self._org_id)
            self._tier_var.set(policy.tier.value)
        except Exception:
            pass

    def _on_tier_changed(self, tier: str):
        if not _BRAIN_OK or not self._asset_id:
            return
        try:
            set_policy(AutonomyPolicy(
                asset_id=self._asset_id,
                org_id=self._org_id,
                tier=AutonomyTier(tier),
            ))
            self._set_status(f"Tier set to {tier}.")
        except Exception as exc:
            self._set_status(f"Tier change failed: {exc}")

    # ── hunt ──────────────────────────────────────────────────────────────────

    def _run_hunt(self):
        if self._hunt_running:
            return
        if not self._asset_id or not self._org_id:
            self._set_status("Set asset/org IDs first.")
            return
        self._hunt_running = True
        self._hunt_btn.configure(state="disabled")
        self._set_status("Running hunt…")
        threading.Thread(target=self._do_hunt, daemon=True).start()

    def _do_hunt(self):
        try:
            from brain.hunt import run_hunt
            report = run_hunt(self._asset_id, self._org_id,
                              max_iterations=5, max_seconds=30.0)
            msg = (f"Hunt done: {report.stopped_reason} — "
                   f"{report.iterations_run} iter, "
                   f"{report.total_events_processed} events, "
                   f"{report.total_actions_taken} actions")
            self.after(0, lambda: self._set_status(msg))
            self.after(0, lambda: threading.Thread(target=self._fetch_all, daemon=True).start())
        except Exception as exc:
            self.after(0, lambda: self._set_status(f"Hunt error: {exc}"))
        finally:
            self._hunt_running = False
            self.after(0, lambda: self._hunt_btn.configure(state="normal"))

    # ── fetch / render ────────────────────────────────────────────────────────

    def _fetch_all(self):
        if not self._asset_id or not self._org_id:
            return
        try:
            import webapp.db as db
            a, o = self._asset_id, self._org_id
            incidents = db.brain_list_incidents(asset_id=a, org_id=o, state="open", limit=200)
            events = db.brain_list_events(asset_id=a, org_id=o, limit=50)
            knowledge = db.brain_list_knowledge(asset_id=a, org_id=o, limit=50)
            actions = db.brain_list_actions(asset_id=a, org_id=o, limit=50)
            ts = datetime.now().strftime("%H:%M:%S")
            self.after(0, lambda: self._render_incidents(incidents))
            self.after(0, lambda: self._render_events(events))
            self.after(0, lambda: self._render_knowledge(knowledge))
            self.after(0, lambda: self._render_actions(actions))
            self.after(0, lambda: self._set_status(
                f"{len(incidents)} incidents · {len(events)} events · "
                f"{len(knowledge)} knowledge · {len(actions)} actions — {ts}"
            ))
        except Exception as exc:
            self.after(0, lambda: self._set_status(f"Fetch error: {exc}"))

    def _render_incidents(self, rows: list):
        self._render_tab("incidents", rows, lambda s, r: _IncidentRow(s, r),
                         "⬡", "No open incidents")

    def _render_events(self, rows: list):
        self._render_tab("events", rows, lambda s, r: _EventRow(s, r),
                         "⬡", "No recent events")

    def _render_knowledge(self, rows: list):
        self._render_tab("knowledge", rows, lambda s, r: _KnowledgeRow(s, r),
                         "⬡", "No knowledge entries")

    def _render_actions(self, rows: list):
        self._render_tab("actions", rows, lambda s, r: _ActionRow(s, r),
                         "⬡", "No actions taken")

    def _render_tab(self, name: str, rows: list, row_factory, empty_icon: str, empty_title: str):
        scroll = getattr(self, f"_scroll_{name}")
        for w in scroll.winfo_children():
            w.destroy()
        if not rows:
            EmptyState(scroll, empty_icon, empty_title).grid(row=0, column=0, pady=SPACE_6)
            return
        for i, r in enumerate(rows):
            widget = row_factory(scroll, r)
            widget.grid(row=i, column=0, sticky="ew", pady=(0, SPACE_2))

    # ── polling ───────────────────────────────────────────────────────────────

    def _set_status(self, msg: str):
        self._status_lbl.configure(text=msg)

    def _schedule_poll(self):
        if self._poll_job:
            self.after_cancel(self._poll_job)
        self._poll_job = self.after(POLL_INTERVAL_MS, self._auto_poll)

    def _auto_poll(self):
        self._update_kill_switch_ui()
        if self._asset_id and self._org_id:
            threading.Thread(target=self._fetch_all, daemon=True).start()
        self._schedule_poll()

    def grid(self, **kwargs):
        super().grid(**kwargs)
        self._schedule_poll()

    def grid_remove(self):
        if self._poll_job:
            self.after_cancel(self._poll_job)
            self._poll_job = None
        super().grid_remove()
