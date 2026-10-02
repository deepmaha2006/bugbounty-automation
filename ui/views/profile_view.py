"""
Profile view: operator identity (editable, persisted locally) plus a real
scan-history summary pulled from the report store. Styled like the web
profile page: purple accent, cover banner + avatar ring on the left,
KPI cards, a semicircle gauge and severity tiles on the right.

The desktop app has no login/session system (that only exists in webapp/),
so there is no existing "user model" to read from. This keeps the minimal
one the app actually needs: a local operator name + role, persisted to
config/profile.json using the same pattern settings_view.py already uses
for config/settings.json.
"""
import datetime
import json
import tkinter as tk
from typing import Dict, Optional

import customtkinter as ctk

from config.settings import APP_NAME, VERSION, PROJECT_ROOT
from ui.theme import (
    TEXT_PRIMARY,
    PROFILE_PAGE, PROFILE_CARD, PROFILE_CARD_2, PROFILE_LINE,
    PROFILE_ACCENT, PROFILE_ACCENT_HOVER, PROFILE_ACCENT_SOFT, PROFILE_ACCENT_TEXT, PROFILE_DIM,
    SEVERITY_COLORS,
    FONTS,
    SPACE_1, SPACE_2, SPACE_3, SPACE_4, SPACE_5, SPACE_6,
    RADIUS_NONE, RADIUS_SM, RADIUS_MD, RADIUS_LG,
    BTN_HEIGHT_MD, BTN_WIDTH_MD,
    INPUT_HEIGHT,
    BORDER_WIDTH_HAIRLINE, BORDER_WIDTH_ACCENT,
)

PROFILE_FILE = PROJECT_ROOT / "config" / "profile.json"
PROFILE_DEFAULTS = {"name": "Operator", "role": "Security Analyst"}
ROLES = ["Security Analyst", "Penetration Tester", "SOC Lead", "Bug Bounty Hunter", "Administrator"]
SEV_TILES = ["Critical", "High", "Medium", "Low"]
PAD = SPACE_6


def load_profile() -> dict:
    try:
        if PROFILE_FILE.exists():
            data = json.loads(PROFILE_FILE.read_text(encoding="utf-8"))
            merged = dict(PROFILE_DEFAULTS)
            merged.update(data)
            return merged
    except (OSError, json.JSONDecodeError):
        pass
    return dict(PROFILE_DEFAULTS)


def save_profile(data: dict) -> None:
    PROFILE_FILE.parent.mkdir(parents=True, exist_ok=True)
    PROFILE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _font(key: str) -> ctk.CTkFont:
    return ctk.CTkFont(*FONTS[key])


def _card(parent, **kw) -> ctk.CTkFrame:
    return ctk.CTkFrame(parent, fg_color=PROFILE_CARD, corner_radius=RADIUS_LG,
                        border_width=BORDER_WIDTH_HAIRLINE, border_color=PROFILE_LINE, **kw)


def _blend(c1: str, c2: str, t: float) -> str:
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))


class ProfileView(ctk.CTkFrame):
    """Operator profile + scan history summary."""

    def __init__(self, master, app):
        super().__init__(master, fg_color=PROFILE_PAGE, corner_radius=RADIUS_NONE)
        self.app = app
        self.profile = load_profile()
        self.build()

    # ------------------------------------------------------------------ data
    def _reports(self):
        try:
            return self.app.report_store.list_reports(limit=100000)
        except OSError:
            return []

    def _latest_counts(self, reports) -> Optional[Dict[str, int]]:
        """Severity counts of the latest scan: this session's report, else
        the newest saved JSON report. None when neither exists."""
        report = getattr(self.app, "last_report_data", None)
        if not report:
            for p in reports:
                if p.suffix == ".json":
                    try:
                        report = json.loads(p.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        report = None
                    break
        if not isinstance(report, dict):
            return None
        raw = report.get("severity_counts")
        if isinstance(raw, dict):
            return {k: int(raw.get(k, 0) or 0) for k in SEV_TILES}
        return None

    # ------------------------------------------------------------------ build
    def build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        body = ctk.CTkScrollableFrame(self, fg_color=PROFILE_PAGE, corner_radius=RADIUS_NONE,
                                      scrollbar_button_color=PROFILE_CARD_2,
                                      scrollbar_button_hover_color=PROFILE_LINE)
        body.grid(row=0, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=10, uniform="pcol")
        body.grid_columnconfigure(1, weight=11, uniform="pcol")

        # Breadcrumb: Account › <name>
        crumb = ctk.CTkFrame(body, fg_color="transparent")
        crumb.grid(row=0, column=0, columnspan=2, sticky="w", padx=PAD, pady=(PAD, SPACE_4))
        ctk.CTkLabel(crumb, text="Account", font=_font("small"), text_color=PROFILE_DIM).grid(row=0, column=0)
        ctk.CTkLabel(crumb, text="  ›  ", font=_font("small"), text_color=PROFILE_DIM).grid(row=0, column=1)
        self.crumb_name = ctk.CTkLabel(crumb, text=self.profile["name"], font=_font("mono"),
                                       text_color=TEXT_PRIMARY)
        self.crumb_name.grid(row=0, column=2)

        reports = self._reports()
        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=1, column=0, sticky="nsew", padx=(PAD, SPACE_3), pady=(0, PAD))
        left.grid_columnconfigure(0, weight=1)
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=1, column=1, sticky="nsew", padx=(SPACE_3, PAD), pady=(0, PAD))
        right.grid_columnconfigure(0, weight=1)

        self._build_profile_card(left, reports)
        self._build_kpis(right, reports)
        self._build_gauge(right, reports)
        self._build_tiles(right, reports)

    # ---- left: profile card -------------------------------------------
    def _build_profile_card(self, parent, reports):
        card = _card(parent)
        card.grid(row=0, column=0, sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        # Cover banner (purple gradient + faint circles) with the avatar ring
        # overlapping its bottom edge, drawn on one canvas.
        self.cover = tk.Canvas(card, height=150, bg=PROFILE_CARD, highlightthickness=0, bd=0)
        self.cover.grid(row=0, column=0, sticky="ew", padx=2, pady=(2, 0))
        self.cover.bind("<Configure>", lambda e: self._draw_cover())

        ident = ctk.CTkFrame(card, fg_color="transparent")
        ident.grid(row=1, column=0, sticky="ew", padx=SPACE_6)
        ident.grid_columnconfigure(0, weight=1)
        self.name_label = ctk.CTkLabel(ident, text=self.profile["name"], font=_font("subheading"),
                                       text_color=TEXT_PRIMARY, anchor="w")
        self.name_label.grid(row=0, column=0, sticky="w")
        self.role_badge = ctk.CTkLabel(ident, text=self.profile["role"], font=_font("small_bold"),
                                       fg_color=PROFILE_ACCENT_SOFT, text_color=PROFILE_ACCENT_TEXT,
                                       corner_radius=RADIUS_SM, height=22, padx=SPACE_3)
        self.role_badge.grid(row=1, column=0, sticky="w", pady=(SPACE_1, 0))

        # Info boxes (Location/Timezone-style)
        info = ctk.CTkFrame(card, fg_color="transparent")
        info.grid(row=2, column=0, sticky="ew", padx=SPACE_6, pady=(SPACE_4, 0))
        info.grid_columnconfigure((0, 1), weight=1, uniform="info")
        last = "No scans yet"
        if reports:
            mtime = max(p.stat().st_mtime for p in reports)
            last = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
        for col, (k, v) in enumerate([("Installation", f"{APP_NAME} v{VERSION}"), ("Last Scan", last)]):
            box = ctk.CTkFrame(info, fg_color=PROFILE_CARD_2, corner_radius=RADIUS_MD,
                               border_width=BORDER_WIDTH_HAIRLINE, border_color=PROFILE_LINE)
            box.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else SPACE_2, 0))
            ctk.CTkLabel(box, text=k, font=_font("small"), text_color=PROFILE_DIM,
                         anchor="w").grid(row=0, column=0, sticky="w", padx=SPACE_4, pady=(SPACE_3, 0))
            ctk.CTkLabel(box, text=v, font=_font("body_bold"), text_color=TEXT_PRIMARY,
                         anchor="w").grid(row=1, column=0, sticky="w", padx=SPACE_4, pady=(0, SPACE_3))

        # Editable form
        ctk.CTkFrame(card, fg_color=PROFILE_LINE, height=1, corner_radius=0).grid(
            row=3, column=0, sticky="ew", padx=SPACE_6, pady=SPACE_5)
        form = ctk.CTkFrame(card, fg_color="transparent")
        form.grid(row=4, column=0, sticky="ew", padx=SPACE_6, pady=(0, SPACE_6))
        form.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(form, text="Name", font=_font("small"), text_color=PROFILE_DIM,
                     anchor="w").grid(row=0, column=0, sticky="w")
        self.name_var = ctk.StringVar(value=self.profile["name"])
        name_entry = ctk.CTkEntry(
            form, textvariable=self.name_var, font=_font("body"), height=INPUT_HEIGHT,
            corner_radius=RADIUS_MD, border_width=BORDER_WIDTH_HAIRLINE, border_color=PROFILE_LINE,
            fg_color=PROFILE_PAGE, text_color=TEXT_PRIMARY,
        )
        name_entry.grid(row=1, column=0, sticky="ew", pady=(SPACE_1, SPACE_4))
        name_entry.bind("<FocusIn>", lambda e: name_entry.configure(
            border_color=PROFILE_ACCENT, border_width=BORDER_WIDTH_ACCENT))
        name_entry.bind("<FocusOut>", lambda e: name_entry.configure(
            border_color=PROFILE_LINE, border_width=BORDER_WIDTH_HAIRLINE))
        self.name_var.trace_add("write", self._on_name_changed)

        ctk.CTkLabel(form, text="Role", font=_font("small"), text_color=PROFILE_DIM,
                     anchor="w").grid(row=2, column=0, sticky="w")
        self.role_var = ctk.StringVar(value=self.profile["role"])
        ctk.CTkOptionMenu(
            form, variable=self.role_var, values=ROLES, font=_font("body"), height=INPUT_HEIGHT,
            corner_radius=RADIUS_MD, fg_color=PROFILE_PAGE, text_color=TEXT_PRIMARY,
            button_color=PROFILE_CARD_2, button_hover_color=PROFILE_ACCENT,
            dropdown_fg_color=PROFILE_CARD, dropdown_text_color=TEXT_PRIMARY,
            dropdown_hover_color=PROFILE_ACCENT_SOFT,
            command=self._on_role_changed,
        ).grid(row=3, column=0, sticky="ew", pady=(SPACE_1, SPACE_5))

        self.save_btn = ctk.CTkButton(
            form, text="Save Profile", command=self._save, font=_font("body_bold"),
            height=BTN_HEIGHT_MD, width=BTN_WIDTH_MD, corner_radius=RADIUS_MD,
            fg_color=PROFILE_ACCENT, hover_color=PROFILE_ACCENT_HOVER, text_color="#ffffff",
        )
        self.save_btn.grid(row=4, column=0, sticky="w")

    def _draw_cover(self):
        c = self.cover
        c.delete("all")
        w = max(c.winfo_width(), 2)
        band = 104
        steps = 48
        for i in range(steps):   # horizontal gradient #3b2f9e → #6c5cff → #2a2350
            t = i / (steps - 1)
            col = _blend("#3b2f9e", "#6c5cff", t * 2) if t < 0.5 else _blend("#6c5cff", "#2a2350", (t - 0.5) * 2)
            c.create_rectangle(w * i / steps, 0, w * (i + 1) / steps + 1, band, fill=col, width=0)
        for r in (60, 90, 120):
            c.create_oval(w - 60 - r, 20 - r, w - 60 + r, 20 + r, outline=_blend("#6c5cff", "#ffffff", 0.18))
        # clip the motif to the banner: repaint everything below it card-coloured
        c.create_rectangle(0, band, w, band + 200, fill=PROFILE_CARD, width=0)
        # role pill, top-right of the banner (the real role, not a status)
        role = self.role_var.get() if hasattr(self, "role_var") else self.profile["role"]
        tid = c.create_text(w - 16, 18, text=f"●  {role}", anchor="ne", fill="#ffffff",
                            font=(FONTS["small_bold"][0], FONTS["small_bold"][1], "bold"))
        x1, y1, x2, y2 = c.bbox(tid)
        c.create_rectangle(x1 - 10, y1 - 4, x2 + 10, y2 + 4, fill=_blend("#0e0e12", "#6c5cff", 0.35),
                           outline=_blend("#6c5cff", "#ffffff", 0.3))
        c.tag_raise(tid)
        # avatar: gradient ring + initial, overlapping the banner edge
        cx, cy, r = 24 + 44, band, 44
        c.create_oval(cx - r - 4, cy - r - 4, cx + r + 4, cy + r + 4, fill=PROFILE_CARD, width=0)
        for i, col in enumerate(["#6c5cff", "#b9b1ff", "#3b2f9e", "#6c5cff"]):
            c.create_arc(cx - r, cy - r, cx + r, cy + r, start=200 + i * 90, extent=91,
                         fill=col, outline=col)
        c.create_oval(cx - r + 3, cy - r + 3, cx + r - 3, cy + r - 3, fill="#1e1b3a", width=0)
        initial = ((self.name_var.get() if hasattr(self, "name_var") else self.profile["name"])[:1] or "?").upper()
        c.create_text(cx, cy, text=initial, fill="#ffffff", font=(FONTS["subheading"][0], 26, "bold"))
        c.configure(height=band + r + 4)

    # ---- right: KPIs, gauge, tiles --------------------------------------
    def _build_kpis(self, parent, reports):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.grid(row=0, column=0, sticky="ew", pady=(0, SPACE_4))
        row.grid_columnconfigure((0, 1, 2), weight=1, uniform="kpi")
        for i, (label, value) in enumerate([
            ("Reports Generated", str(len(reports))),
            ("Scans This Session", str(getattr(self.app, "scan_count", 0))),
            ("Saved Profile", "Yes" if PROFILE_FILE.exists() else "No"),
        ]):
            k = _card(row)
            k.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else SPACE_2, 0))
            ctk.CTkLabel(k, text=value, font=_font("stat_number"), text_color=TEXT_PRIMARY,
                         anchor="w").grid(row=0, column=0, sticky="w", padx=SPACE_5, pady=(SPACE_4, 0))
            ctk.CTkLabel(k, text=label, font=_font("small"), text_color=PROFILE_DIM,
                         anchor="w").grid(row=1, column=0, sticky="w", padx=SPACE_5, pady=(0, SPACE_4))

    def _completeness(self, reports):
        """Profile completeness — never presented as a security score.
        Share of these checks met: a name other than the default, the
        profile saved to disk, and at least one report generated."""
        checks = [
            ("Name", (self.profile.get("name") or "") not in ("", PROFILE_DEFAULTS["name"])),
            ("Saved", PROFILE_FILE.exists()),
            ("Scans", bool(reports)),
        ]
        pct = round(100 * sum(1 for _, ok in checks if ok) / len(checks))
        return pct, checks

    def _build_gauge(self, parent, reports):
        card = _card(parent)
        card.grid(row=1, column=0, sticky="ew", pady=(0, SPACE_4))
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(card, text="Profile Completeness", font=_font("body_bold"), text_color=TEXT_PRIMARY,
                     anchor="w").grid(row=0, column=0, sticky="w", padx=SPACE_6, pady=(SPACE_5, 0))

        pct, checks = self._completeness(reports)
        g = tk.Canvas(card, width=260, height=150, bg=PROFILE_CARD, highlightthickness=0, bd=0)
        g.grid(row=1, column=0, pady=(SPACE_2, 0))
        box = (30, 20, 230, 220)
        g.create_arc(*box, start=0, extent=180, style="arc", outline="#24242d", width=16)
        if pct:
            g.create_arc(*box, start=180, extent=-180 * pct / 100, style="arc",
                         outline=PROFILE_ACCENT, width=16)
        g.create_text(130, 100, text=f"{pct}%", fill=TEXT_PRIMARY,
                      font=(FONTS["score"][0], 30, "bold"))
        g.create_text(130, 132, text="Complete", fill=PROFILE_DIM, font=(FONTS["small"][0], 10))

        chips = ctk.CTkFrame(card, fg_color="transparent")
        chips.grid(row=2, column=0, pady=(0, SPACE_5))
        for i, (label, ok) in enumerate(checks):
            ctk.CTkLabel(chips, text=label, font=_font("small"), corner_radius=RADIUS_MD, height=22, padx=SPACE_3,
                         fg_color=PROFILE_ACCENT_SOFT if ok else PROFILE_CARD_2,
                         text_color=PROFILE_ACCENT_TEXT if ok else PROFILE_DIM).grid(row=0, column=i, padx=SPACE_1)

    def _build_tiles(self, parent, reports):
        counts = self._latest_counts(reports)
        total = sum(counts.values()) if counts else 0
        if not counts or not total:
            return   # no real breakdown to show — hide rather than invent
        card = _card(parent)
        card.grid(row=2, column=0, sticky="ew")
        card.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="tile")
        ctk.CTkLabel(card, text="Findings breakdown", font=_font("body_bold"), text_color=TEXT_PRIMARY,
                     anchor="w").grid(row=0, column=0, columnspan=3, sticky="w", padx=SPACE_6, pady=(SPACE_5, SPACE_3))
        ctk.CTkLabel(card, text="Latest scan", font=_font("small"), text_color=PROFILE_DIM,
                     anchor="e").grid(row=0, column=3, sticky="e", padx=SPACE_6, pady=(SPACE_5, SPACE_3))
        top = max(counts.values())
        for i, sev in enumerate(SEV_TILES):
            n = counts[sev]
            is_top = n == top
            tile = ctk.CTkFrame(card, corner_radius=RADIUS_MD, border_width=BORDER_WIDTH_HAIRLINE,
                                fg_color=PROFILE_ACCENT_SOFT if is_top else PROFILE_CARD_2,
                                border_color=PROFILE_ACCENT if is_top else PROFILE_LINE)
            tile.grid(row=1, column=i, sticky="ew", pady=(0, SPACE_6),
                      padx=(SPACE_6 if i == 0 else SPACE_1, SPACE_6 if i == 3 else SPACE_1))
            tile.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(tile, text=str(n), font=_font("stat_number"), text_color=TEXT_PRIMARY,
                         anchor="w").grid(row=0, column=0, sticky="w", padx=SPACE_4, pady=(SPACE_3, 0))
            ctk.CTkLabel(tile, text=sev, font=_font("small"), text_color=PROFILE_DIM,
                         anchor="w").grid(row=1, column=0, sticky="w", padx=SPACE_4)
            bar = ctk.CTkProgressBar(tile, height=4, corner_radius=2, fg_color="#24242d",
                                     progress_color=(PROFILE_ACCENT if is_top else SEVERITY_COLORS[sev])
                                     if n else "#24242d")
            bar.set(n / total)
            bar.grid(row=2, column=0, sticky="ew", padx=SPACE_4, pady=(SPACE_2, SPACE_4))

    # ------------------------------------------------------------------ events
    def _on_name_changed(self, *_args):
        name = self.name_var.get()
        self.name_label.configure(text=name)
        self.crumb_name.configure(text=name)
        self._draw_cover()

    def _on_role_changed(self, value):
        self.role_badge.configure(text=value)
        self._draw_cover()

    def _save(self):
        self.profile = {"name": self.name_var.get().strip() or PROFILE_DEFAULTS["name"],
                        "role": self.role_var.get()}
        save_profile(self.profile)
        self.save_btn.configure(text="Saved")
        self.after(1600, lambda: self.save_btn.winfo_exists() and self.save_btn.configure(text="Save Profile"))
        self.app.show_message("Profile saved", "Operator profile updated successfully.")

    def refresh(self):
        """Re-read scan history so counts stay current when navigating here."""
        for child in self.winfo_children():
            child.destroy()
        self.build()
