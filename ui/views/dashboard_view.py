"""
Dashboard view — mirrors the web dashboard's "SOC terminal" layout:
header + live pill, a compact KPI strip with share bars, a stacked severity
bar, the recent-scans grid (tinted rows, worst-severity alert badge) and a
quick-scan panel with the latest findings.

Only real data is shown: the latest scan comes from this session's report
(app.last_report_data) or, failing that, the newest saved JSON report; the
grid lists saved report files. Values the data can't supply show "—".
"""

import json
import tkinter as tk
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import customtkinter as ctk

from ui.theme import (
    SURFACE_BASE, SURFACE_MUTED, SURFACE_STRONG, SURFACE_RAISED,
    BORDER_HAIRLINE, BORDER_ACCENT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY, TEXT_INVERSE,
    SEVERITY_COLORS, STATUS_OK, STATUS_INFO,
    ROW_BAD, ROW_GOOD,
    FONTS,
    SPACE_1, SPACE_2, SPACE_3, SPACE_4, SPACE_6,
    RADIUS_NONE, RADIUS_XS, RADIUS_SM, RADIUS_MD,
    BTN_HEIGHT_MD, BTN_WIDTH_MD,
    INPUT_HEIGHT, CARD_PADDING,
    BORDER_WIDTH_HAIRLINE, BORDER_WIDTH_ACCENT,
)
from ui.widgets import GhostButton, PrimaryButton, ThreatFeedWidget, make_card

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
GRID_ROWS = 10
POLL_MS = 2000
MAX_JSON_BYTES = 5 * 1024 * 1024


def _font(key: str) -> ctk.CTkFont:
    return ctk.CTkFont(*FONTS[key])


def _counts(report: Optional[dict]) -> Optional[Dict[str, int]]:
    """Severity counts from a report dict, or None when it has none."""
    if not report:
        return None
    raw = report.get("severity_counts")
    if isinstance(raw, dict):
        return {k: int(raw.get(k, raw.get(k.lower(), 0)) or 0) for k in SEV_ORDER}
    findings = report.get("findings")
    if isinstance(findings, list):
        out = {k: 0 for k in SEV_ORDER}
        for f in findings:
            sev = str((f or {}).get("severity", "Info")).capitalize()
            if sev in out:
                out[sev] += 1
        return out
    return None


def _target_from_filename(path: Path) -> str:
    # report_<target>_<YYYYmmdd>_<HHMMSS>.<ext>  (see core/storage.py)
    stem = path.stem
    if stem.startswith("report_"):
        stem = stem[len("report_"):]
    parts = stem.rsplit("_", 2)
    return parts[0] if len(parts) == 3 else stem


def _relative(ts: Optional[datetime]) -> str:
    if not ts:
        return "—"
    sec = (datetime.now() - ts).total_seconds()
    if sec < 45:
        return "just now"
    if sec < 3600:
        return f"{int(sec // 60)}m ago"
    if sec < 86400:
        return f"{int(sec // 3600)}h ago"
    if sec < 30 * 86400:
        return f"{int(sec // 86400)}d ago"
    return ts.strftime("%b %d")


class ProfessionalDashboardView(ctk.CTkFrame):
    """Dashboard: real counts from the latest scan + saved reports."""

    def __init__(self, master, app):
        super().__init__(master, fg_color=SURFACE_BASE, corner_radius=RADIUS_NONE)
        self.app = app
        self._kpis: Dict[str, dict] = {}
        self._sev_counts: Dict[str, int] = {k: 0 for k in SEV_ORDER}
        self._last_seen_report = None
        self.build()
        self.refresh()
        self.after(POLL_MS, self._poll)

    # ------------------------------------------------------------------ build
    def build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._create_header()

        body = ctk.CTkScrollableFrame(
            self, fg_color=SURFACE_BASE, corner_radius=RADIUS_NONE,
            scrollbar_button_color=SURFACE_STRONG, scrollbar_button_hover_color=BORDER_HAIRLINE,
        )
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        self.body = body

        self._create_kpis(body)
        self._create_sev_bar(body)

        main = ctk.CTkFrame(body, fg_color="transparent")
        main.grid(row=2, column=0, sticky="nsew", padx=SPACE_6, pady=(0, SPACE_6))
        main.grid_columnconfigure(0, weight=5)
        main.grid_columnconfigure(1, weight=3)
        self._create_grid(main)
        self._create_side(main)

    def _create_header(self):
        header = ctk.CTkFrame(self, fg_color=SURFACE_MUTED, corner_radius=RADIUS_NONE,
                              border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE, height=64)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        header.grid_columnconfigure(0, weight=1)
        header.grid_rowconfigure((0, 1), weight=1)

        ctk.CTkLabel(header, text="Overview", font=_font("heading"), text_color=TEXT_PRIMARY,
                     anchor="w").grid(row=0, column=0, sticky="sw", padx=SPACE_6)
        self.scope_label = ctk.CTkLabel(header, text="", font=_font("small"),
                                        text_color=TEXT_SECONDARY, anchor="w")
        self.scope_label.grid(row=1, column=0, sticky="nw", padx=SPACE_6)

        self.live_pill = ctk.CTkLabel(header, text="", font=_font("small_bold"), corner_radius=RADIUS_MD,
                                      fg_color=SURFACE_BASE, text_color=TEXT_SECONDARY, padx=SPACE_4, height=26)
        self.live_pill.grid(row=0, column=1, rowspan=2, padx=SPACE_6)

    def _create_kpis(self, parent):
        strip = ctk.CTkFrame(parent, fg_color="transparent")
        strip.grid(row=0, column=0, sticky="ew", padx=SPACE_6, pady=(SPACE_6, SPACE_3))
        specs = [
            ("reports", "REPORTS", TEXT_TERTIARY),
            ("running", "RUNNING", STATUS_OK),
            ("findings", "FINDINGS", TEXT_TERTIARY),
            ("score", "SECURITY SCORE", TEXT_TERTIARY),
            ("Critical", "CRITICAL", SEVERITY_COLORS["Critical"]),
            ("High", "HIGH", SEVERITY_COLORS["High"]),
            ("Medium", "MEDIUM", SEVERITY_COLORS["Medium"]),
            ("Low", "LOW", SEVERITY_COLORS["Low"]),
        ]
        for i, (key, label, color) in enumerate(specs):
            strip.grid_columnconfigure(i, weight=1, uniform="kpi")
            card = ctk.CTkFrame(strip, fg_color=SURFACE_MUTED, corner_radius=RADIUS_SM,
                                border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE)
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else SPACE_1, 0))
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=label, font=_font("small_bold"), text_color=TEXT_SECONDARY,
                         anchor="w").grid(row=0, column=0, sticky="ew", padx=SPACE_4, pady=(SPACE_3, 0))
            value = ctk.CTkLabel(card, text="—", font=_font("stat_number"), anchor="w",
                                 text_color=color if key in SEV_ORDER else TEXT_PRIMARY)
            value.grid(row=1, column=0, sticky="ew", padx=SPACE_4)
            spark = ctk.CTkProgressBar(card, height=3, corner_radius=2, fg_color=BORDER_HAIRLINE,
                                       progress_color=color)
            spark.set(0)
            spark.grid(row=2, column=0, sticky="ew", padx=SPACE_4, pady=(SPACE_2, SPACE_4))
            self._kpis[key] = {"value": value, "spark": spark, "color": color}

    def _create_sev_bar(self, parent):
        self.sev_canvas = tk.Canvas(parent, height=6, bg=SURFACE_BASE, highlightthickness=0, bd=0)
        self.sev_canvas.grid(row=1, column=0, sticky="ew", padx=SPACE_6, pady=(0, SPACE_6))
        self.sev_canvas.bind("<Configure>", lambda e: self._draw_sev_bar())

    def _create_grid(self, parent):
        card = make_card(parent)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, SPACE_3))
        card.grid_columnconfigure(0, weight=1)

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_3))
        head.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(head, text="Recent Scans", font=_font("subheading"), text_color=TEXT_PRIMARY,
                     anchor="w").grid(row=0, column=0, sticky="w")
        GhostButton(head, text="View all", width=90, height=28,
                    command=lambda: self.app._switch_view("reports")).grid(row=0, column=1, sticky="e")

        # Column header — same columns as the web grid, minus the ones a
        # report file can't answer (Type/Status).
        self._cols = [("TARGET", 5, "w"), ("ALERT", 3, "w"), ("FINDINGS", 2, "e"),
                      ("SCORE", 2, "e"), ("FORMAT", 2, "w"), ("DATE", 2, "e")]
        thead = ctk.CTkFrame(card, fg_color=SURFACE_BASE, corner_radius=RADIUS_NONE, height=28)
        thead.grid(row=1, column=0, sticky="ew", padx=CARD_PADDING)
        self._layout_cols(thead)
        for c, (title, _, anchor) in enumerate(self._cols):
            ctk.CTkLabel(thead, text=title, font=_font("small_bold"), text_color=TEXT_SECONDARY,
                         anchor=anchor).grid(row=0, column=c, sticky="ew", padx=SPACE_3, pady=SPACE_2)

        self.rows_frame = ctk.CTkFrame(card, fg_color="transparent")
        self.rows_frame.grid(row=2, column=0, sticky="ew", padx=CARD_PADDING, pady=(0, CARD_PADDING))
        self.rows_frame.grid_columnconfigure(0, weight=1)

    def _layout_cols(self, frame):
        for c, (_, weight, _) in enumerate(self._cols):
            frame.grid_columnconfigure(c, weight=weight, uniform="dtcol")

    def _create_side(self, parent):
        side = ctk.CTkFrame(parent, fg_color="transparent")
        side.grid(row=0, column=1, sticky="nsew", padx=(SPACE_3, 0))
        side.grid_columnconfigure(0, weight=1)

        # Quick scan
        qs = make_card(side)
        qs.grid(row=0, column=0, sticky="ew", pady=(0, SPACE_4))
        qs.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(qs, text="Quick Scan", font=_font("subheading"), text_color=TEXT_PRIMARY,
                     anchor="w").grid(row=0, column=0, sticky="ew", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_3))

        self.app_target_entry = ctk.CTkEntry(
            qs, placeholder_text="https://target.app", height=INPUT_HEIGHT, font=_font("body"),
            corner_radius=RADIUS_SM, border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE,
            fg_color=SURFACE_BASE, text_color=TEXT_PRIMARY, placeholder_text_color=TEXT_SECONDARY,
        )
        self.app_target_entry.grid(row=1, column=0, sticky="ew", padx=CARD_PADDING, pady=(0, SPACE_3))
        self.app_target_entry.bind("<FocusIn>", lambda e: self.app_target_entry.configure(
            border_color=BORDER_ACCENT, border_width=BORDER_WIDTH_ACCENT))
        self.app_target_entry.bind("<FocusOut>", lambda e: self.app_target_entry.configure(
            border_color=BORDER_HAIRLINE, border_width=BORDER_WIDTH_HAIRLINE))

        self.app_profile_var = ctk.StringVar(value="web-full")
        self.app_profile_menu = ctk.CTkOptionMenu(
            qs, values=["web-full", "cloud", "api-security", "network-infrastructure"],
            variable=self.app_profile_var, font=_font("small"), height=INPUT_HEIGHT,
            corner_radius=RADIUS_SM, fg_color=SURFACE_BASE, text_color=TEXT_PRIMARY,
            button_color=SURFACE_STRONG, button_hover_color=SURFACE_RAISED,
            dropdown_fg_color=SURFACE_MUTED, dropdown_text_color=TEXT_PRIMARY,
            dropdown_hover_color=SURFACE_STRONG,
        )
        self.app_profile_menu.grid(row=2, column=0, sticky="ew", padx=CARD_PADDING, pady=(0, SPACE_3))

        btns = ctk.CTkFrame(qs, fg_color="transparent")
        btns.grid(row=3, column=0, sticky="ew", padx=CARD_PADDING, pady=(0, SPACE_3))
        btns.grid_columnconfigure((0, 1), weight=1)
        self.app_scan_btn = PrimaryButton(btns, text="Start Scan", command=self._start_app_scan,
                                          width=BTN_WIDTH_MD, height=BTN_HEIGHT_MD)
        self.app_scan_btn.grid(row=0, column=0, sticky="ew", padx=(0, SPACE_2))
        self.app_stop_btn = GhostButton(btns, text="Stop", command=self._stop_app_scan,
                                        width=BTN_WIDTH_MD, height=BTN_HEIGHT_MD, state="disabled")
        self.app_stop_btn.grid(row=0, column=1, sticky="ew", padx=(SPACE_2, 0))

        presets = ctk.CTkFrame(qs, fg_color="transparent")
        presets.grid(row=4, column=0, sticky="ew", padx=CARD_PADDING, pady=(0, CARD_PADDING))
        presets.grid_columnconfigure((0, 1), weight=1)
        for i, (label, profile) in enumerate([("Full Scan", "web-full"), ("API Security", "api-security"),
                                              ("Network Infra", "network-infrastructure"), ("Quick Recon", "recon")]):
            GhostButton(presets, text=label, height=28, width=80, font=_font("small"),
                        command=lambda p=profile: self._start_quick_scan(p)).grid(
                row=i // 2, column=i % 2, sticky="ew", padx=(0 if i % 2 == 0 else SPACE_1, 0), pady=(0, SPACE_1))

        # Latest findings (from the latest real scan)
        feed = make_card(side)
        feed.grid(row=1, column=0, sticky="nsew")
        feed.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(feed, text="Latest Findings", font=_font("subheading"), text_color=TEXT_PRIMARY,
                     anchor="w").grid(row=0, column=0, sticky="ew", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_2))
        self.threat_feed = ThreatFeedWidget(feed, threats=[])
        self.threat_feed.grid(row=1, column=0, sticky="nsew", padx=CARD_PADDING, pady=(0, CARD_PADDING))

    # ------------------------------------------------------------------ data
    def _latest_report(self) -> tuple:
        """(report dict, scope text) for the newest scan with real data."""
        report = getattr(self.app, "last_report_data", None)
        if report:
            return report, f"Latest scan: {report.get('target', '')} (this session)"
        for row in self._saved_rows:
            if row.get("data"):
                return row["data"], f"Latest scan: {row['target']} (saved report)"
        return None, "No scans yet"

    def _load_saved_rows(self) -> List[dict]:
        store = getattr(self.app, "report_store", None)
        if not store:
            return []
        rows = []
        try:
            paths = store.list_reports(limit=GRID_ROWS)
        except OSError:
            return []
        for p in paths:
            try:
                mtime = datetime.fromtimestamp(p.stat().st_mtime)
            except OSError:
                continue
            row = {"path": p, "target": _target_from_filename(p), "fmt": p.suffix.lstrip(".").upper(),
                   "when": mtime, "data": None}
            if p.suffix == ".json":
                try:
                    if p.stat().st_size <= MAX_JSON_BYTES:
                        data = json.loads(p.read_text(encoding="utf-8"))
                        if isinstance(data, dict):
                            row["data"] = data
                            row["target"] = str(data.get("target") or row["target"])
                except (OSError, ValueError):
                    pass
            rows.append(row)
        return rows

    def _running_count(self) -> int:
        views = getattr(self.app, "views", {}) or {}
        return sum(1 for key in ("website_scanner", "company_scanner")
                   if getattr(views.get(key), "is_scanning", False))

    def refresh(self):
        """Re-read the latest scan + saved reports and redraw. Called by the
        main window every time this view is shown."""
        self._saved_rows = self._load_saved_rows()
        report, scope = self._latest_report()
        self._last_seen_report = getattr(self.app, "last_report_data", None)
        self.scope_label.configure(text=scope)

        counts = _counts(report)
        total = sum(counts.values()) if counts else None
        store = getattr(self.app, "report_store", None)
        try:
            n_reports = len(store.list_reports(limit=100000)) if store else None
        except OSError:
            n_reports = None

        score = report.get("security_score") if report else None
        self._set_kpi("reports", n_reports, 1.0 if n_reports else 0)
        self._set_running()
        self._set_kpi("findings", total, self._share(counts, ("Critical", "High"), total))
        self._set_kpi("score", f"{int(score)}%" if isinstance(score, (int, float)) else None,
                      (float(score) / 100) if isinstance(score, (int, float)) else 0)
        for sev in ("Critical", "High", "Medium", "Low"):
            self._set_kpi(sev, counts[sev] if counts else None, self._share(counts, (sev,), total))

        self._sev_counts = counts or {k: 0 for k in SEV_ORDER}
        self._draw_sev_bar()
        self._render_rows()
        self._render_feed(report)

    @staticmethod
    def _share(counts, keys, total) -> float:
        if not counts or not total:
            return 0
        return sum(counts[k] for k in keys) / total

    def _set_kpi(self, key, value, frac):
        kpi = self._kpis.get(key)
        if not kpi:
            return
        kpi["value"].configure(text="—" if value is None else str(value))
        frac = max(0.0, min(1.0, float(frac or 0)))
        # CTkProgressBar still paints a rounded cap at 0 — hide it by
        # matching the track colour.
        kpi["spark"].configure(progress_color=kpi["color"] if frac > 0 else BORDER_HAIRLINE)
        kpi["spark"].set(frac)

    def _set_running(self):
        running = self._running_count()
        self._set_kpi("running", running, 1.0 if running else 0)
        if running:
            self.live_pill.configure(text=f"●  {running} running", text_color=STATUS_OK)
        else:
            self.live_pill.configure(text="●  Idle", text_color=TEXT_SECONDARY)

    def _draw_sev_bar(self):
        c = self.sev_canvas
        c.delete("all")
        w = c.winfo_width()
        total = sum(self._sev_counts.get(k, 0) for k in SEV_ORDER[:4])
        if w <= 1:
            return
        if not total:
            c.create_rectangle(0, 0, w, 6, fill=BORDER_HAIRLINE, width=0)
            return
        x = 0.0
        for sev in SEV_ORDER[:4]:
            n = self._sev_counts.get(sev, 0)
            if not n:
                continue
            seg = w * n / total
            c.create_rectangle(x, 0, x + seg - 2, 6, fill=SEVERITY_COLORS[sev], width=0)
            x += seg

    def _render_rows(self):
        for child in self.rows_frame.winfo_children():
            child.destroy()
        rows = list(self._saved_rows)
        session = getattr(self.app, "last_report_data", None)
        if session:
            rows.insert(0, {"path": None, "target": str(session.get("target", "")), "fmt": "SESSION",
                            "when": self._parse_ts(session.get("timestamp")), "data": session})
        if not rows:
            empty = ctk.CTkFrame(self.rows_frame, fg_color="transparent")
            empty.grid(row=0, column=0, sticky="ew", pady=SPACE_6)
            empty.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(empty, text="No scans yet", font=_font("body"),
                         text_color=TEXT_SECONDARY).grid(row=0, column=0, pady=(0, SPACE_3))
            PrimaryButton(empty, text="Run a scan", width=BTN_WIDTH_MD,
                          command=lambda: self.app._switch_view("website_scanner")).grid(row=1, column=0)
            return
        for i, row in enumerate(rows[:GRID_ROWS]):
            self._render_row(i, row)

    def _render_row(self, i: int, row: dict):
        counts = _counts(row.get("data"))
        total = sum(counts.values()) if counts else None
        worst = next((s for s in SEV_ORDER if counts and counts[s] > 0), None)
        bad = bool(counts and (counts["Critical"] + counts["High"]) > 0)
        good = counts is not None and total == 0
        bg = ROW_BAD if bad else ROW_GOOD if good else SURFACE_MUTED

        frame = ctk.CTkFrame(self.rows_frame, fg_color=bg, corner_radius=RADIUS_NONE, height=34)
        frame.grid(row=i, column=0, sticky="ew", pady=(1, 0))
        frame.grid_propagate(False)
        frame.grid_rowconfigure(0, weight=1)
        self._layout_cols(frame)

        dot_color = SEVERITY_COLORS.get(worst, STATUS_INFO) if worst else BORDER_HAIRLINE
        cells = []
        # Leading dot in the worst-severity colour, then the target.
        tcell = ctk.CTkFrame(frame, fg_color="transparent")
        tcell.grid(row=0, column=0, sticky="ew", padx=SPACE_3)
        tcell.grid_columnconfigure(1, weight=1)
        dot = ctk.CTkLabel(tcell, text="●", font=_font("small"), text_color=dot_color, width=12)
        dot.grid(row=0, column=0, padx=(0, SPACE_2))
        target = ctk.CTkLabel(tcell, text=row["target"], font=_font("mono"),
                              text_color=TEXT_PRIMARY, anchor="w")
        target.grid(row=0, column=1, sticky="ew")
        cells.extend([tcell, dot, target])

        if worst:
            alert = ctk.CTkLabel(frame, text=f"{worst} ×{counts[worst]}", font=_font("small_bold"),
                                 fg_color=SEVERITY_COLORS[worst], text_color=TEXT_INVERSE,
                                 corner_radius=RADIUS_XS, height=20, padx=SPACE_2)
            alert.grid(row=0, column=1, sticky="w", padx=SPACE_3)
        else:
            alert = ctk.CTkLabel(frame, text="None" if counts is not None else "—", font=_font("small"),
                                 text_color=TEXT_SECONDARY, anchor="w")
            alert.grid(row=0, column=1, sticky="ew", padx=SPACE_3)
        cells.append(alert)

        score = (row.get("data") or {}).get("security_score")
        for col, text, color in [
            (2, "—" if total is None else str(total), SEVERITY_COLORS.get(worst, TEXT_SECONDARY) if worst else TEXT_SECONDARY),
            (3, f"{int(score)}%" if isinstance(score, (int, float)) else "—", TEXT_SECONDARY),
            (4, row["fmt"], TEXT_SECONDARY),
            (5, _relative(row.get("when")), TEXT_SECONDARY),
        ]:
            lbl = ctk.CTkLabel(frame, text=text, font=_font("mono"), text_color=color,
                               anchor="w" if col == 4 else "e")
            lbl.grid(row=0, column=col, sticky="ew", padx=SPACE_3)
            cells.append(lbl)

        def open_row(_e=None, r=row):
            if r["path"] is None:
                self.app._switch_view("results")
            else:
                self.app.report_store.open_report(r["path"])

        hover = SURFACE_STRONG
        for w in [frame] + cells:
            w.configure(cursor="hand2")
            w.bind("<Button-1>", open_row)
            w.bind("<Enter>", lambda e, f=frame: f.configure(fg_color=hover))
            w.bind("<Leave>", lambda e, f=frame, c=bg: f.configure(fg_color=c))

    @staticmethod
    def _parse_ts(value) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(str(value)) if value else None
        except ValueError:
            return None

    def _render_feed(self, report: Optional[dict]):
        items = self._findings_as_feed_items(report) if report else []
        if not items:
            items = [{"time": "--:--", "threat": "No findings yet — run a scan to populate this feed.",
                      "severity": "Info"}]
        self.threat_feed.update_threats(items[:6])

    _SEVERITY_ORDER = {s: i for i, s in enumerate(SEV_ORDER)}

    def _findings_as_feed_items(self, report: dict) -> list:
        """Flatten a ScanReport.to_dict() (nested results) or a saved,
        normalized report (flat findings) into feed rows."""
        findings = []
        for result in (report.get("results") or {}).values():
            findings.extend(result.get("vulnerabilities") or [])
        if not findings and isinstance(report.get("findings"), list):
            findings = list(report["findings"])
        findings.sort(key=lambda f: self._SEVERITY_ORDER.get(f.get("severity"), 9))

        time_label = ""
        ts = self._parse_ts(report.get("timestamp"))
        if ts:
            time_label = ts.strftime("%H:%M")
        return [{
            "time": time_label,
            "threat": f"{f.get('type', 'Finding')}: {f.get('description') or f.get('url') or ''}".strip(": "),
            "severity": f.get("severity", "Info"),
        } for f in findings]

    # ------------------------------------------------------------------ live
    def _poll(self):
        """Main-thread poll (Tk after(), no worker thread): keep the running
        count live and redraw once a new scan report lands."""
        try:
            if not self.winfo_exists():
                return
            self._set_running()
            if getattr(self.app, "last_report_data", None) is not self._last_seen_report:
                self.refresh()
        except tk.TclError:
            return
        self.after(POLL_MS, self._poll)

    # ------------------------------------------------------------------ actions
    def _start_quick_scan(self, profile_name: str):
        """Open the website scanner (profiles are chosen there)."""
        self.app._switch_view("website_scanner")

    def _start_app_scan(self):
        """Hand the quick-scan target over to the website scanner view."""
        target = self.app_target_entry.get().strip()
        if not target:
            return
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
            self.app_target_entry.delete(0, "end")
            self.app_target_entry.insert(0, target)
        self.app_scan_btn.configure(state="disabled")
        self.app_stop_btn.configure(state="normal")
        self.app._switch_view("website_scanner")

    def _stop_app_scan(self):
        self.app_scan_btn.configure(state="normal")
        self.app_stop_btn.configure(state="disabled")

    def handle_event(self, event):
        """Scan events: a finished scan is picked up by refresh() via
        app.last_report_data, so only the running pill needs updating here."""
        if event and event[0] in ("scan_started", "scan_complete", "scan_error"):
            self._set_running()


__all__ = ["ProfessionalDashboardView"]
