"""
ToolReadinessPanel — a CustomTkinter widget that runs agent preflight checks
in a background thread and displays per-agent tool status.

Designed to be embedded in SettingsView (and future pre-scan dialogs).
Preflight is automatic on first show; a Refresh button re-runs it.
Installation is always an explicit user action — clicking "INSTALL" shows
the recipe and asks for confirmation before executing anything.
"""

import threading
from typing import Dict, List

import customtkinter as ctk

from ui.theme import (
    SURFACE_BASE, SURFACE_MUTED, SURFACE_STRONG,
    BORDER_HAIRLINE,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY, TEXT_INVERSE,
    STATUS_OK, STATUS_CRITICAL, STATUS_HIGH,
    FONTS, SPACE_1, SPACE_2, SPACE_3, SPACE_4,
    RADIUS_SM, RADIUS_MD,
    BTN_HEIGHT_SM, BTN_HEIGHT_MD, BTN_WIDTH_SM, BTN_WIDTH_MD,
    BORDER_WIDTH_HAIRLINE, CARD_PADDING,
)


# Status color mapping
_STATUS_READY = STATUS_OK           # #6fae78 green
_STATUS_NEEDS  = STATUS_CRITICAL    # #d14b4b red
_STATUS_OPTL   = STATUS_HIGH        # #cf7f2e amber (optional missing)
_STATUS_CHECK  = TEXT_SECONDARY     # grey while checking


class ToolReadinessPanel(ctk.CTkFrame):
    """
    Shows per-agent tool readiness. Runs preflight in a background thread
    so the UI never blocks.

    Usage:
        panel = ToolReadinessPanel(parent)
        panel.pack(fill="x")   # or .grid(...)
        panel.run_preflight()  # call after the widget is visible
    """

    def __init__(self, master, **kwargs):
        super().__init__(
            master,
            fg_color=SURFACE_MUTED,
            corner_radius=RADIUS_MD,
            border_width=BORDER_WIDTH_HAIRLINE,
            border_color=BORDER_HAIRLINE,
            **kwargs,
        )
        self._reports: Dict = {}
        self._running = False
        self._build()

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # ── Header row ──────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_3))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr,
            text="🔧  TOOL READINESS",
            font=ctk.CTkFont(*FONTS["subheading"]),
            text_color=TEXT_PRIMARY,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        self._refresh_btn = ctk.CTkButton(
            hdr,
            text="REFRESH",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            fg_color=SURFACE_STRONG,
            hover_color=BORDER_HAIRLINE,
            text_color=TEXT_SECONDARY,
            corner_radius=RADIUS_SM,
            height=BTN_HEIGHT_SM,
            width=BTN_WIDTH_SM,
            command=self.run_preflight,
        )
        self._refresh_btn.grid(row=0, column=1, sticky="e", padx=(SPACE_4, 0))

        # ── Summary line ────────────────────────────────────────────
        self._summary_lbl = ctk.CTkLabel(
            self,
            text="Press Refresh to check tool availability.",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            anchor="w",
        )
        self._summary_lbl.grid(row=1, column=0, sticky="ew", padx=CARD_PADDING, pady=(0, SPACE_3))

        # ── Scrollable agent list ────────────────────────────────────
        self._list_frame = ctk.CTkScrollableFrame(
            self,
            fg_color=SURFACE_BASE,
            corner_radius=RADIUS_SM,
            height=260,
            scrollbar_button_color=SURFACE_STRONG,
            scrollbar_button_hover_color=SURFACE_MUTED,
        )
        self._list_frame.grid(row=2, column=0, sticky="ew",
                               padx=CARD_PADDING, pady=(0, CARD_PADDING))
        self._list_frame.grid_columnconfigure(0, weight=1)

        # Placeholder while empty
        self._placeholder = ctk.CTkLabel(
            self._list_frame,
            text="No preflight data yet.",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            anchor="w",
        )
        self._placeholder.grid(row=0, column=0, sticky="w",
                                padx=SPACE_4, pady=SPACE_4)

    # ------------------------------------------------------------------
    # Preflight execution
    # ------------------------------------------------------------------

    def run_preflight(self):
        """Kick off preflight in a background thread. Safe to call any time."""
        if self._running:
            return
        self._running = True
        self._refresh_btn.configure(state="disabled", text="CHECKING…")
        self._summary_lbl.configure(text="Checking tool availability…", text_color=TEXT_SECONDARY)
        self._clear_list()

        thread = threading.Thread(target=self._do_preflight, daemon=True)
        thread.start()

    def _do_preflight(self):
        from agents.registry import AGENT_MAP
        from agents.toolchain import preflight_all
        try:
            reports = preflight_all(list(AGENT_MAP.values()))
        except Exception as exc:
            reports = {}
            self.after(0, lambda: self._summary_lbl.configure(
                text=f"Preflight error: {exc}", text_color=STATUS_CRITICAL))
        self._reports = reports
        self.after(0, lambda: self._render_results(reports))

    # ------------------------------------------------------------------
    # Result rendering  (always called on main thread via .after())
    # ------------------------------------------------------------------

    def _clear_list(self):
        for w in self._list_frame.winfo_children():
            w.destroy()
        self._placeholder = ctk.CTkLabel(
            self._list_frame,
            text="Checking…",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY,
            anchor="w",
        )
        self._placeholder.grid(row=0, column=0, sticky="w",
                                padx=SPACE_4, pady=SPACE_4)

    def _render_results(self, reports: Dict):
        self._running = False
        self._refresh_btn.configure(state="normal", text="REFRESH")

        # Clear placeholder
        for w in self._list_frame.winfo_children():
            w.destroy()

        if not reports:
            ctk.CTkLabel(
                self._list_frame,
                text="No agents found.",
                font=ctk.CTkFont(*FONTS["small"]),
                text_color=TEXT_SECONDARY,
                anchor="w",
            ).grid(row=0, column=0, sticky="w", padx=SPACE_4, pady=SPACE_4)
            self._summary_lbl.configure(
                text="No agents registered.", text_color=TEXT_SECONDARY)
            return

        ready_count = sum(1 for r in reports.values() if r.can_run)
        total = len(reports)
        needs_count = total - ready_count
        color = _STATUS_READY if needs_count == 0 else _STATUS_NEEDS
        self._summary_lbl.configure(
            text=f"{ready_count}/{total} agents ready"
            + (f"  ·  {needs_count} agent(s) need tools" if needs_count else ""),
            text_color=color,
        )

        # Sort: not-ready first so problems are visible without scrolling
        sorted_keys = sorted(
            reports,
            key=lambda k: (1 if reports[k].can_run else 0, k),
        )

        self._list_frame.grid_columnconfigure(0, weight=1)

        for row_idx, key in enumerate(sorted_keys):
            rep = reports[key]
            self._add_agent_row(row_idx, key, rep)

    def _add_agent_row(self, row_idx: int, key: str, rep):
        from agents.registry import AGENT_MAP

        agent = AGENT_MAP.get(key)
        name = agent.manifest.name if agent else key

        row = ctk.CTkFrame(
            self._list_frame,
            fg_color=SURFACE_STRONG if not rep.can_run else "transparent",
            corner_radius=RADIUS_SM,
        )
        row.grid(row=row_idx, column=0, sticky="ew",
                 padx=SPACE_2, pady=SPACE_1)
        row.grid_columnconfigure(1, weight=1)

        # Status dot
        if rep.can_run and not rep.optional_missing:
            dot_color = _STATUS_READY
            status_text = "✔"
        elif rep.can_run and rep.optional_missing:
            dot_color = _STATUS_OPTL
            status_text = "~"
        else:
            dot_color = _STATUS_NEEDS
            status_text = "✘"

        ctk.CTkLabel(
            row,
            text=status_text,
            font=ctk.CTkFont(*FONTS["small_bold"]),
            text_color=dot_color,
            width=20,
            anchor="center",
        ).grid(row=0, column=0, padx=(SPACE_3, SPACE_2), pady=SPACE_2)

        # Agent name
        ctk.CTkLabel(
            row,
            text=name,
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_PRIMARY if not rep.can_run else TEXT_SECONDARY,
            anchor="w",
        ).grid(row=0, column=1, sticky="w", pady=SPACE_2)

        # Tool detail label (missing / present summary)
        detail = self._make_tool_detail(rep)
        if detail:
            ctk.CTkLabel(
                row,
                text=detail,
                font=ctk.CTkFont(*FONTS["mono"]),
                text_color=TEXT_TERTIARY,
                anchor="w",
                wraplength=340,
            ).grid(row=1, column=1, columnspan=2, sticky="w",
                   padx=(0, SPACE_3), pady=(0, SPACE_2))

        # Install button — only for agents with required missing tools
        if rep.missing and agent and hasattr(agent.manifest, "tools"):
            install_btn = ctk.CTkButton(
                row,
                text="INSTALL",
                font=ctk.CTkFont(*FONTS["small_bold"]),
                fg_color=_STATUS_NEEDS,
                hover_color="#b03030",
                text_color=TEXT_INVERSE,
                corner_radius=RADIUS_SM,
                height=BTN_HEIGHT_SM,
                width=BTN_WIDTH_SM,
                command=lambda k=key, r=rep: self._prompt_install(k, r),
            )
            install_btn.grid(row=0, column=2, rowspan=2, sticky="e",
                             padx=(SPACE_2, SPACE_3), pady=SPACE_2)

    @staticmethod
    def _make_tool_detail(rep) -> str:
        parts = []
        if rep.present:
            parts.append("present: " + ", ".join(rep.present))
        if rep.missing:
            parts.append("MISSING: " + ", ".join(rep.missing))
        if rep.optional_missing:
            parts.append("optional missing: " + ", ".join(rep.optional_missing))
        return "  ·  ".join(parts)

    # ------------------------------------------------------------------
    # Install flow — explicit opt-in only
    # ------------------------------------------------------------------

    def _prompt_install(self, key: str, rep):
        from agents.registry import AGENT_MAP
        import agents.toolchain as tc
        import platform

        agent = AGENT_MAP.get(key)
        if agent is None:
            return

        # Build a human-readable description of what would run
        lines = []
        pm_sys = "apt" if platform.system().lower() == "linux" else (
            "brew" if platform.system().lower() == "darwin" else "pip/go")
        for req in agent.manifest.tools:
            if req.name in rep.missing:
                install_d = req.install_dict()
                cmd = install_d.get(pm_sys) or next(iter(install_d.values()), None)
                cmd_str = " ".join(cmd) if cmd else "(no recipe for this platform)"
                lines.append(f"{req.name}:  {cmd_str}")

        recipe_text = "\n".join(lines) if lines else "(no install recipes defined)"

        dialog = _InstallConfirmDialog(
            self,
            agent_name=agent.manifest.name,
            missing_tools=rep.missing,
            recipe_text=recipe_text,
            on_confirm=lambda: self._do_install(key, agent, rep),
        )
        dialog.grab_set()

    def _do_install(self, key: str, agent, rep):
        """Run install in a background thread after user confirmation."""
        import agents.toolchain as tc

        self._summary_lbl.configure(
            text=f"Installing tools for {agent.manifest.name}…",
            text_color=TEXT_TERTIARY,
        )

        def _run():
            results = tc.install_missing(agent, dry_run=False)
            self.after(0, lambda: self._on_install_done(key, results))

        threading.Thread(target=_run, daemon=True).start()

    def _on_install_done(self, key: str, results: Dict[str, bool]):
        ok = [t for t, s in results.items() if s]
        fail = [t for t, s in results.items() if not s]
        if fail:
            self._summary_lbl.configure(
                text=f"Install: {', '.join(ok)} OK  ·  FAILED: {', '.join(fail)}",
                text_color=_STATUS_NEEDS,
            )
        else:
            self._summary_lbl.configure(
                text=f"Installed: {', '.join(ok)}. Re-running preflight…",
                text_color=_STATUS_READY,
            )
        # Re-run preflight to update the display
        self.run_preflight()


# ---------------------------------------------------------------------------
# Install confirmation dialog
# ---------------------------------------------------------------------------

class _InstallConfirmDialog(ctk.CTkToplevel):
    """Modal dialog that shows what install commands would run and asks to confirm."""

    def __init__(self, master, agent_name: str, missing_tools: List[str],
                 recipe_text: str, on_confirm):
        super().__init__(master)
        self.title("Install Tools — Explicit Opt-in")
        self.resizable(False, False)
        self.configure(fg_color=SURFACE_MUTED)
        self._on_confirm = on_confirm
        self._build(agent_name, missing_tools, recipe_text)
        self._center()

    def _build(self, agent_name: str, missing_tools: List[str], recipe_text: str):
        pad = CARD_PADDING

        ctk.CTkLabel(
            self,
            text="Install Missing Tools",
            font=ctk.CTkFont(*FONTS["subheading"]),
            text_color=TEXT_PRIMARY,
            anchor="w",
        ).pack(fill="x", padx=pad, pady=(pad, SPACE_3))

        ctk.CTkLabel(
            self,
            text=(
                f"Agent: {agent_name}\n"
                f"Missing: {', '.join(missing_tools)}\n\n"
                "The following commands will run on your system:"
            ),
            font=ctk.CTkFont(*FONTS["body"]),
            text_color=TEXT_SECONDARY,
            anchor="w",
            justify="left",
        ).pack(fill="x", padx=pad, pady=(0, SPACE_3))

        recipe_box = ctk.CTkTextbox(
            self,
            height=80,
            fg_color=SURFACE_BASE,
            border_color=BORDER_HAIRLINE,
            border_width=BORDER_WIDTH_HAIRLINE,
            text_color=TEXT_TERTIARY,
            font=ctk.CTkFont(*FONTS["mono"]),
        )
        recipe_box.pack(fill="x", padx=pad, pady=(0, SPACE_3))
        recipe_box.insert("1.0", recipe_text)
        recipe_box.configure(state="disabled")

        ctk.CTkLabel(
            self,
            text="⚠  Only proceed if you trust these commands and have permission to install software on this machine.",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=STATUS_HIGH,
            anchor="w",
            wraplength=400,
            justify="left",
        ).pack(fill="x", padx=pad, pady=(0, SPACE_4))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=pad, pady=(0, pad))

        ctk.CTkButton(
            btn_row,
            text="INSTALL",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            fg_color=_STATUS_NEEDS,
            hover_color="#b03030",
            text_color=TEXT_INVERSE,
            corner_radius=RADIUS_SM,
            height=BTN_HEIGHT_MD,
            width=BTN_WIDTH_MD,
            command=self._confirm,
        ).pack(side="left")

        ctk.CTkButton(
            btn_row,
            text="CANCEL",
            font=ctk.CTkFont(*FONTS["small_bold"]),
            fg_color=SURFACE_STRONG,
            hover_color=BORDER_HAIRLINE,
            text_color=TEXT_SECONDARY,
            corner_radius=RADIUS_SM,
            height=BTN_HEIGHT_MD,
            width=BTN_WIDTH_MD,
            command=self.destroy,
        ).pack(side="left", padx=(SPACE_4, 0))

    def _confirm(self):
        self.destroy()
        self._on_confirm()

    def _center(self):
        self.update_idletasks()
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f"+{x}+{y}")
