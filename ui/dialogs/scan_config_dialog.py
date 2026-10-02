"""
Configure Scans dialog — shared modal scanner-selection UI for the Website,
App and Company scanner views.

Replaces the old inline "scanner toggle card" grid that used to live directly
on each scanner page: with the full ~24-scanner catalog that grid overflowed
its 3-column layout and clipped/overlapped other page content. A modal gives
every scanner a full-width row with room for a complete, wrapped description,
inside its own scrollable area, regardless of how many scanner modules exist.

Parametrized by a `categories` list (the same shape as
`config.settings.SCANNER_CATEGORIES`) so one implementation serves all three
scanner pages instead of three near-identical copies.
"""

import re
from typing import Callable, Dict, List, Optional

import customtkinter as ctk

from config.settings import DEFAULT_SCANNER_KEYS
from ui.theme import (
    SURFACE_BASE, SURFACE_MUTED, SURFACE_RAISED, SURFACE_STRONG,
    BORDER_HAIRLINE, BORDER_ACCENT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY, TEXT_INVERSE,
    FONTS,
    SPACE_1, SPACE_2, SPACE_3, SPACE_4, SPACE_6,
    RADIUS_NONE, RADIUS_XS, RADIUS_SM,
    BTN_HEIGHT_MD, BTN_WIDTH_MD, BTN_WIDTH_LG, BTN_WIDTH_XL,
    INPUT_HEIGHT, CARD_PADDING,
    BORDER_WIDTH_HAIRLINE, BORDER_WIDTH_ACCENT,
)
from ui.widgets import PrimaryButton, GhostButton, make_card


def short_scanner_label(name: str) -> str:
    """Extract the short form of a scanner name for compact display.

    Most catalog names carry an abbreviation in parentheses, e.g.
    "Cross-Site Scripting (XSS)" -> "XSS". Falls back to the full name
    when there's no parenthetical form.
    """
    match = re.search(r"\(([^)]+)\)", name)
    return match.group(1) if match else name


class ScanConfigDialog(ctk.CTkToplevel):
    """Fixed-size modal for choosing which scanner modules are enabled.

    Usage:
        ScanConfigDialog(
            root_window,
            categories=SCANNER_CATEGORIES,
            enabled_keys=self.enabled_scanners,
            on_apply=self._apply_scanner_selection,
        )

    `on_apply` is only invoked when the user clicks Apply, with the final
    sorted list of enabled scanner keys. Cancel (button, [X], or Escape)
    discards all in-dialog changes and never calls back.
    """

    WIDTH = 900
    HEIGHT = 720

    def __init__(
        self,
        master,
        categories: List[dict],
        enabled_keys: List[str],
        on_apply: Callable[[List[str]], None],
        title: str = "Configure Scans",
    ):
        super().__init__(master)
        self.title(title)
        self.configure(fg_color=SURFACE_BASE)
        self.resizable(False, False)
        self.transient(master)

        self.on_apply = on_apply
        self.categories = categories
        self._all_keys = [s["key"] for cat in categories for s in cat["scanners"]]
        self._default_keys = [k for k in self._all_keys if k in DEFAULT_SCANNER_KEYS]
        self._selected = {k for k in enabled_keys if k in self._all_keys}
        self.scanner_vars: Dict[str, ctk.BooleanVar] = {}

        self._center_over(master)
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.bind("<Escape>", lambda e: self._on_cancel())

        self.grab_set()
        self.after(100, self._finalize)

    def _finalize(self):
        self.lift()
        self.focus_force()

    def _center_over(self, master):
        w, h = self.WIDTH, self.HEIGHT
        try:
            master_root = master.winfo_toplevel() if hasattr(master, "winfo_toplevel") else master
            master_root.update_idletasks()
            mx, my = master_root.winfo_rootx(), master_root.winfo_rooty()
            mw, mh = master_root.winfo_width(), master_root.winfo_height()
            x = mx + max(0, (mw - w) // 2)
            y = my + max(0, (mh - h) // 2)
        except Exception:
            x, y = 100, 60
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------
    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Header
        header = ctk.CTkFrame(
            self, fg_color=SURFACE_MUTED, corner_radius=RADIUS_NONE,
            border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE,
        )
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header, text="CONFIGURE SCANS", font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_TERTIARY, anchor="w",
        ).grid(row=0, column=0, padx=SPACE_6, pady=(SPACE_4, 0), sticky="w")
        ctk.CTkLabel(
            header, text="Select which scanner modules run during the scan.",
            font=ctk.CTkFont(*FONTS["small"]), text_color=TEXT_SECONDARY, anchor="w",
        ).grid(row=1, column=0, padx=SPACE_6, pady=(0, SPACE_4), sticky="w")

        # Toolbar: search + bulk actions
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=1, column=0, sticky="ew", padx=SPACE_6, pady=(SPACE_4, SPACE_2))
        toolbar.grid_columnconfigure(0, weight=1)

        self.search_var = ctk.StringVar()
        search_entry = ctk.CTkEntry(
            toolbar, textvariable=self.search_var,
            placeholder_text="Search scanners by name or description...",
            height=INPUT_HEIGHT, corner_radius=RADIUS_SM,
            border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE,
            fg_color=SURFACE_MUTED, text_color=TEXT_PRIMARY,
        )
        search_entry.grid(row=0, column=0, sticky="ew", padx=(0, SPACE_3))
        self.search_var.trace_add("write", lambda *_a: self._render_list())

        bulk_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        bulk_frame.grid(row=0, column=1, sticky="e")
        GhostButton(bulk_frame, text="SELECT ALL", command=self._select_all,
                    width=BTN_WIDTH_MD, height=INPUT_HEIGHT).grid(row=0, column=0, padx=(0, SPACE_2))
        GhostButton(bulk_frame, text="SELECT NONE", command=self._select_none,
                    width=BTN_WIDTH_MD, height=INPUT_HEIGHT).grid(row=0, column=1, padx=(0, SPACE_2))
        GhostButton(bulk_frame, text="RESET TO DEFAULT", command=self._reset_default,
                    width=BTN_WIDTH_LG, height=INPUT_HEIGHT).grid(row=0, column=2)

        # Scrollable scanner list
        self.list_frame = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=SURFACE_STRONG,
            scrollbar_button_hover_color=SURFACE_MUTED,
        )
        self.list_frame.grid(row=2, column=0, sticky="nsew", padx=SPACE_6, pady=(SPACE_2, SPACE_2))
        self.list_frame.grid_columnconfigure(0, weight=1)

        # Footer
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=3, column=0, sticky="ew", padx=SPACE_6, pady=(SPACE_2, SPACE_6))
        footer.grid_columnconfigure(0, weight=1)

        self.count_label = ctk.CTkLabel(
            footer, text="", font=ctk.CTkFont(*FONTS["small"]), text_color=TEXT_SECONDARY, anchor="w",
        )
        self.count_label.grid(row=0, column=0, sticky="w")

        GhostButton(footer, text="CANCEL", command=self._on_cancel,
                    width=BTN_WIDTH_MD, height=BTN_HEIGHT_MD).grid(row=0, column=1, padx=(0, SPACE_3))
        PrimaryButton(footer, text="APPLY", command=self._on_apply,
                      width=BTN_WIDTH_MD, height=BTN_HEIGHT_MD).grid(row=0, column=2)

        self._render_list()

    # ------------------------------------------------------------------
    # List rendering / filtering
    # ------------------------------------------------------------------
    def _render_list(self):
        for widget in self.list_frame.winfo_children():
            widget.destroy()

        query = self.search_var.get().strip().lower()
        row = 0
        any_match = False

        for category in self.categories:
            matches = [
                s for s in category["scanners"]
                if not query or query in s["name"].lower() or query in s.get("desc", "").lower()
            ]
            if not matches:
                continue
            any_match = True
            row = self._render_category(row, category, matches)

        if not any_match:
            ctk.CTkLabel(
                self.list_frame, text="No scanners match your search.",
                font=ctk.CTkFont(*FONTS["body"]), text_color=TEXT_SECONDARY,
            ).grid(row=0, column=0, pady=SPACE_6)

        self._update_count()

    def _render_category(self, row: int, category: dict, matches: List[dict]) -> int:
        cat_frame = make_card(self.list_frame)
        cat_frame.grid(row=row, column=0, sticky="ew", pady=(0, SPACE_3))
        cat_frame.grid_columnconfigure(0, weight=1)
        row += 1

        cat_header = ctk.CTkFrame(cat_frame, fg_color="transparent")
        cat_header.grid(row=0, column=0, sticky="ew", padx=CARD_PADDING, pady=(CARD_PADDING, SPACE_2))
        cat_header.grid_columnconfigure(1, weight=1)

        all_selected = all(s["key"] in self._selected for s in matches)
        cat_check = ctk.CTkCheckBox(
            cat_header, text="", width=20, corner_radius=RADIUS_XS,
            border_width=BORDER_WIDTH_HAIRLINE, border_color=BORDER_HAIRLINE,
            fg_color=SURFACE_RAISED, hover_color=TEXT_TERTIARY, checkmark_color=TEXT_INVERSE,
            command=lambda c=category, ms=matches: self._toggle_category(c, ms),
        )
        cat_check.grid(row=0, column=0, padx=(0, SPACE_2))
        (cat_check.select if all_selected else cat_check.deselect)()

        ctk.CTkLabel(
            cat_header, text=f"{category.get('icon', '')} {category['name'].upper()}",
            font=ctk.CTkFont(*FONTS["body_bold"]), text_color=TEXT_SECONDARY, anchor="w",
        ).grid(row=0, column=1, sticky="w")

        crow = 1
        for scanner in matches:
            key = scanner["key"]
            var = self.scanner_vars.get(key)
            if var is None:
                var = ctk.BooleanVar(value=key in self._selected)
                self.scanner_vars[key] = var
            else:
                var.set(key in self._selected)

            item = ctk.CTkFrame(cat_frame, fg_color="transparent")
            item.grid(row=crow, column=0, sticky="ew", padx=CARD_PADDING, pady=(0, SPACE_3))
            item.grid_columnconfigure(0, weight=1)
            crow += 1

            ctk.CTkCheckBox(
                item, text=scanner["name"], variable=var,
                font=ctk.CTkFont(*FONTS["body_bold"]), text_color=TEXT_PRIMARY,
                corner_radius=RADIUS_XS, border_width=BORDER_WIDTH_HAIRLINE,
                border_color=BORDER_HAIRLINE, fg_color=SURFACE_RAISED,
                hover_color=TEXT_TERTIARY, checkmark_color=TEXT_INVERSE,
                command=lambda k=key, c=category, ms=matches, cc=cat_check: self._on_scanner_toggle(k, c, ms, cc),
            ).grid(row=0, column=0, sticky="w")

            desc = ctk.CTkLabel(
                item, text=scanner.get("desc", ""), font=ctk.CTkFont(*FONTS["small"]),
                text_color=TEXT_SECONDARY, anchor="w", justify="left", wraplength=800,
            )
            desc.grid(row=1, column=0, sticky="ew", padx=(28, 0), pady=(0, 0))

            def _sync_wrap(event, label=desc):
                new_width = max(200, event.width - 28)
                if label.cget("wraplength") != new_width:
                    label.configure(wraplength=new_width)
            item.bind("<Configure>", _sync_wrap)

        return row

    # ------------------------------------------------------------------
    # Selection actions
    # ------------------------------------------------------------------
    def _on_scanner_toggle(self, key: str, category: dict, matches: List[dict], cat_check: ctk.CTkCheckBox):
        if self.scanner_vars[key].get():
            self._selected.add(key)
        else:
            self._selected.discard(key)

        all_selected = all(self.scanner_vars[s["key"]].get() for s in matches)
        (cat_check.select if all_selected else cat_check.deselect)()
        self._update_count()

    def _toggle_category(self, category: dict, matches: List[dict]):
        target = not all(s["key"] in self._selected for s in matches)
        for scanner in matches:
            key = scanner["key"]
            if target:
                self._selected.add(key)
            else:
                self._selected.discard(key)
            if key in self.scanner_vars:
                self.scanner_vars[key].set(target)
        self._update_count()

    def _select_all(self):
        self._selected = set(self._all_keys)
        self._render_list()

    def _select_none(self):
        self._selected = set()
        self._render_list()

    def _reset_default(self):
        self._selected = set(self._default_keys)
        self._render_list()

    def _update_count(self):
        self.count_label.configure(
            text=f"{len(self._selected)} of {len(self._all_keys)} scanners selected"
        )

    # ------------------------------------------------------------------
    # Apply / Cancel
    # ------------------------------------------------------------------
    def _on_apply(self):
        ordered = [k for k in self._all_keys if k in self._selected]
        if self.on_apply:
            self.on_apply(ordered)
        self.grab_release()
        self.destroy()

    def _on_cancel(self):
        self.grab_release()
        self.destroy()
