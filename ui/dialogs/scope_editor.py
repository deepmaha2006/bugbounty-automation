"""
Scope Editor dialog for Bug Bounty Professional.

Allows users to configure scan scope with:
- Allow/deny URL patterns (glob/regex)
- Allow/deny domains
- Crawl limits (pages, depth, smart probes)
- Rate limiting (requests/sec, burst limit)
- Scanner selection (enable/disable individual scanners)
- Custom headers/cookies
- Auth reference

Opens in a modal CTkToplevel window. Returns updated ScopeConfig on save.
"""

import customtkinter as ctk

from config.settings import SCANNER_CATEGORIES, SCANNER_MAP, ALL_SCANNER_KEYS
from config.scope import ScopeConfig
from ui.theme import (BG, SURFACE, SURFACE_ALT, BORDER, TEXT_PRIMARY, TEXT_SECONDARY,
                      ACCENT, ACCENT_HOVER, FONTS, SEVERITY_COLORS,
                      SPACE_1, SPACE_2, SPACE_3, SPACE_4, SPACE_5, SPACE_6, SPACE_7, SPACE_8,
                      RADIUS_XS, RADIUS_SM)


class ScopeEditorDialog(ctk.CTkToplevel):
    """Modal dialog to edit a ScopeConfig."""

    def __init__(self, master, initial: ScopeConfig = None, on_save=None):
        super().__init__(master)
        self.title("Scope Editor")
        self.geometry("720x640")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        self.configure(fg_color=BG)

        self.on_save = on_save
        self.result: ScopeConfig = None
        self._initial = initial or ScopeConfig()

        self._build()
        self._load(self._initial)
        self.after(100, lambda: self.lift())

    # ------------------------------------------------------------------
    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=SPACE_6, pady=(SPACE_6, SPACE_2))
        ctk.CTkLabel(header, text="Scope Configuration", font=FONTS["heading"],
                     text_color=TEXT_PRIMARY, anchor="w").pack(side="left")
        ctk.CTkLabel(header, text="Define what the scanner can and cannot touch",
                     font=FONTS["small"], text_color=TEXT_SECONDARY, anchor="w").pack(side="left", padx=(SPACE_2, 0))

        # Tab buttons
        tab_frame = ctk.CTkFrame(self, fg_color="transparent")
        tab_frame.grid(row=0, column=0, sticky="e", padx=SPACE_6, pady=(SPACE_6, SPACE_2))

        # Body container
        self.body = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.body.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, SPACE_4))
        self.body.grid_columnconfigure(0, weight=1)
        self.body.grid_rowconfigure(0, weight=1)

        # Tabs
        self.tabs = {}
        self.tab_buttons = {}
        tab_defs = [
            ("patterns", "Patterns", self._build_patterns_tab),
            ("domains", "Domains", self._build_domains_tab),
            ("limits", "Limits", self._build_limits_tab),
            ("scanners", "Scanners", self._build_scanners_tab),
            ("advanced", "Advanced", self._build_advanced_tab),
        ]

        for i, (key, label, builder) in enumerate(tab_defs):
            btn = ctk.CTkButton(
                tab_frame, text=label, width=110, height=30, corner_radius=8,
                font=FONTS["small_bold"], fg_color=SURFACE_ALT if i == 0 else "transparent",
                hover_color=ACCENT_HOVER, text_color=TEXT_PRIMARY if i == 0 else TEXT_SECONDARY,
                command=lambda k=key: self._switch_tab(k))
            btn.pack(side="left", padx=(0, 4))
            self.tab_buttons[key] = btn

        for key, label, builder in tab_defs:
            frame = ctk.CTkScrollableFrame(self.body, fg_color=BG, corner_radius=0)
            frame.grid_columnconfigure(0, weight=1)
            frame.grid(row=0, column=0, sticky="nsew")
            frame.grid_remove()
            self.tabs[key] = (frame, builder)

        self._switch_tab("patterns")

        # Footer with actions
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=SPACE_6, pady=(SPACE_2, SPACE_6))
        footer.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(footer, text="Reset to Default", width=int(SPACE_6 * 20.63), height=int(SPACE_6 * 5.4),
                      corner_radius=RADIUS_XS, fg_color="transparent", hover_color=SURFACE_ALT,
                      border_width=int(SPACE_1), border_color=BORDER, text_color=TEXT_SECONDARY,
                      font=FONTS["body_bold"], command=self._reset).pack(side="left")
        ctk.CTkButton(footer, text="Cancel", width=int(SPACE_6 * 15.87), height=int(SPACE_6 * 5.4),
                      corner_radius=RADIUS_XS, fg_color="transparent", hover_color=SURFACE_ALT,
                      border_width=int(SPACE_1), border_color=BORDER, text_color=TEXT_SECONDARY,
                      font=FONTS["body_bold"], command=self.destroy).pack(side="right", padx=(SPACE_2, 0))
        ctk.CTkButton(footer, text="Save Scope", width=int(SPACE_6 * 19.05), height=int(SPACE_6 * 5.4),
                      corner_radius=RADIUS_XS, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      text_color="white", font=FONTS["body_bold"],
                      command=self._save).pack(side="right")

    # ------------------------------------------------------------------
    def _switch_tab(self, key: str):
        for k, (frame, builder) in self.tabs.items():
            if k == key:
                if not frame.winfo_children():
                    builder(frame)
                frame.grid()
                self.tab_buttons[k].configure(fg_color=SURFACE_ALT, text_color=TEXT_PRIMARY)
            else:
                frame.grid_remove()
                self.tab_buttons[k].configure(fg_color="transparent", text_color=TEXT_SECONDARY)

    # ------------------------------------------------------------------
    # Pattern tab
    # ------------------------------------------------------------------
    def _build_patterns_tab(self, parent):
        self._section(parent, "Allowed URL Patterns")
        self._hint(parent, "One pattern per line. Supports glob (/api/**, /admin/*) "
                           "and regex (^/api/v\\d+/.*). Empty = allow all.")
        self.allowed_patterns_box = self._text_area(parent, height=140)

        self._section(parent, "Denied URL Patterns")
        self._hint(parent, "URLs matching any denied pattern are excluded from scope.")
        self.denied_patterns_box = self._text_area(parent, height=140)

    # ------------------------------------------------------------------
    # Domain tab
    # ------------------------------------------------------------------
    def _build_domains_tab(self, parent):
        self._section(parent, "Allowed Domains")
        self._hint(parent, "One domain per line. Use *.example.com for subdomains. "
                           "Empty = all domains in target host.")
        self.allowed_domains_box = self._text_area(parent, height=140)

        self._section(parent, "Denied Domains")
        self._hint(parent, "Domains to exclude (e.g., cdn.example.com, *.cloudfront.net).")
        self.denied_domains_box = self._text_area(parent, height=140)

    # ------------------------------------------------------------------
    # Limits tab
    # ------------------------------------------------------------------
    def _build_limits_tab(self, parent):
        self._section(parent, "Crawl Limits")
        grid = ctk.CTkFrame(parent, fg_color="transparent")
        grid.pack(fill="x", padx=16, pady=(8, 4))
        grid.grid_columnconfigure(1, weight=1)
        grid.grid_columnconfigure(3, weight=1)

        self.max_pages_var = self._number_field(grid, "Max Pages", 0, "200")
        self.max_depth_var = self._number_field(grid, "Max Depth", 1, "5")
        self.max_smart_probes_var = self._number_field(grid, "Max Smart Probes", 2, "500")

        self._section(parent, "Rate Limiting")
        grid2 = ctk.CTkFrame(parent, fg_color="transparent")
        grid2.pack(fill="x", padx=16, pady=(8, 4))
        grid2.grid_columnconfigure(1, weight=1)
        grid2.grid_columnconfigure(3, weight=1)

        self.rps_var = self._number_field(grid2, "Requests / Second", 3, "10.0")
        self.burst_var = self._number_field(grid2, "Burst Limit", 4, "20")

    # ------------------------------------------------------------------
    # Scanners tab
    # ------------------------------------------------------------------
    def _build_scanners_tab(self, parent):
        self._section(parent, "Scanner Selection")
        self._hint(parent, "Enable or disable individual scanners. If none enabled, "
                           "all default scanners run.")

        self.scanner_switches = {}
        for category in SCANNER_CATEGORIES:
            cat_frame = ctk.CTkFrame(parent, fg_color="transparent")
            cat_frame.pack(fill="x", padx=16, pady=(10, 4))
            ctk.CTkLabel(cat_frame, text=f"{category['icon']} {category['name']}",
                         font=FONTS["subheading"], text_color=TEXT_PRIMARY, anchor="w").pack(anchor="w")

            sub = ctk.CTkFrame(parent, fg_color="transparent")
            sub.pack(fill="x", padx=24, pady=(0, 8))

            for scanner in category["scanners"]:
                key = scanner["key"]
                sw = ctk.CTkSwitch(sub, text=scanner["name"], font=FONTS["small"],
                                  text_color=TEXT_PRIMARY, width=200)
                sw.pack(anchor="w", padx=4, pady=2)
                self.scanner_switches[key] = sw

    # ------------------------------------------------------------------
    # Advanced tab
    # ------------------------------------------------------------------
    def _build_advanced_tab(self, parent):
        self._section(parent, "Authentication Reference")
        self._hint(parent, "Key into the auth config store (set in Settings view).")
        self.auth_ref_var = ctk.StringVar()
        ctk.CTkEntry(parent, textvariable=self.auth_ref_var, font=FONTS["body"],
                     height=34, placeholder_text="auth-profile-name").pack(
            fill="x", padx=16, pady=(4, 12))

        self._section(parent, "Custom Headers")
        self._hint(parent, "One per line: Name: Value")
        self.headers_box = self._text_area(parent, height=90)

        self._section(parent, "Custom Cookies")
        self._hint(parent, "One per line: name=value")
        self.cookies_box = self._text_area(parent, height=90)

        self._section(parent, "Crawl Options")
        opt_frame = ctk.CTkFrame(parent, fg_color="transparent")
        opt_frame.pack(fill="x", padx=16, pady=(8, 4))

        self.follow_redirects_var = ctk.BooleanVar(value=True)
        self.respect_robots_var = ctk.BooleanVar(value=False)
        self.crawl_sitemap_var = ctk.BooleanVar(value=True)
        self.crawl_js_var = ctk.BooleanVar(value=True)

        for i, (var, label) in enumerate([
            (self.follow_redirects_var, "Follow Redirects"),
            (self.respect_robots_var, "Respect robots.txt"),
            (self.crawl_sitemap_var, "Crawl Sitemap"),
            (self.crawl_js_var, "Crawl JS Routes"),
        ]):
            sw = ctk.CTkSwitch(opt_frame, text=label, font=FONTS["small"],
                              text_color=TEXT_PRIMARY, variable=var)
            sw.grid(row=i // 2, column=i % 2, sticky="w", padx=4, pady=4)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _section(self, parent, title: str):
        ctk.CTkLabel(parent, text=title, font=FONTS["subheading"],
                     text_color=ACCENT, anchor="w").pack(
            anchor="w", padx=SPACE_4, pady=(SPACE_4, SPACE_1))

    def _hint(self, parent, text: str):
        ctk.CTkLabel(parent, text=text, font=FONTS["small"],
                     text_color=TEXT_SECONDARY, anchor="w", justify="left",
                     wraplength=660).pack(anchor="w", padx=SPACE_4, pady=(0, SPACE_2))

    def _text_area(self, parent, height: int = 100):
        box = ctk.CTkTextbox(parent, height=height, font=FONTS["mono"],
                             fg_color=SURFACE_ALT, corner_radius=8)
        box.configure(border_width=1, border_color=BORDER)
        box.pack(fill="x", padx=16, pady=(0, 12))
        return box

    def _number_field(self, grid, label: str, col: int, default: str):
        var = ctk.StringVar(value=default)
        ctk.CTkLabel(grid, text=label, font=FONTS["small"],
                     text_color=TEXT_SECONDARY).grid(row=0, column=col * 2, sticky="w", padx=(0, 8), pady=4)
        entry = ctk.CTkEntry(grid, textvariable=var, font=FONTS["body"],
                             height=32, width=120)
        entry.grid(row=0, column=col * 2 + 1, sticky="w", padx=(0, 16), pady=4)
        return var

    # ------------------------------------------------------------------
    # Load / Save
    # ------------------------------------------------------------------
    def _load(self, cfg: ScopeConfig):
        self.allowed_patterns_box.insert("0.0", "\n".join(cfg.allowed_patterns))
        self.denied_patterns_box.insert("0.0", "\n".join(cfg.denied_patterns))
        self.allowed_domains_box.insert("0.0", "\n".join(cfg.allowed_domains))
        self.denied_domains_box.insert("0.0", "\n".join(cfg.denied_domains))

        self.max_pages_var.set(str(cfg.max_pages))
        self.max_depth_var.set(str(cfg.max_depth))
        self.max_smart_probes_var.set(str(cfg.max_smart_probes))
        self.rps_var.set(str(cfg.requests_per_second))
        self.burst_var.set(str(cfg.burst_limit))

        enabled = set(cfg.enabled_scanners) if cfg.enabled_scanners else set()
        disabled = set(cfg.disabled_scanners)
        for key, sw in self.scanner_switches.items():
            if enabled:
                if key in enabled:
                    sw.select()
                else:
                    sw.deselect()
            elif key in disabled:
                sw.deselect()
            else:
                sw.select()

        self.auth_ref_var.set(cfg.auth_ref)
        headers = "\n".join(f"{k}: {v}" for k, v in cfg.custom_headers.items())
        self.headers_box.insert("0.0", headers)
        cookies = "\n".join(f"{k}={v}" for k, v in cfg.custom_cookies.items())
        self.cookies_box.insert("0.0", cookies)

        self.follow_redirects_var.set(cfg.follow_redirects)
        self.respect_robots_var.set(cfg.respect_robots_txt)
        self.crawl_sitemap_var.set(cfg.crawl_sitemap)
        self.crawl_js_var.set(cfg.crawl_js_routes)

    def _reset(self):
        self._load(ScopeConfig())

    def _save(self):
        allowed = self._lines(self.allowed_patterns_box)
        denied = self._lines(self.denied_patterns_box)
        allowed_dom = self._lines(self.allowed_domains_box)
        denied_dom = self._lines(self.denied_domains_box)

        selected = [k for k, sw in self.scanner_switches.items() if sw.get()]
        disabled = [k for k in ALL_SCANNER_KEYS if k not in selected]

        headers = {}
        for line in self._lines(self.headers_box):
            if ":" in line:
                name, _, val = line.partition(":")
                headers[name.strip()] = val.strip()

        cookies = {}
        for line in self._lines(self.cookies_box):
            if "=" in line:
                name, _, val = line.partition("=")
                cookies[name.strip()] = val.strip()

        cfg = ScopeConfig(
            allowed_patterns=allowed,
            denied_patterns=denied,
            allowed_domains=allowed_dom,
            denied_domains=denied_dom,
            max_pages=self._int(self.max_pages_var.get(), 200),
            max_depth=self._int(self.max_depth_var.get(), 5),
            max_smart_probes=self._int(self.max_smart_probes_var.get(), 500),
            requests_per_second=self._float(self.rps_var.get(), 10.0),
            burst_limit=self._int(self.burst_var.get(), 20),
            auth_ref=self.auth_ref_var.get().strip(),
            follow_redirects=self.follow_redirects_var.get(),
            respect_robots_txt=self.respect_robots_var.get(),
            crawl_sitemap=self.crawl_sitemap_var.get(),
            crawl_js_routes=self.crawl_js_var.get(),
            enabled_scanners=selected if len(selected) < len(ALL_SCANNER_KEYS) else [],
            disabled_scanners=disabled if len(selected) < len(ALL_SCANNER_KEYS) else [],
            custom_headers=headers,
            custom_cookies=cookies,
        )

        self.result = cfg
        if self.on_save:
            self.on_save(cfg)
        self.destroy()

    # ------------------------------------------------------------------
    @staticmethod
    def _lines(box) -> list:
        text = box.get("0.0", "end").strip()
        return [l.strip() for l in text.splitlines() if l.strip()]

    @staticmethod
    def _int(val: str, default: int) -> int:
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _float(val: str, default: float) -> float:
        try:
            return float(val)
        except (ValueError, TypeError):
            return default
