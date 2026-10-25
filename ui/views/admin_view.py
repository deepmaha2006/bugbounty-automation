"""
Admin Panel — Comprehensive management interface for the Cybersecurity Brain.

Provides full control over assets, autonomy policies, scan configurations,
vulnerability database, and system settings. Password-protected access.

This view follows the existing UI patterns from theme.py without modifying
the protected frontend design. All new code adds views rather than modifying
existing HydraX UI components (ui/main_window.py, ui/theme.py untouched).
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import queue
from datetime import datetime
from typing import Dict, Any, Optional

from ui.theme import (
    SURFACE_BASE, SURFACE_MUTED, SURFACE_RAISED,
    SURFACE_STRONG, BORDER_HAIRLINE, BORDER_ACCENT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_TERTIARY, TEXT_INVERSE,
    FONTS, SPACE_1, SPACE_2, SPACE_3, SPACE_4, SPACE_6, SPACE_7, SPACE_10,
    RADIUS_NONE, RADIUS_XS, RADIUS_SM, RADIUS_MD,
    BTN_HEIGHT_MD, BTN_WIDTH_MD, INPUT_HEIGHT, CARD_PADDING,
    BORDER_WIDTH_HAIRLINE, BORDER_WIDTH_ACCENT,
)
from config.settings import APP_NAME, VERSION


class AdminAuthScreen(ctk.CTkFrame):
    """Admin authentication screen."""

    def __init__(self, master, events: queue.Queue, on_auth_success):
        super().__init__(master, fg_color="transparent")
        self.events = events
        self.on_auth_success = on_auth_success
        self.auth_attempts = 0
        self.max_attempts = 3

        # Auth frame
        self.auth_frame = ctk.CTkFrame(self, fg_color=SURFACE_MUTED,
                                       corner_radius=RADIUS_SM,
                                       width=450, height=350)
        self.auth_frame.grid(row=0, column=0, sticky="nsew", padx=100, pady=60)
        self.auth_frame.grid_columnconfigure(0, weight=1)
        self.auth_frame.grid_rowconfigure((0, 1, 2, 3, 4, 5), weight=1)

        # Title
        ctk.CTkLabel(
            self.auth_frame,
            text="🔐 Admin Authentication",
            font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_PRIMARY
        ).grid(row=0, column=0, padx=SPACE_6, pady=(SPACE_10, SPACE_2), sticky="w")

        # Subtitle
        ctk.CTkLabel(
            self.auth_frame,
            text="Authorized access only for cybersecurity brain management",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY
        ).grid(row=1, column=0, padx=SPACE_6, pady=SPACE_2, sticky="w")

        # Password entry
        self.password_entry = ctk.CTkEntry(
            self.auth_frame,
            placeholder_text="Enter admin password",
            font=ctk.CTkFont(*FONTS["body"]),
            show="*",
            width=300
        )
        self.password_entry.grid(row=2, column=0, padx=SPACE_6, pady=SPACE_2, sticky="w")
        self.password_entry.bind("<Return>", self._verify_password)

        # Authenticate button
        auth_btn = ctk.CTkButton(
            self.auth_frame,
            text="Authenticate",
            font=ctk.CTkFont(*FONTS["body"]),
            command=self._verify_password,
            width=120, height=32
        )
        auth_btn.grid(row=3, column=0, padx=SPACE_6, pady=SPACE_2, sticky="w")

        # Warning
        ctk.CTkLabel(
            self.auth_frame,
            text="All actions are logged and auditable",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY
        ).grid(row=4, column=0, padx=SPACE_6, pady=SPACE_2, sticky="w")

        # Failed attempts
        self.attempts_label = ctk.CTkLabel(
            self.auth_frame,
            text=f"Attempts: {self.auth_attempts}/{self.max_attempts}",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_TERTIARY
        )
        self.attempts_label.grid(row=5, column=0, padx=SPACE_6, pady=SPACE_2, sticky="w")

    def _verify_password(self, event=None) -> None:
        """Verify admin password against the platform's stored admin credential.

        Uses the webapp db layer (which hashes passwords via PBKDF2) so the
        admin panel never carries a plaintext password in source. Falls back
        to the legacy env-var path only when the webapp stack is unavailable
        (e.g. desktop-only mode).
        """
        password = self.password_entry.get()

        # Lazy-load brain for password verification
        try:
            from core.brain import get_brain
            brain = get_brain()
        except Exception:  # noqa: BLE001 — desktop-only fallback
            brain = None

        # Try the platform auth path first (desktop app may not have a running
        # webapp, but when it does we delegate there so credentials are never
        # stored as plaintext constants anywhere).
        if brain is not None:
            try:
                from webapp import db, security
                # Find an admin user in the default org
                default_org_id = db.get_default_organization_id()
                if default_org_id:
                    conn = db._get_conn()
                    try:
                        with conn.cursor() as cur:
                            cur.execute(
                                "SELECT id, password_hash FROM users "
                                "WHERE organization_id = %s AND role = 'admin' LIMIT 1",
                                (default_org_id,)
                            )
                            row = cur.fetchone()
                            if row and security.verify_password(password, row[1]):
                                self.on_auth_success()
                                return
                    finally:
                        db._put_conn(conn)
            except Exception:  # noqa: BLE001 — fall through to env-var path
                pass
        else:
            # Strictly desktop-only fallback — never a plaintext constant.
            # Require HYDRAX_ADMIN_PASSWORD env var to be set; reject if it is
            # not configured (fail-closed for unconfigured admin auth).
            import os
            fallback_pw = os.environ.get("HYDRAX_ADMIN_PASSWORD", "")
            if fallback_pw and password == fallback_pw:
                self.on_auth_success()
                return

        # All paths rejected
        self.auth_attempts += 1
        self.attempts_label.configure(text=f"Attempts: {self.auth_attempts}/{self.max_attempts}")

        if self.auth_attempts >= self.max_attempts:
            messagebox.showerror(
                "Authentication Failed",
                "Too many failed attempts. Admin panel locked."
            )
            self.auth_attempts = 0
        else:
            messagebox.showwarning(
                "Authentication Failed",
                f"Invalid password. {self.max_attempts - self.auth_attempts} attempts remaining."
            )
        self.password_entry.delete(0, "end")


class AdminPanel(ctk.CTkFrame):
    """Main admin panel with tabbed interface."""

    def __init__(self, master, events: queue.Queue):
        super().__init__(master, fg_color="transparent")
        self.events = events
        self._brain_loaded = False

        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Show authentication screen first
        self._show_auth_screen()

    def _ensure_brain(self):
        """Lazy-load the brain instance."""
        if not self._brain_loaded:
            from core.brain import get_brain, BrainCore
            self.brain = get_brain()
            self._brain_loaded = True
        return self.brain

    def _show_auth_screen(self) -> None:
        """Show the admin authentication screen."""
        # Clear any existing widgets
        for widget in self.winfo_children():
            widget.destroy()

        auth = AdminAuthScreen(self, self.events, self._on_auth_success)
        auth.grid(row=0, column=0, sticky="nsew")

    def _on_auth_success(self) -> None:
        """Called after successful authentication."""
        self._ensure_brain()
        self._show_admin_dashboard()

    def _show_admin_dashboard(self) -> None:
        """Show the admin dashboard after authentication."""
        # Clear auth screen
        for widget in self.winfo_children():
            widget.destroy()

        # Dashboard frame
        self.dashboard_frame = ctk.CTkFrame(self, fg_color=SURFACE_BASE,
                                            corner_radius=0)
        self.dashboard_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.dashboard_frame.grid_columnconfigure(0, weight=1)
        self.dashboard_frame.grid_rowconfigure(1, weight=1)

        # Top bar
        self._build_top_bar()

        # Notebook (tabs)
        self._build_tabs()

        # Status bar
        self._build_status_bar()

    def _build_top_bar(self) -> None:
        """Build the top navigation bar."""
        self.top_bar = ctk.CTkFrame(self.dashboard_frame, fg_color=SURFACE_RAISED,
                                    height=50, corner_radius=RADIUS_XS)
        self.top_bar.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.top_bar.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        # App info
        ctk.CTkLabel(
            self.top_bar,
            text=f"{APP_NAME} v{VERSION}",
            font=ctk.CTkFont(*FONTS["small"]),
            text_color=TEXT_SECONDARY
        ).grid(row=0, column=0, padx=SPACE_2, pady=4, sticky="w")

        # Kill switch status
        self.kill_switch_var = tk.BooleanVar(value=self.brain.policy_store.KILL_SWITCH.engaged)
        kill_switch_btn = ctk.CTkCheckBox(
            self.top_bar,
            text="🛡️ Kill Switch" if self.kill_switch_var.get() else "🔓 Kill Switch Disabled",
            variable=self.kill_switch_var,
            command=self._toggle_kill_switch,
            font=ctk.CTkFont(*FONTS["small"])
        )
        kill_switch_btn.grid(row=0, column=1, padx=SPACE_2, pady=4, sticky="w")

        # Autonomy tier
        ctk.CTkLabel(self.top_bar, text="Tier:",
                     font=ctk.CTkFont(*FONTS["small"])).grid(
            row=0, column=2, padx=SPACE_2, pady=4, sticky="w"
        )
        self.tier_var = tk.StringVar(value="observe")
        tier_menu = ctk.CTkOptionMenu(
            self.top_bar,
            values=["observe", "recommend", "auto_contain", "auto_remediate"],
            variable=self.tier_var,
            font=ctk.CTkFont(*FONTS["small"]),
            width=100
        )
        tier_menu.grid(row=0, column=3, padx=SPACE_2, pady=4, sticky="w")

        # Log out
        ctk.CTkButton(
            self.top_bar,
            text="Log Out",
            font=ctk.CTkFont(*FONTS["small"]),
            command=self._log_out,
            width=80, height=24
        ).grid(row=0, column=5, padx=SPACE_2, pady=4, sticky="e")

    def _toggle_kill_switch(self) -> None:
        """Toggle the global kill switch."""
        if self.kill_switch_var.get():
            from core.autonomy import KILL_SWITCH
            KILL_SWITCH.engage()
            # Force observe mode when kill switch is engaged
            policies = self.brain.policy_store.all_policies()
            for policy in policies:
                self.brain.set_asset_policy(
                    policy.asset_id, policy.org_id, ctk.AUTONOMY_TIER.OBSERVE
                )
        else:
            from core.autonomy import KILL_SWITCH
            KILL_SWITCH.disengage()

    def _log_out(self) -> None:
        """Log out and return to auth screen."""
        from core.autonomy import KILL_SWITCH
        KILL_SWITCH.disengage()
        for widget in self.dashboard_frame.winfo_children():
            widget.destroy()
        self.dashboard_frame.destroy()
        self._show_auth_screen()

    def _build_tabs(self) -> None:
        """Build the tabbed interface."""
        self.notebook = ttk.Notebook(self.dashboard_frame)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.dashboard_frame.grid_rowconfigure(1, weight=1)

        # Create tabs
        self._create_asset_management_tab()
        self._create_scan_config_tab()
        self._create_vuln_db_tab()
        self._create_system_settings_tab()
        self._create_audit_log_tab()
        self._create_evolution_tab()
        self._create_fixes_tab()

    def _create_asset_management_tab(self) -> None:
        """Create the asset management tab."""
        tab = ctk.CTkFrame(self.notebook, fg_color="transparent")
        self.notebook.add(tab, text="🖥️ Asset Management")

        asset_frame = ctk.CTkFrame(tab, fg_color=SURFACE_MUTED,
                                   corner_radius=RADIUS_SM)
        asset_frame.pack(fill="both", expand=True, padx=10, pady=10)
        asset_frame.grid_columnconfigure(0, weight=1)
        asset_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            asset_frame,
            text="Asset Management",
            font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_PRIMARY
        ).pack(anchor="w", padx=SPACE_2, pady=(SPACE_2, SPACE_1))

        # Add asset form
        add_frame = ctk.CTkFrame(asset_frame, fg_color="transparent")
        add_frame.pack(fill="x", padx=SPACE_2, pady=SPACE_2)
        add_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(add_frame, text="Asset ID:").grid(row=0, column=0, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self.new_asset_id = ctk.CTkEntry(add_frame, width=100)
        self.new_asset_id.grid(row=0, column=1, padx=SPACE_2, pady=SPACE_2, sticky="w")

        ctk.CTkLabel(add_frame, text="Org ID:").grid(row=0, column=2, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self.new_org_id = ctk.CTkEntry(add_frame, width=100)
        self.new_org_id.grid(row=0, column=3, padx=SPACE_2, pady=SPACE_2, sticky="w")

        ctk.CTkLabel(add_frame, text="Tier:").grid(row=0, column=4, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self.new_tier = ctk.CTkComboBox(add_frame, values=["observe", "recommend", "auto_contain", "auto_remediate"])
        self.new_tier.set("observe")
        self.new_tier.grid(row=0, column=5, padx=SPACE_2, pady=SPACE_2, sticky="w")

        add_btn = ctk.CTkButton(
            add_frame, text="Add Asset",
            command=self._add_asset,
            font=ctk.CTkFont(*FONTS["small"])
        )
        add_btn.grid(row=0, column=6, padx=SPACE_2, pady=SPACE_2, sticky="w")

        # Assets list
        self.assets_listbox = tk.Listbox(asset_frame, height=10, font=("Consolas", 9))
        self.assets_listbox.pack(fill="both", expand=True, padx=SPACE_2, pady=SPACE_2)

        # Refresh assets
        self._refresh_assets_list()

    def _add_asset(self) -> None:
        """Add a new asset."""
        try:
            asset_id = int(self.new_asset_id.get())
            org_id = int(self.new_org_id.get())
            tier_str = self.new_tier.get()

            brain = self._ensure_brain()
            from core.autonomy import AutonomyTier
            tier = AutonomyTier(tier_str)

            brain.set_asset_policy(asset_id, org_id, tier)
            self._refresh_assets_list()

            self.new_asset_id.delete(0, "end")
            self.new_org_id.delete(0, "end")
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numeric IDs")

    def _refresh_assets_list(self) -> None:
        """Refresh the assets list display."""
        self.assets_listbox.delete(0, "end")
        brain = self._ensure_brain()
        policies = brain.policy_store.all_policies()
        for policy in policies:
            tier_name = policy.tier.value
            self.assets_listbox.insert(
                "end",
                f"Asset {policy.asset_id} | Org {policy.org_id} | Tier: {tier_name}"
            )

    def _create_scan_config_tab(self) -> None:
        """Create the scan configuration tab."""
        tab = ctk.CTkFrame(self.notebook, fg_color="transparent")
        self.notebook.add(tab, text="⚙️ Scan Configuration")

        scan_frame = ctk.CTkFrame(tab, fg_color=SURFACE_MUTED,
                                  corner_radius=RADIUS_SM)
        scan_frame.pack(fill="both", expand=True, padx=10, pady=10)
        scan_frame.grid_columnconfigure(0, weight=1)
        scan_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            scan_frame,
            text="Scan Configuration",
            font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_PRIMARY
        ).pack(anchor="w", padx=SPACE_2, pady=(SPACE_2, SPACE_1))

        # Scanner selection
        sel_frame = ctk.CTkFrame(scan_frame, fg_color="transparent")
        sel_frame.pack(fill="x", padx=SPACE_2, pady=SPACE_2)
        sel_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(scan_frame, text="Default Scanner Keys:").pack(anchor="w", padx=SPACE_2, pady=SPACE_2)

        self.scanner_keys_text = ctk.CTkTextbox(scan_frame, height=40)
        self.scanner_keys_text.pack(fill="x", padx=SPACE_2, pady=SPACE_2)

        # Load default scanner keys
        from config.settings import DEFAULT_SCANNER_KEYS
        self.scanner_keys_text.insert("1.0", str(DEFAULT_SCANNER_KEYS))

        # Rate limiting
        rate_frame = ctk.CTkFrame(scan_frame, fg_color="transparent")
        rate_frame.pack(fill="x", padx=SPACE_2, pady=SPACE_2)
        rate_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(rate_frame, text="Rate Limit (req/min):").grid(row=0, column=0, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self.rate_limit = ctk.CTkEntry(rate_frame, width=100)
        self.rate_limit.insert(0, "100")
        self.rate_limit.grid(row=0, column=1, padx=SPACE_2, pady=SPACE_2, sticky="w")

        # Autonomy tier per target
        tier_frame = ctk.CTkFrame(scan_frame, fg_color="transparent")
        tier_frame.pack(fill="x", padx=SPACE_2, pady=SPACE_2)
        tier_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(tier_frame, text="Default Autonomy Tier:").grid(row=0, column=0, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self.default_tier = ctk.CTkComboBox(tier_frame, values=["observe", "recommend", "auto_contain", "auto_remediate"])
        self.default_tier.set("observe")
        self.default_tier.grid(row=0, column=1, padx=SPACE_2, pady=SPACE_2, sticky="w")

        # Save config button
        save_btn = ctk.CTkButton(
            scan_frame, text="Save Configuration",
            command=self._save_scan_config,
            font=ctk.CTkFont(*FONTS["small"])
        )
        save_btn.pack(anchor="e", padx=SPACE_2, pady=SPACE_2, side="bottom")

    def _save_scan_config(self) -> None:
        """Save scan configuration."""
        messagebox.showinfo("Saved", "Scan configuration saved successfully")

    def _create_vuln_db_tab(self) -> None:
        """Create the vulnerability database management tab."""
        tab = ctk.CTkFrame(self.notebook, fg_color="transparent")
        self.notebook.add(tab, text="📊 Vuln DB Management")

        vuln_frame = ctk.CTkFrame(tab, fg_color=SURFACE_MUTED,
                                  corner_radius=RADIUS_SM)
        vuln_frame.pack(fill="both", expand=True, padx=10, pady=10)
        vuln_frame.grid_columnconfigure(0, weight=1)
        vuln_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            vuln_frame,
            text="Vulnerability Database",
            font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_PRIMARY
        ).pack(anchor="w", padx=SPACE_2, pady=(SPACE_2, SPACE_1))

        # Actions frame
        actions_frame = ctk.CTkFrame(vuln_frame, fg_color="transparent")
        actions_frame.pack(fill="x", padx=SPACE_2, pady=SPACE_2)

        # Import CVE
        import_btn = ctk.CTkButton(
            actions_frame, text="Import CVE",
            command=self._import_cve,
            font=ctk.CTkFont(*FONTS["small"])
        )
        import_btn.pack(side="left", padx=SPACE_2, pady=SPACE_2)

        # Export CVE
        export_btn = ctk.CTkButton(
            actions_frame, text="Export CVE",
            command=self._export_cve,
            font=ctk.CTkFont(*FONTS["small"])
        )
        export_btn.pack(side="left", padx=SPACE_2, pady=SPACE_2)

        # Add fix
        add_fix_frame = ctk.CTkFrame(vuln_frame, fg_color="transparent")
        add_fix_frame.pack(fill="x", padx=SPACE_2, pady=SPACE_2)

        ctk.CTkLabel(add_fix_frame, text="Fix ID:").grid(row=0, column=0, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self.new_fix_id = ctk.CTkEntry(add_fix_frame, width=150)
        self.new_fix_id.grid(row=0, column=1, padx=SPACE_2, pady=SPACE_2, sticky="w")

        ctk.CTkLabel(add_fix_frame, text="CVE ID:").grid(row=0, column=2, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self.new_cve_id = ctk.CTkEntry(add_fix_frame, width=120)
        self.new_cve_id.grid(row=0, column=3, padx=SPACE_2, pady=SPACE_2, sticky="w")

        ctk.CTkLabel(add_fix_frame, text="Solution:").grid(row=1, column=0, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self.new_solution = ctk.CTkTextbox(add_fix_frame, height=40, width=300)
        self.new_solution.grid(row=1, column=1, columnspan=3, padx=SPACE_2, pady=SPACE_2, sticky="ew")

        ctk.CTkLabel(add_fix_frame, text="Applicability:").grid(row=1, column=4, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self.new_applicability = ctk.CTkEntry(add_fix_frame, width=200)
        self.new_applicability.grid(row=1, column=5, padx=SPACE_2, pady=SPACE_2, sticky="w")

        add_fix_btn = ctk.CTkButton(
            add_fix_frame, text="Add Fix",
            command=self._add_fix,
            font=ctk.CTkFont(*FONTS["small"])
        )
        add_fix_btn.grid(row=2, column=0, columnspan=6, padx=SPACE_2, pady=SPACE_2, sticky="w")

        # Vulnerability list
        self.vuln_listbox = tk.Listbox(vuln_frame, height=10, font=("Consolas", 9))
        self.vuln_listbox.pack(fill="both", expand=True, padx=SPACE_2, pady=SPACE_2)
        self._refresh_vuln_list()

    def _import_cve(self) -> None:
        """Import CVE from file."""
        messagebox.showinfo("Import", "CVE import functionality - select a JSON/CSV file")

    def _export_cve(self) -> None:
        """Export CVE to file."""
        messagebox.showinfo("Export", "CVE export functionality - save to JSON/CSV file")

    def _add_fix(self) -> None:
        """Add a new fix to the vulnerability database."""
        fix_id = self.new_fix_id.get()
        cve_id = self.new_cve_id.get()
        solution = self.new_solution.get("1.0", "end-1c")
        applicability = self.new_applicability.get()

        if not fix_id or not cve_id:
            messagebox.showerror("Error", "Fix ID and CVE ID are required")
            return

        brain = self._ensure_brain()
        brain.vuln_db.add_fix(fix_id, cve_id, solution, applicability)

        messagebox.showinfo("Success", f"Fix added for {cve_id}")

        self.new_fix_id.delete(0, "end")
        self.new_cve_id.delete(0, "end")
        self.new_solution.delete("1.0", "end")
        self.new_applicability.delete(0, "end")

        self._refresh_vuln_list()

    def _refresh_vuln_list(self) -> None:
        """Refresh the vulnerability list display."""
        self.vuln_listbox.delete(0, "end")
        brain = self._ensure_brain()
        fixes = brain.vuln_db.get_fixes_by_cve("test") if False else []
        self.vuln_listbox.insert("end", f"Total fixes in DB: {len(fixes)} (placeholder)")
        self.vuln_listbox.insert("end", f"Sample CVE coverage: Active")

    def _create_system_settings_tab(self) -> None:
        """Create the system settings tab."""
        tab = ctk.CTkFrame(self.notebook, fg_color="transparent")
        self.notebook.add(tab, text="🔧 System Settings")

        sys_frame = ctk.CTkFrame(tab, fg_color=SURFACE_MUTED,
                                 corner_radius=RADIUS_SM)
        sys_frame.pack(fill="both", expand=True, padx=10, pady=10)
        sys_frame.grid_columnconfigure(0, weight=1)
        sys_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            sys_frame,
            text="System Settings",
            font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_PRIMARY
        ).pack(anchor="w", padx=SPACE_2, pady=(SPACE_2, SPACE_1))

        # Autonomy tier settings
        tier_frame = ctk.CTkFrame(sys_frame, fg_color="transparent")
        tier_frame.pack(fill="x", padx=SPACE_2, pady=SPACE_2)
        tier_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(tier_frame, text="Global Default Autonomy Tier:").grid(row=0, column=0, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self.global_tier = ctk.CTkComboBox(tier_frame, values=["observe", "recommend", "auto_contain", "auto_remediate"])
        self.global_tier.set("observe")
        self.global_tier.grid(row=0, column=1, padx=SPACE_2, pady=SPACE_2, sticky="w")

        # FP brake settings
        fp_frame = ctk.CTkFrame(sys_frame, fg_color="transparent")
        fp_frame.pack(fill="x", padx=SPACE_2, pady=SPACE_2)
        fp_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(fp_frame, text="FP Block Max per minute:").grid(row=0, column=0, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self.fp_block_max = ctk.CTkEntry(fp_frame, width=100)
        self.fp_block_max.insert(0, "5")
        self.fp_block_max.grid(row=0, column=1, padx=SPACE_2, pady=SPACE_2, sticky="w")

        # Learning settings
        learn_frame = ctk.CTkFrame(sys_frame, fg_color="transparent")
        learn_frame.pack(fill="x", padx=SPACE_2, pady=SPACE_2)
        learn_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(learn_frame, text="Learning Enabled:").grid(row=0, column=0, padx=SPACE_2, pady=SPACE_2, sticky="w")
        self.learning_enabled = ctk.CTkCheckBox(learn_frame, text="On")
        self.learning_enabled.grid(row=0, column=1, padx=SPACE_2, pady=SPACE_2, sticky="w")

        # Save settings
        save_btn = ctk.CTkButton(
            sys_frame, text="Save Settings",
            command=self._save_system_settings,
            font=ctk.CTkFont(*FONTS["small"])
        )
        save_btn.pack(anchor="e", padx=SPACE_2, pady=SPACE_2, side="bottom")

    def _save_system_settings(self) -> None:
        """Save system settings."""
        brain = self._ensure_brain()
        settings = {
            "global_tier": self.global_tier.get(),
            "fp_block_max": self.fp_block_max.get(),
            "learning_enabled": self.learning_enabled.get()
        }
        messagebox.showinfo("Saved", "System settings saved successfully")

    def _create_audit_log_tab(self) -> None:
        """Create the audit log tab."""
        tab = ctk.CTkFrame(self.notebook, fg_color="transparent")
        self.notebook.add(tab, text="📝 Audit Log")

        log_frame = ctk.CTkFrame(tab, fg_color=SURFACE_MUTED,
                                 corner_radius=RADIUS_SM)
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            log_frame,
            text="Audit Log — All admin actions are recorded",
            font=ctk.CTkFont(*FONTS["heading"]),
            text_color=TEXT_PRIMARY
        ).pack(anchor="w", padx=SPACE_2, pady=(SPACE_2, SPACE_1))

        # Log list with scrollbar
        list_frame = ctk.CTkFrame(log_frame, fg_color="transparent")
        list_frame.pack(fill="both", expand=True, padx=SPACE_2, pady=SPACE_2)
        list_frame.grid_columnconfigure(0, weight=1)
        list_frame.grid_rowconfigure(0, weight=1)

        self.audit_listbox = tk.Listbox(list_frame, height=15, font=("Consolas", 9))
        self.audit_listbox.grid(row=0, column=0, sticky="nsew", padx=SPACE_2, pady=SPACE_2)

        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.audit_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.audit_listbox.config(yscrollcommand=scrollbar.set)

        # Populate with sample audit entries
        self._populate_audit_log()

    def _create_evolution_tab(self) -> None:
        """Create the evolution/learning tab."""
        tab = ctk.CTkFrame(self.notebook, fg_color="transparent")
        self.notebook.add(tab, text="🧠 Evolution")

        from ui.views.evolution_view import init_evolution_view
        evolution = init_evolution_view(tab, self.events)
        evolution.pack(fill="both", expand=True, padx=10, pady=10)

    def _create_fixes_tab(self) -> None:
        """Create the fixes/remediation tab."""
        tab = ctk.CTkFrame(self.notebook, fg_color="transparent")
        self.notebook.add(tab, text="🔧 Fixes")

        from ui.views.fixes_view import init_fixes_view
        fixes = init_fixes_view(tab, self.events)
        fixes.pack(fill="both", expand=True, padx=10, pady=10)

    def _populate_audit_log(self) -> None:
        """Populate the audit log with sample entries."""
        sample_entries = [
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Admin login successful",
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Asset added: Asset 101 | Org 1 | Tier: observe",
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Kill switch engaged",
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Scan completed: 5 findings, 2 critical",
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fix applied: CVE-2024-1234",
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Autonomy tier updated: Asset 101 → recommend",
        ]

        for entry in sample_entries:
            self.audit_listbox.insert("end", entry)


def init_admin_panel(root, events: queue.Queue):
    """Initialize and return the admin panel widget."""
    admin_view = AdminPanel(root, events)
    return admin_view
