"""
Design tokens and theme configuration for the HydraX desktop interface.

Uses the design the (since removed) web frontend used: a monochrome dark
base, the fixed severity palette as the only saturated colour, cyber red as
the accent, soft 6-8px corners, a sans body font and a monospace face for
numbers. Views import these names directly, so changing a value here
restyles every view.
"""
from typing import Any, Dict

# ═══════════════════════════════════════════════════════════════════════════════
# COLOR TOKENS — mirrors the web --bg-*/--line-*/--txt-*/--sev-* tokens
# ═══════════════════════════════════════════════════════════════════════════════

# Surface scale — cyber red / SOC terminal palette
SURFACE_BASE = "#080b0f"      # Deep black — terminal background
SURFACE_MUTED = "#0f1318"     # Cards, panels, inputs
SURFACE_RAISED = "#c41e3a"    # Primary accent — cyber red
SURFACE_STRONG = "#181e24"    # Hover/active rows

# Border scale
BORDER_HAIRLINE = "#1c2530"   # Dividers, card outlines
BORDER_ACCENT = "#c41e3a"     # Focus rings, active borders (red)

# Text scale
TEXT_PRIMARY = "#e8edf2"      # Headlines, body
TEXT_SECONDARY = "#8fa0b0"    # Supporting copy
TEXT_TERTIARY = "#ff5a6e"     # Accent text, links, counts (threat red)
TEXT_INVERSE = "#0f1318"      # Text on accent surfaces

# Status / Severity — spec-mandated SOC severity palette
STATUS_CRITICAL = "#E5484D"   # Red — critical findings
STATUS_HIGH     = "#FF8B3D"   # Orange — high findings
STATUS_MEDIUM   = "#F5C518"   # Yellow — medium findings
STATUS_LOW      = "#8B97A7"   # Gray/Blue — low / info
STATUS_INFO     = "#8B97A7"   # Same as LOW
STATUS_OK       = "#3DD68C"   # Green — success / clean

# Severity colors for vulnerability findings — used everywhere in the UI
SEVERITY_COLORS = {
    "Critical": STATUS_CRITICAL,
    "High":     STATUS_HIGH,
    "Medium":   STATUS_MEDIUM,
    "Low":      STATUS_LOW,
    "Info":     STATUS_INFO,
    # lowercase aliases so callers don't need to title-case
    "critical": STATUS_CRITICAL,
    "high":     STATUS_HIGH,
    "medium":   STATUS_MEDIUM,
    "low":      STATUS_LOW,
    "info":     STATUS_INFO,
}

# Severity order for live defense gauge and priority ordering
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

# Status chip colors — STANDBY/CONNECTED/SCANNING/PAUSED/ERROR
STATUS_CHIP_COLORS = {
    "STANDBY":   ("#8B97A7", SURFACE_STRONG),    # gray text, dark bg
    "CONNECTED": ("#3DD68C", "#0d2018"),          # green text, dark green bg
    "SCANNING":  ("#3DD68C", "#0d2018"),          # animated green pulse
    "PAUSED":    ("#F5C518", "#201a04"),          # yellow text
    "ERROR":     ("#E5484D", "#280d0e"),          # red text
}

STATUS_RUNNING_COLOR = "#3DD68C"   # animated pulse color when scanning

# Pulse animation configuration for real-time indicators
def pulse_animation_config() -> Dict[str, Any]:
    """Return pulse animation parameters for live defense view."""
    return {
        "enabled": True,
        "interval_ms": 1000,          # Pulse cycle time
        "opacity_range": (0.5, 1.0),  # Min/max alpha for pulse
        "critical_speed_ms": 500,     # Faster pulse for critical
        "high_speed_ms": 800,         # High severity pulse
        "medium_speed_ms": 1200,      # Medium severity pulse
        "low_speed_ms": 2000,         # Slow pulse for low
    }

# Row tints for the scanner grid (web .is-bad / .is-good, pre-blended on
# SURFACE_MUTED because Tk has no alpha)
ROW_BAD = "#1a0c0f"
ROW_GOOD = "#0d1710"

# Status indicator colors (for StatusIndicator widget)
STATUS_COLORS = {
    "idle":    TEXT_SECONDARY,
    "active":  STATUS_RUNNING_COLOR,
    "success": STATUS_OK,
    "warning": STATUS_HIGH,
    "error":   STATUS_CRITICAL,
}

# Profile page accent (web .profile-pro tokens)
PROFILE_PAGE = "#0e0e12"
PROFILE_CARD = "#16161c"
PROFILE_CARD_2 = "#1b1b23"
PROFILE_LINE = "#26262e"
PROFILE_ACCENT = "#6c5cff"
PROFILE_ACCENT_HOVER = "#7c6cff"
PROFILE_ACCENT_SOFT = "#221f3d"   # accent at ~14% on PROFILE_CARD
PROFILE_ACCENT_TEXT = "#b9b1ff"
PROFILE_DIM = "#8b8b98"

# ═══════════════════════════════════════════════════════════════════════════════
# TYPOGRAPHY — sans body, serif display headings, mono numbers (as on the web)
# ═══════════════════════════════════════════════════════════════════════════════

# First installed family wins; resolve_fonts() picks it once a Tk root exists.
FONT_STACK = ("Inter", "Segoe UI", "Helvetica Neue", "DejaVu Sans", "Helvetica")
DISPLAY_STACK = ("Playfair Display", "Georgia", "DejaVu Serif", "Times New Roman")
MONO_STACK = ("JetBrains Mono", "Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Courier New")

# (stack, size, weight) — turned into FONTS below.
_FONT_SPEC = {
    "heading":     (DISPLAY_STACK, 26, "bold"),
    "subheading":  (FONT_STACK, 16, "bold"),
    "body":        (FONT_STACK, 13, "normal"),
    "body_bold":   (FONT_STACK, 13, "bold"),
    "small":       (FONT_STACK, 11, "normal"),
    "small_bold":  (FONT_STACK, 11, "bold"),
    "mono":        (MONO_STACK, 12, "normal"),
    "score":       (MONO_STACK, 44, "bold"),
    "stat_number": (MONO_STACK, 20, "bold"),
    "brand":       (DISPLAY_STACK, 17, "bold"),
}

# Views read FONTS[...] when they build widgets (after the root exists), so
# resolve_fonts() updates this dict in place and every view sees the result.
FONTS = {k: (stack[0], size, weight) for k, (stack, size, weight) in _FONT_SPEC.items()}


def resolve_fonts():
    """Swap each font to the first family installed on this machine.

    Needs a Tk root (tkinter.font.families() does); call it right after the
    root window is created. Safe to call more than once."""
    try:
        import tkinter.font as tkfont
        installed = set(tkfont.families())
    except Exception:
        return
    for key, (stack, size, weight) in _FONT_SPEC.items():
        family = next((f for f in stack if f in installed), stack[-1])
        FONTS[key] = (family, size, weight)


# ═══════════════════════════════════════════════════════════════════════════════
# SPACING — 8-point base
# ═══════════════════════════════════════════════════════════════════════════════

SPACE_1 = 4
SPACE_2 = 6
SPACE_3 = 9
SPACE_4 = 12
SPACE_5 = 16
SPACE_6 = 20
SPACE_7 = 28
SPACE_8 = 40
SPACE_9 = 50
SPACE_10 = 60

# Semantic spacing aliases
SPACE_XS = SPACE_1
SPACE_SM = SPACE_2
SPACE_MD = SPACE_4
SPACE_LG = SPACE_6
SPACE_XL = SPACE_7
SPACE_2XL = SPACE_8

# ═══════════════════════════════════════════════════════════════════════════════
# RADIUS — soft corners, as on the web (RADIUS_NONE stays a true 0)
# ═══════════════════════════════════════════════════════════════════════════════

RADIUS_NONE = 0
RADIUS_XS = 4
RADIUS_SM = 6
RADIUS_MD = 8
RADIUS_LG = 14

# ═══════════════════════════════════════════════════════════════════════════════
# MOTION
# ═══════════════════════════════════════════════════════════════════════════════

MOTION_INSTANT = 0
MOTION_FAST = 100
MOTION_NORMAL = 150
MOTION_SLOW = 200

# ═══════════════════════════════════════════════════════════════════════════════
# COMPONENT TOKENS
# ═══════════════════════════════════════════════════════════════════════════════

BTN_HEIGHT_SM = 28
BTN_HEIGHT_MD = 34
BTN_HEIGHT_LG = 40

BTN_WIDTH_SM = 80
BTN_WIDTH_MD = 120
BTN_WIDTH_LG = 160
BTN_WIDTH_XL = 200

INPUT_HEIGHT = 34

CARD_PADDING = SPACE_5

BORDER_WIDTH_HAIRLINE = 1
BORDER_WIDTH_ACCENT = 2

FOCUS_RING_WIDTH = 2
FOCUS_RING_COLOR = BORDER_ACCENT
FOCUS_RING_OFFSET = 2

# ═══════════════════════════════════════════════════════════════════════════════
# BACKWARD COMPATIBILITY ALIASES (existing imports keep working)
# ═══════════════════════════════════════════════════════════════════════════════

BG = SURFACE_BASE
SURFACE = SURFACE_MUTED
SURFACE_ALT = SURFACE_STRONG
BORDER = BORDER_HAIRLINE
ACCENT = SURFACE_RAISED
ACCENT_HOVER = "#e02040"   # brighter red for hover
ACCENT_DARK = "#9c1630"    # darker red for pressed

# Severity row tint helpers — pre-blended on SURFACE_MUTED (Tk has no alpha)
SEV_ROW = {
    "critical": "#210a0b",
    "high":     "#1f100a",
    "medium":   "#1a1502",
    "low":      "#0d1014",
    "info":     "#0d1014",
}

# ═══════════════════════════════════════════════════════════════════════════════
# THEME APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

def configure_app():
    """Configure CustomTkinter appearance. Fonts are resolved separately by
    resolve_fonts() once the root window exists."""
    import customtkinter as ctk

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")  # base theme; widgets pass explicit colors
