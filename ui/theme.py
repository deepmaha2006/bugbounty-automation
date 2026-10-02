"""
Design tokens and theme configuration for the HydraX desktop interface.

Uses the design the (since removed) web frontend used: a monochrome dark
base, the fixed severity palette as the only saturated colour, gold as the
accent, soft 6-8px corners, a sans body font and a monospace face for
numbers. Views import these names directly, so changing a value here
restyles every view.
"""

# ═══════════════════════════════════════════════════════════════════════════════
# COLOR TOKENS — mirrors the web --bg-*/--line-*/--txt-*/--sev-* tokens
# ═══════════════════════════════════════════════════════════════════════════════

# Surface scale
SURFACE_BASE = "#0b0b0b"      # App background        (web --dt-page)
SURFACE_MUTED = "#121212"     # Cards, panels, inputs (web --dt-panel)
SURFACE_RAISED = "#bda14a"    # Primary accent surface (web --accent, gold)
SURFACE_STRONG = "#1d1d1d"    # Hover/active rows

# Border scale
BORDER_HAIRLINE = "#222222"   # Dividers, card outlines (web --dt-line)
BORDER_ACCENT = "#bda14a"     # Focus rings, active borders (gold)

# Text scale
TEXT_PRIMARY = "#f2f2f2"      # Headlines, body
TEXT_SECONDARY = "#a8a8a8"    # Supporting copy
TEXT_TERTIARY = "#d4bc6a"     # Accent text, links, counts (light gold)
TEXT_INVERSE = "#0b0b0b"      # Text on accent surfaces

# Status / Severity — the fixed web severity palette
STATUS_CRITICAL = "#d14b4b"
STATUS_HIGH = "#cf7f2e"
STATUS_MEDIUM = "#bda14a"
STATUS_LOW = "#7f97ad"
STATUS_INFO = "#8f8f8f"
STATUS_OK = "#6fae78"         # Success / ok (web --dt-green)

# Severity colors for vulnerability findings
SEVERITY_COLORS = {
    "Critical": STATUS_CRITICAL,
    "High": STATUS_HIGH,
    "Medium": STATUS_MEDIUM,
    "Low": STATUS_LOW,
    "Info": STATUS_INFO,
}

# Row tints for the scanner grid (web .is-bad / .is-good, pre-blended on
# SURFACE_MUTED because Tk has no alpha)
ROW_BAD = "#1f1414"
ROW_GOOD = "#151c16"

# Status indicator colors (for StatusIndicator widget)
STATUS_COLORS = {
    "idle": TEXT_SECONDARY,
    "active": TEXT_TERTIARY,
    "success": STATUS_OK,
    "warning": STATUS_HIGH,
    "error": STATUS_CRITICAL,
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
ACCENT_HOVER = "#cdb25c"   # lighter gold for hover
ACCENT_DARK = "#9c843a"    # darker gold for pressed

# ═══════════════════════════════════════════════════════════════════════════════
# THEME APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

def configure_app():
    """Configure CustomTkinter appearance. Fonts are resolved separately by
    resolve_fonts() once the root window exists."""
    import customtkinter as ctk

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")  # base theme; widgets pass explicit colors
