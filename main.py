"""
Bug Bounty Professional — application entry point.

Launches the GUI. All logic lives in the config/, core/, scanners/,
utils/ and ui/ packages; this file only shows the startup banner
and starts the application.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import settings
from ui.main_window import run

# Pure-ASCII 5-row block letters so the banner survives any Windows
# console encoding (cp1252/GBK/UTF-8) without Unicode errors.
_LETTERS = {
    'H': [' _   _ ', '| | | |', '| |_| |', '|  _  |', '|_| |_|'],
    'Y': [' __   __', ' \\\\ \\\\ / /', '  \\\\ V / ', '   | |  ', '   |_|  '],
    'D': [' ____  ', '|  _ \\\\ ', '| | | |', '| |_| |', '|____/ '],
    'R': [' ____  ', '|  _ \\\\ ', '| |_) |', '|  _ < ', '|_| \\\\_\\\\'],
    'A': ['  ___  ', ' / _ \\\\ ', '| (_) |', ' > _ < ', '|_| \\\\_\\\\'],
    'X': [' __  __', ' \\\\ \\\\/ /', '  \\\\  / ', ' / /\\\\ \\\\', '/_/  \\\\_\\\\'],
    ' ': ['      ', '      ', '      ', '      ', '      '],
}



def _render(text: str) -> str:
    """Render a string as 5-row ASCII block letters."""
    rows = ["", "", "", "", ""]
    for ch in text.upper():
        art = _LETTERS.get(ch, _LETTERS[' '])
        for i in range(5):
            rows[i] += art[i] + " "
    return "\n".join(r.rstrip() for r in rows)


def print_banner() -> None:
    """Print the ASCII startup banner with application metadata."""
    body = _render("HYDRAX")
    width = max(len(line) for line in body.splitlines())
    print(body)
    print("=" * width)
    print(f"  {settings.APP_NAME}  v{settings.VERSION}")
    print(f"  {settings.APP_TAGLINE}")
    print("=" * width)
    print(f"  Python {sys.version.split()[0]}  |  {sys.platform}")
    print("  Authorized use only. Scanning systems you do not own is illegal.")
    print("=" * width)
    print()


if __name__ == "__main__":
    print_banner()
    run()
