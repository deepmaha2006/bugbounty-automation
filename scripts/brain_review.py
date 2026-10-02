"""Print the remediation engine's review queue: finding types it keeps seeing
but cannot yet resolve, most frequent first, with nearest-KB hints.

    python scripts/brain_review.py [--sort frequency|recent|signature] [--limit N]

Read-only: it only reads webapp/data/brain/unresolved.json. To promote a
completed draft, use remediation_service.promote_unresolved() (docs/BRAIN.md).
"""
import argparse
import logging
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
warnings.filterwarnings("ignore")
logging.disable(logging.WARNING)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # noqa: BLE001
    pass

from webapp.services import remediation_service as rs  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sort", default="frequency", choices=["frequency", "recent", "signature"])
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()
    print(rs.format_review_queue(limit=args.limit, sort=args.sort))


if __name__ == "__main__":
    main()
