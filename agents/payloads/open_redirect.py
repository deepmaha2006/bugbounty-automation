"""Open redirect payload bundle — single source of truth is utils/payloads.py."""

from utils.payloads import Payloads

BUNDLES = {
    "redirect": Payloads.OPEN_REDIRECT,
}


def get_payloads(bundle_name: str) -> list:
    return list(BUNDLES.get(bundle_name, []))
