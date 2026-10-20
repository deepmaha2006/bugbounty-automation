"""
XSS payload bundle.

References the curated payloads already in utils/payloads.py so there is
one source of truth for payload strings. Agents that need raw payload lists
call get_payloads(bundle_name).
"""

from utils.payloads import Payloads

BUNDLES = {
    "reflected": Payloads.XSS_REFLECTED,
    "stored":    Payloads.XSS_STORED,
    "dom":       Payloads.XSS_DOM_BASED,
    "blind":     Payloads.BLIND_XSS,
}


def get_payloads(bundle_name: str) -> list:
    """Return a copy of the named payload list, or [] if unknown."""
    return list(BUNDLES.get(bundle_name, []))
