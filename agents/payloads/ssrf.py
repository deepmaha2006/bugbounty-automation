"""SSRF payload bundle — single source of truth is utils/payloads.py."""

from utils.payloads import Payloads

BUNDLES = {
    "internal": Payloads.SSRF_INTERNAL,
}


def get_payloads(bundle_name: str) -> list:
    return list(BUNDLES.get(bundle_name, []))
