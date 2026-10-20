"""SQLi payload bundle — single source of truth is utils/payloads.py."""

from utils.payloads import Payloads

BUNDLES = {
    "error":   Payloads.SQLI_ERROR_BASED,
    "boolean": Payloads.BLIND_SQLI_BOOLEAN,
    "time":    Payloads.SQLI_TIME_BASED,
    "union":   Payloads.SQLI_UNION,
}


def get_payloads(bundle_name: str) -> list:
    return list(BUNDLES.get(bundle_name, []))
