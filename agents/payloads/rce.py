"""RCE / command injection payload bundle — single source of truth is utils/payloads.py."""

from utils.payloads import Payloads

BUNDLES = {
    "cmd":  Payloads.CMD_INJECTION,
    "ssti": [p[0] if isinstance(p, tuple) else p for p in Payloads.SSTI],
}


def get_payloads(bundle_name: str) -> list:
    return list(BUNDLES.get(bundle_name, []))
