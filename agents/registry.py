"""
Agent registry — discovers all ScanAgent subclasses in this package and
builds AGENT_MAP keyed by scanner key.

For scanner keys that don't yet have a proper ScanAgent, a LegacyAdapter
is created from the existing SCANNER_MAP entry so that:

    AGENT_MAP.keys() == SCANNER_MAP.keys()

at all times. Back-compat: code that imports SCANNER_MAP from config.settings
is unaffected — the registry is additive.
"""

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Dict

from agents.base import ScanAgent

_AGENTS_DIR = Path(__file__).parent

# Public registry — populated by build_registry() at import time.
AGENT_MAP: Dict[str, ScanAgent] = {}


def _discover_proper_agents() -> Dict[str, ScanAgent]:
    """Import every *_agent.py module in this package and collect ScanAgents."""
    found: Dict[str, ScanAgent] = {}
    for module_info in pkgutil.iter_modules([str(_AGENTS_DIR)]):
        if not module_info.name.endswith("_agent"):
            continue
        try:
            mod = importlib.import_module(f"agents.{module_info.name}")
        except Exception:
            continue
        for _name, obj in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(obj, ScanAgent)
                and obj is not ScanAgent
                and hasattr(obj, "manifest")
                and not getattr(obj, "_is_legacy_adapter", False)
            ):
                try:
                    instance = obj()
                    found[instance.manifest.key] = instance
                except Exception:
                    continue
    return found


def _fill_legacy_adapters(
    known: Dict[str, ScanAgent],
) -> Dict[str, ScanAgent]:
    """Create LegacyAdapter entries for every SCANNER_MAP key not yet ported."""
    from config.settings import SCANNER_MAP, SCANNER_META
    from agents._legacy_adapter import LegacyAdapter

    result = dict(known)
    for key, cls in SCANNER_MAP.items():
        if key not in result:
            meta = dict(SCANNER_META.get(key, {"key": key, "name": key}))
            result[key] = LegacyAdapter(cls, meta)
    return result


def build_registry() -> None:
    """Populate AGENT_MAP. Called automatically on first import."""
    global AGENT_MAP
    proper = _discover_proper_agents()
    AGENT_MAP = _fill_legacy_adapters(proper)


# Build on first import.
build_registry()
