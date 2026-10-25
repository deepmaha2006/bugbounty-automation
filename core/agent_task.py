"""
Factory for building ParallelScanScheduler ModuleDef callables that run real
agents from AGENT_MAP, sharing a pre-computed discovery context.

Usage (inside a UI view)::

    from core.agent_task import build_module_defs

    module_defs = build_module_defs(
        keys=["xss", "sqli", "headers"],
        target=target,
        discovery=discovery_dict,   # from URLDiscovery.discover()
        emit=self._q.put_nowait,
    )
    scheduler = ParallelScanScheduler(
        modules=module_defs, target=target,
        emit=self._q.put_nowait, stop_event=stop_event
    )
    scheduler.run()

If an agent key is not in AGENT_MAP (e.g. shannon, hexstrike), a no-op stub
is returned so the chip at least transitions QUEUED → DONE cleanly.
"""

from __future__ import annotations

import datetime
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from config import settings as _cfg
from core.parallel_scheduler import ModuleDef


def _run_real_agent(
    key: str,
    target: str,
    discovery: Dict[str, Any],
    stop: threading.Event,
) -> List[Dict[str, Any]]:
    """Run one agent from AGENT_MAP and return its findings as dicts."""
    from agents.registry import AGENT_MAP
    from agents.base import AgentContext
    from agents.toolchain import preflight
    from core.scan_context import ScanContext, set_scan_context, ScanAborted
    from utils.sync_rate_limiter import get_shared_rate_limiter
    from utils.http_client import HTTPClient

    agent = AGENT_MAP.get(key)
    if agent is None:
        return []

    # Quick preflight — raise MODULE_NOT_READY if required tools are absent
    report = preflight(agent)
    if not report.can_run:
        missing = ", ".join(getattr(report, "missing", []) or [])
        raise RuntimeError(
            f"MODULE_NOT_READY: {missing}" if missing else "MODULE_NOT_READY: dependency check failed"
        )

    if stop.is_set():
        return []

    http_client = HTTPClient()
    rate_limiter = get_shared_rate_limiter()
    workdir = Path(getattr(_cfg, "REPORTS_DIR", "."))

    def _noop_emit(*args):
        pass  # agent-level events suppressed; scheduler emits module_status

    ctx = AgentContext(
        target=target,
        scope=None,
        stop=stop,
        rate_limiter=rate_limiter,
        http_client=http_client,
        emit=_noop_emit,
        workdir=workdir,
    )
    ctx.discovered_targets = discovery.get("urls", [target])
    ctx.discovery_summary = discovery

    # Legacy ScanContext so wrapped scanners keep working
    legacy = ScanContext(target=target, options={})
    legacy.stop_event = stop
    legacy.discovered_targets = ctx.discovered_targets
    legacy.discovery_summary = ctx.discovery_summary
    set_scan_context(legacy)

    try:
        raw = agent.run(ctx) or []
        max_f = getattr(_cfg, "MAX_FINDINGS_PER_SCANNER", 50)
        findings = []
        for f in raw[:max_f]:
            if stop.is_set():
                break
            findings.append(f.to_dict() if hasattr(f, "to_dict") else dict(f))
        return findings
    except ScanAborted:
        return []
    except Exception:
        raise   # let the scheduler mark the chip as FAILED


def _stub_task(target: str, stop: threading.Event) -> List[Dict]:
    """No-op task for keys without a real agent (e.g. shannon, hexstrike)."""
    return []


def build_module_defs(
    keys: List[str],
    target: str,
    discovery: Dict[str, Any],
    emit: Optional[Callable] = None,
) -> List[ModuleDef]:
    """Return a ModuleDef list whose run callables use real agents.

    For keys not in AGENT_MAP, a stub that immediately returns [] is used
    so the chip still transitions through QUEUED → DONE without an error.
    """
    from agents.registry import AGENT_MAP
    from config.settings import SCANNER_META

    defs: List[ModuleDef] = []
    for key in keys:
        label = SCANNER_META.get(key, {}).get("name", key)

        if key in AGENT_MAP:
            # Closure captures key + discovery dict (shared, read-only)
            def _make_run(k: str, disc: Dict) -> Callable:
                def _run(tgt: str, stop: threading.Event) -> List[Dict]:
                    return _run_real_agent(k, tgt, disc, stop)
                return _run
            run_fn = _make_run(key, discovery)
        else:
            run_fn = _stub_task

        defs.append(ModuleDef(key=key, label=label, run=run_fn))

    return defs
