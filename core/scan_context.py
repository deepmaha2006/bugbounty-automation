"""
Shared per-scan context.

The ScanEngine builds one ScanContext per scan run: it holds the stop
event (propagated to every in-flight HTTP request so "stop" actually
aborts work), plus the result of the URL/parameter discovery pass so
every scanner tests the same real attack surface without re-crawling.

The context is stored in thread-local storage and injected into each
scanner worker thread by the engine, keeping the scanner interface
(scan(target_url)) unchanged and backwards compatible.
"""

import threading
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from config.scope import ScopeConfig
    from core.auth import AuthState


class ScanAborted(Exception):
    """Raised inside a scanner when the user requested a stop."""


class ScanContext:
    """Everything a scanner may need to know about the current run."""

    def __init__(self, target: str, options: Optional[Dict[str, Any]] = None):
        self.target = target
        self.options = options or {}
        self.stop_event = threading.Event()
        # Populated by the engine's discovery phase before scanners run.
        self.discovered_targets: List[Any] = []
        self.discovery_summary: Dict[str, Any] = {}
        self.duration_limit = float(self.options.get("scanner_timeout", 600))

        # Authentication state (set by AuthManager.bind_to_context)
        self.auth_state: Optional["AuthState"] = None

        # Scope configuration (set by ScanEngine)
        self.scope: Optional["ScopeConfig"] = None

    def request_stop(self) -> None:
        self.stop_event.set()

    @property
    def stopped(self) -> bool:
        return self.stop_event.is_set()


_thread_local = threading.local()


def set_scan_context(ctx: Optional[ScanContext]) -> None:
    """Bind a context to the current thread (called inside worker threads)."""
    _thread_local.ctx = ctx


def get_scan_context() -> Optional[ScanContext]:
    return getattr(_thread_local, "ctx", None)


def clear_scan_context() -> None:
    try:
        delattr(_thread_local, "ctx")
    except AttributeError:
        pass


def stop_requested() -> bool:
    """True when the user asked the current scan to stop."""
    ctx = get_scan_context()
    return bool(ctx and ctx.stopped)


def abort_if_stopped() -> None:
    """Raise ScanAborted when a stop was requested (call between requests)."""
    if stop_requested():
        raise ScanAborted("Scan stopped by user")


def get_test_targets(max_targets: int = 0, include_get: bool = True,
                      include_post: bool = True) -> List[Tuple[str, List[str], str, Dict[str, str]]]:
    """
    Return the discovered attack surface for the current scan as a list of
    (url, param_names, method, form_fields) tuples. Scanners use this to
    test every discovered endpoint/parameter, not just the bare target URL.

    Args:
        max_targets: cap on the number of returned targets (0 = no limit).
        include_get: include GET targets.
        include_post: include POST (form) targets.
    """
    ctx = get_scan_context()
    if not ctx or not ctx.discovered_targets:
        return []

    # Apply scope filtering if configured
    scope = getattr(ctx, "scope", None)

    out = []
    for t in ctx.discovered_targets:
        url = getattr(t, "url", "")
        if scope and not scope.is_in_scope(url):
            continue

        method = getattr(t, "method", "get") or "get"
        if method == "post" and not include_post:
            continue
        if method == "get" and not include_get:
            continue
        params = list(getattr(t, "params", []) or [])
        fields = dict(getattr(t, "form_fields", {}) or {})
        out.append((t.url, params, method, fields))
        if max_targets and len(out) >= max_targets:
            break
    return out


def inject_param(url: str, param: str, value: str) -> str:
    """Return url with `param` set to `value` (preserving other parameters)."""
    from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
