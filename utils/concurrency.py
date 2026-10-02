"""
Shared helper for running a scanner's independent scan phases concurrently.

Every scanner's scan() method is a sequential pipeline of phase methods
(e.g. XSSScanner: _scan_discovered_targets, _scan_reflected_xss,
_scan_stored_xss, _scan_dom_based_xss, _scan_blind_xss) that each issue
dozens of real HTTP requests through HTTPClient (which adds a per-request
rate-limit delay on top of network latency) and append their own findings
to self.findings. Running them one after another made a single scanner take
minutes even against a small site — not because inter-scanner parallelism
was missing (ScanEngine already runs selected scanners concurrently), but
because each *individual* scanner's own phases were serial.

Each phase only appends to shared state and never reads another phase's
in-progress findings, so they're safe to fan out across threads: CPython's
GIL makes list.append() atomic, and there is no cross-phase dependency.
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List


def run_phases_concurrently(phases: List[Callable[[], None]], max_workers: int = None) -> None:
    """Run independent, no-return scan-phase callables concurrently.

    Each phase is a zero-argument callable (bind its real arguments via a
    lambda or nested function) that mutates shared scanner state, typically
    self.findings. Exceptions from a phase propagate to the caller once all
    phases have finished, matching the behavior of calling each phase
    directly in sequence.
    """
    if not phases:
        return
    with ThreadPoolExecutor(max_workers=max_workers or len(phases)) as executor:
        futures = [executor.submit(phase) for phase in phases]
        for future in futures:
            future.result()
