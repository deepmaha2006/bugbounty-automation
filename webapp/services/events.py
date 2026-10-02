"""
In-memory event bus for live scan progress (SSE).

Each scan has a bounded deque of events. Consumers (SSE endpoints) drain it
and stream to the browser. Events are simple dicts:
    {"type": "phase"|"status"|"progress"|"finding"|"done"|"error", ...}
"""
import threading
from collections import deque
from typing import Dict, Deque, List

_bus: Dict[int, Deque[dict]] = {}
_lock = threading.Lock()
MAX_EVENTS = 2000


def new_scan_bus(scan_id: int) -> None:
    with _lock:
        _bus[scan_id] = deque(maxlen=MAX_EVENTS)


def emit(scan_id: int, event: dict) -> None:
    with _lock:
        bus = _bus.get(scan_id)
        if bus is not None:
            bus.append(event)


def drain(scan_id: int) -> List[dict]:
    with _lock:
        bus = _bus.get(scan_id)
        if not bus:
            return []
        out = list(bus)
        bus.clear()
        return out


def snapshot(scan_id: int) -> List[dict]:
    with _lock:
        bus = _bus.get(scan_id)
        return list(bus) if bus else []


def drop(scan_id: int) -> None:
    with _lock:
        _bus.pop(scan_id, None)
