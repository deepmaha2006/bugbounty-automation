"""
HydraBrain sensors — normalize connector-reported telemetry into Event objects
and persist them to brain_events.

Phase 13: observe mode only. Events are ingested and stored; no action is taken.

Safety: ingest_connector_telemetry() always verifies a current
get_active_authorization() row exists before writing any events.  Out-of-scope
or unauthorized assets are refused with AuthorizationError.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Authorization error
# ---------------------------------------------------------------------------

class AuthorizationError(Exception):
    """Raised when an asset lacks a current authorization row."""


# ---------------------------------------------------------------------------
# Event dataclass
# ---------------------------------------------------------------------------

@dataclass
class Event:
    asset_id: int
    org_id: int
    ts: datetime
    src_ip: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    signals: Dict[str, Any] = field(default_factory=dict)
    raw_line: Optional[str] = None


# ---------------------------------------------------------------------------
# Log-line parsers
# ---------------------------------------------------------------------------

# Apache / Nginx combined log format:
# 1.2.3.4 - user [10/Oct/2000:13:55:36 -0700] "GET /path HTTP/1.1" 200 1234 "ref" "ua"
_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+'           # client IP
    r'\S+\s+\S+\s+'              # ident, user
    r'\[(?P<ts>[^\]]+)\]\s+'     # timestamp
    r'"(?P<method>\S+)\s+'       # method
    r'(?P<path>\S+)\s+'          # path
    r'\S+"\s+'                   # protocol
    r'(?P<status>\d{3})'         # status
)

# Months used in Apache/Nginx combined format timestamps.
_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Signal detection patterns (attack recognition only — no offensive payloads).
_PATH_TRAVERSAL_RE = re.compile(r'\.\.[\\/]|%2e%2e|%252e', re.IGNORECASE)
_SQLI_HINTS_RE = re.compile(
    r"(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b|'--|\bOR\b\s+['\d]+=|"
    r"sleep\s*\(|benchmark\s*\(|INFORMATION_SCHEMA)",
    re.IGNORECASE,
)
_XSS_HINTS_RE = re.compile(
    r'<script|javascript:|onerror\s*=|onload\s*=|%3cscript|%3c/script',
    re.IGNORECASE,
)
_SCANNER_UA_RE = re.compile(
    r'(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|ffuf|hydra|burpsuite)',
    re.IGNORECASE,
)


def _parse_combined_ts(raw: str) -> datetime:
    """Parse Apache/Nginx combined log timestamp, e.g. '10/Oct/2000:13:55:36 -0700'."""
    try:
        day, rest = raw.split("/", 1)
        month_name, rest2 = rest.split("/", 1)
        year, rest3 = rest2.split(":", 1)
        time_part, tz_part = rest3.rsplit(" ", 1)
        hh, mm, ss = time_part.split(":")
        month = _MONTH_MAP.get(month_name, 1)
        tz_sign = 1 if tz_part[0] == "+" else -1
        tz_h = int(tz_part[1:3])
        tz_m = int(tz_part[3:5])
        from datetime import timedelta, timezone as _tz
        offset = _tz(timedelta(hours=tz_sign * tz_h, minutes=tz_sign * tz_m))
        return datetime(int(year), month, int(day),
                        int(hh), int(mm), int(ss), tzinfo=offset)
    except (ValueError, IndexError):
        return datetime.now(timezone.utc)


def _detect_signals(path: Optional[str], user_agent: Optional[str] = None) -> Dict[str, Any]:
    """Return a signals dict describing observed attack hints in path/UA."""
    signals: Dict[str, Any] = {}
    text = path or ""
    if _PATH_TRAVERSAL_RE.search(text):
        signals["path_traversal"] = True
    if _SQLI_HINTS_RE.search(text):
        signals["sqli_hint"] = True
    if _XSS_HINTS_RE.search(text):
        signals["xss_hint"] = True
    if user_agent and _SCANNER_UA_RE.search(user_agent):
        signals["scanner_signature"] = True
    return signals


def parse_log_line(raw_line: str, source_file: str = "") -> Optional[Event]:
    """Parse a raw log line into an Event.

    Tries Apache/Nginx combined format first, then JSON, then falls back to a
    minimal event that preserves the raw line for later analysis.

    Returns None only for blank lines.
    """
    raw_line = raw_line.strip()
    if not raw_line:
        return None

    # 1. Apache/Nginx combined log format
    m = _COMBINED_RE.match(raw_line)
    if m:
        path = m.group("path")
        signals = _detect_signals(path)
        if source_file:
            signals["log_source"] = source_file
        return Event(
            asset_id=0, org_id=0,  # filled in by ingest_connector_telemetry
            ts=_parse_combined_ts(m.group("ts")),
            src_ip=m.group("ip"),
            method=m.group("method"),
            path=path,
            status=int(m.group("status")),
            signals=signals,
            raw_line=raw_line,
        )

    # 2. JSON log line (e.g. from structured loggers like morgan/winston/logrus)
    if raw_line.startswith("{"):
        try:
            obj = json.loads(raw_line)
            ts_str = obj.get("time") or obj.get("timestamp") or obj.get("ts") or ""
            try:
                ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                ts = datetime.now(timezone.utc)
            path = obj.get("path") or obj.get("url") or obj.get("uri")
            ua = obj.get("user-agent") or obj.get("userAgent") or obj.get("user_agent")
            signals = _detect_signals(path, ua)
            if source_file:
                signals["log_source"] = source_file
            return Event(
                asset_id=0, org_id=0,
                ts=ts,
                src_ip=obj.get("ip") or obj.get("remote_addr") or obj.get("remoteAddress"),
                method=(obj.get("method") or "").upper() or None,
                path=path,
                status=obj.get("status") or obj.get("statusCode"),
                signals=signals,
                raw_line=raw_line,
            )
        except (json.JSONDecodeError, TypeError):
            pass

    # 3. Fallback — preserve raw line; mark it for later pattern matching
    signals = _detect_signals(raw_line)
    if source_file:
        signals["log_source"] = source_file
    signals["unparsed"] = True
    return Event(
        asset_id=0, org_id=0,
        ts=datetime.now(timezone.utc),
        src_ip=None, method=None, path=None, status=None,
        signals=signals,
        raw_line=raw_line,
    )


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

def ingest_connector_telemetry(
    asset_id: int,
    org_id: int,
    telemetry_result: dict,
) -> List[Event]:
    """Normalize and persist telemetry from a collect_telemetry connector job.

    Requires an active authorization row for asset_id/org_id — raises
    AuthorizationError if none exists.  Skips entries that have an 'error' key
    (I/O failures on the connector side).

    Phase 13: observe mode only.  Events are stored; no action is taken.
    """
    import webapp.db as db

    auth = db.get_active_authorization(asset_id, org_id)
    if auth is None:
        raise AuthorizationError(
            f"No active authorization for asset_id={asset_id} org_id={org_id}; "
            "refusing to ingest telemetry."
        )

    saved: List[Event] = []
    for entry in telemetry_result.get("log_entries", []):
        if "error" in entry:
            continue
        raw = entry.get("line", "")
        source = entry.get("source_file", "")
        event = parse_log_line(raw, source)
        if event is None:
            continue
        event.asset_id = asset_id
        event.org_id = org_id
        db.brain_insert_event(
            asset_id=asset_id,
            org_id=org_id,
            src_ip=event.src_ip,
            method=event.method,
            path=event.path,
            status=event.status,
            signals=event.signals,
        )
        saved.append(event)

    return saved
