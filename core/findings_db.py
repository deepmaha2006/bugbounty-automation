"""
Central SQLite findings store (§8 Engineering).

All scanner findings are written here, deduplicated by a SHA-256 fingerprint
of (target, type, url, severity).  The UI and report generator can read
the full history without touching the file-based HTML/JSON reports.

Schema
------
findings
    id          INTEGER PRIMARY KEY
    fingerprint TEXT UNIQUE        -- SHA-256 of (target, type, url, severity)
    target      TEXT
    scan_type   TEXT
    severity    TEXT
    type        TEXT
    description TEXT
    url         TEXT
    evidence    TEXT
    remediation TEXT
    confidence  TEXT
    verified    INTEGER            -- 0 / 1
    first_seen  TEXT               -- ISO-8601
    last_seen   TEXT               -- ISO-8601
    seen_count  INTEGER DEFAULT 1

scans
    id          INTEGER PRIMARY KEY
    target      TEXT
    started_at  TEXT               -- ISO-8601
    finished_at TEXT
    duration_s  REAL
    finding_ids TEXT               -- JSON array of findings.id values
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.settings import REPORTS_DIR

_DB_PATH = Path(REPORTS_DIR) / "hydrax_findings.db"


def _fingerprint(target: str, ftype: str, url: str, severity: str) -> str:
    raw = f"{target}|{ftype}|{url}|{severity}".lower().encode()
    return hashlib.sha256(raw).hexdigest()


class FindingsDB:
    """Thread-safe SQLite findings store with deduplication."""

    def __init__(self, db_path: Path = _DB_PATH):
        self._path = db_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS findings (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT    UNIQUE NOT NULL,
                    target      TEXT    NOT NULL,
                    scan_type   TEXT    DEFAULT '',
                    severity    TEXT    DEFAULT 'Info',
                    type        TEXT    DEFAULT 'Unknown',
                    description TEXT    DEFAULT '',
                    url         TEXT    DEFAULT '',
                    evidence    TEXT    DEFAULT '',
                    remediation TEXT    DEFAULT '',
                    confidence  TEXT    DEFAULT 'confirmed',
                    verified    INTEGER DEFAULT 1,
                    first_seen  TEXT    NOT NULL,
                    last_seen   TEXT    NOT NULL,
                    seen_count  INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target      TEXT    NOT NULL,
                    started_at  TEXT    NOT NULL,
                    finished_at TEXT,
                    duration_s  REAL    DEFAULT 0.0,
                    finding_ids TEXT    DEFAULT '[]'
                );

                CREATE INDEX IF NOT EXISTS idx_findings_target
                    ON findings(target);
                CREATE INDEX IF NOT EXISTS idx_findings_severity
                    ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_scans_target
                    ON scans(target);
            """)

    # ------------------------------------------------------------------
    # Context manager for connections
    # ------------------------------------------------------------------

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self._path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Public write API
    # ------------------------------------------------------------------

    def insert_findings(
        self,
        target: str,
        findings: List[Dict[str, Any]],
    ) -> List[int]:
        """Insert a list of finding dicts, deduplicating by fingerprint.

        Returns the list of row IDs that were inserted or updated.
        """
        now = datetime.utcnow().isoformat(timespec="seconds")
        ids: List[int] = []

        with self._lock:
            with self._connect() as conn:
                for f in findings:
                    ftype    = str(f.get("type", "Unknown"))
                    url      = str(f.get("url", ""))
                    severity = str(f.get("severity", "Info"))
                    fp       = _fingerprint(target, ftype, url, severity)

                    existing = conn.execute(
                        "SELECT id FROM findings WHERE fingerprint = ?", (fp,)
                    ).fetchone()

                    if existing:
                        conn.execute(
                            """UPDATE findings
                               SET last_seen = ?, seen_count = seen_count + 1
                               WHERE fingerprint = ?""",
                            (now, fp),
                        )
                        ids.append(existing["id"])
                    else:
                        cur = conn.execute(
                            """INSERT INTO findings
                               (fingerprint, target, scan_type, severity, type,
                                description, url, evidence, remediation,
                                confidence, verified, first_seen, last_seen)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (
                                fp, target,
                                str(f.get("scan_type", "")),
                                severity, ftype,
                                str(f.get("description", "")),
                                url,
                                str(f.get("evidence", "")),
                                str(f.get("remediation", "")),
                                str(f.get("confidence", "confirmed")),
                                int(bool(f.get("verified", True))),
                                now, now,
                            ),
                        )
                        ids.append(cur.lastrowid)

        return ids

    def record_scan(
        self,
        target: str,
        started_at: datetime,
        finished_at: datetime,
        finding_ids: List[int],
    ) -> int:
        """Write a scan record; return the new scan row id."""
        duration = max(0.0, (finished_at - started_at).total_seconds())
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    """INSERT INTO scans
                       (target, started_at, finished_at, duration_s, finding_ids)
                       VALUES (?,?,?,?,?)""",
                    (
                        target,
                        started_at.isoformat(timespec="seconds"),
                        finished_at.isoformat(timespec="seconds"),
                        duration,
                        json.dumps(finding_ids),
                    ),
                )
                return cur.lastrowid

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    def get_findings(
        self,
        target: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Return findings, optionally filtered by target and/or severity."""
        sql = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []
        if target:
            sql += " AND target = ?"
            params.append(target)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def get_scan_history(
        self,
        target: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return past scan records, newest first."""
        sql = "SELECT * FROM scans"
        params: List[Any] = []
        if target:
            sql += " WHERE target = ?"
            params.append(target)
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def severity_summary(self, target: Optional[str] = None) -> Dict[str, int]:
        """Return {severity: count} across all (or target-specific) findings."""
        sql = "SELECT severity, COUNT(*) as n FROM findings"
        params: List[Any] = []
        if target:
            sql += " WHERE target = ?"
            params.append(target)
        sql += " GROUP BY severity"

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return {r["severity"]: r["n"] for r in rows}

    def total_findings(self, target: Optional[str] = None) -> int:
        sql = "SELECT COUNT(*) FROM findings"
        params: List[Any] = []
        if target:
            sql += " WHERE target = ?"
            params.append(target)
        with self._connect() as conn:
            return conn.execute(sql, params).fetchone()[0]

    def delete_findings_for_target(self, target: str) -> int:
        """Remove all findings for a target. Returns deleted row count."""
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "DELETE FROM findings WHERE target = ?", (target,)
                )
                return cur.rowcount


# Module-level singleton — import and use directly.
_db: Optional[FindingsDB] = None
_db_lock = threading.Lock()


def get_db() -> FindingsDB:
    global _db
    if _db is None:
        with _db_lock:
            if _db is None:
                _db = FindingsDB()
    return _db
