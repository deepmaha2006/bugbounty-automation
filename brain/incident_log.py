"""
HydraBrain append-only signed incident audit log.

Every detection, decision, action, approval, and rollback is written here.
Each entry carries:
  - A monotonically increasing sequence number.
  - A HMAC-SHA256 signature of the entry's canonical JSON.
  - A chain hash: HMAC-SHA256(previous_chain_hash + canonical(entry)).
    This means any modification to a historical entry also invalidates the
    chain hash of every subsequent entry, making tampering evident.

The log is in-memory by default (suitable for tests and Phase 12).
Phase 13+ will persist entries to brain_actions / an audit table via db.py.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Entry types
# ---------------------------------------------------------------------------

VALID_ENTRY_TYPES = frozenset({
    "detection",   # a Threat detected from an Event
    "decision",    # a Decision made by decision.py
    "action",      # an Action dispatched to the connector
    "approval",    # a human-approved a proposed action
    "rejection",   # a human rejected a proposed action
    "rollback",    # an action was rolled back
    "kill_switch", # the global kill switch was engaged or disengaged
})


# ---------------------------------------------------------------------------
# Signing helpers
# ---------------------------------------------------------------------------

def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _hmac_hex(secret: bytes, data: bytes) -> str:
    return hmac.new(secret, data, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# IncidentLog
# ---------------------------------------------------------------------------

class IncidentLog:
    """Append-only, HMAC-signed audit log.

    Parameters
    ----------
    secret:
        Signing secret (bytes).  If None, a random secret is generated and
        used for the lifetime of this instance — useful for tests where
        cross-instance verification is not needed.
    """

    def __init__(self, secret: Optional[bytes] = None) -> None:
        self._secret = secret if secret is not None else os.urandom(32)
        self._entries: List[Dict[str, Any]] = []
        self._chain_hash = "0" * 64  # genesis chain hash
        self._seq = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def append(
        self,
        entry_type: str,
        asset_id: int,
        org_id: int,
        payload: dict,
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append a signed entry and return it.

        Raises ValueError for unknown entry_type.
        """
        if entry_type not in VALID_ENTRY_TYPES:
            raise ValueError(f"Unknown incident log entry type: {entry_type!r}")

        with self._lock:
            self._seq += 1
            ts = datetime.now(timezone.utc).isoformat()

            entry: Dict[str, Any] = {
                "seq": self._seq,
                "ts": ts,
                "type": entry_type,
                "asset_id": asset_id,
                "org_id": org_id,
                "actor": actor,
                "payload": payload,
            }

            sig = _hmac_hex(self._secret, _canonical(entry))
            entry["sig"] = sig

            chain_input = (self._chain_hash + sig).encode()
            self._chain_hash = _hmac_hex(self._secret, chain_input)
            entry["chain_hash"] = self._chain_hash

            self._entries.append(entry)
            return copy.deepcopy(entry)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list(
        self,
        asset_id: Optional[int] = None,
        org_id: Optional[int] = None,
        entry_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return a filtered, immutable snapshot of entries."""
        with self._lock:
            result = list(self._entries)

        if asset_id is not None:
            result = [e for e in result if e["asset_id"] == asset_id]
        if org_id is not None:
            result = [e for e in result if e["org_id"] == org_id]
        if entry_type is not None:
            result = [e for e in result if e["type"] == entry_type]

        return [copy.deepcopy(e) for e in result]

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> bool:
        """Verify the integrity of every entry and the full chain.

        Returns True iff:
        - Every entry's 'sig' is a valid HMAC of its canonical JSON (excluding
          'sig' and 'chain_hash' fields).
        - The chain hashes are consistent from genesis through to the last entry.
        """
        with self._lock:
            entries = list(self._entries)

        chain = "0" * 64
        for entry in entries:
            base = {k: v for k, v in entry.items() if k not in ("sig", "chain_hash")}
            expected_sig = _hmac_hex(self._secret, _canonical(base))
            if not hmac.compare_digest(entry.get("sig", ""), expected_sig):
                return False

            chain_input = (chain + expected_sig).encode()
            expected_chain = _hmac_hex(self._secret, chain_input)
            if not hmac.compare_digest(entry.get("chain_hash", ""), expected_chain):
                return False

            chain = expected_chain

        return True


# ---------------------------------------------------------------------------
# Module-level singleton (shared by the whole brain subsystem at runtime).
# Tests that need isolation should instantiate their own IncidentLog().
# ---------------------------------------------------------------------------

_LOG_SECRET = os.environ.get("HYDRAX_INCIDENT_LOG_SECRET", "").encode() or os.urandom(32)
INCIDENT_LOG = IncidentLog(secret=_LOG_SECRET)
