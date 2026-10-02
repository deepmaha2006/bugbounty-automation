"""Shared fixtures for the HydraX regression test suite.

Tests never touch the production hydrax database, never resolve public DNS,
and never launch scanner/tool subprocesses. A FakeDB in-memory double stands
in for the PostgreSQL-backed webapp.db module, and the scan service dispatch
(start_web_scan) is replaced with a recording stub in the tests that need it.
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Pin a deterministic JWT secret and an open register path for the tests.
os.environ.setdefault("HYDRAX_JWT_SECRET", "pytest-only-secret-not-for-production")
os.environ.setdefault("HYDRAX_ADMIN_SIGNUP_TOKEN", "testregistertoken")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import webapp.config  # noqa: E402
import webapp.db as db_module  # noqa: E402
from webapp.main import app  # noqa: E402

SIGNUP_EMAIL_SUFFIX = "@hydrax.local"


class _FakeCursor:
    """Cursor double for the raw-SQL paths (verification token updates)."""

    def __init__(self, fake, log):
        self._fake = fake
        self._log = log

    def execute(self, sql, params=None):
        self._log.append((sql, params))
        # Persist the DNS TXT token written by generate_dns_txt_challenge so a
        # generate() -> verify() round-trip works end-to-end against the fake.
        if "update targets" in (sql or "").lower() and "dns_txt_token" in (sql or "").lower():
            # (token, target_id) or (token, target_id, organization_id) —
            # the org filter added in Phase 2 doesn't change what's written.
            if isinstance(params, (tuple, list)) and len(params) in (2, 3):
                token, tid = params[0], params[1]
                if tid in self._fake.targets:
                    self._fake.targets[tid]["dns_txt_token"] = token
                    self._fake.targets[tid]["verification_method"] = "dns_txt"
                    self._fake.targets[tid]["verification_status"] = "pending"

    def fetchone(self):
        # Only meaningfully exercised by webapp/services/health.py's
        # "SELECT 1" liveness probe today — a real cursor always supports
        # this, so the fake should too rather than raising AttributeError.
        return (1,)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeConn:
    def __init__(self, fake):
        self._fake = fake
        self._log = fake.sql_log

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self, cursor_factory=None):
        return _FakeCursor(self._fake, self._log)

    def commit(self):
        pass

    def rollback(self):
        pass


class FakeDB:
    """In-memory double for the subset of webapp.db used by the tested routes."""

    def __init__(self):
        self.reset()

    def reset(self):
        self._seq = {"user": 0, "target": 0, "scan": 0, "finding": 0, "org": 0}
        self.organizations = {}
        self.users = {}
        self.targets = {}
        self.scans = {}
        self.findings = []
        self.reports = []
        self.asset_authorizations = []
        self.refresh_tokens = {}
        self.api_keys = {}
        self.notification_channels = {}
        self.alerts = {}
        self.notifications = []
        self.remediation_tasks = {}
        self.remediation_comments = []
        self.connector_enrollment_tokens = {}
        self.connectors = {}
        self.connector_jobs = {}
        self.audit = []
        self.sql_log = []
        self._settings = {}
        self._profiles = {}
        # Every fixture-driven test starts with the same Default Organization
        # a fresh real DB would have after init_db()'s migration.
        self._seq["org"] += 1
        self.organizations[1] = {
            "id": 1, "name": "Default Organization", "slug": "default",
            "created_at": self._now(), "updated_at": self._now(),
        }

    # --- raw connection doubles ---------------------------------------------
    def _get_conn(self):
        return _FakeConn(self)

    def _put_conn(self, conn):
        pass

    def _now(self):
        return "2026-09-13T00:00:00+00:00"

    def init_db(self):
        pass  # never touch the real database in tests

    def _seed_defaults(self, conn):
        pass

    # --- organizations -------------------------------------------------------
    def create_organization(self, name):
        self._seq["org"] += 1
        oid = self._seq["org"]
        base_slug = "-".join(name.strip().lower().split()) or "org"
        slug, suffix = base_slug, 1
        existing_slugs = {o["slug"] for o in self.organizations.values()}
        while slug in existing_slugs:
            suffix += 1
            slug = f"{base_slug}-{suffix}"
        self.organizations[oid] = {
            "id": oid, "name": name.strip() or "Untitled Organization", "slug": slug,
            "created_at": self._now(), "updated_at": self._now(),
        }
        return oid

    def get_organization(self, org_id):
        o = self.organizations.get(org_id)
        return dict(o) if o else None

    def get_default_organization_id(self):
        return 1

    def organization_counts(self, org_id):
        users_n = sum(1 for u in self.users.values() if u["organization_id"] == org_id)
        assets_n = sum(1 for t in self.targets.values() if t["organization_id"] == org_id)
        return {"users": users_n, "assets": assets_n}

    # --- users -------------------------------------------------------------
    def count_users(self):
        return len(self.users)

    def create_user(self, username, email, password_hash, organization_id=1):
        self._seq["user"] += 1
        uid = self._seq["user"]
        self.users[uid] = {"id": uid, "username": username, "email": email,
                           "password_hash": password_hash, "role": "security_analyst",
                           "organization_id": organization_id,
                           "mfa_enabled": False, "mfa_secret": None,
                           "failed_login_count": 0, "locked_until": None,
                           "created_at": self._now()}
        return uid

    def get_user_by_username(self, username):
        for u in self.users.values():
            if u["username"] == username:
                return dict(u)
        return None

    def get_user_by_id(self, uid):
        u = self.users.get(uid)
        return dict(u) if u else None

    def promote_to_admin(self, uid):
        if uid in self.users:
            self.users[uid]["role"] = "admin"

    def set_user_role(self, uid, role):
        if uid in self.users:
            self.users[uid]["role"] = role

    def update_password_hash(self, uid, password_hash):
        if uid in self.users:
            self.users[uid]["password_hash"] = password_hash

    _LIST_USERS_SAFE_FIELDS = ("id", "username", "email", "role", "organization_id",
                              "created_at", "mfa_enabled")

    def list_users(self, organization_id=1):
        # Mirrors the real db.py's explicit column allowlist exactly (Phase
        # 20 audit) — this used to return every stored field, including
        # password_hash and mfa_secret, which the real SQL never selected.
        # A test asserting admin_info() doesn't leak those would have
        # silently passed against real Postgres while failing (correctly!)
        # against this fixture, or vice versa depending on which way the
        # mismatch ran — either way, the double didn't match the real
        # contract it's supposed to stand in for.
        return [{k: u[k] for k in self._LIST_USERS_SAFE_FIELDS}
               for u in self.users.values() if u["organization_id"] == organization_id]

    # --- account lockout (Phase 3) -------------------------------------------
    def record_login_failure(self, uid, threshold, lockout_minutes):
        u = self.users.get(uid)
        if not u:
            return 0
        u["failed_login_count"] += 1
        if u["failed_login_count"] >= threshold:
            from datetime import datetime, timedelta, timezone
            u["locked_until"] = (datetime.now(timezone.utc)
                                 + timedelta(minutes=lockout_minutes)).isoformat()
        return u["failed_login_count"]

    def clear_login_failures(self, uid):
        if uid in self.users:
            self.users[uid]["failed_login_count"] = 0
            self.users[uid]["locked_until"] = None

    def admin_unlock_user(self, uid, organization_id=1):
        u = self.users.get(uid)
        if not u or u["organization_id"] != organization_id:
            return False
        u["failed_login_count"] = 0
        u["locked_until"] = None
        return True

    # --- MFA (Phase 3) --------------------------------------------------------
    def set_mfa_secret_pending(self, uid, secret):
        if uid in self.users:
            self.users[uid]["mfa_secret"] = secret
            self.users[uid]["mfa_enabled"] = False

    def enable_mfa(self, uid):
        if uid in self.users:
            self.users[uid]["mfa_enabled"] = True

    def disable_mfa(self, uid):
        if uid in self.users:
            self.users[uid]["mfa_enabled"] = False
            self.users[uid]["mfa_secret"] = None

    # --- refresh tokens (Phase 3) ----------------------------------------------
    def create_refresh_token(self, user_id, token_hash, expires_at):
        self._seq.setdefault("refresh", 0)
        self._seq["refresh"] += 1
        rid = self._seq["refresh"]
        self.refresh_tokens[rid] = {
            "id": rid, "user_id": user_id, "token_hash": token_hash,
            "created_at": self._now(), "expires_at": expires_at,
            "revoked_at": None, "replaced_by_id": None,
        }
        return rid

    def get_refresh_token(self, token_hash):
        for r in self.refresh_tokens.values():
            if r["token_hash"] == token_hash:
                return dict(r)
        return None

    def rotate_refresh_token(self, old_id, new_token_hash, expires_at):
        old = self.refresh_tokens.get(old_id)
        if not old or old["revoked_at"]:
            # Mirrors the real db.py's atomic UPDATE...WHERE revoked_at IS
            # NULL: already-revoked (or nonexistent) means "lost the race."
            return None
        new_id = self.create_refresh_token(old["user_id"], new_token_hash, expires_at)
        old["revoked_at"] = self._now()
        old["replaced_by_id"] = new_id
        return new_id

    def revoke_refresh_token(self, token_hash):
        for r in self.refresh_tokens.values():
            if r["token_hash"] == token_hash and not r["revoked_at"]:
                r["revoked_at"] = self._now()

    def revoke_all_refresh_tokens_for_user(self, user_id):
        for r in self.refresh_tokens.values():
            if r["user_id"] == user_id and not r["revoked_at"]:
                r["revoked_at"] = self._now()

    # --- API keys (Phase 3) -----------------------------------------------------
    def create_api_key(self, organization_id, user_id, name, key_prefix, key_hash):
        self._seq.setdefault("api_key", 0)
        self._seq["api_key"] += 1
        kid = self._seq["api_key"]
        self.api_keys[kid] = {
            "id": kid, "organization_id": organization_id, "user_id": user_id,
            "name": name, "key_prefix": key_prefix, "key_hash": key_hash,
            "created_at": self._now(), "last_used_at": None, "revoked_at": None,
        }
        return kid

    def get_api_key_by_hash(self, key_hash):
        for k in self.api_keys.values():
            if k["key_hash"] == key_hash and not k["revoked_at"]:
                return dict(k)
        return None

    def touch_api_key(self, key_id):
        if key_id in self.api_keys:
            self.api_keys[key_id]["last_used_at"] = self._now()

    def list_api_keys(self, organization_id):
        return [dict(k) for k in self.api_keys.values()
               if k["organization_id"] == organization_id]

    def revoke_api_key(self, key_id, organization_id):
        k = self.api_keys.get(key_id)
        if not k or k["organization_id"] != organization_id or k["revoked_at"]:
            return False
        k["revoked_at"] = self._now()
        return True

    # --- targets / assets ----------------------------------------------------
    _ASSET_DEFAULTS = {
        "asset_type": "WEB_APPLICATION", "hostname": "",
        "environment": "production", "business_criticality": "medium",
        "authorization_status": "pending", "monitoring_status": "inactive",
        "first_seen": None, "last_seen": None,
        "monitoring_frequency": "manual", "next_scan_at": None, "last_scan_at": None,
    }

    def add_target(self, url, organization_id=1, verification_method="dns_txt",
                   added_by_user_id=None, name=""):
        self._seq["target"] += 1
        tid = self._seq["target"]
        row = {
            "id": tid, "url": url, "organization_id": organization_id,
            "added_by_user_id": added_by_user_id,
            "verification_method": verification_method,
            "verification_status": "pending",
            "dns_txt_token": None, "engagement_letter_path": None,
            "verified_at": None, "name": name or url,
            "created_at": "2026-09-13T00:00:00+00:00",
            "updated_at": "2026-09-13T00:00:00+00:00",
        }
        row.update(self._ASSET_DEFAULTS)
        self.targets[tid] = row
        return tid

    def record_asset_authorization(self, organization_id, asset_id, authorized_by_user_id,
                                   method, status, evidence=None):
        self.asset_authorizations.append({
            "organization_id": organization_id, "asset_id": asset_id,
            "authorized_by_user_id": authorized_by_user_id, "method": method,
            "status": status, "evidence": evidence, "created_at": self._now(),
        })

    def get_or_create_target(self, url, organization_id=1, verification_method="dns_txt",
                             added_by_user_id=None):
        t = self.get_target_by_url(url, organization_id)
        if t:
            return t["id"]
        return self.add_target(url, organization_id, verification_method, added_by_user_id)

    def get_target_by_url(self, url, organization_id=1):
        for t in self.targets.values():
            if t["url"] == url and t["organization_id"] == organization_id:
                return dict(t)
        return None

    def get_target(self, tid, organization_id=1):
        t = self.targets.get(tid)
        if t and t["organization_id"] == organization_id:
            return dict(t)
        return None

    def update_target_verification(self, tid, status, token=None):
        if tid in self.targets:
            # Mirrors the real SQL: dns_txt_token is always overwritten.
            self.targets[tid]["dns_txt_token"] = token
            self.targets[tid]["verification_status"] = status
            self.targets[tid]["updated_at"] = self._now()
            if status == "verified":
                self.targets[tid]["verified_at"] = self._now()
                self.targets[tid]["authorization_status"] = "authorized"

    def verify_target_with_letter(self, tid, letter_path):
        if tid in self.targets:
            self.targets[tid]["verification_status"] = "verified"
            self.targets[tid]["engagement_letter_path"] = letter_path
            self.targets[tid]["verified_at"] = self._now()
            self.targets[tid]["updated_at"] = self._now()
            self.targets[tid]["authorization_status"] = "authorized"

    def list_targets(self, organization_id=1, limit=50):
        rows = [t for t in self.targets.values() if t["organization_id"] == organization_id]
        return [dict(t) for t in rows[-limit:][::-1]]

    # --- assets (API-facing) --------------------------------------------------
    def create_asset(self, organization_id, name, asset_type, url, hostname="",
                     environment="production", business_criticality="medium",
                     added_by_user_id=None):
        tid = self.add_target(url, organization_id, verification_method="dns_txt",
                              added_by_user_id=added_by_user_id, name=name)
        self.targets[tid].update({
            "asset_type": asset_type, "hostname": hostname,
            "environment": environment, "business_criticality": business_criticality,
            "first_seen": self._now(),
        })
        return tid

    def list_assets(self, organization_id, asset_type=None, limit=200):
        rows = [t for t in self.targets.values() if t["organization_id"] == organization_id]
        if asset_type:
            rows = [t for t in rows if t["asset_type"] == asset_type]
        return [dict(t) for t in rows[-limit:][::-1]]

    def get_asset(self, asset_id, organization_id):
        return self.get_target(asset_id, organization_id)

    _ASSET_UPDATABLE = {"name", "hostname", "environment", "business_criticality",
                        "monitoring_status", "authorization_status", "last_seen"}

    def update_asset(self, asset_id, organization_id, **fields):
        t = self.targets.get(asset_id)
        if not t or t["organization_id"] != organization_id:
            return False
        for k, v in fields.items():
            if k in self._ASSET_UPDATABLE:
                t[k] = v
        t["updated_at"] = self._now()
        return True

    def delete_asset(self, asset_id, organization_id):
        t = self.targets.get(asset_id)
        if not t or t["organization_id"] != organization_id:
            return False
        del self.targets[asset_id]
        return True

    # --- continuous monitoring schedule (Phase 5) -----------------------------
    def set_asset_monitoring(self, asset_id, organization_id, monitoring_status,
                             monitoring_frequency):
        t = self.targets.get(asset_id)
        if not t or t["organization_id"] != organization_id:
            return False
        t["monitoring_status"] = monitoring_status
        t["monitoring_frequency"] = monitoring_frequency
        t["next_scan_at"] = self._now() if (monitoring_status == "active"
                                            and monitoring_frequency != "manual") else None
        t["updated_at"] = self._now()
        return True

    def list_due_assets(self, now=None):
        from datetime import datetime, timezone
        now_dt = now or datetime.now(timezone.utc)

        def _due(t):
            if t["monitoring_status"] != "active" or t["monitoring_frequency"] == "manual":
                return False
            if not t["next_scan_at"]:
                return False
            nsa = t["next_scan_at"]
            nsa_dt = datetime.fromisoformat(nsa) if isinstance(nsa, str) else nsa
            if nsa_dt.tzinfo is None:
                nsa_dt = nsa_dt.replace(tzinfo=timezone.utc)
            return nsa_dt <= now_dt

        return [dict(t) for t in self.targets.values() if _due(t)]

    def mark_asset_scanned(self, asset_id):
        from datetime import datetime, timedelta, timezone
        from webapp import config as _cfg
        t = self.targets.get(asset_id)
        if not t:
            return
        minutes = _cfg.MONITORING_FREQUENCY_MINUTES.get(t["monitoring_frequency"])
        if not minutes:
            return
        now = datetime.now(timezone.utc)
        t["last_scan_at"] = now.isoformat()
        t["next_scan_at"] = (now + timedelta(minutes=minutes)).isoformat()

    # --- scans --------------------------------------------------------------
    def create_scan(self, user_id, target_id, scan_type, selected_keys):
        self._seq["scan"] += 1
        sid = self._seq["scan"]
        user = self.users.get(user_id)
        self.scans[sid] = {
            "id": sid, "user_id": user_id, "target_id": target_id,
            "organization_id": user["organization_id"] if user else 1,
            "scan_type": scan_type, "status": "queued", "progress": 0.0,
            "phase": None, "message": None, "stats": {},
            "selected_keys": list(selected_keys or []),
            "created_at": self._now(),
            "started_at": None, "finished_at": None,
        }
        return sid

    def update_scan(self, scan_id, **fields):
        if scan_id in self.scans:
            allowed = {"status", "progress", "phase", "message", "stats",
                       "started_at", "finished_at"}
            for k, v in fields.items():
                if k in allowed:
                    self.scans[scan_id][k] = v

    def get_scan(self, scan_id, organization_id=1):
        s = self.scans.get(scan_id)
        if not s or s["organization_id"] != organization_id:
            return None
        row = dict(s)
        row["target"] = self._target_url(s.get("target_id"))
        row["findings"] = self.get_findings(scan_id)
        return row

    def get_scan_status(self, scan_id):
        s = self.scans.get(scan_id)
        return s["status"] if s else None

    def list_interrupted_scans(self):
        return [dict(s) for s in self.scans.values() if s["status"] in ("running", "queued")]

    def list_scans(self, organization_id=1, user_id=None, limit=50):
        rows = [s for s in self.scans.values() if s["organization_id"] == organization_id]
        if user_id:
            rows = [s for s in rows if s["user_id"] == user_id]
        out = []
        for s in rows:
            r = dict(s)
            r["target"] = self._target_url(s.get("target_id"))
            out.append(r)
        return out[-limit:][::-1]

    def _target_url(self, tid):
        t = self.targets.get(tid)
        return t["url"] if t else ""

    # --- findings (Phase 4: fingerprint dedup + lifecycle) --------------------
    def add_finding(self, scan_id, finding):
        scan = self.scans.get(scan_id)
        org_id = scan["organization_id"] if scan else None
        target_id = scan.get("target_id") if scan else None
        category = finding.get("type") or finding.get("category") or "Finding"
        component = finding.get("parameter") or category
        evidence = finding.get("evidence") or ""
        severity = finding.get("severity", "Info")
        fingerprint = db_module.compute_fingerprint(org_id, target_id, category, component, evidence)

        existing = next((f for f in self.findings
                         if f["fingerprint"] == fingerprint and f["organization_id"] == org_id
                         and f.get("target_id") == target_id), None)
        if existing:
            existing["occurrence_count"] += 1
            existing["last_seen"] = self._now()
            existing["scan_id"] = scan_id
            was_reopened = existing["status"] == "FIXED"
            if was_reopened:
                existing["status"] = "REOPENED"
            # Mirrors the real db.py's return contract exactly (Phase 20
            # audit): this used to return None unconditionally, which would
            # crash webapp/services/web_scan_service.py's own
            # `result["is_new_or_reopened"]` the instant a real scan (not
            # bypassed by a test's own direct fake.add_finding() call, or a
            # monkeypatched start_web_scan) actually reached this code path
            # — nothing in the existing suite exercised that path end-to-end
            # to catch it. See test_wstg_audit.py's dedicated end-to-end test.
            return {"finding_id": existing["id"], "is_new_or_reopened": was_reopened}

        self._seq["finding"] += 1
        cwe, cvss = db_module.classify_finding(category, severity)
        self.findings.append({
            "id": self._seq["finding"], "scan_id": scan_id,
            "organization_id": org_id, "target_id": target_id,
            "severity": severity,
            "type": category,
            "description": finding.get("description", ""),
            "evidence": evidence,
            "url": finding.get("url", ""),
            "remediation": finding.get("remediation", ""),
            "tool": finding.get("tool", ""),
            "parameter": finding.get("parameter"),
            "payload": finding.get("payload"),
            "confidence": finding.get("confidence", "confirmed"),
            "verified": bool(finding.get("verified", True)),
            "tool_command": finding.get("tool_command", ""),
            "raw_output": finding.get("raw_output", ""),
            "discovered_at": self._now(),
            "status": "NEW", "cve": None, "cwe": cwe, "cvss": cvss,
            "fingerprint": fingerprint, "occurrence_count": 1,
            "last_seen": self._now(), "affected_component": component,
            "business_impact": None, "technical_impact": None,
        })
        return {"finding_id": self._seq["finding"], "is_new_or_reopened": True}

    def get_findings(self, scan_id):
        return [dict(f) for f in self.findings if f["scan_id"] == scan_id]

    def _with_risk(self, f):
        row = dict(f)
        t = self.targets.get(f.get("target_id"))
        risk = db_module.compute_risk(
            f["severity"], f["type"], f["confidence"],
            (t or {}).get("business_criticality", "medium"),
            (t or {}).get("asset_type", "WEB_APPLICATION"),
        )
        row.update(risk)
        return row

    def get_finding(self, finding_id, organization_id=1):
        for f in self.findings:
            if f["id"] == finding_id and f["organization_id"] == organization_id:
                return self._with_risk(f)
        return None

    def update_finding_status(self, finding_id, organization_id, status):
        for f in self.findings:
            if f["id"] == finding_id and f["organization_id"] == organization_id:
                f["status"] = status
                return True
        return False

    def list_findings(self, organization_id=1, status=None, severity=None, limit=200):
        rows = [f for f in self.findings if f["organization_id"] == organization_id]
        if status:
            rows = [f for f in rows if f["status"] == status]
        if severity:
            rows = [f for f in rows if f["severity"] == severity]
        return [self._with_risk(f) for f in rows[-limit:]]

    def severity_counts(self, scan_id):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.get_findings(scan_id):
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        return counts

    # --- alerting (Phase 9) -----------------------------------------------------
    def get_finding_unscoped(self, finding_id):
        for f in self.findings:
            if f["id"] == finding_id:
                return self._with_risk(f)
        return None

    def create_notification_channel(self, organization_id, channel_type, name, config):
        self._seq.setdefault("channel", 0)
        self._seq["channel"] += 1
        cid = self._seq["channel"]
        self.notification_channels[cid] = {
            "id": cid, "organization_id": organization_id, "channel_type": channel_type,
            "name": name, "config": dict(config), "enabled": True, "created_at": self._now(),
        }
        return cid

    def list_notification_channels(self, organization_id, enabled_only=False):
        rows = [c for c in self.notification_channels.values() if c["organization_id"] == organization_id]
        if enabled_only:
            rows = [c for c in rows if c["enabled"]]
        return [dict(c) for c in rows]

    def get_notification_channel(self, channel_id, organization_id):
        c = self.notification_channels.get(channel_id)
        if c and c["organization_id"] == organization_id:
            return dict(c)
        return None

    def delete_notification_channel(self, channel_id, organization_id):
        c = self.notification_channels.get(channel_id)
        if not c or c["organization_id"] != organization_id:
            return False
        del self.notification_channels[channel_id]
        return True

    def get_or_create_alert(self, organization_id, finding_id, asset_id, severity):
        for a in self.alerts.values():
            if a["finding_id"] == finding_id:
                return dict(a)
        self._seq.setdefault("alert", 0)
        self._seq["alert"] += 1
        aid = self._seq["alert"]
        self.alerts[aid] = {
            "id": aid, "organization_id": organization_id, "finding_id": finding_id,
            "asset_id": asset_id, "severity": severity, "status": "open",
            "created_at": self._now(), "last_notified_at": None,
            "acknowledged_at": None, "acknowledged_by_user_id": None,
        }
        return dict(self.alerts[aid])

    def should_notify(self, alert, cooldown_minutes):
        from datetime import datetime, timedelta, timezone
        last = alert.get("last_notified_at")
        if not last:
            return True
        last_dt = datetime.fromisoformat(last) if isinstance(last, str) else last
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - last_dt >= timedelta(minutes=cooldown_minutes)

    def mark_alert_notified(self, alert_id):
        # Real wall-clock time, not self._now()'s frozen fake timestamp —
        # should_notify()'s cooldown math (also real-wall-clock-based, to
        # match the real db.py implementation) needs a genuine "just now"
        # here, not a fixed date from the fixture's past.
        from datetime import datetime, timezone
        if alert_id in self.alerts:
            self.alerts[alert_id]["last_notified_at"] = datetime.now(timezone.utc).isoformat()

    def record_notification(self, alert_id, channel_id, status, error_message=None):
        self._seq.setdefault("notification", 0)
        self._seq["notification"] += 1
        self.notifications.append({
            "id": self._seq["notification"], "alert_id": alert_id, "channel_id": channel_id,
            "status": status, "error_message": error_message, "sent_at": self._now(),
        })

    def list_alerts(self, organization_id, status=None, limit=200):
        rows = [a for a in self.alerts.values() if a["organization_id"] == organization_id]
        if status:
            rows = [a for a in rows if a["status"] == status]
        return [dict(a) for a in rows[-limit:]]

    def get_alert(self, alert_id, organization_id):
        a = self.alerts.get(alert_id)
        if a and a["organization_id"] == organization_id:
            return dict(a)
        return None

    def acknowledge_alert(self, alert_id, organization_id, user_id):
        a = self.alerts.get(alert_id)
        if not a or a["organization_id"] != organization_id:
            return False
        a["status"] = "acknowledged"
        a["acknowledged_at"] = self._now()
        a["acknowledged_by_user_id"] = user_id
        return True

    def list_alert_notifications(self, alert_id):
        return [dict(n) for n in self.notifications if n["alert_id"] == alert_id]

    # --- remediation workflow (Phase 10) ---------------------------------------
    _MANUAL_REMEDIATION_STATUSES = ("OPEN", "ASSIGNED", "IN_PROGRESS")

    def create_remediation_task(self, organization_id, finding_id, assignee_user_id,
                                team, priority, due_date):
        self._seq.setdefault("task", 0)
        self._seq["task"] += 1
        tid = self._seq["task"]
        self.remediation_tasks[tid] = {
            "id": tid, "organization_id": organization_id, "finding_id": finding_id,
            "assignee_user_id": assignee_user_id, "team": team, "priority": priority,
            "due_date": due_date, "status": "ASSIGNED" if assignee_user_id else "OPEN",
            "verification_scan_id": None, "verification_evidence": None,
            "created_at": self._now(), "updated_at": self._now(),
        }
        return tid

    def get_remediation_task(self, task_id, organization_id):
        t = self.remediation_tasks.get(task_id)
        if t and t["organization_id"] == organization_id:
            return dict(t)
        return None

    def get_remediation_task_unscoped(self, task_id):
        t = self.remediation_tasks.get(task_id)
        return dict(t) if t else None

    def list_remediation_tasks(self, organization_id, status=None, assignee_user_id=None, limit=200):
        rows = [t for t in self.remediation_tasks.values() if t["organization_id"] == organization_id]
        if status:
            rows = [t for t in rows if t["status"] == status]
        if assignee_user_id:
            rows = [t for t in rows if t["assignee_user_id"] == assignee_user_id]
        return [dict(t) for t in rows[-limit:]]

    def update_remediation_task(self, task_id, organization_id, **fields):
        t = self.remediation_tasks.get(task_id)
        if not t or t["organization_id"] != organization_id:
            return False
        for k, v in fields.items():
            if k == "status" and v not in self._MANUAL_REMEDIATION_STATUSES:
                raise ValueError(
                    f"Status '{v}' can't be set directly — use /submit-fix, which drives "
                    "the automatic verification pipeline instead."
                )
            if k in ("assignee_user_id", "team", "priority", "due_date", "status"):
                t[k] = v
        t["updated_at"] = self._now()
        return True

    def submit_fix(self, task_id, organization_id, verification_scan_id):
        t = self.remediation_tasks.get(task_id)
        if not t or t["organization_id"] != organization_id:
            return False
        t["status"] = "RESCAN"
        t["verification_scan_id"] = verification_scan_id
        t["updated_at"] = self._now()
        f = next((f for f in self.findings if f["id"] == t["finding_id"]), None)
        if f:
            f["status"] = "FIX_PENDING_VERIFICATION"
        return True

    def list_tasks_awaiting_verification(self):
        rows = []
        for t in self.remediation_tasks.values():
            if t["status"] != "RESCAN" or not t["verification_scan_id"]:
                continue
            scan = self.scans.get(t["verification_scan_id"])
            if scan and scan["status"] in ("completed", "error"):
                rows.append(dict(t))
        return rows

    def finalize_verification(self, task_id, still_present, evidence):
        t = self.remediation_tasks.get(task_id)
        if not t:
            return
        new_status = "REOPENED" if still_present else "FIXED"
        t["status"] = new_status
        t["verification_evidence"] = evidence
        t["updated_at"] = self._now()
        f = next((f for f in self.findings if f["id"] == t["finding_id"]), None)
        if f:
            f["status"] = new_status

    def add_remediation_comment(self, task_id, user_id, comment):
        self._seq.setdefault("comment", 0)
        self._seq["comment"] += 1
        cid = self._seq["comment"]
        self.remediation_comments.append({
            "id": cid, "task_id": task_id, "user_id": user_id,
            "comment": comment, "created_at": self._now(),
        })
        return cid

    def list_remediation_comments(self, task_id):
        return [dict(c) for c in self.remediation_comments if c["task_id"] == task_id]

    # --- Company Connector (Phase 8) --------------------------------------------
    def create_enrollment_token(self, organization_id, created_by_user_id, token_hash, expires_at):
        self._seq.setdefault("enroll_token", 0)
        self._seq["enroll_token"] += 1
        tid = self._seq["enroll_token"]
        self.connector_enrollment_tokens[tid] = {
            "id": tid, "organization_id": organization_id, "created_by_user_id": created_by_user_id,
            "token_hash": token_hash, "created_at": self._now(), "expires_at": expires_at, "used_at": None,
        }
        return tid

    def get_enrollment_token(self, token_hash):
        for t in self.connector_enrollment_tokens.values():
            if t["token_hash"] == token_hash:
                return dict(t)
        return None

    def mark_enrollment_token_used(self, token_id):
        if token_id in self.connector_enrollment_tokens:
            self.connector_enrollment_tokens[token_id]["used_at"] = self._now()

    def create_connector(self, organization_id, name, public_key_pem, secret_hash, version, os_name):
        from datetime import datetime, timezone
        self._seq.setdefault("connector", 0)
        self._seq["connector"] += 1
        cid = self._seq["connector"]
        self.connectors[cid] = {
            "id": cid, "organization_id": organization_id, "name": name,
            "public_key_pem": public_key_pem, "secret_hash": secret_hash,
            "version": version, "os": os_name, "current_job_id": None,
            # Real wall-clock time, not self._now()'s frozen fake timestamp —
            # connector_state()'s heartbeat-age math (also real-wall-clock-
            # based, matching the real db.py implementation) needs a genuine
            # "just now" here. Same class of bug as Phase 9's
            # mark_alert_notified fix.
            "paused": False, "revoked_at": None,
            "last_heartbeat_at": datetime.now(timezone.utc).isoformat(),
            "created_at": self._now(),
        }
        return cid

    def get_connector(self, connector_id, organization_id):
        c = self.connectors.get(connector_id)
        if c and c["organization_id"] == organization_id:
            return dict(c)
        return None

    def get_connector_by_secret_hash(self, secret_hash):
        for c in self.connectors.values():
            if c["secret_hash"] == secret_hash:
                return dict(c)
        return None

    def list_connectors(self, organization_id):
        return [dict(c) for c in self.connectors.values() if c["organization_id"] == organization_id]

    def record_connector_heartbeat(self, connector_id, version, os_name):
        if connector_id in self.connectors:
            from datetime import datetime, timezone
            self.connectors[connector_id]["last_heartbeat_at"] = datetime.now(timezone.utc).isoformat()
            self.connectors[connector_id]["version"] = version
            self.connectors[connector_id]["os"] = os_name

    def revoke_connector(self, connector_id, organization_id):
        c = self.connectors.get(connector_id)
        if not c or c["organization_id"] != organization_id:
            return False
        from datetime import datetime, timezone
        c["revoked_at"] = datetime.now(timezone.utc).isoformat()
        return True

    def set_connector_paused(self, connector_id, organization_id, paused):
        c = self.connectors.get(connector_id)
        if not c or c["organization_id"] != organization_id:
            return False
        c["paused"] = paused
        return True

    def create_connector_job(self, organization_id, connector_id, job_type, scope,
                             authorized_by_user_id, expires_at):
        self._seq.setdefault("connector_job", 0)
        self._seq["connector_job"] += 1
        jid = self._seq["connector_job"]
        job = {
            "id": jid, "organization_id": organization_id, "connector_id": connector_id,
            "job_type": job_type, "scope": scope, "authorized_by_user_id": authorized_by_user_id,
            "signature": None, "status": "pending", "result": None, "result_signature": None,
            "rejection_reason": None, "created_at": self._now(), "expires_at": expires_at,
            "sent_at": None, "completed_at": None,
        }
        self.connector_jobs[jid] = job
        return dict(job)

    def set_connector_job_signature(self, job_id, signature):
        if job_id in self.connector_jobs:
            self.connector_jobs[job_id]["signature"] = signature

    def get_connector_job(self, job_id, organization_id):
        j = self.connector_jobs.get(job_id)
        if j and j["organization_id"] == organization_id:
            return dict(j)
        return None

    def list_connector_jobs(self, connector_id, organization_id, limit=100):
        rows = [j for j in self.connector_jobs.values()
               if j["connector_id"] == connector_id and j["organization_id"] == organization_id]
        return [dict(j) for j in rows[-limit:]]

    def get_next_pending_job(self, connector_id):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)

        def _expiry(j):
            e = j["expires_at"]
            e_dt = datetime.fromisoformat(e) if isinstance(e, str) else e
            if e_dt.tzinfo is None:
                e_dt = e_dt.replace(tzinfo=timezone.utc)
            return e_dt

        for j in self.connector_jobs.values():
            if j["connector_id"] == connector_id and j["status"] == "pending" and _expiry(j) <= now:
                j["status"] = "expired"

        candidates = [j for j in self.connector_jobs.values()
                     if j["connector_id"] == connector_id and j["status"] == "pending" and _expiry(j) > now]
        if not candidates:
            return None
        job = min(candidates, key=lambda j: j["created_at"])
        job["status"] = "sent"
        job["sent_at"] = self._now()
        self.connectors[connector_id]["current_job_id"] = job["id"]
        return dict(job)

    def submit_connector_job_result(self, job_id, connector_id, result, result_signature):
        j = self.connector_jobs.get(job_id)
        if not j or j["connector_id"] != connector_id or j["status"] != "sent":
            return False
        j["status"] = "completed"
        j["result"] = result
        j["result_signature"] = result_signature
        j["completed_at"] = self._now()
        if self.connectors[connector_id]["current_job_id"] == job_id:
            self.connectors[connector_id]["current_job_id"] = None
        return True

    def reject_connector_job_result(self, job_id, connector_id, reason):
        j = self.connector_jobs.get(job_id)
        if not j:
            return
        j["status"] = "rejected"
        j["rejection_reason"] = reason
        if self.connectors.get(connector_id, {}).get("current_job_id") == job_id:
            self.connectors[connector_id]["current_job_id"] = None

    # --- reports --------------------------------------------------------------
    def add_report(self, scan_id, target_id, scan_type, fmt, path):
        scan = self.scans.get(scan_id)
        self.reports.append({
            "id": len(self.reports) + 1, "scan_id": scan_id, "target_id": target_id,
            "organization_id": scan["organization_id"] if scan else None,
            "scan_type": scan_type, "format": fmt, "path": path,
            "created_at": self._now(),
        })

    def list_reports(self, organization_id=1, limit=100):
        rows = [r for r in self.reports if r["organization_id"] == organization_id]
        out = []
        for r in rows[-limit:][::-1]:
            row = dict(r)
            row["target"] = self._target_url(r.get("target_id"))
            out.append(row)
        return out

    def get_report(self, report_id, organization_id=1):
        for r in self.reports:
            if r["id"] == report_id and r["organization_id"] == organization_id:
                row = dict(r)
                row["target"] = self._target_url(r.get("target_id"))
                return row
        return None

    # --- dashboard ------------------------------------------------------------
    def dashboard_stats(self, organization_id=1):
        scans = [s for s in self.scans.values() if s["organization_id"] == organization_id]
        findings = [f for f in self.findings if f["organization_id"] == organization_id]
        sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        by_status = {}
        for f in findings:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
            st = f.get("status", "NEW")
            by_status[st] = by_status.get(st, 0) + 1

        assets = [t for t in self.targets.values() if t["organization_id"] == organization_id]
        monitored_assets = sum(1 for a in assets if a["monitoring_status"] == "active")

        connectors = [c for c in self.connectors.values() if c["organization_id"] == organization_id]
        online = sum(1 for c in connectors if db_module.connector_state(c) == "ONLINE")
        offline = sum(1 for c in connectors if db_module.connector_state(c) in ("OFFLINE", "DEGRADED"))

        open_tasks = sum(1 for t in self.remediation_tasks.values()
                         if t["organization_id"] == organization_id
                         and t["status"] not in ("FIXED", "REOPENED"))

        alerts = sorted([a for a in self.alerts.values() if a["organization_id"] == organization_id],
                       key=lambda a: a["created_at"], reverse=True)[:10]
        recent_alerts = []
        for a in alerts:
            f = next((f for f in self.findings if f["id"] == a["finding_id"]), None)
            recent_alerts.append({
                "id": a["id"], "finding_id": a["finding_id"], "asset_id": a.get("asset_id"),
                "severity": a["severity"], "status": a["status"],
                "vulnerability": f["type"] if f else None, "created_at": a["created_at"],
            })

        return {
            "total_scans": len(scans),
            "running_scans": sum(1 for s in scans if s["status"] in ("running", "queued")),
            "total_findings": len(findings),
            "critical": sev["Critical"], "high": sev["High"], "medium": sev["Medium"],
            "low": sev["Low"], "info": sev["Info"], "avg_security_score": 100,
            "by_type": [], "recent_scans": [], "trend": [],
            "total_assets": len(assets), "monitored_assets": monitored_assets,
            "connectors_online": online, "connectors_offline": offline,
            "new_vulnerabilities": by_status.get("NEW", 0),
            "fixed_vulnerabilities": by_status.get("FIXED", 0),
            "reopened_vulnerabilities": by_status.get("REOPENED", 0),
            "open_remediation_tasks": open_tasks,
            "recent_alerts": recent_alerts,
        }

    def system_health_metrics(self, organization_id=1):
        # Simplified vs. the real db.py: no real 7-day time-window filtering
        # (this fixture's timestamps are a frozen fake clock, not real wall
        # time — same simplification already used for dashboard_stats'
        # by_type/recent_scans/trend fields) — aggregates all scans/
        # notifications for the org instead.
        scans = [s for s in self.scans.values() if s["organization_id"] == organization_id]
        total = len(scans)
        failed = sum(1 for s in scans if s["status"] == "error")
        durations = []
        for s in scans:
            if s.get("started_at") and s.get("finished_at"):
                start = s["started_at"] if isinstance(s["started_at"], str) else s["started_at"].isoformat()
                end = s["finished_at"] if isinstance(s["finished_at"], str) else s["finished_at"].isoformat()
                try:
                    from datetime import datetime as _dt
                    durations.append((_dt.fromisoformat(end) - _dt.fromisoformat(start)).total_seconds())
                except (ValueError, TypeError):
                    pass

        alert_ids = {a["id"] for a in self.alerts.values() if a["organization_id"] == organization_id}
        notif_counts = {}
        for n in self.notifications:
            if n["alert_id"] in alert_ids:
                notif_counts[n["status"]] = notif_counts.get(n["status"], 0) + 1

        return {
            "scan_count_7d": total,
            "scan_failure_count_7d": failed,
            "scan_failure_rate_7d": round(failed / total, 4) if total else 0.0,
            "avg_scan_duration_seconds_7d": (
                round(sum(durations) / len(durations), 1) if durations else None),
            "alert_deliveries_sent_7d": notif_counts.get("sent", 0),
            "alert_deliveries_failed_7d": notif_counts.get("failed", 0),
        }

    # --- misc ---------------------------------------------------------------
    def get_setting(self, key, default=""):
        return self._settings.get(key, default)

    # --- profiles (mirrors webapp.db.get_profile / upsert_profile) ----------
    def get_profile(self, uid):
        row = self._profiles.get(uid)
        if row:
            # Real query is SELECT * FROM profiles — no email column.
            return dict(row)
        user = self.users.get(uid)
        return {"user_id": uid, "full_name": "", "organization": "", "job_title": "",
                "email": user["email"] if user else ""}

    def upsert_profile(self, uid, data):
        self._profiles[uid] = {"user_id": uid,
                               "full_name": data.get("full_name", ""),
                               "organization": data.get("organization", ""),
                               "job_title": data.get("job_title", "")}
        if "email" in data and uid in self.users:
            self.users[uid]["email"] = data["email"]

    def get_all_settings(self):
        return dict(self._settings)

    def set_setting(self, key, value):
        # The real db.set_setting stores str(value) in a TEXT column.
        self._settings[key] = str(value)

    def add_audit_log(self, user_id, action, target_id=None, scan_id=None,
                      details=None, organization_id=None):
        if user_id is None and organization_id is None:
            raise ValueError("add_audit_log requires organization_id when user_id is None")
        user = self.users.get(user_id) if user_id is not None else None
        org_id = organization_id if organization_id is not None else (
            user["organization_id"] if user else None)
        self._seq.setdefault("audit", 0)
        self._seq["audit"] += 1
        self.audit.append({"id": self._seq["audit"], "user_id": user_id, "action": action,
                           "target_id": target_id, "scan_id": scan_id,
                           "organization_id": org_id, "details": details,
                           "timestamp": self._now(),
                           "username": user["username"] if user else None})

    def get_audit_log(self, organization_id=1, limit=100, offset=0):
        # LEFT JOIN semantics: actor-less (user_id=None) rows still appear,
        # matching the real db.py fix for Phase 12's nullable user_id.
        rows = [a for a in self.audit if a["organization_id"] == organization_id]
        rows = rows[::-1]
        return [dict(a) for a in rows[offset:offset + limit]]


_fake = FakeDB()


@pytest.fixture(autouse=True)
def reset_auth_limiters():
    """Fresh in-memory auth rate-limit state per test so brute-force counters
    never bleed between tests."""
    from webapp.routers.auth import login_limiter, register_limiter
    login_limiter.reset()
    register_limiter.reset()
    yield


@pytest.fixture(autouse=True)
def reset_api_rate_limiters():
    """Same as reset_auth_limiters, for Phase 13's generic per-user API
    abuse limiters (scan creation, report generation)."""
    from webapp.routers.scans import scan_start_limiter
    from webapp.routers.reports import report_generation_limiter
    from webapp.routers.brain import brain_resolve_limiter
    scan_start_limiter.reset()
    report_generation_limiter.reset()
    brain_resolve_limiter.reset()
    yield


@pytest.fixture(autouse=True)
def isolated_unresolved_store(tmp_path, monkeypatch):
    """Point the remediation engine's persistent unresolved store at a
    per-test temp file, so no test ever writes into webapp/data/."""
    from webapp.services import remediation_service
    monkeypatch.setattr(remediation_service, "UNRESOLVED_PATH",
                        tmp_path / "brain" / "unresolved.json")
    monkeypatch.setattr(remediation_service, "FEEDBACK_PATH",
                        tmp_path / "brain" / "feedback.json")
    yield


@pytest.fixture(autouse=True)
def reset_scan_manager():
    """Fresh ScanManager per test — no registry/queue/coordinator-thread state
    may bleed between tests."""
    from webapp.services import scan_manager
    scan_manager.reset()
    yield
    scan_manager.shutdown()


@pytest.fixture()
def fake(monkeypatch):
    """Install a fresh FakeDB over the webapp.db functions for one test."""
    _fake.reset()
    for name in dir(_fake):
        if name.startswith("_"):
            continue
        attr = getattr(_fake, name)
        if callable(attr) and hasattr(db_module, name):
            monkeypatch.setattr(db_module, name, attr)
    # Explicit underscore members the routers call directly.
    monkeypatch.setattr(db_module, "_get_conn", _fake._get_conn)
    monkeypatch.setattr(db_module, "_put_conn", _fake._put_conn)
    monkeypatch.setattr(db_module, "_now", _fake._now)

    # Phase 7's SSRF self-protection (utils/ssrf_guard.py) does real DNS
    # resolution — this suite's own hermetic promise at the top of this file
    # is "never resolve public DNS", and existing fixtures use 127.0.0.1-
    # style URLs as safe local placeholder targets, which the real guard
    # correctly rejects (it's loopback). Bypassed here for every test that
    # goes through a scan-service call; the guard's actual behavior is
    # covered directly (no client/fake fixture, real function calls) in
    # tests/test_phase7_ssrf_guard.py.
    from webapp.services import system_scan_service, web_scan_service
    monkeypatch.setattr(web_scan_service, "assert_safe_scan_target", lambda url: None)
    monkeypatch.setattr(system_scan_service, "assert_safe_ip_or_cidr", lambda raw: None)
    monkeypatch.setattr(system_scan_service, "resolve_and_check", lambda host: None)
    # Same bypass for notification-channel URLs (Phase 20 audit): both the
    # create-time check (webapp/routers/alerts.py) and the delivery-time
    # re-check (webapp/services/alert_engine.py) use the same real-DNS SSRF
    # guard, which correctly rejects this suite's 127.0.0.1-style test
    # webhook server. The guard's real behavior is covered directly in
    # tests/test_phase7_ssrf_guard.py; the *wiring* (that these two call
    # sites actually invoke it) is covered in tests/test_wstg_audit.py
    # without going through this bypass.
    from webapp.routers import alerts as alerts_router
    from webapp.services import alert_engine
    monkeypatch.setattr(alerts_router, "assert_safe_scan_target", lambda url: None)
    monkeypatch.setattr(alert_engine, "assert_safe_scan_target", lambda url: None)
    return _fake


@pytest.fixture()
def client(fake):
    with TestClient(app) as c:
        yield c


def register_user(client, username, signup_email=False,
                  password="passw0rd1234", organization_name=None):
    # Once any user exists, registration is closed unless the caller supplies
    # the configured signup token via <token>@hydrax.local (see auth router).
    email = (os.environ.get("HYDRAX_ADMIN_SIGNUP_TOKEN") + "@hydrax.local"
             if signup_email else f"{username}{SIGNUP_EMAIL_SUFFIX}")
    body = {"username": username, "email": email, "password": password}
    if organization_name:
        body["organization_name"] = organization_name
    r = client.post("/api/auth/register", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_headers(client):
    """The platform's first registered user is auto-promoted to admin."""
    return auth_headers(register_user(client, "badmin")["access_token"])


@pytest.fixture()
def user_headers(client, admin_headers):
    """A regular (non-admin) user, registered via the closed-signup token."""
    data = register_user(client, "buser", signup_email=True)
    return auth_headers(data["access_token"])