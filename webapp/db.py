"""
PostgreSQL persistence layer for HydraX platform.
Uses connection pool for thread safety.
"""
import os
import json
import hashlib
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from psycopg2.pool import ThreadedConnectionPool

from webapp import config

# Connection pool
_pool: Optional[ThreadedConnectionPool] = None
_pool_lock = threading.Lock()


def _get_pool() -> ThreadedConnectionPool:
    global _pool
    with _pool_lock:
        if _pool is None:
            db_config = {
                'host': config.POSTGRES_HOST,
                'port': config.POSTGRES_PORT,
                'dbname': config.POSTGRES_DB,
                'user': config.POSTGRES_USER,
                'password': config.POSTGRES_PASSWORD
            }
            _pool = ThreadedConnectionPool(1, 20, **db_config)
        return _pool


def _get_conn():
    pool = _get_pool()
    return pool.getconn()


def _put_conn(conn):
    pool = _get_pool()
    pool.putconn(conn)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def init_db() -> None:
    """Initialize database schema with required tables."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                # Enable UUID extension if needed
                cur.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")

                # Create tables
                # organizations / roles are created first — users and assets
                # reference organizations, and both predate multi-tenancy so
                # every column that depends on them is added idempotently
                # below rather than inline here (see "Idempotent schema
                # migrations" further down).
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS organizations (
                        id SERIAL PRIMARY KEY,
                        name TEXT NOT NULL,
                        slug TEXT NOT NULL UNIQUE,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                    );
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS roles (
                        id SERIAL PRIMARY KEY,
                        key TEXT NOT NULL UNIQUE,
                        name TEXT NOT NULL,
                        description TEXT NOT NULL DEFAULT ''
                    );
                """)
                cur.execute("""
                    INSERT INTO roles (key, name, description) VALUES
                        ('admin', 'Admin',
                         'Full control: organizations, users, assets, connectors, monitoring, scanning, alerts, remediation, risk acceptance'),
                        ('security_manager', 'Security Manager',
                         'Assets, connectors, monitoring, scanning, alerts, remediation, risk acceptance'),
                        ('security_analyst', 'Security Analyst',
                         'Triage findings, run scans, manage assigned remediation tasks'),
                        ('viewer', 'Viewer',
                         'Read-only access to assets, findings, reports and dashboards')
                    ON CONFLICT (key) DO NOTHING;
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'user',
                        created_at TIMESTAMP NOT NULL DEFAULT NOW()
                    );
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT
                    );
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS profiles (
                        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                        full_name TEXT DEFAULT '',
                        organization TEXT DEFAULT '',
                        job_title TEXT DEFAULT ''
                    );
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS targets (
                        id SERIAL PRIMARY KEY,
                        url TEXT NOT NULL UNIQUE,
                        added_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        verification_method TEXT NOT NULL CHECK (verification_method IN ('dns_txt', 'engagement_letter')),
                        verification_status TEXT NOT NULL DEFAULT 'pending' CHECK (verification_status IN ('pending', 'verified', 'failed')),
                        dns_txt_token TEXT,
                        engagement_letter_path TEXT,
                        verified_at TIMESTAMP,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                    );
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                        scan_type TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'queued',
                        progress REAL NOT NULL DEFAULT 0,
                        phase TEXT,
                        message TEXT,
                        stats JSONB DEFAULT '{}',
                        selected_keys JSONB DEFAULT '[]',
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        started_at TIMESTAMP,
                        finished_at TIMESTAMP
                    );
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id SERIAL PRIMARY KEY,
                        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        tool_source TEXT NOT NULL,
                        category TEXT NOT NULL,
                        severity TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
                        confidence TEXT NOT NULL CHECK (confidence IN ('confirmed', 'needs_verification')),
                        affected_endpoint TEXT NOT NULL,
                        evidence TEXT NOT NULL,
                        remediation TEXT,
                        tool_command TEXT,
                        raw_output TEXT,
                        discovered_at TIMESTAMP NOT NULL DEFAULT NOW()
                    );
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS reports (
                        id SERIAL PRIMARY KEY,
                        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
                        scan_type TEXT NOT NULL,
                        format TEXT NOT NULL,
                        path TEXT NOT NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW()
                    );
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        action TEXT NOT NULL,
                        target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
                        scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
                        details JSONB,
                        timestamp TIMESTAMP NOT NULL DEFAULT NOW()
                    );
                """)

                # Insert default settings
                cur.execute("""
                    INSERT INTO settings (key, value) VALUES
                        ('default_threads', %s),
                        ('default_timeout', %s),
                        ('verify_ssl', %s),
                        ('accent', %s)
                    ON CONFLICT (key) DO NOTHING;
                """, (
                    str(config.DEFAULT_THREADS),
                    str(config.DEFAULT_TIMEOUT),
                    str(config.VERIFY_SSL).lower(),
                    "#e63946",  # Accent color for critical findings
                ))
                # Legacy-settings cleanup (intentional): drop rows for the removed
                # HexStrike / AI-enrichment settings left by older installs.
                cur.execute("""
                    DELETE FROM settings
                    WHERE key IN ('hexstrike_url', 'enable_hexstrike', 'enable_ai_enrichment');
                """)

                # Create indexes for performance
                cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);")

                # --- Idempotent schema migrations (existing databases) -------
                # targets.added_by_user_id — the list_targets LEFT JOIN depends on it.
                cur.execute("""
                    ALTER TABLE targets
                        ADD COLUMN IF NOT EXISTS added_by_user_id INTEGER
                        REFERENCES users(id) ON DELETE SET NULL
                """)
                # scans / reports target_id — allow NULL (e.g. system scans have no web target row).
                cur.execute("ALTER TABLE scans ALTER COLUMN target_id DROP NOT NULL")
                cur.execute("ALTER TABLE reports ALTER COLUMN target_id DROP NOT NULL")
                # findings — preserve description / parameter / payload from service findings.
                cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''")
                cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS parameter TEXT")
                cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS payload TEXT")

                # --- Multi-tenancy migration -------------------------------
                # 1. Ensure a Default Organization exists so pre-existing
                #    (or zero-config-bootstrap) single-tenant data always has
                #    somewhere to land — see docs/ARCHITECTURE.md Phase 2.
                cur.execute("""
                    INSERT INTO organizations (name, slug) VALUES ('Default Organization', 'default')
                    ON CONFLICT (slug) DO NOTHING;
                """)
                cur.execute("SELECT id FROM organizations WHERE slug = 'default'")
                default_org_id = cur.fetchone()[0]

                # 2. users.organization_id — every user belongs to exactly one org.
                cur.execute("""
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id
                        INTEGER REFERENCES organizations(id) ON DELETE CASCADE
                """)
                cur.execute("UPDATE users SET organization_id = %s WHERE organization_id IS NULL",
                           (default_org_id,))
                cur.execute("ALTER TABLE users ALTER COLUMN organization_id SET NOT NULL")

                # 3. targets -> the asset model (spec: WEB_APPLICATION | COMPANY_CONNECTOR).
                #    The physical table keeps its name (renaming it would touch every
                #    call site with no real Postgres available in this environment to
                #    verify the rename against — see docs/ARCHITECTURE.md Phase 2 notes);
                #    it is exposed to the API/UI as "assets" via webapp/routers/assets.py.
                #    "owner" from the spec's asset field list maps to the existing
                #    added_by_user_id column rather than a duplicate column.
                cur.execute("""
                    ALTER TABLE targets ADD COLUMN IF NOT EXISTS organization_id
                        INTEGER REFERENCES organizations(id) ON DELETE CASCADE
                """)
                cur.execute("""
                    ALTER TABLE targets ADD COLUMN IF NOT EXISTS asset_type TEXT
                        NOT NULL DEFAULT 'WEB_APPLICATION'
                        CHECK (asset_type IN ('WEB_APPLICATION', 'COMPANY_CONNECTOR'))
                """)
                cur.execute("ALTER TABLE targets ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT ''")
                cur.execute("ALTER TABLE targets ADD COLUMN IF NOT EXISTS hostname TEXT NOT NULL DEFAULT ''")
                cur.execute("""
                    ALTER TABLE targets ADD COLUMN IF NOT EXISTS environment TEXT
                        NOT NULL DEFAULT 'production'
                        CHECK (environment IN ('production', 'staging', 'development', 'other'))
                """)
                cur.execute("""
                    ALTER TABLE targets ADD COLUMN IF NOT EXISTS business_criticality TEXT
                        NOT NULL DEFAULT 'medium'
                        CHECK (business_criticality IN ('critical', 'high', 'medium', 'low'))
                """)
                cur.execute("""
                    ALTER TABLE targets ADD COLUMN IF NOT EXISTS authorization_status TEXT
                        NOT NULL DEFAULT 'pending'
                        CHECK (authorization_status IN ('pending', 'authorized', 'revoked'))
                """)
                cur.execute("""
                    ALTER TABLE targets ADD COLUMN IF NOT EXISTS monitoring_status TEXT
                        NOT NULL DEFAULT 'inactive'
                        CHECK (monitoring_status IN ('active', 'paused', 'inactive'))
                """)
                cur.execute("ALTER TABLE targets ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP")
                cur.execute("ALTER TABLE targets ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP")
                cur.execute("UPDATE targets SET organization_id = %s WHERE organization_id IS NULL",
                           (default_org_id,))
                cur.execute("UPDATE targets SET name = url WHERE name = ''")
                cur.execute("UPDATE targets SET first_seen = created_at WHERE first_seen IS NULL")
                # A previously-verified target has, by definition, already been
                # through an authorization check.
                cur.execute("""
                    UPDATE targets SET authorization_status = 'authorized'
                    WHERE verification_status = 'verified' AND authorization_status = 'pending'
                """)
                cur.execute("ALTER TABLE targets ALTER COLUMN organization_id SET NOT NULL")
                # url was globally UNIQUE — must become unique per-organization so two
                # different companies can each register the same URL as their own asset.
                cur.execute("ALTER TABLE targets DROP CONSTRAINT IF EXISTS targets_url_key")
                cur.execute("""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1 FROM pg_constraint WHERE conname = 'targets_org_url_unique'
                        ) THEN
                            ALTER TABLE targets ADD CONSTRAINT targets_org_url_unique UNIQUE (organization_id, url);
                        END IF;
                    END $$;
                """)

                # 4. asset_authorizations — one row per authorization attempt/decision,
                #    alongside (not yet replacing) targets.verification_status which
                #    still gates scan execution.
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS asset_authorizations (
                        id SERIAL PRIMARY KEY,
                        organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        asset_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                        authorized_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        method TEXT NOT NULL CHECK (method IN ('dns_txt', 'engagement_letter')),
                        status TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'authorized', 'revoked', 'failed')),
                        evidence JSONB,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        expires_at TIMESTAMP
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_asset_auth_asset_id ON asset_authorizations(asset_id)")

                # 5. organization_id on every other security-sensitive table —
                #    denormalized from the nearest owning row so every table can be
                #    scoped directly without always joining back to users/scans.
                cur.execute("""
                    ALTER TABLE scans ADD COLUMN IF NOT EXISTS organization_id
                        INTEGER REFERENCES organizations(id) ON DELETE CASCADE
                """)
                cur.execute("""
                    UPDATE scans s SET organization_id = u.organization_id
                    FROM users u WHERE s.user_id = u.id AND s.organization_id IS NULL
                """)
                cur.execute("ALTER TABLE scans ALTER COLUMN organization_id SET NOT NULL")

                cur.execute("""
                    ALTER TABLE findings ADD COLUMN IF NOT EXISTS organization_id
                        INTEGER REFERENCES organizations(id) ON DELETE CASCADE
                """)
                cur.execute("""
                    UPDATE findings f SET organization_id = s.organization_id
                    FROM scans s WHERE f.scan_id = s.id AND f.organization_id IS NULL
                """)

                cur.execute("""
                    ALTER TABLE reports ADD COLUMN IF NOT EXISTS organization_id
                        INTEGER REFERENCES organizations(id) ON DELETE CASCADE
                """)
                cur.execute("""
                    UPDATE reports r SET organization_id = s.organization_id
                    FROM scans s WHERE r.scan_id = s.id AND r.organization_id IS NULL
                """)

                cur.execute("""
                    ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS organization_id
                        INTEGER REFERENCES organizations(id) ON DELETE CASCADE
                """)
                cur.execute("""
                    UPDATE audit_log a SET organization_id = u.organization_id
                    FROM users u WHERE a.user_id = u.id AND a.organization_id IS NULL
                """)
                # Phase 12: some security-relevant events (e.g. a connector's
                # own signed job-result submission) have no human actor at
                # all -- user_id must be nullable so those get a real audit
                # row too instead of being silently unloggable.
                cur.execute("ALTER TABLE audit_log ALTER COLUMN user_id DROP NOT NULL")

                cur.execute("CREATE INDEX IF NOT EXISTS idx_users_organization_id ON users(organization_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_targets_organization_id ON targets(organization_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_organization_id ON scans(organization_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_organization_id ON findings(organization_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_reports_organization_id ON reports(organization_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_organization_id ON audit_log(organization_id)")

                # --- Phase 3: RBAC, account lockout, MFA, refresh tokens, API keys --
                # 1. RBAC — migrate the old binary admin/user scheme onto the 4 real
                #    roles seeded into `roles` above. A legacy 'user' becomes
                #    'security_analyst' (able to run scans / manage assets, not just
                #    view) rather than the more restrictive 'viewer', since that's
                #    the closer functional match to what "user" could always do
                #    once RBAC actually differentiates access.
                cur.execute("UPDATE users SET role = 'security_analyst' WHERE role = 'user'")
                cur.execute("ALTER TABLE users ALTER COLUMN role SET DEFAULT 'security_analyst'")
                cur.execute("""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1 FROM pg_constraint WHERE conname = 'users_role_fkey'
                        ) THEN
                            ALTER TABLE users ADD CONSTRAINT users_role_fkey
                                FOREIGN KEY (role) REFERENCES roles(key);
                        END IF;
                    END $$;
                """)

                # 2. Account lockout — persistent, user-keyed (see config.py comment).
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0")
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP")

                # 3. MFA (TOTP) — secret is set (pending) by /mfa/setup and only
                #    takes effect at login once /mfa/enable confirms a real code.
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT")
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE")

                # 4. Refresh tokens — only the hash is ever stored; rotation chain
                #    (replaced_by_id) lets a reused/stolen token be detected: a
                #    lookup that finds a *revoked* row proves the token was already
                #    rotated away, so the whole family is untrusted from that point.
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS refresh_tokens (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        token_hash TEXT NOT NULL UNIQUE,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        expires_at TIMESTAMP NOT NULL,
                        revoked_at TIMESTAMP,
                        replaced_by_id INTEGER REFERENCES refresh_tokens(id) ON DELETE SET NULL
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash)")

                # 5. API keys — machine clients, distinct from user session tokens,
                #    scoped to an organization and individually revocable (spec §17,
                #    §18 — API key creation/revocation must be audited).
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS api_keys (
                        id SERIAL PRIMARY KEY,
                        organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        name TEXT NOT NULL,
                        key_prefix TEXT NOT NULL,
                        key_hash TEXT NOT NULL UNIQUE,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        last_used_at TIMESTAMP,
                        revoked_at TIMESTAMP
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_organization_id ON api_keys(organization_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash)")

                # --- Phase 4: finding lifecycle, classification, fingerprinting ----
                cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS cve TEXT")
                cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS cwe TEXT")
                cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss NUMERIC(3,1)")
                cur.execute("""
                    ALTER TABLE findings ADD COLUMN IF NOT EXISTS status TEXT
                        NOT NULL DEFAULT 'NEW'
                        CHECK (status IN ('NEW', 'OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS',
                                          'FIX_PENDING_VERIFICATION', 'FIXED', 'REOPENED',
                                          'FALSE_POSITIVE', 'ACCEPTED_RISK'))
                """)
                cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint TEXT")
                cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS occurrence_count INTEGER NOT NULL DEFAULT 1")
                cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP")
                cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS affected_component TEXT")
                cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS business_impact TEXT")
                cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS technical_impact TEXT")
                cur.execute("""
                    ALTER TABLE findings ADD COLUMN IF NOT EXISTS target_id
                        INTEGER REFERENCES targets(id) ON DELETE SET NULL
                """)
                cur.execute("UPDATE findings SET last_seen = discovered_at WHERE last_seen IS NULL")
                cur.execute("""
                    UPDATE findings f SET target_id = s.target_id
                    FROM scans s WHERE f.scan_id = s.id AND f.target_id IS NULL
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_target_id ON findings(target_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)")

                # Backfill a fingerprint for pre-existing rows in Python (not raw
                # SQL) so it's computed with the exact same compute_fingerprint()
                # used for every new insert — a SQL-side sha256() would depend on
                # a Postgres version/extension (pgcrypto, or core sha256() which
                # only exists from PG14+) this environment has no way to confirm.
                cur.execute("""
                    SELECT id, organization_id, target_id, category, parameter, evidence
                    FROM findings WHERE fingerprint IS NULL
                """)
                to_backfill = cur.fetchall()
                for fid, org_id, tgt_id, category, parameter, evidence in to_backfill:
                    fp = compute_fingerprint(org_id, tgt_id, category, parameter or category, evidence)
                    cur.execute("UPDATE findings SET fingerprint = %s WHERE id = %s", (fp, fid))

                # Phase 20 audit (CWE-362): add_finding()'s dedup used to be a
                # SELECT-then-branch (check for an existing fingerprint, then
                # either UPDATE or INSERT) with no database-level backstop —
                # two concurrent scans detecting the identical vulnerability
                # at the same moment could each see "no existing row" and
                # both INSERT, silently producing duplicate finding rows (and
                # a duplicate alert each, since alerts key off finding_id).
                # A real UNIQUE index lets add_finding() use a single atomic
                # `INSERT ... ON CONFLICT DO UPDATE` instead. Before adding
                # it: merge any duplicates the old race already produced
                # (summing occurrence_count / taking the latest last_seen
                # rather than just dropping the extra rows' history) so the
                # index creation itself can't fail against real, populated
                # data — a no-op once there are no duplicates left.
                cur.execute("""
                    UPDATE findings f SET
                        occurrence_count = agg.total_occurrences,
                        last_seen = agg.max_last_seen
                    FROM (
                        SELECT organization_id, fingerprint,
                               MIN(id) AS keep_id,
                               SUM(occurrence_count) AS total_occurrences,
                               MAX(last_seen) AS max_last_seen
                        FROM findings
                        WHERE fingerprint IS NOT NULL
                        GROUP BY organization_id, fingerprint
                        HAVING COUNT(*) > 1
                    ) agg
                    WHERE f.id = agg.keep_id
                """)
                cur.execute("""
                    DELETE FROM findings f USING (
                        SELECT id,
                               ROW_NUMBER() OVER (
                                   PARTITION BY organization_id, fingerprint ORDER BY id
                               ) AS rn
                        FROM findings
                        WHERE fingerprint IS NOT NULL
                    ) dup
                    WHERE f.id = dup.id AND dup.rn > 1
                """)
                cur.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_org_fingerprint_unique
                        ON findings(organization_id, fingerprint) WHERE fingerprint IS NOT NULL
                """)

                # --- Phase 5: continuous monitoring schedule (per asset) -----------
                # Scheduling metadata lives on the asset row itself (one recurring
                # schedule per asset) rather than a separate scan_jobs table — see
                # docs/ROADMAP.md Phase 5 for why this simplification was made.
                cur.execute("""
                    ALTER TABLE targets ADD COLUMN IF NOT EXISTS monitoring_frequency TEXT
                        NOT NULL DEFAULT 'manual'
                        CHECK (monitoring_frequency IN ('manual', '5m', '15m', '30m',
                                                        'hourly', 'daily', 'weekly'))
                """)
                cur.execute("ALTER TABLE targets ADD COLUMN IF NOT EXISTS next_scan_at TIMESTAMP")
                cur.execute("ALTER TABLE targets ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMP")
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_targets_next_scan_at ON targets(next_scan_at)
                        WHERE monitoring_status = 'active'
                """)

                # --- Phase 9: real-time alerting ------------------------------------
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS notification_channels (
                        id SERIAL PRIMARY KEY,
                        organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        channel_type TEXT NOT NULL CHECK (channel_type IN ('email', 'webhook', 'slack', 'teams')),
                        name TEXT NOT NULL,
                        config JSONB NOT NULL,
                        enabled BOOLEAN NOT NULL DEFAULT TRUE,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW()
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_notification_channels_org ON notification_channels(organization_id)")

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id SERIAL PRIMARY KEY,
                        organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                        asset_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged')),
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        last_notified_at TIMESTAMP,
                        acknowledged_at TIMESTAMP,
                        acknowledged_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        UNIQUE (finding_id)
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_org ON alerts(organization_id)")

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS notifications (
                        id SERIAL PRIMARY KEY,
                        alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                        channel_id INTEGER REFERENCES notification_channels(id) ON DELETE SET NULL,
                        status TEXT NOT NULL CHECK (status IN ('sent', 'failed')),
                        error_message TEXT,
                        sent_at TIMESTAMP NOT NULL DEFAULT NOW()
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_notifications_alert ON notifications(alert_id)")

                # --- Phase 10: remediation workflow + automatic verification -------
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS remediation_tasks (
                        id SERIAL PRIMARY KEY,
                        organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                        assignee_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        team TEXT,
                        priority TEXT NOT NULL DEFAULT 'medium'
                            CHECK (priority IN ('critical', 'high', 'medium', 'low')),
                        due_date DATE,
                        status TEXT NOT NULL DEFAULT 'OPEN'
                            CHECK (status IN ('OPEN', 'ASSIGNED', 'IN_PROGRESS', 'FIX_SUBMITTED',
                                              'RESCAN', 'VERIFICATION', 'FIXED', 'REOPENED')),
                        verification_scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
                        verification_evidence JSONB,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_remediation_tasks_org ON remediation_tasks(organization_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_remediation_tasks_finding ON remediation_tasks(finding_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_remediation_tasks_status ON remediation_tasks(status)")

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS remediation_comments (
                        id SERIAL PRIMARY KEY,
                        task_id INTEGER NOT NULL REFERENCES remediation_tasks(id) ON DELETE CASCADE,
                        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        comment TEXT NOT NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW()
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_remediation_comments_task ON remediation_comments(task_id)")

                # --- Phase 8: Company Connector ------------------------------------
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS connectors (
                        id SERIAL PRIMARY KEY,
                        organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        name TEXT NOT NULL,
                        public_key_pem TEXT NOT NULL,
                        secret_hash TEXT NOT NULL UNIQUE,
                        version TEXT,
                        os TEXT,
                        current_job_id INTEGER,
                        paused BOOLEAN NOT NULL DEFAULT FALSE,
                        revoked_at TIMESTAMP,
                        last_heartbeat_at TIMESTAMP,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW()
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_connectors_org ON connectors(organization_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_connectors_secret_hash ON connectors(secret_hash)")

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS connector_enrollment_tokens (
                        id SERIAL PRIMARY KEY,
                        organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        token_hash TEXT NOT NULL UNIQUE,
                        created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        expires_at TIMESTAMP NOT NULL,
                        used_at TIMESTAMP
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_connector_enroll_tokens_hash ON connector_enrollment_tokens(token_hash)")

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS connector_jobs (
                        id SERIAL PRIMARY KEY,
                        organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                        connector_id INTEGER NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
                        job_type TEXT NOT NULL CHECK (job_type IN (
                            'inventory_check', 'configuration_check',
                            'vulnerability_assessment', 'telemetry_collection'
                        )),
                        scope JSONB NOT NULL DEFAULT '{}',
                        authorized_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        signature TEXT,
                        status TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'sent', 'completed', 'rejected', 'expired')),
                        result JSONB,
                        result_signature TEXT,
                        rejection_reason TEXT,
                        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                        expires_at TIMESTAMP NOT NULL,
                        sent_at TIMESTAMP,
                        completed_at TIMESTAMP
                    );
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_connector_jobs_connector ON connector_jobs(connector_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_connector_jobs_org ON connector_jobs(organization_id)")
                cur.execute("""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1 FROM pg_constraint WHERE conname = 'connectors_current_job_fkey'
                        ) THEN
                            ALTER TABLE connectors ADD CONSTRAINT connectors_current_job_fkey
                                FOREIGN KEY (current_job_id) REFERENCES connector_jobs(id) ON DELETE SET NULL;
                        END IF;
                    END $$;
                """)
    finally:
        _put_conn(conn)


def _seed_defaults(conn) -> None:
    """Kept for compatibility - now handled in init_db"""
    pass


# --- setting helpers --------------------------------------------
def get_setting(key: str, default: str = "") -> str:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT value FROM settings WHERE key = %s", (key,))
            row = cur.fetchone()
            return row["value"] if row else default
    finally:
        _put_conn(conn)


def set_setting(key: str, value: str) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO settings(key, value) VALUES(%s, %s)
                       ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value""",
                    (key, str(value))
                )
    finally:
        _put_conn(conn)


def get_all_settings() -> dict:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT key, value FROM settings")
            rows = cur.fetchall()
            return {r["key"]: r["value"] for r in rows}
    finally:
        _put_conn(conn)


# --- organizations -------------------------------------------------------
import re as _re


def _slugify(name: str) -> str:
    slug = _re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "org"


def create_organization(name: str) -> int:
    """Create a new, isolated organization. Returns its id.

    Slug collisions (e.g. two orgs both named "Acme") are resolved by
    appending a numeric suffix rather than failing the signup.
    """
    base_slug = _slugify(name)
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                slug = base_slug
                suffix = 1
                while True:
                    cur.execute("SELECT 1 FROM organizations WHERE slug = %s", (slug,))
                    if cur.fetchone() is None:
                        break
                    suffix += 1
                    slug = f"{base_slug}-{suffix}"
                cur.execute(
                    """INSERT INTO organizations(name, slug) VALUES(%s, %s)
                       RETURNING id""",
                    (name.strip() or "Untitled Organization", slug)
                )
                return cur.fetchone()[0]
    finally:
        _put_conn(conn)


def get_organization(org_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM organizations WHERE id = %s", (org_id,))
            row = cur.fetchone()
            if row:
                for field in ("created_at", "updated_at"):
                    if row[field]:
                        row[field] = row[field].isoformat()
                return dict(row)
            return None
    finally:
        _put_conn(conn)


def get_default_organization_id() -> int:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM organizations WHERE slug = 'default'")
            row = cur.fetchone()
            return row[0] if row else None
    finally:
        _put_conn(conn)


def organization_counts(org_id: int) -> Dict[str, int]:
    """Cheap per-org counts for the organization-info endpoint."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users WHERE organization_id = %s", (org_id,))
            users_n = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM targets WHERE organization_id = %s", (org_id,))
            assets_n = cur.fetchone()[0]
            return {"users": users_n, "assets": assets_n}
    finally:
        _put_conn(conn)


# --- users -------------------------------------------------------------
def count_users() -> int:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM users")
            row = cur.fetchone()
            return row[0] if row else 0
    finally:
        _put_conn(conn)


def promote_to_admin(uid: int) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET role = 'admin' WHERE id = %s", (uid,))
    finally:
        _put_conn(conn)


def list_users(organization_id: int) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Explicit column allowlist — never `SELECT *`, so a future
            # column added to `users` (or its own sensitivity forgotten)
            # can't silently start flowing through this into an admin-facing
            # listing without a deliberate change here (Phase 20 audit:
            # webapp/routers/settings.py::admin_info exposes this with no
            # response_model of its own to catch such a regression either —
            # see AdminInfoOut, added the same audit, for the other half of
            # this defense-in-depth pair).
            cur.execute("""
                SELECT id, username, email, role, organization_id, created_at, mfa_enabled
                FROM users
                WHERE organization_id = %s
                ORDER BY id
            """, (organization_id,))
            rows = cur.fetchall()
            # Convert datetime to ISO string
            for row in rows:
                if row['created_at']:
                    row['created_at'] = row['created_at'].isoformat()
            return rows
    finally:
        _put_conn(conn)


def create_user(username: str, email: str, password_hash: str,
                organization_id: int) -> int:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO users(username, email, password_hash, organization_id, created_at)
                       VALUES(%s, %s, %s, %s, %s)
                       RETURNING id""",
                    (username, email, password_hash, organization_id, _now())
                )
                row = cur.fetchone()
                return row[0] if row else None
    finally:
        _put_conn(conn)


def get_user_by_username(username: str) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            if row:
                # Convert datetime
                if row['created_at']:
                    row['created_at'] = row['created_at'].isoformat()
                return dict(row)
            return None
    finally:
        _put_conn(conn)


def get_user_by_id(uid: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
            row = cur.fetchone()
            if row:
                if row['created_at']:
                    row['created_at'] = row['created_at'].isoformat()
                return dict(row)
            return None
    finally:
        _put_conn(conn)


def update_password_hash(uid: int, password_hash: str) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (password_hash, uid))
    finally:
        _put_conn(conn)


def set_user_role(uid: int, role: str) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET role = %s WHERE id = %s", (role, uid))
    finally:
        _put_conn(conn)


# --- account lockout (Phase 3) --------------------------------------------
def record_login_failure(uid: int, threshold: int, lockout_minutes: int) -> int:
    """Increment the failed-login counter; lock the account once it reaches
    `threshold`. Returns the new failure count."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE users SET failed_login_count = failed_login_count + 1
                       WHERE id = %s RETURNING failed_login_count""",
                    (uid,)
                )
                count = cur.fetchone()[0]
                if count >= threshold:
                    cur.execute(
                        """UPDATE users SET locked_until = NOW() + (%s || ' minutes')::interval
                           WHERE id = %s""",
                        (lockout_minutes, uid)
                    )
                return count
    finally:
        _put_conn(conn)


def clear_login_failures(uid: int) -> None:
    """Called on a successful login — resets the counter and any lock."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = %s",
                    (uid,)
                )
    finally:
        _put_conn(conn)


def admin_unlock_user(uid: int, organization_id: int) -> bool:
    """Admin-initiated early unlock. Org-scoped so an admin can't unlock a
    user outside their own organization."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE users SET failed_login_count = 0, locked_until = NULL
                       WHERE id = %s AND organization_id = %s""",
                    (uid, organization_id)
                )
                return cur.rowcount > 0
    finally:
        _put_conn(conn)


# --- MFA (Phase 3) ---------------------------------------------------------
def set_mfa_secret_pending(uid: int, secret: str) -> None:
    """Store a newly generated secret without enabling MFA yet — it only
    takes effect once /mfa/enable confirms a real code against it."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET mfa_secret = %s, mfa_enabled = FALSE WHERE id = %s",
                    (secret, uid)
                )
    finally:
        _put_conn(conn)


def enable_mfa(uid: int) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET mfa_enabled = TRUE WHERE id = %s", (uid,))
    finally:
        _put_conn(conn)


def disable_mfa(uid: int) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL WHERE id = %s",
                    (uid,)
                )
    finally:
        _put_conn(conn)


# --- refresh tokens (Phase 3) ----------------------------------------------
def create_refresh_token(user_id: int, token_hash: str, expires_at) -> int:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO refresh_tokens(user_id, token_hash, expires_at)
                       VALUES(%s, %s, %s) RETURNING id""",
                    (user_id, token_hash, expires_at)
                )
                return cur.fetchone()[0]
    finally:
        _put_conn(conn)


def get_refresh_token(token_hash: str) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM refresh_tokens WHERE token_hash = %s", (token_hash,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        _put_conn(conn)


def rotate_refresh_token(old_id: int, new_token_hash: str, expires_at) -> Optional[int]:
    """Revoke `old_id` and link it to a freshly created replacement row.

    The revoke is a single atomic `UPDATE ... WHERE revoked_at IS NULL
    RETURNING`, not a separate check-then-act — two concurrent refresh
    requests for the *same* token (e.g. a stolen token replayed at the same
    moment as its legitimate use) must not both be able to successfully
    rotate it. Returns None when the row was already revoked (lost the
    race, or the caller re-used an already-rotated token) — the router
    treats that identically to explicit reuse detection: revoke the whole
    token family. Fixed during the Phase 20 audit (CWE-362); the previous
    unconditional UPDATE let both concurrent requests "win."
    """
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE refresh_tokens SET revoked_at = NOW()
                       WHERE id = %s AND revoked_at IS NULL
                       RETURNING user_id""",
                    (old_id,)
                )
                row = cur.fetchone()
                if not row:
                    return None
                user_id = row[0]
                cur.execute(
                    """INSERT INTO refresh_tokens(user_id, token_hash, expires_at)
                       VALUES (%s, %s, %s) RETURNING id""",
                    (user_id, new_token_hash, expires_at)
                )
                new_id = cur.fetchone()[0]
                cur.execute(
                    "UPDATE refresh_tokens SET replaced_by_id = %s WHERE id = %s",
                    (new_id, old_id)
                )
                return new_id
    finally:
        _put_conn(conn)


def revoke_refresh_token(token_hash: str) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = %s AND revoked_at IS NULL",
                    (token_hash,)
                )
    finally:
        _put_conn(conn)


def revoke_all_refresh_tokens_for_user(user_id: int) -> None:
    """Reuse-detection response: a replayed (already-rotated) refresh token
    means the whole family may be compromised — kill every session."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = %s AND revoked_at IS NULL",
                    (user_id,)
                )
    finally:
        _put_conn(conn)


# --- API keys (Phase 3) -----------------------------------------------------
def create_api_key(organization_id: int, user_id: int, name: str,
                   key_prefix: str, key_hash: str) -> int:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO api_keys(organization_id, user_id, name, key_prefix, key_hash)
                       VALUES(%s, %s, %s, %s, %s) RETURNING id""",
                    (organization_id, user_id, name, key_prefix, key_hash)
                )
                return cur.fetchone()[0]
    finally:
        _put_conn(conn)


def get_api_key_by_hash(key_hash: str) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM api_keys WHERE key_hash = %s AND revoked_at IS NULL", (key_hash,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        _put_conn(conn)


def touch_api_key(key_id: int) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE api_keys SET last_used_at = NOW() WHERE id = %s", (key_id,))
    finally:
        _put_conn(conn)


def list_api_keys(organization_id: int) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT id, organization_id, user_id, name, key_prefix, created_at,
                          last_used_at, revoked_at
                   FROM api_keys WHERE organization_id = %s ORDER BY created_at DESC""",
                (organization_id,)
            )
            return cur.fetchall()
    finally:
        _put_conn(conn)


def revoke_api_key(key_id: int, organization_id: int) -> bool:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE api_keys SET revoked_at = NOW()
                       WHERE id = %s AND organization_id = %s AND revoked_at IS NULL""",
                    (key_id, organization_id)
                )
                return cur.rowcount > 0
    finally:
        _put_conn(conn)


# --- profile -------------------------------------------------------------
def get_profile(uid: int) -> Dict:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM profiles WHERE user_id = %s", (uid,))
            row = cur.fetchone()
            if row:
                return dict(row)
            # No profile yet - return default with user email
            user = get_user_by_id(uid)
            return {
                "user_id": uid,
                "full_name": "",
                "organization": "",
                "job_title": "",
                "email": user["email"] if user else ""
            }
    finally:
        _put_conn(conn)


def upsert_profile(uid: int, data: dict) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO profiles(user_id, full_name, organization, job_title)
                       VALUES(%s, %s, %s, %s)
                       ON CONFLICT(user_id) DO UPDATE SET
                           full_name = EXCLUDED.full_name,
                           organization = EXCLUDED.organization,
                           job_title = EXCLUDED.job_title""",
                    (uid, data.get("full_name", ""), data.get("organization", ""), data.get("job_title", ""))
                )
                if "email" in data:
                    cur.execute("UPDATE users SET email = %s WHERE id = %s", (data["email"], uid))
    finally:
        _put_conn(conn)


# --- targets / assets -----------------------------------------------------
# The physical table is still named "targets" (see the Phase 2 migration note
# in init_db()); asset_type distinguishes WEB_APPLICATION from
# COMPANY_CONNECTOR rows within it. Every function here is organization-scoped
# — a lookup for another org's target/asset returns None exactly as if the
# row didn't exist, never leaking whether it belongs to someone else.
def add_target(url: str, organization_id: int, verification_method: str = "dns_txt",
               added_by_user_id: Optional[int] = None, name: str = "") -> int:
    """Add a new target/asset for verification. Returns its ID."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO targets(url, organization_id, verification_method,
                                           added_by_user_id, name)
                       VALUES(%s, %s, %s, %s, %s)
                       RETURNING id""",
                    (url, organization_id, verification_method, added_by_user_id,
                     name or url)
                )
                row = cur.fetchone()
                return row[0] if row else None
    finally:
        _put_conn(conn)


def get_or_create_target(url: str, organization_id: int, verification_method: str = "dns_txt",
                         added_by_user_id: Optional[int] = None) -> Optional[int]:
    """Return the ID of an existing target/asset row in this organization,
    creating one if absent.

    Used by scan services that must persist a target_id foreign key but operate
    on a raw target string (system scans).
    """
    target = get_target_by_url(url, organization_id)
    if target:
        return target["id"]
    try:
        return add_target(url, organization_id, verification_method, added_by_user_id)
    except Exception:
        # Race: another worker inserted the row between our SELECT and INSERT.
        target = get_target_by_url(url, organization_id)
        return target["id"] if target else None


def get_target(target_id: int, organization_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM targets WHERE id = %s AND organization_id = %s",
                       (target_id, organization_id))
            row = cur.fetchone()
            if row:
                # Convert datetimes
                for field in ['created_at', 'updated_at', 'verified_at', 'first_seen', 'last_seen', 'next_scan_at', 'last_scan_at']:
                    if row.get(field):
                        row[field] = row[field].isoformat()
                return dict(row)
            return None
    finally:
        _put_conn(conn)


def record_asset_authorization(organization_id: int, asset_id: int,
                               authorized_by_user_id: Optional[int], method: str,
                               status: str, evidence: Optional[Dict] = None) -> None:
    """One row per authorization decision (spec §3 asset_authorizations)."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO asset_authorizations(
                           organization_id, asset_id, authorized_by_user_id,
                           method, status, evidence
                       ) VALUES(%s, %s, %s, %s, %s, %s)""",
                    (organization_id, asset_id, authorized_by_user_id, method, status,
                     Json(evidence) if evidence else None)
                )
    finally:
        _put_conn(conn)


def get_target_by_url(url: str, organization_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM targets WHERE url = %s AND organization_id = %s",
                       (url, organization_id))
            row = cur.fetchone()
            if row:
                for field in ['created_at', 'updated_at', 'verified_at', 'first_seen', 'last_seen', 'next_scan_at', 'last_scan_at']:
                    if row.get(field):
                        row[field] = row[field].isoformat()
                return dict(row)
            return None
    finally:
        _put_conn(conn)


def update_target_verification(target_id: int, status: str, token: str = None) -> None:
    """Update target verification status (DNS TXT challenge)."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE targets
                       SET verification_status = %s,
                           dns_txt_token = %s,
                           updated_at = NOW()
                       WHERE id = %s""",
                    (status, token, target_id)
                )
    finally:
        _put_conn(conn)


def verify_target_with_letter(target_id: int, letter_path: str) -> None:
    """Mark target as verified via engagement letter upload."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE targets
                       SET verification_status = 'verified',
                           engagement_letter_path = %s,
                           verified_at = NOW(),
                           updated_at = NOW()
                       WHERE id = %s""",
                    (letter_path, target_id)
                )
    finally:
        _put_conn(conn)


def list_targets(organization_id: int, limit: int = 50) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT t.*, u.username as added_by_username
                FROM targets t
                LEFT JOIN users u ON t.added_by_user_id = u.id
                WHERE t.organization_id = %s
                ORDER BY t.created_at DESC
                LIMIT %s
            """, (organization_id, limit))
            rows = cur.fetchall()
            for row in rows:
                for field in ['created_at', 'updated_at', 'verified_at', 'first_seen', 'last_seen', 'next_scan_at', 'last_scan_at']:
                    if row.get(field):
                        row[field] = row[field].isoformat()
            return rows
    finally:
        _put_conn(conn)


# --- assets (API-facing view over the targets table) ----------------------
_ASSET_TIME_FIELDS = ('created_at', 'updated_at', 'verified_at', 'first_seen', 'last_seen',
                      'next_scan_at', 'last_scan_at')


def _asset_row(row: Dict[str, Any]) -> Dict[str, Any]:
    for field in _ASSET_TIME_FIELDS:
        if row.get(field):
            row[field] = row[field].isoformat()
    return dict(row)


def create_asset(organization_id: int, name: str, asset_type: str, url: str,
                 hostname: str = "", environment: str = "production",
                 business_criticality: str = "medium",
                 added_by_user_id: Optional[int] = None) -> int:
    """Register a new asset (WEB_APPLICATION or COMPANY_CONNECTOR). Returns its ID."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO targets(
                           url, organization_id, verification_method, added_by_user_id,
                           name, asset_type, hostname, environment, business_criticality,
                           first_seen
                       ) VALUES(%s, %s, 'dns_txt', %s, %s, %s, %s, %s, %s, NOW())
                       RETURNING id""",
                    (url, organization_id, added_by_user_id, name or url, asset_type,
                     hostname, environment, business_criticality)
                )
                return cur.fetchone()[0]
    finally:
        _put_conn(conn)


def list_assets(organization_id: int, asset_type: Optional[str] = None,
                limit: int = 200) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if asset_type:
                cur.execute("""
                    SELECT * FROM targets
                    WHERE organization_id = %s AND asset_type = %s
                    ORDER BY created_at DESC LIMIT %s
                """, (organization_id, asset_type, limit))
            else:
                cur.execute("""
                    SELECT * FROM targets
                    WHERE organization_id = %s
                    ORDER BY created_at DESC LIMIT %s
                """, (organization_id, limit))
            return [_asset_row(r) for r in cur.fetchall()]
    finally:
        _put_conn(conn)


def get_asset(asset_id: int, organization_id: int) -> Optional[Dict]:
    return get_target(asset_id, organization_id)


_ASSET_UPDATABLE = {"name", "hostname", "environment", "business_criticality",
                    "monitoring_status", "authorization_status", "last_seen"}


def update_asset(asset_id: int, organization_id: int, **fields) -> bool:
    """Update mutable asset fields. Returns False if the asset doesn't exist
    in this organization (never distinguishes that from "wrong org")."""
    sets, vals = [], []
    for k, v in fields.items():
        if k in _ASSET_UPDATABLE:
            sets.append(f"{k} = %s")
            vals.append(v)
    if not sets:
        return get_target(asset_id, organization_id) is not None
    sets.append("updated_at = NOW()")
    vals.extend([asset_id, organization_id])
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    # nosec B608 - `sets` entries come only from _ASSET_UPDATABLE
                    # (a fixed allowlist), never from a raw field name; values
                    # are still parameterized via `vals`.
                    f"UPDATE targets SET {', '.join(sets)} WHERE id = %s AND organization_id = %s",  # nosec B608
                    vals
                )
                return cur.rowcount > 0
    finally:
        _put_conn(conn)


def delete_asset(asset_id: int, organization_id: int) -> bool:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM targets WHERE id = %s AND organization_id = %s",
                           (asset_id, organization_id))
                return cur.rowcount > 0
    finally:
        _put_conn(conn)


# --- continuous monitoring schedule (Phase 5) -------------------------------
def set_asset_monitoring(asset_id: int, organization_id: int, monitoring_status: str,
                         monitoring_frequency: str) -> bool:
    """Configure (or pause) continuous monitoring for one asset. Activating
    with a real frequency schedules an immediate first due-check
    (next_scan_at = NOW()); anything else clears next_scan_at so the
    scheduler stops picking the asset up."""
    schedule_now = monitoring_status == "active" and monitoring_frequency != "manual"
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    # nosec B608 - the only interpolation is a fixed literal
                    # ("NOW()"/"NULL") chosen by a Python bool, never
                    # user input; every actual value below is parameterized.
                    f"""UPDATE targets
                        SET monitoring_status = %s, monitoring_frequency = %s,
                            next_scan_at = {"NOW()" if schedule_now else "NULL"}, updated_at = NOW()
                        WHERE id = %s AND organization_id = %s""",  # nosec B608
                    (monitoring_status, monitoring_frequency, asset_id, organization_id)
                )
                return cur.rowcount > 0
    finally:
        _put_conn(conn)


def list_due_assets(now=None) -> List[Dict]:
    """Every active, scheduled asset whose next_scan_at has passed — across
    all organizations. Used only by the scheduler's own periodic check
    (webapp/tasks.py), never a user-facing route — same pattern as
    list_interrupted_scans."""
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT * FROM targets
                   WHERE monitoring_status = 'active' AND monitoring_frequency != 'manual'
                         AND next_scan_at IS NOT NULL AND next_scan_at <= COALESCE(%s, NOW())""",
                (now,)
            )
            return cur.fetchall()
    finally:
        _put_conn(conn)


def mark_asset_scanned(asset_id: int) -> None:
    """After a scheduled scan is enqueued for an asset, push next_scan_at
    forward by its own monitoring_frequency and record last_scan_at."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT monitoring_frequency FROM targets WHERE id = %s", (asset_id,))
                row = cur.fetchone()
                if not row:
                    return
                minutes = config.MONITORING_FREQUENCY_MINUTES.get(row[0])
                if not minutes:
                    return
                cur.execute(
                    """UPDATE targets
                       SET last_scan_at = NOW(),
                           next_scan_at = NOW() + (%s || ' minutes')::interval
                       WHERE id = %s""",
                    (minutes, asset_id)
                )
    finally:
        _put_conn(conn)


# --- scans -------------------------------------------------------------
def create_scan(user_id: int, target_id: int, scan_type: str, selected_keys: List[str]) -> int:
    """Create a new scan record. Returns scan ID.

    organization_id is derived from user_id (a scan always belongs to its
    creator's organization) rather than taken as a separate parameter, so
    every existing call site keeps working unchanged.
    """
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO scans(user_id, target_id, scan_type, selected_keys,
                                         organization_id, created_at)
                       VALUES(%s, %s, %s, %s, (SELECT organization_id FROM users WHERE id = %s), %s)
                       RETURNING id""",
                    (user_id, target_id, scan_type, Json(selected_keys), user_id, _now())
                )
                row = cur.fetchone()
                return row[0] if row else None
    finally:
        _put_conn(conn)


def update_scan(scan_id: int, **fields) -> None:
    """Update scan fields. Allowed: status, progress, phase, message, stats, started_at, finished_at."""
    allowed = {"status", "progress", "phase", "message", "stats", "started_at", "finished_at"}
    sets = []
    vals = []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = %s")
            if k == "stats" and isinstance(v, dict):
                v = Json(v)
            vals.append(v)
    if not sets:
        return
    vals.append(scan_id)
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    # nosec B608 - `sets` entries come only from `allowed`
                    # above (a fixed allowlist), never a raw field name;
                    # values are still parameterized via `vals`.
                    f"UPDATE scans SET {', '.join(sets)} WHERE id = %s",  # nosec B608
                    vals
                )
    finally:
        _put_conn(conn)


def list_interrupted_scans() -> List[Dict]:
    """Every scan left running/queued by a previous process, across ALL
    organizations. Used only by ScanManager's own crash-recovery sweep at
    startup — not org-scoped because it's an internal operational check, not
    a user-facing read."""
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM scans WHERE status IN ('running', 'queued')")
            return cur.fetchall()
    finally:
        _put_conn(conn)


def get_scan_status(scan_id: int) -> Optional[str]:
    """Raw status lookup with no org filter — used only by ScanManager to
    check on a job it itself just submitted, never exposed to a user-facing
    route."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM scans WHERE id = %s", (scan_id,))
            row = cur.fetchone()
            return row[0] if row else None
    finally:
        _put_conn(conn)


def get_scan(scan_id: int, organization_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT s.*, COALESCE(t.url, '') as target
                FROM scans s
                LEFT JOIN targets t ON s.target_id = t.id
                WHERE s.id = %s AND s.organization_id = %s
            """, (scan_id, organization_id))
            row = cur.fetchone()
            if row:
                # Convert datetimes and JSONB
                for field in ['created_at', 'started_at', 'finished_at']:
                    if row[field]:
                        row[field] = row[field].isoformat()
                if row['stats'] is not None:
                    row['stats'] = json.loads(row['stats']) if isinstance(row['stats'], str) else row['stats']
                if row['selected_keys'] is not None:
                    row['selected_keys'] = json.loads(row['selected_keys']) if isinstance(row['selected_keys'], str) else row['selected_keys']
                # Attach findings so a single get_scan() call returns everything.
                row['findings'] = get_findings(scan_id)
                return dict(row)
            return None
    finally:
        _put_conn(conn)


def list_scans(organization_id: int, user_id: Optional[int] = None, limit: int = 50) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if user_id:
                cur.execute("""
                    SELECT s.*, COALESCE(t.url, '') as target
                    FROM scans s
                    LEFT JOIN targets t ON s.target_id = t.id
                    WHERE s.organization_id = %s AND s.user_id = %s
                    ORDER BY s.created_at DESC
                    LIMIT %s
                """, (organization_id, user_id, limit))
            else:
                cur.execute("""
                    SELECT s.*, COALESCE(t.url, '') as target
                    FROM scans s
                    LEFT JOIN targets t ON s.target_id = t.id
                    WHERE s.organization_id = %s
                    ORDER BY s.created_at DESC
                    LIMIT %s
                """, (organization_id, limit))
            rows = cur.fetchall()
            for row in rows:
                for field in ['created_at', 'started_at', 'finished_at']:
                    if row[field]:
                        row[field] = row[field].isoformat()
                if row['stats'] is not None:
                    row['stats'] = json.loads(row['stats']) if isinstance(row['stats'], str) else row['stats']
                if row['selected_keys'] is not None:
                    row['selected_keys'] = json.loads(row['selected_keys']) if isinstance(row['selected_keys'], str) else row['selected_keys']
            return rows
    finally:
        _put_conn(conn)


def _finding_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Translate a findings row back into the service-layer finding shape.

    Services produce findings with keys: severity, type, description, evidence,
    url, remediation, tool, parameter, payload, confidence, verified,
    tool_command, raw_output. The table stores type→category, url→
    affected_endpoint and tool→tool_source; `verified` is derived from
    `confidence == 'confirmed'`.
    """
    out = {
        "id": row["id"],
        "scan_id": row["scan_id"],
        "organization_id": row.get("organization_id"),
        "target_id": row.get("target_id"),
        "severity": row["severity"],
        "type": row["category"],
        "description": row["description"] or "",
        "evidence": row["evidence"] or "",
        "url": row["affected_endpoint"] or "",
        "remediation": row["remediation"] or "",
        "tool": row["tool_source"],
        "parameter": row["parameter"],
        "payload": row["payload"],
        "confidence": row["confidence"],
        "verified": row["confidence"] == "confirmed",
        "tool_command": row["tool_command"] or "",
        "raw_output": row["raw_output"] or "",
        "discovered_at": row["discovered_at"],
        # Phase 4 lifecycle/classification fields — see docs/ROADMAP.md Phase 4.
        "status": row.get("status", "NEW"),
        "cve": row.get("cve"),
        "cwe": row.get("cwe"),
        "cvss": float(row["cvss"]) if row.get("cvss") is not None else None,
        "fingerprint": row.get("fingerprint"),
        "occurrence_count": row.get("occurrence_count", 1),
        "last_seen": row.get("last_seen"),
        "affected_component": row.get("affected_component"),
        "business_impact": row.get("business_impact"),
        "technical_impact": row.get("technical_impact"),
    }
    # Phase 6 risk engine — only computed when the caller joined the owning
    # asset in (business_criticality/asset_type present on the row); callers
    # that don't need risk (e.g. get_findings(scan_id) for the scan-detail
    # inline list) skip the join and simply don't get these keys added.
    if "business_criticality" in row or "asset_type" in row:
        out.update(compute_risk(
            row["severity"], row["category"], row["confidence"],
            row.get("business_criticality") or "medium",
            row.get("asset_type") or "WEB_APPLICATION",
        ))
    return out


_SEVERITY_MAP = {"critical": "Critical", "high": "High", "medium": "Medium",
                 "low": "Low", "info": "Info", "informational": "Info"}


def _normalize_severity(sev: Any) -> str:
    sev = str(sev or "Info")
    sev = _SEVERITY_MAP.get(sev.lower(), sev)
    return sev if sev in ("Critical", "High", "Medium", "Low", "Info") else "Info"


# CWE mappings are included only where the scanner category maps to one
# specific, well-established CWE ID (per MITRE's CWE list) — a category that
# actually spans many different weakness classes (e.g. "api", generic "cloud"
# misconfiguration) is deliberately left unmapped (None) rather than guessed,
# per the platform's "no fabricated classification" principle.
CATEGORY_CWE_MAP = {
    "xss": "CWE-79", "sqli": "CWE-89", "csrf": "CWE-352", "ssrf": "CWE-918",
    "rce": "CWE-94", "file_upload": "CWE-434", "open_redirect": "CWE-601",
    "clickjack": "CWE-1021", "bac": "CWE-284", "sec_misconfig": "CWE-16",
    "info_disclosure": "CWE-200", "xml": "CWE-611", "smuggling": "CWE-444",
    "proto_pollution": "CWE-1321", "auth_session": "CWE-287",
    "business_logic": "CWE-840", "ddos": "CWE-400",
    "mobile": "CWE-798",  # this scanner detects hardcoded secrets, not APK content
}

# A severity-derived CVSS estimate, not a formally scored CVSS vector (the
# scanners here don't compute attack-vector/complexity/privileges metrics).
# Uses the floor of each official CVSS v3.1 qualitative band — a
# conservative, honestly-labeled estimate rather than a fabricated precise
# score. Exposed to the API as `cvss_estimated` for exactly this reason.
SEVERITY_CVSS_FLOOR = {"Critical": 9.0, "High": 7.0, "Medium": 4.0, "Low": 0.1, "Info": 0.0}


def classify_finding(category: str, severity: str) -> tuple:
    """Returns (cwe_or_None, estimated_cvss)."""
    return CATEGORY_CWE_MAP.get(category), SEVERITY_CVSS_FLOOR.get(severity, 0.0)


# --- Risk engine (Phase 6, spec §10) ----------------------------------------
# "Do not rely only on CVSS" — these are the separately-stored/reported
# factors the spec asks for. Exploitability is a heuristic per vulnerability
# *class* (an RCE is inherently more directly exploitable than an
# information-disclosure finding), same honesty rule as the CWE map: only
# categories with a reasonably confident bucket are mapped, everything else
# defaults to Medium rather than a guessed extreme.
EXPLOITABILITY_MAP = {
    "rce": "High", "sqli": "High", "ssrf": "High", "file_upload": "High",
    "xss": "Medium", "csrf": "Medium", "bac": "Medium", "auth_session": "Medium",
    "xml": "Medium", "smuggling": "Medium", "proto_pollution": "Medium",
    "open_redirect": "Low", "clickjack": "Low", "info_disclosure": "Low",
    "sec_misconfig": "Low", "ddos": "Low", "mobile": "Low",
}

# WEB_APPLICATION assets are reached over the internet by construction (that's
# how a URL gets scanned at all); COMPANY_CONNECTOR assets are the agent
# installed *inside* the customer's network by design (spec §5) — internal by
# construction, not a guess.
ASSET_TYPE_EXPOSURE = {"WEB_APPLICATION": "internet_facing", "COMPANY_CONNECTOR": "internal"}

_SEVERITY_WEIGHT = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
_EXPLOITABILITY_WEIGHT = {"High": 3, "Medium": 2, "Low": 1}
_CRITICALITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_EXPOSURE_WEIGHT = {"internet_facing": 2, "internal": 1}
_CONFIDENCE_WEIGHT = {"confirmed": 1.0, "needs_verification": 0.6}
_MAX_RISK_RAW = 5 * 3 * 4 * 2 * 1.0  # every factor at its highest


def compute_risk(severity: str, category: str, confidence: str,
                 asset_criticality: str, asset_type: str) -> Dict[str, Any]:
    """Composite, explainable risk score (0-100) from 5 separately-reported
    factors — never a CVSS passthrough. Every factor is returned alongside
    the score so an admin can see exactly why a finding scored the way it
    did (spec §10's explicit requirement)."""
    exploitability = EXPLOITABILITY_MAP.get(category, "Medium")
    exposure = ASSET_TYPE_EXPOSURE.get(asset_type, "internet_facing")
    raw = (_SEVERITY_WEIGHT.get(severity, 1) * _EXPLOITABILITY_WEIGHT[exploitability]
          * _CRITICALITY_WEIGHT.get(asset_criticality, 2) * _EXPOSURE_WEIGHT[exposure]
          * _CONFIDENCE_WEIGHT.get(confidence, 0.6))
    return {
        "risk_score": round(raw / _MAX_RISK_RAW * 100, 1),
        "risk_factors": {
            "severity": severity, "exploitability": exploitability,
            "asset_criticality": asset_criticality, "exposure": exposure,
            "confidence": confidence,
        },
    }


def compute_fingerprint(organization_id: int, target_id: Optional[int], category: str,
                        component: str, evidence: str) -> str:
    """Stable identity for "the same vulnerability" across repeated scans of
    the same asset — organization + asset + vulnerability + affected
    component + a normalized slice of the evidence (spec §8)."""
    normalized_evidence = (evidence or "").strip().lower()[:500]
    raw = f"{organization_id}|{target_id}|{category}|{component}|{normalized_evidence}"
    return hashlib.sha256(raw.encode()).hexdigest()


def add_finding(scan_id: int, finding: Dict[str, Any]) -> Dict[str, Any]:
    """Persist a service-layer finding, deduplicated by fingerprint.

    Accepts either the service key names (tool, type, url, description) or the
    legacy table key names (tool_source, category, affected_endpoint) so both
    the FastAPI services and the GUI scanners can insert findings.

    A repeat detection of the same vulnerability on the same asset (same
    fingerprint) updates last_seen/occurrence_count on the existing row
    instead of inserting a duplicate (spec §8) — and if it had previously
    been marked FIXED, reappearing means the fix didn't hold, so it flips to
    REOPENED. A FALSE_POSITIVE/ACCEPTED_RISK determination is a human
    judgment call and is deliberately left alone even if the same evidence
    resurfaces — occurrence_count/last_seen still update, but the status
    doesn't silently override that decision.

    Returns {"finding_id", "is_new_or_reopened"} — the caller (a scan
    service) uses is_new_or_reopened to decide whether to run this finding
    through the Alert Engine (Phase 9): only a genuinely new detection or a
    fix that didn't hold should ever generate a fresh alert, never a finding
    whose occurrence_count just ticked up with nothing else changed.
    """
    sev = _normalize_severity(finding.get("severity"))
    category = finding.get("type") or finding.get("category") or "Finding"
    component = finding.get("parameter") or category
    evidence = finding.get("evidence") or ""
    cwe, cvss = classify_finding(category, sev)

    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT organization_id, target_id FROM scans WHERE id = %s", (scan_id,))
                scan_row = cur.fetchone()
                organization_id = scan_row[0] if scan_row else None
                target_id = scan_row[1] if scan_row else None
                fingerprint = compute_fingerprint(organization_id, target_id, category, component, evidence)

                # Single atomic INSERT ... ON CONFLICT DO UPDATE, not a
                # separate SELECT-then-branch (Phase 20 audit, CWE-362): two
                # concurrent scans detecting the identical vulnerability at
                # the same instant must not both be able to see "no existing
                # row" and both INSERT, which the previous check-then-act
                # allowed. `idx_findings_org_fingerprint_unique` (this
                # function's own migration, above) is the ON CONFLICT
                # arbiter. `(xmax = 0)` is the standard Postgres idiom for
                # "was this RETURNING row a fresh insert (xmax=0) or an
                # update-in-place via the ON CONFLICT path (xmax set)."
                cur.execute(
                    """INSERT INTO findings(
                           scan_id, tool_source, category, severity, confidence,
                           affected_endpoint, evidence, remediation, description,
                           parameter, payload, tool_command, raw_output, discovered_at,
                           organization_id, target_id, fingerprint, status, cwe, cvss,
                           affected_component, occurrence_count, last_seen
                       ) VALUES(
                           %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           %s, %s, %s, 'NEW', %s, %s, %s, 1, %s
                       )
                       ON CONFLICT (organization_id, fingerprint) WHERE fingerprint IS NOT NULL
                       DO UPDATE SET
                           occurrence_count = findings.occurrence_count + 1,
                           last_seen = EXCLUDED.last_seen,
                           scan_id = EXCLUDED.scan_id,
                           status = CASE WHEN findings.status = 'FIXED' THEN 'REOPENED'
                                        ELSE findings.status END
                       RETURNING id, status, (xmax = 0) AS was_inserted""",
                    (
                        scan_id,
                        finding.get("tool") or finding.get("tool_source") or "unknown",
                        category,
                        sev,
                        finding.get("confidence", "needs_verification") or "needs_verification",
                        finding.get("url") or finding.get("affected_endpoint") or "",
                        evidence,
                        finding.get("remediation") or "",
                        finding.get("description") or evidence,
                        finding.get("parameter"),
                        finding.get("payload"),
                        finding.get("tool_command", ""),
                        finding.get("raw_output", ""),
                        _now(),
                        organization_id, target_id, fingerprint, cwe, cvss, component,
                        _now(),
                    )
                )
                row_id, status, was_inserted = cur.fetchone()
                return {"finding_id": row_id, "is_new_or_reopened": bool(was_inserted or status == "REOPENED")}
    finally:
        _put_conn(conn)


def get_findings(scan_id: int) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT * FROM findings
                   WHERE scan_id = %s
                   ORDER BY
                       CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
                                    WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
                       id""",
                (scan_id,)
            )
            rows = cur.fetchall()
            out = []
            for row in rows:
                if row['discovered_at']:
                    row['discovered_at'] = row['discovered_at'].isoformat()
                if row.get('last_seen'):
                    row['last_seen'] = row['last_seen'].isoformat()
                out.append(_finding_from_row(row))
            return out
    finally:
        _put_conn(conn)


def get_finding(finding_id: int, organization_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT f.*, t.business_criticality, t.asset_type
                   FROM findings f LEFT JOIN targets t ON f.target_id = t.id
                   WHERE f.id = %s AND f.organization_id = %s""",
                (finding_id, organization_id)
            )
            row = cur.fetchone()
            if not row:
                return None
            if row.get('discovered_at'):
                row['discovered_at'] = row['discovered_at'].isoformat()
            if row.get('last_seen'):
                row['last_seen'] = row['last_seen'].isoformat()
            return _finding_from_row(row)
    finally:
        _put_conn(conn)


def get_finding_unscoped(finding_id: int) -> Optional[Dict]:
    """No organization filter — used only by the Alert Engine, which is
    called immediately after add_finding() with just the finding_id it
    returned (already a trusted, just-persisted row), never from a
    user-facing route. Same internal-only pattern as
    list_interrupted_scans/get_scan_status."""
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT f.*, t.business_criticality, t.asset_type
                   FROM findings f LEFT JOIN targets t ON f.target_id = t.id
                   WHERE f.id = %s""",
                (finding_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            if row.get('discovered_at'):
                row['discovered_at'] = row['discovered_at'].isoformat()
            if row.get('last_seen'):
                row['last_seen'] = row['last_seen'].isoformat()
            return _finding_from_row(row)
    finally:
        _put_conn(conn)


_VALID_FINDING_STATUSES = ("NEW", "OPEN", "ACKNOWLEDGED", "IN_PROGRESS",
                           "FIX_PENDING_VERIFICATION", "FIXED", "REOPENED",
                           "FALSE_POSITIVE", "ACCEPTED_RISK")


def update_finding_status(finding_id: int, organization_id: int, status: str) -> bool:
    if status not in _VALID_FINDING_STATUSES:
        raise ValueError(f"Invalid finding status: {status}")
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE findings SET status = %s WHERE id = %s AND organization_id = %s",
                    (status, finding_id, organization_id)
                )
                return cur.rowcount > 0
    finally:
        _put_conn(conn)


def list_findings(organization_id: int, status: Optional[str] = None,
                  severity: Optional[str] = None, limit: int = 200) -> List[Dict]:
    """Cross-scan finding listing for the vulnerability list/detail API —
    each fingerprint appears once, at its current lifecycle state."""
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            clauses = ["f.organization_id = %s"]
            params: list = [organization_id]
            if status:
                clauses.append("f.status = %s")
                params.append(status)
            if severity:
                clauses.append("f.severity = %s")
                params.append(severity)
            params.append(limit)
            cur.execute(
                # nosec B608 - `clauses` entries are fixed strings appended
                # conditionally above, never built from a raw field name or
                # user-supplied value; every actual value is in `params`.
                f"""SELECT f.*, t.business_criticality, t.asset_type
                    FROM findings f LEFT JOIN targets t ON f.target_id = t.id
                    WHERE {' AND '.join(clauses)}
                    ORDER BY
                        CASE f.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
                                       WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
                        f.last_seen DESC NULLS LAST
                    LIMIT %s""",  # nosec B608
                params
            )
            rows = cur.fetchall()
            out = []
            for row in rows:
                if row.get('discovered_at'):
                    row['discovered_at'] = row['discovered_at'].isoformat()
                if row.get('last_seen'):
                    row['last_seen'] = row['last_seen'].isoformat()
                out.append(_finding_from_row(row))
            return out
    finally:
        _put_conn(conn)


def severity_counts(scan_id: int) -> Dict[str, int]:
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT severity, COUNT(*) as count
                   FROM findings
                   WHERE scan_id = %s
                   GROUP BY severity""",
                (scan_id,)
            )
            rows = cur.fetchall()
            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for row in rows:
                counts[row[0]] = row[1]
            return counts
    finally:
        _put_conn(conn)


# --- alerting (Phase 9) -----------------------------------------------------
def create_notification_channel(organization_id: int, channel_type: str, name: str,
                                config: Dict[str, Any]) -> int:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO notification_channels(organization_id, channel_type, name, config)
                       VALUES(%s, %s, %s, %s) RETURNING id""",
                    (organization_id, channel_type, name, Json(config))
                )
                return cur.fetchone()[0]
    finally:
        _put_conn(conn)


def list_notification_channels(organization_id: int, enabled_only: bool = False) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if enabled_only:
                cur.execute(
                    "SELECT * FROM notification_channels WHERE organization_id = %s AND enabled = TRUE",
                    (organization_id,)
                )
            else:
                cur.execute(
                    "SELECT * FROM notification_channels WHERE organization_id = %s ORDER BY created_at DESC",
                    (organization_id,)
                )
            return cur.fetchall()
    finally:
        _put_conn(conn)


def get_notification_channel(channel_id: int, organization_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM notification_channels WHERE id = %s AND organization_id = %s",
                (channel_id, organization_id)
            )
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        _put_conn(conn)


def delete_notification_channel(channel_id: int, organization_id: int) -> bool:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM notification_channels WHERE id = %s AND organization_id = %s",
                    (channel_id, organization_id)
                )
                return cur.rowcount > 0
    finally:
        _put_conn(conn)


def get_or_create_alert(organization_id: int, finding_id: int, asset_id: Optional[int],
                        severity: str) -> Dict[str, Any]:
    """One alert per finding (UNIQUE(finding_id)) — this is the dedup: a
    finding that keeps reappearing shares the same alert row rather than
    spawning a new one every time."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM alerts WHERE finding_id = %s", (finding_id,))
                existing = cur.fetchone()
                if existing:
                    return dict(existing)
                cur.execute(
                    """INSERT INTO alerts(organization_id, finding_id, asset_id, severity)
                       VALUES(%s, %s, %s, %s) RETURNING *""",
                    (organization_id, finding_id, asset_id, severity)
                )
                return dict(cur.fetchone())
    finally:
        _put_conn(conn)


def should_notify(alert: Dict[str, Any], cooldown_minutes: int) -> bool:
    """False within the cooldown window since the last notification attempt
    (spec §9: never re-notify for the same unchanged vulnerability) — the
    caller decides when an alert counts as "unchanged" (see alert_engine.py);
    this function only enforces the time-based cooldown itself."""
    last = alert.get("last_notified_at")
    if not last:
        return True
    last_dt = datetime.fromisoformat(last) if isinstance(last, str) else last
    if last_dt.tzinfo is None:
        last_dt = last_dt.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - last_dt >= timedelta(minutes=cooldown_minutes)


def mark_alert_notified(alert_id: int) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE alerts SET last_notified_at = NOW() WHERE id = %s", (alert_id,))
    finally:
        _put_conn(conn)


def record_notification(alert_id: int, channel_id: Optional[int], status: str,
                        error_message: Optional[str] = None) -> None:
    """Every delivery *attempt* — spec: "Alert sent" must represent an actual
    notification attempt, never a simulated/assumed success."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO notifications(alert_id, channel_id, status, error_message)
                       VALUES(%s, %s, %s, %s)""",
                    (alert_id, channel_id, status, error_message)
                )
    finally:
        _put_conn(conn)


def list_alerts(organization_id: int, status: Optional[str] = None, limit: int = 200) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if status:
                cur.execute(
                    """SELECT * FROM alerts WHERE organization_id = %s AND status = %s
                       ORDER BY created_at DESC LIMIT %s""",
                    (organization_id, status, limit)
                )
            else:
                cur.execute(
                    "SELECT * FROM alerts WHERE organization_id = %s ORDER BY created_at DESC LIMIT %s",
                    (organization_id, limit)
                )
            return cur.fetchall()
    finally:
        _put_conn(conn)


def get_alert(alert_id: int, organization_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM alerts WHERE id = %s AND organization_id = %s",
                       (alert_id, organization_id))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        _put_conn(conn)


def acknowledge_alert(alert_id: int, organization_id: int, user_id: int) -> bool:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE alerts SET status = 'acknowledged', acknowledged_at = NOW(),
                                         acknowledged_by_user_id = %s
                       WHERE id = %s AND organization_id = %s""",
                    (user_id, alert_id, organization_id)
                )
                return cur.rowcount > 0
    finally:
        _put_conn(conn)


def list_alert_notifications(alert_id: int) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM notifications WHERE alert_id = %s ORDER BY sent_at DESC", (alert_id,))
            return cur.fetchall()
    finally:
        _put_conn(conn)


# --- remediation workflow (Phase 10) ----------------------------------------
_REMEDIATION_STATUSES = ("OPEN", "ASSIGNED", "IN_PROGRESS", "FIX_SUBMITTED",
                        "RESCAN", "VERIFICATION", "FIXED", "REOPENED")
# Transitions an admin/operator may set directly via PATCH — the automatic
# verification pipeline (submit_fix / finalize) owns FIX_SUBMITTED, RESCAN,
# VERIFICATION, FIXED and REOPENED so a human can't shortcut straight to
# FIXED without the system ever actually re-checking (spec §15's whole
# point: "do NOT simply change it to FIXED").
_MANUAL_REMEDIATION_STATUSES = ("OPEN", "ASSIGNED", "IN_PROGRESS")


def create_remediation_task(organization_id: int, finding_id: int,
                            assignee_user_id: Optional[int], team: Optional[str],
                            priority: str, due_date: Optional[str]) -> int:
    status = "ASSIGNED" if assignee_user_id else "OPEN"
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO remediation_tasks(
                           organization_id, finding_id, assignee_user_id, team,
                           priority, due_date, status
                       ) VALUES(%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                    (organization_id, finding_id, assignee_user_id, team, priority, due_date, status)
                )
                return cur.fetchone()[0]
    finally:
        _put_conn(conn)


def get_remediation_task(task_id: int, organization_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM remediation_tasks WHERE id = %s AND organization_id = %s",
                (task_id, organization_id)
            )
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        _put_conn(conn)


def get_remediation_task_unscoped(task_id: int) -> Optional[Dict]:
    """No organization filter — used only by the verification finalization
    sweep (webapp/tasks.py), which already has a trusted task_id from its own
    due-list query. Same internal-only pattern as get_finding_unscoped."""
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM remediation_tasks WHERE id = %s", (task_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        _put_conn(conn)


def list_remediation_tasks(organization_id: int, status: Optional[str] = None,
                           assignee_user_id: Optional[int] = None, limit: int = 200) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            clauses = ["organization_id = %s"]
            params: list = [organization_id]
            if status:
                clauses.append("status = %s")
                params.append(status)
            if assignee_user_id:
                clauses.append("assignee_user_id = %s")
                params.append(assignee_user_id)
            params.append(limit)
            cur.execute(
                # nosec B608 - `clauses` entries are fixed strings appended
                # conditionally above, never built from a raw field name or
                # user-supplied value; every actual value is in `params`.
                f"""SELECT * FROM remediation_tasks WHERE {' AND '.join(clauses)}
                    ORDER BY created_at DESC LIMIT %s""",  # nosec B608
                params
            )
            return cur.fetchall()
    finally:
        _put_conn(conn)


def update_remediation_task(task_id: int, organization_id: int, **fields) -> bool:
    """Manual field edits (assignee/team/priority/due_date) and manual status
    moves restricted to OPEN/ASSIGNED/IN_PROGRESS — see
    _MANUAL_REMEDIATION_STATUSES. Raises ValueError for a disallowed status
    rather than silently ignoring it."""
    updatable = {"assignee_user_id", "team", "priority", "due_date", "status"}
    sets, vals = [], []
    for k, v in fields.items():
        if k not in updatable:
            continue
        if k == "status" and v not in _MANUAL_REMEDIATION_STATUSES:
            raise ValueError(
                f"Status '{v}' can't be set directly — use /submit-fix, which drives "
                "the automatic verification pipeline instead."
            )
        sets.append(f"{k} = %s")
        vals.append(v)
    if not sets:
        return get_remediation_task(task_id, organization_id) is not None
    sets.append("updated_at = NOW()")
    vals.extend([task_id, organization_id])
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    # nosec B608 - `sets` entries come only from `updatable`
                    # above (a fixed allowlist), never a raw field name;
                    # values are still parameterized via `vals`.
                    f"UPDATE remediation_tasks SET {', '.join(sets)} WHERE id = %s AND organization_id = %s",  # nosec B608
                    vals
                )
                return cur.rowcount > 0
    finally:
        _put_conn(conn)


def submit_fix(task_id: int, organization_id: int, verification_scan_id: int) -> bool:
    """FIX_SUBMITTED -> RESCAN, with the verification scan linked. Also
    advances the underlying finding to FIX_PENDING_VERIFICATION (spec §8)."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE remediation_tasks
                       SET status = 'RESCAN', verification_scan_id = %s, updated_at = NOW()
                       WHERE id = %s AND organization_id = %s
                       RETURNING finding_id""",
                    (verification_scan_id, task_id, organization_id)
                )
                row = cur.fetchone()
                if not row:
                    return False
                cur.execute(
                    "UPDATE findings SET status = 'FIX_PENDING_VERIFICATION' WHERE id = %s",
                    (row[0],)
                )
                return True
    finally:
        _put_conn(conn)


def list_tasks_awaiting_verification() -> List[Dict]:
    """Every RESCAN task whose verification scan has reached a terminal
    status — used only by the verification finalization sweep
    (webapp/tasks.py), not a user-facing route."""
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT rt.* FROM remediation_tasks rt
                   JOIN scans s ON rt.verification_scan_id = s.id
                   WHERE rt.status = 'RESCAN' AND s.status IN ('completed', 'error')"""
            )
            return cur.fetchall()
    finally:
        _put_conn(conn)


def finalize_verification(task_id: int, still_present: bool, evidence: Dict[str, Any]) -> None:
    """The core of spec §15: never a direct manual FIXED — only this
    function, called after an actual verification scan's real result is
    known, sets FIXED or REOPENED, on both the task and its finding."""
    new_status = "REOPENED" if still_present else "FIXED"
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE remediation_tasks
                       SET status = %s, verification_evidence = %s, updated_at = NOW()
                       WHERE id = %s RETURNING finding_id""",
                    (new_status, Json(evidence), task_id)
                )
                row = cur.fetchone()
                if not row:
                    return
                cur.execute("UPDATE findings SET status = %s WHERE id = %s", (new_status, row[0]))
    finally:
        _put_conn(conn)


def add_remediation_comment(task_id: int, user_id: Optional[int], comment: str) -> int:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO remediation_comments(task_id, user_id, comment)
                       VALUES(%s, %s, %s) RETURNING id""",
                    (task_id, user_id, comment)
                )
                return cur.fetchone()[0]
    finally:
        _put_conn(conn)


def list_remediation_comments(task_id: int) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM remediation_comments WHERE task_id = %s ORDER BY created_at",
                (task_id,)
            )
            return cur.fetchall()
    finally:
        _put_conn(conn)


# --- Company Connector (Phase 8) --------------------------------------------
JOB_TYPES = ("inventory_check", "configuration_check",
            "vulnerability_assessment", "telemetry_collection")


def create_enrollment_token(organization_id: int, created_by_user_id: int,
                            token_hash: str, expires_at) -> int:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO connector_enrollment_tokens(
                           organization_id, created_by_user_id, token_hash, expires_at
                       ) VALUES(%s, %s, %s, %s) RETURNING id""",
                    (organization_id, created_by_user_id, token_hash, expires_at)
                )
                return cur.fetchone()[0]
    finally:
        _put_conn(conn)


def get_enrollment_token(token_hash: str) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM connector_enrollment_tokens WHERE token_hash = %s", (token_hash,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        _put_conn(conn)


def mark_enrollment_token_used(token_id: int) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE connector_enrollment_tokens SET used_at = NOW() WHERE id = %s", (token_id,))
    finally:
        _put_conn(conn)


def create_connector(organization_id: int, name: str, public_key_pem: str,
                     secret_hash: str, version: str, os_name: str) -> int:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO connectors(
                           organization_id, name, public_key_pem, secret_hash, version, os,
                           last_heartbeat_at
                       ) VALUES(%s, %s, %s, %s, %s, %s, NOW()) RETURNING id""",
                    (organization_id, name, public_key_pem, secret_hash, version, os_name)
                )
                return cur.fetchone()[0]
    finally:
        _put_conn(conn)


def get_connector(connector_id: int, organization_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM connectors WHERE id = %s AND organization_id = %s",
                       (connector_id, organization_id))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        _put_conn(conn)


def get_connector_by_secret_hash(secret_hash: str) -> Optional[Dict]:
    """No organization filter — this IS the connector's own identity
    lookup (its secret already proves which connector/org it is); every
    other connector function it calls takes the resolved organization_id
    from here."""
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM connectors WHERE secret_hash = %s", (secret_hash,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        _put_conn(conn)


def list_connectors(organization_id: int) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM connectors WHERE organization_id = %s ORDER BY created_at DESC",
                       (organization_id,))
            return cur.fetchall()
    finally:
        _put_conn(conn)


def record_connector_heartbeat(connector_id: int, version: str, os_name: str) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE connectors SET last_heartbeat_at = NOW(), version = %s, os = %s WHERE id = %s",
                    (version, os_name, connector_id)
                )
    finally:
        _put_conn(conn)


def revoke_connector(connector_id: int, organization_id: int) -> bool:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE connectors SET revoked_at = NOW() WHERE id = %s AND organization_id = %s",
                    (connector_id, organization_id)
                )
                return cur.rowcount > 0
    finally:
        _put_conn(conn)


def set_connector_paused(connector_id: int, organization_id: int, paused: bool) -> bool:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE connectors SET paused = %s WHERE id = %s AND organization_id = %s",
                    (paused, connector_id, organization_id)
                )
                return cur.rowcount > 0
    finally:
        _put_conn(conn)


def connector_state(connector: Dict[str, Any]) -> str:
    """Live-computed, never stored — a connector's state is a function of
    whether it's revoked and how stale its last heartbeat is, so it's always
    correct at read time without a background job keeping it in sync."""
    if connector.get("revoked_at"):
        return "REVOKED"
    last = connector.get("last_heartbeat_at")
    if not last:
        return "OFFLINE"
    last_dt = datetime.fromisoformat(last) if isinstance(last, str) else last
    if last_dt.tzinfo is None:
        last_dt = last_dt.replace(tzinfo=timezone.utc)
    age_minutes = (datetime.now(timezone.utc) - last_dt).total_seconds() / 60
    if age_minutes > config.CONNECTOR_OFFLINE_AFTER_MINUTES:
        return "OFFLINE"
    if age_minutes > config.CONNECTOR_DEGRADED_AFTER_MINUTES:
        return "DEGRADED"
    return "ONLINE"


def create_connector_job(organization_id: int, connector_id: int, job_type: str,
                         scope: Dict[str, Any], authorized_by_user_id: int,
                         expires_at) -> Dict[str, Any]:
    """Inserts the job WITHOUT a signature and returns the full row —
    job_id and created_at are DB-generated, but both are part of what the
    signature must cover, so the caller (webapp/routers/connectors.py) signs
    the returned row's canonical payload and calls set_connector_job_signature
    right after. Two-step by necessity, not by choice."""
    if job_type not in JOB_TYPES:
        raise ValueError(f"Unknown job_type: {job_type}")
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """INSERT INTO connector_jobs(
                           organization_id, connector_id, job_type, scope,
                           authorized_by_user_id, expires_at
                       ) VALUES(%s, %s, %s, %s, %s, %s) RETURNING *""",
                    (organization_id, connector_id, job_type, Json(scope),
                     authorized_by_user_id, expires_at)
                )
                return dict(cur.fetchone())
    finally:
        _put_conn(conn)


def set_connector_job_signature(job_id: int, signature: str) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE connector_jobs SET signature = %s WHERE id = %s", (signature, job_id))
    finally:
        _put_conn(conn)


def get_connector_job(job_id: int, organization_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM connector_jobs WHERE id = %s AND organization_id = %s",
                       (job_id, organization_id))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        _put_conn(conn)


def list_connector_jobs(connector_id: int, organization_id: int, limit: int = 100) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT * FROM connector_jobs WHERE connector_id = %s AND organization_id = %s
                   ORDER BY created_at DESC LIMIT %s""",
                (connector_id, organization_id, limit)
            )
            return cur.fetchall()
    finally:
        _put_conn(conn)


def get_next_pending_job(connector_id: int) -> Optional[Dict]:
    """Called by the connector itself (already authenticated via its
    secret) — the oldest still-valid pending job, marked 'sent' and set as
    the connector's current job atomically. Expired-but-still-pending jobs
    are marked 'expired' in passing rather than ever being handed out.

    The find-and-claim is a single `UPDATE ... WHERE id = (SELECT ... FOR
    UPDATE SKIP LOCKED)` statement, not a separate SELECT followed by an
    UPDATE (Phase 20 audit, CWE-362): two near-simultaneous polls for the
    same connector — a retrying agent, or an attacker racing a stolen
    connector secret against the legitimate poller — must not both be able
    to claim the same job. The previous SELECT-then-UPDATE had exactly that
    window.
    """
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """UPDATE connector_jobs SET status = 'expired'
                       WHERE connector_id = %s AND status = 'pending' AND expires_at <= NOW()""",
                    (connector_id,)
                )
                cur.execute(
                    """UPDATE connector_jobs SET status = 'sent', sent_at = NOW()
                       WHERE id = (
                           SELECT id FROM connector_jobs
                           WHERE connector_id = %s AND status = 'pending' AND expires_at > NOW()
                           ORDER BY created_at ASC LIMIT 1
                           FOR UPDATE SKIP LOCKED
                       )
                       RETURNING *""",
                    (connector_id,)
                )
                job = cur.fetchone()
                if not job:
                    return None
                cur.execute("UPDATE connectors SET current_job_id = %s WHERE id = %s",
                           (job["id"], connector_id))
                return dict(job)
    finally:
        _put_conn(conn)


def submit_connector_job_result(job_id: int, connector_id: int, result: Dict[str, Any],
                                result_signature: str) -> bool:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE connector_jobs
                       SET status = 'completed', result = %s, result_signature = %s, completed_at = NOW()
                       WHERE id = %s AND connector_id = %s AND status = 'sent'""",
                    (Json(result), result_signature, job_id, connector_id)
                )
                if cur.rowcount == 0:
                    return False
                cur.execute(
                    "UPDATE connectors SET current_job_id = NULL WHERE id = %s AND current_job_id = %s",
                    (connector_id, job_id)
                )
                return True
    finally:
        _put_conn(conn)


def reject_connector_job_result(job_id: int, connector_id: int, reason: str) -> None:
    """A result whose signature doesn't verify — recorded as rejected, never
    trusted, and audited by the caller."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE connector_jobs SET status = 'rejected', rejection_reason = %s
                       WHERE id = %s AND connector_id = %s""",
                    (reason, job_id, connector_id)
                )
                cur.execute(
                    "UPDATE connectors SET current_job_id = NULL WHERE id = %s AND current_job_id = %s",
                    (connector_id, job_id)
                )
    finally:
        _put_conn(conn)


# --- reports -------------------------------------------------------------
def add_report(scan_id: int, target_id: int, scan_type: str, fmt: str, path: str) -> int:
    """organization_id is derived from scan_id, matching create_scan's pattern."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO reports(scan_id, target_id, scan_type, format, path,
                                           organization_id, created_at)
                       VALUES(%s, %s, %s, %s, %s, (SELECT organization_id FROM scans WHERE id = %s), %s)
                       RETURNING id""",
                    (scan_id, target_id, scan_type, fmt, path, scan_id, _now())
                )
                row = cur.fetchone()
                return row[0] if row else None
    finally:
        _put_conn(conn)


def list_reports(organization_id: int, limit: int = 100) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT r.*, COALESCE(t.url, '') as target
                FROM reports r
                LEFT JOIN targets t ON r.target_id = t.id
                WHERE r.organization_id = %s
                ORDER BY r.created_at DESC
                LIMIT %s
            """, (organization_id, limit))
            rows = cur.fetchall()
            for row in rows:
                if row['created_at']:
                    row['created_at'] = row['created_at'].isoformat()
            return rows
    finally:
        _put_conn(conn)


def get_report(report_id: int, organization_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT r.*, COALESCE(t.url, '') as target
                FROM reports r
                LEFT JOIN targets t ON r.target_id = t.id
                WHERE r.id = %s AND r.organization_id = %s
            """, (report_id, organization_id))
            row = cur.fetchone()
            if row:
                if row['created_at']:
                    row['created_at'] = row['created_at'].isoformat()
                return dict(row)
            return None
    finally:
        _put_conn(conn)


# --- dashboard -----------------------------------------------------------
def dashboard_stats(organization_id: int) -> Dict:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get recent scans
            cur.execute("""
                SELECT s.*, COALESCE(t.url, '') as target
                FROM scans s
                LEFT JOIN targets t ON s.target_id = t.id
                WHERE s.organization_id = %s
                ORDER BY s.created_at DESC
                LIMIT 200
            """, (organization_id,))
            scans = cur.fetchall()

            # Get all findings for this org
            cur.execute("SELECT * FROM findings WHERE organization_id = %s", (organization_id,))
            findings = cur.fetchall()

            running_scans = sum(1 for s in scans if s["status"] in ("running", "queued"))

            sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            by_type = {}
            by_scan_sev: Dict[int, Dict[str, int]] = {}
            for f in findings:
                sev[f["severity"]] = sev.get(f["severity"], 0) + 1
                by_type[f["category"]] = by_type.get(f["category"], 0) + 1
                scan_sev = by_scan_sev.setdefault(
                    f["scan_id"], {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0})
                scan_sev[f["severity"]] = scan_sev.get(f["severity"], 0) + 1

            score_sum, scored = 0, 0
            trend = []
            for s in scans:
                stats = s["stats"]
                if isinstance(stats, str):
                    try:
                        stats = json.loads(stats)
                    except Exception:
                        stats = {}
                sc = stats.get("security_score", 0)
                if sc:
                    score_sum += sc
                    scored += 1
                trend.append({
                    "id": s["id"],
                    "target": s["target"],
                    "status": s["status"],
                    "score": sc,
                    "created_at": s["created_at"].isoformat() if s["created_at"] else None
                })

            by_type_list = [{"type": k, "count": v} for k, v in
                            sorted(by_type.items(), key=lambda x: -x[1])][:15]

            # --- Phase 11: the rest of spec §11's real-data SOC dashboard ------
            by_status = {}
            for f in findings:
                st = f.get("status", "NEW")
                by_status[st] = by_status.get(st, 0) + 1

            cur.execute("""
                SELECT asset_type, monitoring_status FROM targets WHERE organization_id = %s
            """, (organization_id,))
            assets = cur.fetchall()
            total_assets = len(assets)
            monitored_assets = sum(1 for a in assets if a["monitoring_status"] == "active")

            cur.execute("SELECT * FROM connectors WHERE organization_id = %s", (organization_id,))
            connectors = cur.fetchall()
            connectors_online = sum(1 for c in connectors if connector_state(c) == "ONLINE")
            connectors_offline = sum(1 for c in connectors if connector_state(c) in ("OFFLINE", "DEGRADED"))

            cur.execute(
                "SELECT COUNT(*) FROM remediation_tasks WHERE organization_id = %s "
                "AND status NOT IN ('FIXED', 'REOPENED')",
                (organization_id,)
            )
            open_remediation_tasks = cur.fetchone()[0]

            cur.execute(
                """SELECT a.*, f.type AS finding_type FROM alerts a
                   JOIN findings f ON a.finding_id = f.id
                   WHERE a.organization_id = %s ORDER BY a.created_at DESC LIMIT 10""",
                (organization_id,)
            )
            recent_alerts = [{
                "id": a["id"], "finding_id": a["finding_id"], "asset_id": a.get("asset_id"),
                "severity": a["severity"], "status": a["status"], "vulnerability": a["finding_type"],
                "created_at": a["created_at"].isoformat() if a["created_at"] else None,
            } for a in cur.fetchall()]

            return {
                "total_scans": len(scans),
                "running_scans": running_scans,
                "total_findings": len(findings),
                "critical": sev["Critical"], "high": sev["High"], "medium": sev["Medium"],
                "low": sev["Low"], "info": sev["Info"],
                "avg_security_score": round(score_sum / scored) if scored else 100,
                "by_type": by_type_list,
                "recent_scans": [
                    {
                        "id": s["id"],
                        "target": s["target"],
                        "scan_type": s["scan_type"],
                        "status": s["status"],
                        "created_at": s["created_at"].isoformat() if s["created_at"] else None,
                        "severity_counts": by_scan_sev.get(s["id"], {
                            "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}),
                    }
                    for s in scans[:10]
                ],
                "trend": trend[-20:],
                # spec §11's explicit real-data fields — every one queried
                # fresh here, none hardcoded or cached stale.
                "total_assets": total_assets,
                "monitored_assets": monitored_assets,
                "connectors_online": connectors_online,
                "connectors_offline": connectors_offline,
                "new_vulnerabilities": by_status.get("NEW", 0),
                "fixed_vulnerabilities": by_status.get("FIXED", 0),
                "reopened_vulnerabilities": by_status.get("REOPENED", 0),
                "open_remediation_tasks": open_remediation_tasks,
                "recent_alerts": recent_alerts,
            }
    finally:
        _put_conn(conn)


# --- observability: system health metrics (Phase 14, spec §22) -------------
def system_health_metrics(organization_id: int) -> Dict:
    """7-day scan reliability + alert delivery metrics for the admin
    dashboard's own 'system health' view (distinct from customer-facing
    findings) — every number computed fresh from real rows, never stored."""
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT status, started_at, finished_at FROM scans
                   WHERE organization_id = %s AND created_at > NOW() - INTERVAL '7 days'""",
                (organization_id,)
            )
            scans = cur.fetchall()
            total = len(scans)
            failed = sum(1 for s in scans if s["status"] == "error")
            durations = [(s["finished_at"] - s["started_at"]).total_seconds()
                        for s in scans if s.get("started_at") and s.get("finished_at")]

            cur.execute(
                """SELECT n.status AS notif_status, COUNT(*) AS cnt FROM notifications n
                   JOIN alerts a ON n.alert_id = a.id
                   WHERE a.organization_id = %s AND n.sent_at > NOW() - INTERVAL '7 days'
                   GROUP BY n.status""",
                (organization_id,)
            )
            notif_counts = {row["notif_status"]: row["cnt"] for row in cur.fetchall()}

            return {
                "scan_count_7d": total,
                "scan_failure_count_7d": failed,
                "scan_failure_rate_7d": round(failed / total, 4) if total else 0.0,
                "avg_scan_duration_seconds_7d": (
                    round(sum(durations) / len(durations), 1) if durations else None),
                "alert_deliveries_sent_7d": notif_counts.get("sent", 0),
                "alert_deliveries_failed_7d": notif_counts.get("failed", 0),
            }
    finally:
        _put_conn(conn)


# --- audit log ---------------------------------------------------------
def add_audit_log(user_id: Optional[int], action: str, target_id: Optional[int] = None,
                  scan_id: Optional[int] = None, details: Optional[Dict] = None,
                  organization_id: Optional[int] = None) -> None:
    """Add an entry to the audit log.

    organization_id is derived from user_id when not given explicitly.
    user_id may be None for events with no human actor (e.g. a connector's
    own signed job-result submission) — those callers MUST pass
    organization_id directly, since there's no user row to derive it from.
    """
    if user_id is None and organization_id is None:
        raise ValueError("add_audit_log requires organization_id when user_id is None")
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO audit_log(user_id, action, target_id, scan_id, details,
                                             organization_id)
                       VALUES(%s, %s, %s, %s, %s,
                              COALESCE(%s, (SELECT organization_id FROM users WHERE id = %s)))""",
                    (user_id, action, target_id, scan_id, Json(details) if details else None,
                     organization_id, user_id)
                )
    finally:
        _put_conn(conn)


def get_audit_log(organization_id: int, limit: int = 100, offset: int = 0) -> List[Dict]:
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # LEFT JOIN: user_id is nullable (Phase 12) for actor-less,
            # machine-generated events (e.g. a connector's own signed job
            # result) — an INNER JOIN would silently drop those rows.
            cur.execute(
                """SELECT al.*, u.username
                   FROM audit_log al
                   LEFT JOIN users u ON al.user_id = u.id
                   WHERE al.organization_id = %s
                   ORDER BY al.timestamp DESC
                   LIMIT %s OFFSET %s""",
                (organization_id, limit, offset)
            )
            rows = cur.fetchall()
            for row in rows:
                if row['timestamp']:
                    row['timestamp'] = row['timestamp'].isoformat()
            return rows
    finally:
        _put_conn(conn)