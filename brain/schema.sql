-- HydraBrain schema reference (Phase 12/13).
-- These CREATE statements are applied via webapp/db.py init_db() using
-- CREATE TABLE IF NOT EXISTS, so they are idempotent and safe to re-run.
-- This file is documentation only — do not run it directly.

CREATE TABLE IF NOT EXISTS brain_events (
    id          BIGSERIAL PRIMARY KEY,
    asset_id    INTEGER NOT NULL,
    org_id      INTEGER NOT NULL,
    ts          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    src_ip      TEXT,
    method      TEXT,
    path        TEXT,
    status      INTEGER,
    signals     JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_brain_events_asset ON brain_events(asset_id, org_id);
CREATE INDEX IF NOT EXISTS idx_brain_events_ts    ON brain_events(ts);

CREATE TABLE IF NOT EXISTS brain_incidents (
    id          BIGSERIAL PRIMARY KEY,
    asset_id    INTEGER NOT NULL,
    org_id      INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'medium',
    first_seen  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    state       TEXT NOT NULL DEFAULT 'open'
                    CHECK (state IN ('open','contained','remediated','closed')),
    finding_id  INTEGER,
    summary     TEXT
);

CREATE INDEX IF NOT EXISTS idx_brain_incidents_asset ON brain_incidents(asset_id, org_id);
CREATE INDEX IF NOT EXISTS idx_brain_incidents_fp    ON brain_incidents(fingerprint);

CREATE TABLE IF NOT EXISTS brain_actions (
    id              BIGSERIAL PRIMARY KEY,
    incident_id     BIGINT,
    asset_id        INTEGER NOT NULL,
    org_id          INTEGER NOT NULL,
    ts              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    type            TEXT NOT NULL,
    params          JSONB NOT NULL DEFAULT '{}',
    tier_at_time    TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'proposed'
                        CHECK (status IN ('proposed','approved','applied','rolled_back','failed')),
    approver        TEXT,
    rollback_token  TEXT
);

CREATE INDEX IF NOT EXISTS idx_brain_actions_incident ON brain_actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_brain_actions_asset    ON brain_actions(asset_id, org_id);

CREATE TABLE IF NOT EXISTS brain_knowledge (
    id                    BIGSERIAL PRIMARY KEY,
    asset_id              INTEGER NOT NULL,
    org_id                INTEGER NOT NULL,
    signature_fingerprint TEXT NOT NULL,
    attack_class          TEXT NOT NULL,
    recommended_action    JSONB NOT NULL DEFAULT '{}',
    remediation           JSONB NOT NULL DEFAULT '{}',
    confidence            NUMERIC(5,4) NOT NULL DEFAULT 0.5,
    times_seen            INTEGER NOT NULL DEFAULT 1,
    success_rate          NUMERIC(5,4) NOT NULL DEFAULT 0.0,
    updated_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (asset_id, org_id, signature_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_brain_knowledge_asset ON brain_knowledge(asset_id, org_id);
CREATE INDEX IF NOT EXISTS idx_brain_knowledge_fp    ON brain_knowledge(signature_fingerprint);
