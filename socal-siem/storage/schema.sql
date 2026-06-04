-- ============================================================
-- SOCal SIEM - Database Schema
-- Compatible with TimescaleDB (PostgreSQL) and SQLite
-- ============================================================

-- Hot logs table (hypertable in TimescaleDB)
CREATE TABLE IF NOT EXISTS logs (
    id          BIGSERIAL,
    time        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source      TEXT,
    hostname    TEXT,
    message     TEXT,
    raw         JSONB,
    template    TEXT,
    template_id INTEGER,
    severity    TEXT,
    process_pid INTEGER,
    user_uid    TEXT,
    event_type  TEXT,
    tags        TEXT[],
    network_src TEXT,
    network_dst TEXT,
    extra_data  JSONB
);

-- Create hypertable (TimescaleDB specific)
SELECT create_hypertable('logs', 'time', if_not_exists => TRUE);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_logs_time ON logs (time DESC);
CREATE INDEX IF NOT EXISTS idx_logs_source ON logs (source);
CREATE INDEX IF NOT EXISTS idx_logs_hostname ON logs (hostname);
CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs (severity);

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id              SERIAL PRIMARY KEY,
    rule_id         TEXT,
    rule_name       TEXT,
    severity        TEXT,
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    timestamp       TIMESTAMPTZ,
    event_timestamp TIMESTAMPTZ,
    hostname        TEXT,
    source          TEXT,
    message         TEXT,
    raw             TEXT,
    tags            TEXT[],
    correlation_count INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'open',
    alert_data      JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);

-- Investigations table
CREATE TABLE IF NOT EXISTS investigations (
    id          SERIAL PRIMARY KEY,
    alert_id    INTEGER REFERENCES alerts(id),
    alert_rule  TEXT,
    severity    TEXT,
    hostname    TEXT,
    report_text TEXT,
    iocs        JSONB,
    confidence  TEXT,
    mitre_map   JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- MITRE ATT&CK cache
CREATE TABLE IF NOT EXISTS mitre_attack (
    id          TEXT PRIMARY KEY,
    type        TEXT,
    name        TEXT,
    description TEXT,
    matrix      TEXT,
    tactics     TEXT[],
    techniques  JSONB
);

-- Host inventory
CREATE TABLE IF NOT EXISTS inventory (
    hostname    TEXT PRIMARY KEY,
    ip          TEXT,
    os          TEXT,
    criticality TEXT,
    services    JSONB,
    last_seen   TIMESTAMPTZ DEFAULT NOW()
);

-- ML model metadata
CREATE TABLE IF NOT EXISTS ml_models (
    id          SERIAL PRIMARY KEY,
    model_type  TEXT,
    trained_at  TIMESTAMPTZ DEFAULT NOW(),
    samples     INTEGER,
    metrics     JSONB,
    active      BOOLEAN DEFAULT TRUE
);

-- Dashboard sessions
CREATE TABLE IF NOT EXISTS dash_sessions (
    id          TEXT PRIMARY KEY,
    user_name   TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    last_active TIMESTAMPTZ DEFAULT NOW()
);
