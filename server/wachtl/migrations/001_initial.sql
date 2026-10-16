-- Wachtl Grundschema. Zeitstempel = Unix-Sekunden, JSON = TEXT.
-- tenant_id ist für einen späteren Mehrkundenbetrieb reserviert (heute immer 1).

CREATE TABLE sites (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    INTEGER NOT NULL DEFAULT 1,
    name         TEXT NOT NULL UNIQUE,
    customer_no  TEXT,
    description  TEXT,
    created_at   BIGINT NOT NULL
);

CREATE TABLE probes (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     INTEGER NOT NULL DEFAULT 1,
    site_id       BIGINT NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    hostname      TEXT NOT NULL,
    os            TEXT,
    version       TEXT,
    token_hash    TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',      -- active | disabled
    created_at    BIGINT NOT NULL,
    last_seen     BIGINT,
    last_ip       TEXT,
    buffer_items  BIGINT,
    uptime_s      BIGINT,
    UNIQUE (site_id, hostname)
);

CREATE TABLE enrollment_tokens (
    id           BIGSERIAL PRIMARY KEY,
    site_id      BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    description  TEXT,
    expires_at   BIGINT NOT NULL,
    max_uses     INTEGER NOT NULL DEFAULT 1,
    uses         INTEGER NOT NULL DEFAULT 0,
    revoked      BOOLEAN NOT NULL DEFAULT FALSE,
    created_by   TEXT,
    created_at   BIGINT NOT NULL
);

CREATE TABLE checks (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    INTEGER NOT NULL DEFAULT 1,
    name         TEXT NOT NULL,
    type         TEXT NOT NULL DEFAULT 'ping',          -- ping (MVP); traceroute, dns, http, tcp, iperf folgen
    target       TEXT NOT NULL,                         -- IP, Hostname oder 'gateway'
    role         TEXT NOT NULL DEFAULT 'target',        -- gateway | reference | target
    interval_s   INTEGER NOT NULL DEFAULT 1,
    timeout_ms   INTEGER NOT NULL DEFAULT 1000,
    params       TEXT NOT NULL DEFAULT '{}',
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   BIGINT NOT NULL,
    updated_at   BIGINT NOT NULL
);

CREATE TABLE check_assignments (
    id        BIGSERIAL PRIMARY KEY,
    check_id  BIGINT NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
    scope     TEXT NOT NULL,                            -- all | site | probe
    scope_id  BIGINT,
    UNIQUE (check_id, scope, scope_id)
);

CREATE TABLE alert_rules (
    id          BIGSERIAL PRIMARY KEY,
    kind        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    threshold   DOUBLE PRECISION NOT NULL,
    window_s    INTEGER NOT NULL,
    for_s       INTEGER NOT NULL DEFAULT 0,
    severity    TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at  BIGINT NOT NULL
);

CREATE TABLE alert_events (
    id           BIGSERIAL PRIMARY KEY,
    fingerprint  TEXT NOT NULL,
    alertname    TEXT NOT NULL,
    severity     TEXT,
    status       TEXT NOT NULL,                         -- firing | resolved
    labels       TEXT NOT NULL,
    summary      TEXT,
    starts_at    BIGINT NOT NULL,
    ends_at      BIGINT,
    acked_by     TEXT,
    acked_at     BIGINT,
    silence_id   TEXT,
    updated_at   BIGINT NOT NULL,
    UNIQUE (fingerprint, starts_at)
);
CREATE INDEX alert_events_status_idx ON alert_events (status, starts_at);

CREATE TABLE users (
    id             BIGSERIAL PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL,                       -- admin | operator | readonly
    failed_logins  INTEGER NOT NULL DEFAULT 0,
    locked_until   BIGINT,
    created_at     BIGINT NOT NULL,
    last_login     BIGINT
);

CREATE TABLE audit_log (
    id        BIGSERIAL PRIMARY KEY,
    ts        BIGINT NOT NULL,
    username  TEXT,
    action    TEXT NOT NULL,
    object    TEXT,
    detail    TEXT
);
CREATE INDEX audit_log_ts_idx ON audit_log (ts);

CREATE TABLE ingest_batches (
    batch_id     TEXT PRIMARY KEY,
    probe_id     BIGINT NOT NULL,
    received_at  BIGINT NOT NULL
);
CREATE INDEX ingest_batches_received_idx ON ingest_batches (received_at);
