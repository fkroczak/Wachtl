-- 1.0: Netzwerkscan – Geräte im Kundennetz, ihre Anwesenheit und offene Dienste (docs/NETZWERKSCAN.md).

-- Ein Eintrag je Scan einer Probe
CREATE TABLE netscan_runs (
    id              BIGSERIAL PRIMARY KEY,
    probe_id        BIGINT NOT NULL REFERENCES probes(id) ON DELETE CASCADE,
    check_id        BIGINT NOT NULL,
    site_id         BIGINT NOT NULL,
    ts              BIGINT NOT NULL,
    duration_s      DOUBLE PRECISION,
    subnets         TEXT,                  -- JSON-Liste der gescannten Netze
    hosts_found     INTEGER NOT NULL DEFAULT 0,
    trigger         TEXT,                  -- schedule | manual
    error           TEXT
);
CREATE INDEX netscan_runs_lookup ON netscan_runs (site_id, ts);
CREATE INDEX netscan_runs_check ON netscan_runs (probe_id, check_id, ts);

-- Gerät je Standort: eindeutig über die MAC, ohne MAC über die IP (dev_key = "mac:…" bzw. "ip:…")
CREATE TABLE net_devices (
    id              BIGSERIAL PRIMARY KEY,
    site_id         BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    dev_key         TEXT NOT NULL,
    mac             TEXT,
    ip              TEXT,                  -- zuletzt gesehene Adresse
    hostname        TEXT,
    vendor          TEXT,
    is_probe        BOOLEAN NOT NULL DEFAULT FALSE,
    rtt_ms          DOUBLE PRECISION,
    first_seen      BIGINT NOT NULL,
    last_seen       BIGINT NOT NULL,
    last_run_id     BIGINT,
    ip_changes      INTEGER NOT NULL DEFAULT 0,
    note            TEXT,                  -- eigene Bezeichnung im Web-UI
    UNIQUE (site_id, dev_key)
);
CREATE INDEX net_devices_seen ON net_devices (site_id, last_seen);

-- Anwesenheit: zusammenhängende Zeiträume, in denen ein Gerät bei aufeinanderfolgenden Scans gesehen wurde
CREATE TABLE net_presence (
    id              BIGSERIAL PRIMARY KEY,
    device_id       BIGINT NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    probe_id        BIGINT NOT NULL,
    check_id        BIGINT NOT NULL,
    first_ts        BIGINT NOT NULL,
    last_ts         BIGINT NOT NULL,
    last_run_id     BIGINT NOT NULL,
    ip              TEXT
);
CREATE INDEX net_presence_device ON net_presence (device_id, last_ts);

-- Offene Ports und erkannte Dienste je Gerät
CREATE TABLE net_services (
    id              BIGSERIAL PRIMARY KEY,
    device_id       BIGINT NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    port            INTEGER NOT NULL,
    service         TEXT NOT NULL,
    tls             BOOLEAN NOT NULL DEFAULT FALSE,
    banner          TEXT,
    http_status     INTEGER,
    http_server     TEXT,
    http_title      TEXT,
    tls_subject     TEXT,
    first_seen      BIGINT NOT NULL,
    last_seen       BIGINT NOT NULL,
    UNIQUE (device_id, port)
);

-- Auffälligkeiten aus den Scans: IP-Konflikt, unregelmäßiges Gerät, neues Gerät
CREATE TABLE net_events (
    id              BIGSERIAL PRIMARY KEY,
    site_id         BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    device_id       BIGINT REFERENCES net_devices(id) ON DELETE CASCADE,
    run_id          BIGINT,
    ts              BIGINT NOT NULL,
    kind            TEXT NOT NULL,         -- ip_conflict | ip_changed | new_device | device_back | device_gone
    ip              TEXT,
    detail          TEXT
);
CREATE INDEX net_events_site ON net_events (site_id, ts);
