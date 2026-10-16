-- 0.3: Pfadanalyse (Traceroute + Hop-Pings), Bandbreite (iperf3, WAN-Speedtest), Befehle an Probes.

-- Probe als iperf3-Gegenstelle und ihre lokalen Adressen (vom Heartbeat)
ALTER TABLE probes ADD COLUMN iperf_server BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE probes ADD COLUMN iperf_port INTEGER NOT NULL DEFAULT 5201;
ALTER TABLE probes ADD COLUMN iperf_address TEXT;
ALTER TABLE probes ADD COLUMN addresses TEXT;

-- ermittelte Pfade; ein Eintrag je Pfad, solange er gleich bleibt (first_ts .. ts)
CREATE TABLE path_runs (
    id         BIGSERIAL PRIMARY KEY,
    probe_id   BIGINT NOT NULL,
    check_id   BIGINT NOT NULL,
    first_ts   BIGINT NOT NULL,
    ts         BIGINT NOT NULL,
    reason     TEXT,
    reached    BOOLEAN NOT NULL DEFAULT FALSE,
    hops       TEXT NOT NULL,           -- JSON [{"hop":1,"ip":"…","rtt_ms":0.4}, {"hop":2,"ip":null}]
    path_hash  TEXT NOT NULL,
    changed    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX path_runs_lookup ON path_runs (probe_id, check_id, ts);

-- Bandbreitenmessungen (iperf3 und HTTP-Speedtest)
CREATE TABLE bandwidth_runs (
    id           BIGSERIAL PRIMARY KEY,
    probe_id     BIGINT NOT NULL,
    check_id     BIGINT NOT NULL,
    ts           BIGINT NOT NULL,
    kind         TEXT NOT NULL,         -- iperf | speedtest
    direction    TEXT NOT NULL,         -- up | down
    peer         TEXT,
    protocol     TEXT,
    mbps         DOUBLE PRECISION,
    jitter_ms    DOUBLE PRECISION,
    loss_pct     DOUBLE PRECISION,
    retransmits  BIGINT,
    latency_ms   DOUBLE PRECISION,
    duration_s   DOUBLE PRECISION,
    trigger      TEXT,                  -- schedule | manual
    error        TEXT
);
CREATE INDEX bandwidth_runs_lookup ON bandwidth_runs (probe_id, check_id, ts);

-- Aufträge an Probes ("Jetzt messen"), ausgeliefert mit dem nächsten Heartbeat
CREATE TABLE probe_commands (
    id            BIGSERIAL PRIMARY KEY,
    probe_id      BIGINT NOT NULL,
    type          TEXT NOT NULL,
    check_id      BIGINT,
    created_by    TEXT,
    created_at    BIGINT NOT NULL,
    delivered_at  BIGINT
);
CREATE INDEX probe_commands_pending ON probe_commands (probe_id, delivered_at);
