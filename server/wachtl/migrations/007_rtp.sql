-- 0.9: Sprachtest (RTP/VoIP) – ein Eintrag je Test mit Werten je Richtung und MOS.

CREATE TABLE rtp_runs (
    id              BIGSERIAL PRIMARY KEY,
    probe_id        BIGINT NOT NULL,
    check_id        BIGINT NOT NULL,
    ts              BIGINT NOT NULL,
    peer            TEXT,
    codec           TEXT,
    ptime_ms        INTEGER,
    duration_s      DOUBLE PRECISION,
    mode            TEXT,                  -- wachtl (Werte je Richtung) | echo (nur Hin- und Rückweg)
    sent            INTEGER,
    received        INTEGER,
    rtt_ms          DOUBLE PRECISION,      -- Mittel Hin- und Rückweg
    rtt_max_ms      DOUBLE PRECISION,
    loss_pct        DOUBLE PRECISION,      -- Hin- und Rückweg zusammen
    up_loss_pct     DOUBLE PRECISION,      -- Probe -> Gegenstelle
    down_loss_pct   DOUBLE PRECISION,      -- Gegenstelle -> Probe
    jitter_ms       DOUBLE PRECISION,      -- schlechtere Richtung
    up_jitter_ms    DOUBLE PRECISION,
    down_jitter_ms  DOUBLE PRECISION,
    out_of_order    INTEGER,
    r_factor        DOUBLE PRECISION,
    mos             DOUBLE PRECISION,
    trigger         TEXT,                  -- schedule | manual
    error           TEXT
);
CREATE INDEX rtp_runs_lookup ON rtp_runs (probe_id, check_id, ts);
