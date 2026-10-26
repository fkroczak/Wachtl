-- 1.0: Störungen direkt aus den 1-s-Rohdaten beim Eingang erkennen – auch nachgelieferte (PC ohne Netz puffert
-- und lädt später hoch) und jeden einzelnen verlorenen Ping.

-- Stand der Auswertung je Probe und Ping-Check (Zeitstempel in ms wie die Messwerte)
CREATE TABLE ping_tracks (
    probe_id      BIGINT NOT NULL,
    check_id      BIGINT NOT NULL,
    last_ts       BIGINT NOT NULL,          -- letzter ausgewerteter Ping
    fail_start    BIGINT,                   -- erster Fehlschlag der laufenden Serie, NULL = letzter Ping ok
    fail_last     BIGINT,
    fail_n        INTEGER NOT NULL DEFAULT 0,
    down_id       BIGINT,                   -- offener Ausfall
    loss_id       BIGINT,                   -- offene Verlust-Störung
    loss_last     BIGINT,                   -- letzter verlorener Ping der offenen Verlust-Störung
    loss_lost     INTEGER NOT NULL DEFAULT 0,
    loss_sent     INTEGER NOT NULL DEFAULT 0,
    loss_sent_at  INTEGER NOT NULL DEFAULT 0, -- gesendete Pings bis zum letzten Verlust
    PRIMARY KEY (probe_id, check_id)
);

-- Erkannte Störungen: down = Ziel antwortet nicht, wan = alle Internet-Referenzen zugleich, loss = einzelne Pings verloren
CREATE TABLE disturbances (
    id            BIGSERIAL PRIMARY KEY,
    probe_id      BIGINT NOT NULL,
    site_id       BIGINT,
    check_id      BIGINT,                   -- NULL bei wan
    kind          TEXT NOT NULL,
    role          TEXT,
    target        TEXT,
    check_name    TEXT,
    start_ts      BIGINT NOT NULL,          -- Unix-Sekunden
    end_ts        BIGINT,                   -- NULL = dauert an
    lost          INTEGER,
    sent          INTEGER,
    detected_at   BIGINT NOT NULL,
    late          BOOLEAN NOT NULL DEFAULT FALSE,  -- erst mit nachgelieferten Werten erkannt
    posted_at     BIGINT,                   -- zuletzt an Alertmanager gemeldet
    posted_state  TEXT,                     -- firing | resolved
    updated_at    BIGINT NOT NULL
);
CREATE INDEX disturbances_time_idx ON disturbances (start_ts);
CREATE INDEX disturbances_probe_idx ON disturbances (probe_id, kind, start_ts);
-- Meldung an Alertmanager: offene (NULL) und laufende (firing) schnell finden
CREATE INDEX disturbances_post_idx ON disturbances (posted_state);
