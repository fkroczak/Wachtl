-- 1.0: Verlauf der Switch-Topologie (docs/TOPOLOGIE.md, Abschnitt „Verlauf“) – schnelle Port-Abfrage, Ereignisse,
-- Stände zum Zurückblättern.

-- Zeitpunkt der letzten vollständigen Abfrage (MAC-Tabelle, Nachbarn); last_poll gilt auch für die schnelle
ALTER TABLE net_switches ADD COLUMN last_full BIGINT;

-- Ereignisse: Stufe und Vorher/Nachher (JSON, z. B. {"from": "up", "to": "down"}) für Zeitleiste und Port-Verlauf
ALTER TABLE net_topo_events ADD COLUMN severity TEXT NOT NULL DEFAULT 'info';
ALTER TABLE net_topo_events ADD COLUMN data TEXT;
CREATE INDEX net_topo_events_port ON net_topo_events (switch_id, if_index, ts);

-- Gespeicherte Stände je Switch (nur wenn sich der Aufbau geändert hat, sonst einmal täglich), zlib + Base64
CREATE TABLE net_switch_history (
    id              BIGSERIAL PRIMARY KEY,
    switch_id       BIGINT NOT NULL REFERENCES net_switches(id) ON DELETE CASCADE,
    ts              BIGINT NOT NULL,
    hash            TEXT NOT NULL,
    snapshot        TEXT NOT NULL
);
CREATE INDEX net_switch_history_lookup ON net_switch_history (switch_id, ts);

-- Wo ein Gerät zuletzt gelernt wurde (je Switch): erkennt neue und umgesteckte Geräte
CREATE TABLE net_topo_macs (
    id              BIGSERIAL PRIMARY KEY,
    switch_id       BIGINT NOT NULL REFERENCES net_switches(id) ON DELETE CASCADE,
    mac             TEXT NOT NULL,
    if_index        INTEGER NOT NULL,
    first_seen      BIGINT NOT NULL,
    last_seen       BIGINT NOT NULL,
    UNIQUE (switch_id, mac)
);
