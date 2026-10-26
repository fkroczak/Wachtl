-- 1.0: Switch-Topologie per SNMP (docs/TOPOLOGIE.md) – Switche mit Zugangsdaten, letzte Abfrage, Auffälligkeiten.

-- Ein verwalteter Switch je Standort. Zugangsdaten verschlüsselt (secretbox.py, Schlüssel aus WACHTL_SECRET_KEY).
CREATE TABLE net_switches (
    id              BIGSERIAL PRIMARY KEY,
    site_id         BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    name            TEXT,                  -- eigene Bezeichnung; leer = Name aus SNMP (sysName)
    host            TEXT NOT NULL,         -- IP-Adresse oder Hostname
    port            INTEGER NOT NULL DEFAULT 161,
    snmp_version    TEXT NOT NULL,         -- 1 | 2c | 3
    secret          TEXT NOT NULL,         -- verschlüsseltes JSON: Community bzw. v3-Benutzer und Passwörter
    location        TEXT,                  -- Ort im Gebäude (eigene Angabe)
    status          TEXT NOT NULL DEFAULT 'draft',   -- draft (Assistent noch nicht abgeschlossen) | active | disabled
    poll_requested  BIGINT,                -- „Jetzt abfragen“
    last_poll       BIGINT,
    last_ok         BIGINT,
    last_error      TEXT,
    sys_name        TEXT,
    sys_descr       TEXT,
    sys_object_id   TEXT,
    sys_location    TEXT,
    uptime_s        BIGINT,
    base_mac        TEXT,
    snapshot        TEXT,                  -- JSON der letzten erfolgreichen Abfrage (Ports, Nachbarn, MAC-Tabelle)
    created_at      BIGINT NOT NULL,
    updated_at      BIGINT NOT NULL,
    UNIQUE (site_id, host, port)
);
CREATE INDEX net_switches_site ON net_switches (site_id);

-- Neue Eingangsfehler je Port zwischen zwei Abfragen (nur wenn > 0)
CREATE TABLE net_port_errors (
    id              BIGSERIAL PRIMARY KEY,
    switch_id       BIGINT NOT NULL REFERENCES net_switches(id) ON DELETE CASCADE,
    if_index        INTEGER NOT NULL,
    ts              BIGINT NOT NULL,
    errors          BIGINT NOT NULL
);
CREATE INDEX net_port_errors_lookup ON net_port_errors (switch_id, ts);

-- Verlauf: Port gewechselt, Geschwindigkeit geändert, MAC-Adresse an anderem Port (Schleifenverdacht)
CREATE TABLE net_topo_events (
    id              BIGSERIAL PRIMARY KEY,
    site_id         BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    switch_id       BIGINT REFERENCES net_switches(id) ON DELETE CASCADE,
    ts              BIGINT NOT NULL,
    kind            TEXT NOT NULL,         -- speed_changed | mac_moved | link_down | link_up
    if_index        INTEGER,
    mac             TEXT,
    detail          TEXT
);
CREATE INDEX net_topo_events_site ON net_topo_events (site_id, ts);
CREATE INDEX net_topo_events_mac ON net_topo_events (switch_id, mac, ts);

-- Auffälligkeiten der Topologie; aktiv, solange last_seen zur letzten Auswertung gehört
CREATE TABLE net_topo_findings (
    id              BIGSERIAL PRIMARY KEY,
    site_id         BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    fkey            TEXT NOT NULL,         -- eindeutig je Befund, z. B. "errors:12:4"
    kind            TEXT NOT NULL,
    severity        TEXT NOT NULL,         -- critical | warning | info
    switch_id       BIGINT,
    if_index        INTEGER,
    title           TEXT NOT NULL,
    detail          TEXT,
    first_seen      BIGINT NOT NULL,
    last_seen       BIGINT NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    ack_by          TEXT,
    ack_at          BIGINT,
    UNIQUE (site_id, fkey)
);
CREATE INDEX net_topo_findings_site ON net_topo_findings (site_id, active);
