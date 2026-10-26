-- 1.1: Switches automatisch finden (docs/TOPOLOGIE.md#switches-automatisch-finden) und Switches ohne SNMP
-- über ihre Weboberfläche abfragen (TP-Link Easy Smart).

-- Zugangsart je Switch: snmp (Standard) | easysmart (Weboberfläche TP-Link Easy Smart, HTTP)
ALTER TABLE net_switches ADD COLUMN access TEXT NOT NULL DEFAULT 'snmp';
-- Woher der Eintrag stammt: manuell | erkannt (aus einem gefundenen Switch übernommen)
ALTER TABLE net_switches ADD COLUMN origin TEXT NOT NULL DEFAULT 'manuell';

-- Gefundene Switches je Standort: aus Netzwerkscan (Hersteller der MAC, Weboberfläche), LLDP/CDP der
-- verwalteten Switches und dem Rundruf der Server-Probe (TP-Link Easy Smart, Netgear ProSAFE Plus).
-- Eindeutig über die MAC, ohne MAC über die IP (cand_key = "mac:…" bzw. "ip:…").
CREATE TABLE net_switch_candidates (
    id              BIGSERIAL PRIMARY KEY,
    site_id         BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    cand_key        TEXT NOT NULL,
    mac             TEXT,
    ip              TEXT,
    vendor          TEXT,                  -- z. B. TP-Link, D-Link, Zyxel, Netgear, Aruba
    model           TEXT,                  -- falls bekannt (Rundruf, LLDP, Titel der Weboberfläche)
    name            TEXT,                  -- Name, den der Switch selbst meldet
    firmware        TEXT,
    access          TEXT NOT NULL,         -- snmp | easysmart | none (Switch ohne Abfragemöglichkeit)
    sources         TEXT NOT NULL,         -- JSON-Liste: oui | web | lldp | cdp | easysmart | nsdp
    confidence      INTEGER NOT NULL,      -- 0..100: wie sicher es ein Switch ist
    state           TEXT NOT NULL DEFAULT 'new',   -- new (Zugangsdaten fehlen) | added | ignored
    switch_id       BIGINT REFERENCES net_switches(id) ON DELETE SET NULL,
    first_seen      BIGINT NOT NULL,
    last_seen       BIGINT NOT NULL,
    UNIQUE (site_id, cand_key)
);
CREATE INDEX net_switch_candidates_site ON net_switch_candidates (site_id, state);
