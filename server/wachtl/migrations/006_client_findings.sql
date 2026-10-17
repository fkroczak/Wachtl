-- 0.7: Kurzausfälle ab 5 s und Client-Hinweise der Probes (Netzwerkkarte, Kabel, Treiber).

-- Ausfälle werden ab einer Mindestdauer in Sekunden erkannt statt nach „N Fehlern in Folge“ bzw. 30 s.
-- Nur die alten Standardwerte werden angepasst, eigene Werte bleiben.
UPDATE alert_rules SET name = 'Ziel nicht erreichbar ab (Sekunden ohne Antwort)',
    threshold = CASE WHEN threshold = 3 THEN 5 ELSE threshold END
    WHERE kind = 'target_down';
UPDATE alert_rules SET name = 'Alle Internet-Referenzen gestört ab (Sekunden)',
    threshold = CASE WHEN threshold = 30 THEN 5 ELSE threshold END
    WHERE kind = 'wan_down';

-- Sekundengenauer Beginn und Ende eines Ausfalls aus den 1-s-Rohdaten (NULL = noch nicht nachgerechnet)
ALTER TABLE alert_events ADD COLUMN exact_start BIGINT;
ALTER TABLE alert_events ADD COLUMN exact_end BIGINT;
ALTER TABLE alert_events ADD COLUMN refined_at BIGINT;

-- Hinweise, die eine Probe auf ihrem PC erkennt (Kabel getrennt, Link-Geschwindigkeit, Treiber …)
CREATE TABLE client_findings (
    id                   BIGSERIAL PRIMARY KEY,
    probe_id             BIGINT NOT NULL REFERENCES probes(id) ON DELETE CASCADE,
    site_id              BIGINT REFERENCES sites(id) ON DELETE SET NULL,
    finding_id           TEXT NOT NULL,          -- ID der Probe je Vorkommen, macht Nachliefern idempotent
    kind                 TEXT NOT NULL,          -- cable_unplugged | link_speed_changed | driver_error | …
    severity             TEXT NOT NULL,          -- info | warning | critical
    state                TEXT NOT NULL,          -- active | resolved
    adapter              TEXT,
    adapter_description  TEXT,
    title                TEXT NOT NULL,
    message              TEXT,
    solution             TEXT,
    details              TEXT,                   -- JSON-Objekt
    detected_at          BIGINT NOT NULL,
    resolved_at          BIGINT,
    received_at          BIGINT NOT NULL,
    updated_at           BIGINT NOT NULL,
    UNIQUE (probe_id, finding_id)
);
CREATE INDEX client_findings_probe_idx ON client_findings (probe_id, detected_at);
CREATE INDEX client_findings_state_idx ON client_findings (state, detected_at);
