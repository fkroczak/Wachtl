-- 0.5: Störungsmeldungen von Benutzern (Tray-Symbol auf Clients und Server), siehe docs/STOERUNGSMELDUNGEN.md.
-- Wird eine Probe oder ein Standort gelöscht, bleiben die Meldungen erhalten (wie die Messdaten):
-- probe_id/site_id werden NULL, Hostname und Benutzer stehen weiter in der Meldung.

CREATE TABLE incident_reports (
    id             BIGSERIAL PRIMARY KEY,
    probe_id       BIGINT REFERENCES probes(id) ON DELETE SET NULL,
    site_id        BIGINT REFERENCES sites(id) ON DELETE SET NULL,   -- Standort der Probe beim Eingang
    report_id      TEXT NOT NULL,                  -- UUID der Probe, macht das Nachliefern idempotent
    occurred_at    BIGINT NOT NULL,                -- gemeldeter Zeitpunkt der Störung
    received_at    BIGINT NOT NULL,
    category       TEXT NOT NULL,                  -- no_connection | slow | dropouts | voice_video | application | other
    duration       TEXT NOT NULL DEFAULT 'unknown',-- unknown | short | minutes | long | ongoing
    description    TEXT,
    reported_user  TEXT,
    hostname       TEXT,
    status         TEXT NOT NULL DEFAULT 'open',   -- open | done
    done_by        TEXT,
    done_at        BIGINT,
    done_note      TEXT,
    UNIQUE (probe_id, report_id)
);
CREATE INDEX incident_reports_time_idx ON incident_reports (occurred_at);
CREATE INDEX incident_reports_probe_idx ON incident_reports (probe_id, occurred_at);
CREATE INDEX incident_reports_site_idx ON incident_reports (site_id, occurred_at);
CREATE INDEX incident_reports_status_idx ON incident_reports (status, occurred_at);
