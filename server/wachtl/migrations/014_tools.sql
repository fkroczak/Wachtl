-- 1.1: Werkzeuge (Ping, MTU, Traceroute, DNS, Port, HTTP(S), Zertifikat) als Einzeltest von einer Probe aus.
-- Das Web-UI legt einen Auftrag an, die gewählte Probe holt ihn ab, meldet Fortschritt und Ergebnis.
CREATE TABLE tool_jobs (
    id            BIGSERIAL PRIMARY KEY,
    probe_id      BIGINT NOT NULL REFERENCES probes(id) ON DELETE CASCADE,
    tool          TEXT NOT NULL,              -- ping | mtu | trace | dns | port | http | tls
    target        TEXT NOT NULL,              -- Host, Name oder Adresse (Anzeige)
    args          TEXT NOT NULL,              -- JSON, geprüft (services/tools.py)
    status        TEXT NOT NULL DEFAULT 'queued',  -- queued | running | ok | error
    progress      DOUBLE PRECISION,           -- 0..1, NULL = unbekannt
    step          TEXT,                       -- aktueller Schritt („Paket 3 von 10: 12,1 ms“)
    output        TEXT,                       -- Zeilen, wie sie bisher kamen
    result        TEXT,                       -- JSON: Zusammenfassung, Tabelle, Ausgabe
    error         TEXT,
    created_by    TEXT,
    created_at    BIGINT NOT NULL,
    started_at    BIGINT,
    updated_at    BIGINT,
    finished_at   BIGINT
);
CREATE INDEX tool_jobs_probe ON tool_jobs (probe_id, status, id);
CREATE INDEX tool_jobs_created ON tool_jobs (created_at);
