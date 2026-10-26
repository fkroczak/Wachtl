-- 1.1: Gateways automatisch erkennen (docs/TOPOLOGIE.md#gateway-automatisch-erkennen) und als Wurzel des Baums zeigen.

-- Default-Gateway, das jede Probe selbst sieht (Heartbeat), mit MAC aus ihrer ARP-Tabelle
ALTER TABLE probes ADD COLUMN gateway TEXT;
ALTER TABLE probes ADD COLUMN gateway_mac TEXT;

-- Was die Server-Probe über ihr Gateway herausgefunden hat: Weboberfläche (Titel, Server, Zertifikat), UPnP/TR-064
CREATE TABLE net_gateway_info (
    id            BIGSERIAL PRIMARY KEY,
    site_id       BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    ip            TEXT NOT NULL,
    mac           TEXT,
    data          TEXT NOT NULL,          -- JSON: services [{port, http_title, http_server, tls_subject, tls}], upnp {…}
    ts            BIGINT NOT NULL,
    UNIQUE (site_id, ip)
);
