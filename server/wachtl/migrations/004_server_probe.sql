-- 0.4: Server-Probe (der Wachtl-Server misst selbst) und Abmeldung von Probes bei der Deinstallation.

-- probe = Windows-Probe, server = eingebaute Server-Probe
ALTER TABLE probes ADD COLUMN kind TEXT NOT NULL DEFAULT 'probe';
-- Zeitpunkt der Abmeldung durch den Deinstaller (Token ist dann ungültig)
ALTER TABLE probes ADD COLUMN deregistered_at BIGINT;
