-- Einstellungen, die im Web-UI gepflegt werden (z. B. Benachrichtigungen).
CREATE TABLE settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  BIGINT NOT NULL
);
