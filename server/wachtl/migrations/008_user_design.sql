-- 0.9: Design je Benutzer (Benutzermenü → Design)
-- theme: system | light | dark – „system“ folgt der Einstellung des Betriebssystems
-- contrast: normal | high
ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'system';
ALTER TABLE users ADD COLUMN contrast TEXT NOT NULL DEFAULT 'normal';
