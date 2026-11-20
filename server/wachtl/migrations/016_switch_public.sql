-- 1.1: Gefundene Switches zuerst mit SNMPv2c „public“ abfragen (docs/TOPOLOGIE.md#switches-automatisch-finden).
-- Zeitpunkt des letzten Versuchs; antwortet der Switch, wird er mit diesen Zugangsdaten eingetragen.
ALTER TABLE net_switch_candidates ADD COLUMN public_tried BIGINT;
