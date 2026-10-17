# API-Referenz

Alle Endpunkte laufen über HTTPS (Traefik). JSON in snake_case, Zeitstempel in Unix-Sekunden, Messwerte in Millisekunden-Zeitstempeln.

## Probe-API `/api/probe/v1`

Authentifizierung: `Authorization: Bearer <probe_id>.<secret>` (außer `enroll`).

| Methode | Pfad | Body | Antwort |
| --- | --- | --- | --- |
| POST | `/enroll` | `{"enrollment_token", "hostname", "os", "version"}` | 201 `{"probe_id", "token", "site_name"}` · 400 ungültig · 403 Token abgelaufen/verbraucht |
| GET | `/config` | Header `If-None-Match: "<etag>"` | 200 Konfiguration (siehe BETRIEB.md) · 304 unverändert |
| POST | `/ingest` | Prometheus-Text, optional `Content-Encoding: gzip`, Header `X-Batch-Id` | 204 gespeichert oder bereits bekannt · 422 alle Zeilen verworfen · 503 Speicher nicht erreichbar (Probe wiederholt) |
| POST | `/heartbeat` | `{"version", "os", "hostname", "buffer_items", "uptime_s"}` | 200 `{"config_etag", "server_time"}` |
| POST | `/deregister` | `{}` | 204 – Probe abgemeldet (Deinstallation): deaktiviert, Token ab sofort ungültig, offene Aufträge verworfen |
| POST | `/findings` | `{"findings": [{"finding_id", "kind", "severity", "state", "adapter", "adapter_description", "title", "message", "solution", "details", "detected_at", "resolved_at"}]}` (höchstens 50) | 200 `{"stored", "new", "rejected", "errors"}` – ungültige Einträge werden einzeln übersprungen · 400 `{"error"}` Körper unbrauchbar – Client-Hinweise der Probe, Details in CLIENT-HINWEISE.md |
| POST | `/report` | `{"report_id", "occurred_at", "category", "duration", "description", "user", "hostname"}` | 201 `{"id"}` neu · 200 `{"id"}` dieselbe `report_id` gab es schon · 400 `{"error"}` (deutsch) – Störungsmeldung vom Tray-Symbol, Details in STOERUNGSMELDUNGEN.md |

Fehler bei Authentifizierung: 401 (Token fehlt/falsch), 403 (Probe deaktiviert).

### Ingest-Format

```
wachtl_ping_up{check_id="2"} 1 1760620800000
wachtl_ping_rtt_ms{check_id="2"} 12.41 1760620800000
wachtl_ping_ttl{check_id="2"} 117 1760620800000
wachtl_ping_jitter_ms{check_id="2"} 1.8 1760620860000
```

Erlaubte Metriken: `wachtl_ping_up`, `wachtl_ping_rtt_ms`, `wachtl_ping_ttl`, `wachtl_ping_jitter_ms`. Der Server
übernimmt nur `check_id` (muss der Probe zugewiesen sein) und setzt `probe`, `probe_name`, `site`, `site_name`,
`check_id`, `target`, `role` selbst. Zeitstempel älter als 8 Tage oder mehr als 5 min in der Zukunft werden verworfen.

## Admin-API `/api/v1`

Authentifizierung über die Web-Sitzung; ändernde Aufrufe brauchen den Header `X-CSRF-Token` (Wert aus `<meta name="csrf-token">`).

| Methode | Pfad | Rolle | Antwort |
| --- | --- | --- | --- |
| GET | `/sites` | Nur lesen | Standorte |
| GET | `/probes` | Nur lesen | Probes inkl. `online`, `kind` (`probe` oder `server` = Server-Probe), `deregistered_at` |
| GET | `/checks` | Nur lesen | Checks |
| GET | `/check-status` | Nur lesen | `[{"probe_id", "hostname", "online", "check_id", "name", "type", "state", "detail", "ts"}]` – Zustand jeder Messung aller aktiven Probes; `state` = `ok`, `warn`, `down`, `stale` (keine Daten/überfällig) oder `waiting` |
| GET | `/status` | Nur lesen | `[{"probe", "check_id", "up", "rtt", "loss"}]` – letzter Zustand aller Ziele |
| GET | `/probes/{id}/checks/{id}/series?range=1h\|6h\|24h\|7d\|30d[&at=<unix>]` | Nur lesen | `{"source": "raw"\|"agg", "step_s", "start", "end", "series": {"avg", "min", "max", "loss": [[ts_ms, wert], …]}}` – `at` legt das Fenster mittig um diesen Zeitpunkt (z. B. eine Störungsmeldung), ohne `at` endet es jetzt |
| GET | `/probes/{id}/checks/{id}/stats` | Nur lesen | `{"1m"\|"5m"\|"15m"\|"1h"\|"24h": {"min", "median", "avg", "max", "jitter", "loss"}}` |
| GET | `/client-findings?days=7[&probe=<id>]` | Nur lesen | Client-Hinweise der Probes: aktive immer, behobene der letzten `days` Tage (1–400), aktive und schwere zuerst |
| GET | `/alerts?status=firing\|resolved` | Nur lesen | Alarme |
| POST | `/alerts/{id}/ack` | Operator | `{"hours": 4, "comment": "…"}` → `{"silence_id"}` |

Störungsmeldungen für die Graph-Markierungen (Pfad ohne `/v1`, wie im Vertrag STOERUNGSMELDUNGEN.md):

| Methode | Pfad | Rolle | Antwort |
| --- | --- | --- | --- |
| GET | `/api/reports?from=<unix>&to=<unix>[&probe_id=<id>][&site_id=<id>]` | Nur lesen | `{"reports": [{"id", "ts", "probe_id", "probe", "site", "category", "category_label", "duration_label", "description", "user", "status"}]}`, zeitlich aufsteigend; ohne `from`/`to` die letzten 24 h · 400 bei ungültigen Zahlen |

Web-UI: `/meldungen?status=open|done|all&site=<id>&probe=<id>&page=<n>`; `POST /meldungen/<id>/status` (`action=done|open`, `note`, CSRF, Operator) mit Audit-Eintrag `report.done` / `report.reopen`.

## Intern

| Methode | Pfad | Zweck |
| --- | --- | --- |
| POST | `/api/internal/alertmanager` | Webhook von Alertmanager (Bearer = `WACHTL_WEBHOOK_SECRET`), schreibt die Alarm-Historie. Linux: nur im Docker-Netz; Windows: nur auf 127.0.0.1:8427 |
| GET | `/healthz` | Healthcheck für Docker |

## Datenbankschema

Siehe `server/wachtl/migrations/001_initial.sql`. Neue Schemaversionen kommen als weitere nummerierte SQL-Datei
dazu und werden beim Start (`flask --app wachtl init`) automatisch eingespielt.
