# Entscheidungsprotokoll Audit 2026-10-21

Branch `audit/2026-10-21` (von `main`-Stand `9f379db`). Jede Entscheidung einzeln rücknehmbar.
Komplett verwerfen: Branch löschen, `main` ist unberührt.

## E-01 · 02:50 · Arbeitsgrundlage
- **Anlass:** Auftrag nennt Rollen „Betrachter/Bearbeiter/Admin“, Kundenzugang-Schalter, Grafana, PWA, Farbschema „Zink“, noindex. Der Code hat Rollen `readonly`/`operator`/`admin` („Nur lesen“/„Operator“/„Administrator“), kein Grafana, keinen Kundenzugang, kein PWA-Manifest, kein noindex.
- **Optionen:** (a) fehlende Features nachbauen; (b) Code-Stand als Wahrheit nehmen, Abweichungen dokumentieren.
- **Gewählt:** (b) – Auftrag sagt „Funktionen bleiben unverändert“, YAGNI. Abweichungen stehen im Bericht unter „Offene Risiken“. **PRÜFEN**
- **Dateien:** keine · **Commit:** – · **Risiko:** niedrig · **Rückbau:** –

## E-02 · 02:55 · Screenshot-Skript und Vorher-Bilder
- **Anlass:** Vorher/Nachher-Vergleich gefordert.
- **Optionen:** (a) manuell; (b) kleines Skript auf Basis der vorhandenen Playwright-Seitenliste `e2e/pages.js`.
- **Gewählt:** (b), 30 Zeilen, keine neue Abhängigkeit.
- **Dateien:** `server/e2e/screens.js`, `docs/audit/screens/vorher/*`
- **Commit:** siehe `git log --grep E-02` · **Risiko:** niedrig · **Rückbau:** `git revert <hash>`

## E-03 · 03:15 · noindex fehlte
- **Anlass:** Vorgabe „keine Indexierung (noindex beibehalten)“ – im Code gab es weder Meta-Tag noch Header.
- **Optionen:** (a) `<meta name="robots">` in `base.html`; (b) Header `X-Robots-Tag` für alle Antworten; (c) `robots.txt`-Route.
- **Gewählt:** (b) – eine Zeile, deckt auch Login, Downloads und statische Dateien ab. Folge: Lighthouse-SEO meldet „is-crawlable“ (in `lighthouserc.cjs` nur Warnung) – gewollt. **PRÜFEN**
- **Dateien:** `server/wachtl/__init__.py`, `server/tests/test_web.py`
- **Commit:** `9766c16` · **Risiko:** niedrig · **Rückbau:** `git revert 9766c16`

## E-04 · 03:25 · Login-CSRF und 500 bei Nicht-ASCII-Token
- **Anlass:** `/login` verglich `form.csrf_token != session.csrf`; ohne Sitzung ist beides `None` → fremde Seite kann Opfer in ein Angreiferkonto einloggen. `hmac.compare_digest` warf bei „ä“ im Token TypeError (500, ohne Anmeldung erreichbar).
- **Optionen:** (a) Login separat flicken; (b) eine Funktion `csrf_ok()` für beide Stellen, Vergleich als Bytes.
- **Gewählt:** (b).
- **Dateien:** `server/wachtl/security.py`, `server/wachtl/web.py`, `server/tests/test_web.py`
- **Commit:** `2468168` · **Risiko:** niedrig · **Rückbau:** `git revert 2468168`

## E-05 · 03:40 · Sitzungen überlebten Passwortwechsel  — PRÜFEN
- **Anlass:** Cookie-Sitzung prüfte nur die Benutzer-ID. Nach „Passwort zurücksetzen“ (Admin) oder eigenem Wechsel blieben alte/gestohlene Sitzungen bis 12 h (gleitend) gültig.
- **Optionen:** (a) Spalte `session_gen` + Migration; (b) Kennung aus dem Passwort-Hash (`sha256(hash)[:16]`) in der Sitzung, ohne Schemaänderung.
- **Gewählt:** (b) – keine Migration. Eigene Sitzung bleibt beim eigenen Wechsel erhalten.
- **Folge beim Einspielen:** Alle bestehenden Sitzungen enden einmalig (Benutzer melden sich neu an). Login-Sperre unverändert.
- **Dateien:** `server/wachtl/security.py`, `server/wachtl/web.py`, `server/tests/test_web.py`
- **Commit:** `7325ae3` · **Risiko:** mittel (Anmeldung) · **Rückbau:** `git revert 7325ae3`

## E-06 · 03:55 · 500 bei ungültigen Zahlen
- **Anlass:** `int(...)` ohne Fehlerbehandlung: Alarm bestätigen (`hours`), Token anlegen (`site_id`, `days`, `max_uses`), Standardpaket (`site_id`), API `since`, API-Bestätigen (`hours` als Liste) und Probe-Token `Bearer ².x` (ohne Anmeldung) → 500.
- **Optionen:** (a) globaler Handler für ValueError (verdeckt echte Fehler); (b) Flasks `get(..., type=int)` an den Stellen.
- **Gewählt:** (b). Heartbeat der Probe (`buffer_items`) bewusst **nicht** angefasst (Probe-Ingest, echte Probes senden Zahlen).
- **Randfall:** API `?since=` (leer) bedeutet jetzt „Standard 30 Tage“ statt „seit 0“.
- **Dateien:** `server/wachtl/web.py`, `server/wachtl/api_admin.py`, `server/wachtl/security.py`, `server/tests/test_web.py`
- **Commit:** `a0ad35a` · **Risiko:** niedrig · **Rückbau:** `git revert a0ad35a`
