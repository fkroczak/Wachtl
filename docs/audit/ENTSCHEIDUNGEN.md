# Entscheidungsprotokoll Audit 2026-10-21

Branch `audit/2026-10-21` (von `main`-Stand `9f379db`). Jede Entscheidung einzeln rücknehmbar.
Uhrzeiten = Commit-Zeit (Europe/Berlin).
Komplett verwerfen: Branch löschen, `main` ist unberührt.

## E-01 · 02:47 · Arbeitsgrundlage
- **Anlass:** Auftrag nennt Rollen „Betrachter/Bearbeiter/Admin“, Kundenzugang-Schalter, Grafana, PWA, Farbschema „Zink“, noindex. Der Code hat Rollen `readonly`/`operator`/`admin` („Nur lesen“/„Operator“/„Administrator“), kein Grafana, keinen Kundenzugang, kein PWA-Manifest, kein noindex.
- **Optionen:** (a) fehlende Features nachbauen; (b) Code-Stand als Wahrheit nehmen, Abweichungen dokumentieren.
- **Gewählt:** (b) – Auftrag sagt „Funktionen bleiben unverändert“, YAGNI. Abweichungen stehen im Bericht unter „Offene Risiken“. **PRÜFEN**
- **Dateien:** keine · **Commit:** – · **Risiko:** niedrig · **Rückbau:** –

## E-02 · 02:53 · Screenshot-Skript und Vorher-Bilder
- **Anlass:** Vorher/Nachher-Vergleich gefordert.
- **Optionen:** (a) manuell; (b) kleines Skript auf Basis der vorhandenen Playwright-Seitenliste `e2e/pages.js`.
- **Gewählt:** (b), 30 Zeilen, keine neue Abhängigkeit.
- **Dateien:** `server/e2e/screens.js`, `docs/audit/screens/vorher/*`
- **Commit:** siehe `git log --grep E-02` · **Risiko:** niedrig · **Rückbau:** `git revert <hash>`

## E-03 · 02:53 · noindex fehlte
- **Anlass:** Vorgabe „keine Indexierung (noindex beibehalten)“ – im Code gab es weder Meta-Tag noch Header.
- **Optionen:** (a) `<meta name="robots">` in `base.html`; (b) Header `X-Robots-Tag` für alle Antworten; (c) `robots.txt`-Route.
- **Gewählt:** (b) – eine Zeile, deckt auch Login, Downloads und statische Dateien ab. Folge: Lighthouse-SEO meldet „is-crawlable“ (in `lighthouserc.cjs` nur Warnung) – gewollt. **PRÜFEN**
- **Dateien:** `server/wachtl/__init__.py`, `server/tests/test_web.py`
- **Commit:** `9766c16` · **Risiko:** niedrig · **Rückbau:** `git revert 9766c16`

## E-04 · 02:55 · Login-CSRF und 500 bei Nicht-ASCII-Token
- **Anlass:** `/login` verglich `form.csrf_token != session.csrf`; ohne Sitzung ist beides `None` → fremde Seite kann Opfer in ein Angreiferkonto einloggen. `hmac.compare_digest` warf bei „ä“ im Token TypeError (500, ohne Anmeldung erreichbar).
- **Optionen:** (a) Login separat flicken; (b) eine Funktion `csrf_ok()` für beide Stellen, Vergleich als Bytes.
- **Gewählt:** (b).
- **Dateien:** `server/wachtl/security.py`, `server/wachtl/web.py`, `server/tests/test_web.py`
- **Commit:** `2468168` · **Risiko:** niedrig · **Rückbau:** `git revert 2468168`

## E-05 · 02:58 · Sitzungen überlebten Passwortwechsel  — PRÜFEN
- **Anlass:** Cookie-Sitzung prüfte nur die Benutzer-ID. Nach „Passwort zurücksetzen“ (Admin) oder eigenem Wechsel blieben alte/gestohlene Sitzungen bis 12 h (gleitend) gültig.
- **Optionen:** (a) Spalte `session_gen` + Migration; (b) Kennung aus dem Passwort-Hash (`sha256(hash)[:16]`) in der Sitzung, ohne Schemaänderung.
- **Gewählt:** (b) – keine Migration. Eigene Sitzung bleibt beim eigenen Wechsel erhalten.
- **Folge beim Einspielen:** Alle bestehenden Sitzungen enden einmalig (Benutzer melden sich neu an). Login-Sperre unverändert.
- **Dateien:** `server/wachtl/security.py`, `server/wachtl/web.py`, `server/tests/test_web.py`
- **Commit:** `7325ae3` · **Risiko:** mittel (Anmeldung) · **Rückbau:** `git revert 7325ae3`

## E-06 · 03:00 · 500 bei ungültigen Zahlen
- **Anlass:** `int(...)` ohne Fehlerbehandlung: Alarm bestätigen (`hours`), Token anlegen (`site_id`, `days`, `max_uses`), Standardpaket (`site_id`), API `since`, API-Bestätigen (`hours` als Liste) und Probe-Token `Bearer ².x` (ohne Anmeldung) → 500.
- **Optionen:** (a) globaler Handler für ValueError (verdeckt echte Fehler); (b) Flasks `get(..., type=int)` an den Stellen.
- **Gewählt:** (b). Heartbeat der Probe (`buffer_items`) bewusst **nicht** angefasst (Probe-Ingest, echte Probes senden Zahlen).
- **Randfall:** API `?since=` (leer) bedeutet jetzt „Standard 30 Tage“ statt „seit 0“.
- **Dateien:** `server/wachtl/web.py`, `server/wachtl/api_admin.py`, `server/wachtl/security.py`, `server/tests/test_web.py`
- **Commit:** `a0ad35a` · **Risiko:** niedrig · **Rückbau:** `git revert a0ad35a`

## E-07 · 03:01 · Deaktivierte Probe per Neu-Registrierung reaktivierbar — PRÜFEN
- **Anlass:** `enroll` setzte bei gleichem Standort+Hostname immer `status='active'`. Wer einen gültigen Registrierungs-Token hat (steckt im verteilten Setup, bis 500 Nutzungen/90 Tage), hob die Admin-Sperre auf. Das UI verspricht „ihr Token wird abgelehnt“.
- **Optionen:** (a) nichts tun, dokumentieren; (b) Neu-Registrierung nur für vom Admin deaktivierte Probes ablehnen (403 mit Hinweis); (c) zusätzlich Übernahme aktiver Probes verhindern.
- **Gewählt:** (b). Deinstallierte Probes (`deregistered_at`) dürfen weiter neu installiert werden. (c) ändert den vorgesehenen Ablauf „PC neu aufsetzen“ → nur als Finding.
- **Folge:** Neuinstallation auf einem im Web-UI deaktivierten PC scheitert mit „Probe ist im Web-UI deaktiviert – dort zuerst aktivieren“. Probe-Code und Messbetrieb unberührt.
- **Dateien:** `server/wachtl/api_probe.py`, `server/tests/test_probe_api.py`
- **Commit:** `a65207c` · **Risiko:** mittel · **Rückbau:** `git revert a65207c`

## E-08 · 03:04 · Offline-Alarm für deaktivierte/deinstallierte Probes — PRÜFEN
- **Anlass:** Regel `WachtlProbeOffline` filterte nicht nach Status → nach Deaktivieren/Deinstallieren bis 24 h kritischer Alarm (E-Mail/Teams alle 4 h) und ein Eintrag in „Ausfälle“.
- **Optionen:** (a) Positivliste aktiver Probes (neue Probe ohne Regel-Neuschreiben hätte **keinen** Offline-Alarm – gefährlich); (b) Ausschlussliste `probe!~"…"` nicht-aktiver Probes.
- **Gewählt:** (b) – Fehlerrichtung bleibt „Alarm zu viel“, nie „Alarm fehlt“. Regeln werden bei Aktivieren/Deaktivieren, Abmeldung und Wieder-Registrierung neu geschrieben; ein Fehler dabei bricht Registrierung/Abmeldung nicht ab.
- **Shortcut:** gelöschte Probes alarmieren weiter bis 24 h (ID nicht mehr in der DB). Hartkodiertes `[24h]` statt `window_s` unverändert gelassen.
- **Dateien:** `server/wachtl/services/alertgen.py`, `server/wachtl/api_probe.py`, `server/wachtl/web.py`, `server/tests/test_alertgen.py`
- **Commit:** `2b3dea5` · **Risiko:** mittel (Alarmierung; Prober/Scheduler unberührt) · **Rückbau:** `git revert 2b3dea5`, danach `flask --app wachtl regen-rules` bzw. Neustart schreibt Regeln neu

## E-09 · 03:04 · Fokusring im Benutzermenü unsichtbar
- **Anlass:** `.topbar :focus-visible` (fast weiß) galt auch im weißen Menü-Panel → Kontrast ≈ 1,1:1.
- **Gewählt:** Panel nutzt `--focus`. Eine Zeile CSS.
- **Dateien:** `server/wachtl/static/app.css` · **Commit:** `c13dbdd` · **Risiko:** niedrig · **Rückbau:** `git revert c13dbdd`

## E-10 · 03:05 · Touch-Ziele ≥ 44 px
- **Anlass:** Tabellen-Aktionen ≈ 22 px, Navigation ≈ 31 px, Buttons ≈ 36 px, Checkboxen 13 px.
- **Optionen:** (a) überall 44 px (Desktop-Tabellen werden luftig, Layout-Tests „Gesetz der Nähe“ betroffen); (b) nur `@media (pointer: coarse)`.
- **Gewählt:** (b). Geprüft mit iPhone-13-Emulation auf allen 21 Seiten aus `e2e/pages.js`: kein Ziel < 44 px, kein horizontales Scrollen.
- **Dateien:** `server/wachtl/static/app.css` · **Commit:** `d070b1e` · **Risiko:** niedrig · **Rückbau:** `git revert d070b1e`

## E-11 · 03:05 · „Aktivieren“ bei deinstallierter Probe scheitert immer
- **Gewählt:** statt des Knopfs ein Hinweis „Deinstalliert – Setup neu installieren“. Server-Prüfung bleibt.
- **Dateien:** `server/wachtl/templates/probe.html`, `server/tests/test_v04.py` · **Commit:** `0235bbc` · **Risiko:** niedrig · **Rückbau:** `git revert 0235bbc`

## E-12 · 03:07 · Ungültiger Proxy beim „Setup herunterladen“
- **Anlass:** Token wurde erst angelegt, dann `abort(400)` → verwaister Token, Fehlerseite ohne Rückweg.
- **Gewählt:** Proxy vor dem Anlegen prüfen, Meldung im Formular-Abschnitt.
- **Dateien:** `server/wachtl/web.py`, `server/tests/test_web.py` · **Commit:** `d582d1c` · **Risiko:** niedrig · **Rückbau:** `git revert d582d1c`

## E-13 · 03:07 · Fehlerseiten 405/500 englisch, ohne nächsten Schritt
- **Gewählt:** 405/500 nutzen die deutsche Fehlerseite; alle Fehlerseiten bieten „Zurück zur vorigen Seite“ (Referer, durch `Referrer-Policy: same-origin` nur eigene Seiten) und „Zur Übersicht“. API-Pfade bekommen JSON wie bisher bei 400/403/404.
- **Dateien:** `server/wachtl/__init__.py`, `server/wachtl/templates/error.html`, `server/tests/test_web.py` · **Commit:** `2f2c1d6` · **Risiko:** niedrig · **Rückbau:** `git revert 2f2c1d6`

## E-14 · 03:10 · Ein/Aus- und Probe-Zustände einheitlich
- **Anlass:** Vorgabe „Ein/Aus überall gleich benannt und farbig“. Vorher: Checks „aktiv/pausiert“ (Klartext), Alarmregeln „Aktiv“, Gegenstelle „aktiv …/aus“; Probe „abgemeldet“ (Probe-Seite) vs. „deinstalliert“ (Übersicht); Standort-Matrix zeigte deaktivierte/deinstallierte Probes als „offline“ (falsch).
- **Optionen:** (a) nur Wörter angleichen; (b) zwei Makros in `_links.html`: `onoff(on)` → Badge „Ein“ (grün hinterlegt) / „Aus“ (grau) und `probe_state(p)` → Punkt + online/offline/deaktiviert/deinstalliert.
- **Gewählt:** (b). Knöpfe „Pausieren/Aktivieren“ (Checks) → „Ausschalten/Einschalten“, Spalte „Aktiv“ (Alarmregeln) → „Ein“. Check-Schalten gibt jetzt eine Bestätigung. Probe „Deaktivieren/Aktivieren“ bleibt (anderer Begriff: Sperre, kein Schalter). Audit-Log-Texte („an/aus“) bewusst unverändert, damit alte und neue Einträge gleich lesbar bleiben. Badge-Kontraste im Guardrail-Test ergänzt (hell/dunkel/erhöht ≥ 4,5:1).
- **Dateien:** `templates/_links.html`, `overview.html`, `site.html`, `probe.html`, `admin.html`, `static/app.css`, `web.py`, `tests/test_v04.py`, `tests/test_ui_quality.py`
- **Commit:** `cc283d9` · **Risiko:** niedrig · **Rückbau:** `git revert cc283d9` **PRÜFEN** (Wortwahl)

## E-15 · 03:11 · Wiederholte Tabellen-Aktionen ohne eindeutigen Namen
- **Anlass:** Screenreader hörte zehnmal „Löschen“ ohne Bezug (Guardrail-Regel in `docs/quality-guardrails.md`).
- **Gewählt:** `aria-label="<sichtbarer Text>: <Objekt>"` (beginnt mit dem sichtbaren Text, WCAG 2.5.3). Dazu fehlender Abstand zwischen „Bearbeiten“ und „Ausschalten“.
- **Dateien:** `templates/admin.html`, `templates/probe.html`, `static/app.css` · **Commit:** `0c4062e` · **Risiko:** niedrig · **Rückbau:** `git revert 0c4062e`

## E-16 · 03:13 · Standort-Matrix: Zustand nur über Farbe
- **Gewählt:** Problemzustände (auffällig/gestört/keine Daten) als drittes Wort in der Zelle, „ok“ nur für Screenreader. Pfad-Zellen zeigten den Zustand schon.
- **Dateien:** `templates/site.html` · **Commit:** `9816bea` · **Risiko:** niedrig · **Rückbau:** `git revert 9816bea`

## E-17 · 03:14 · Toter Code (Python)
- **Anlass:** `ruff --select F`: 7 ungenutzte Importe (Tests), fehlender `Path`-Import in `repo.py` (nur Typ-Annotation, F821), ungenutzte Template-Variablen `probes`, `intervals`, `merged` (Verwaltung) und `server_url` (Token-Seite).
- **Gewählt:** entfernt. `token_package` (ZIP-Download, nur noch von Tests aufgerufen) **bewusst behalten** – Route ist eine Funktion; Entfernen wäre Funktionsänderung → Finding.
- **Dateien:** `server/tests/*`, `server/wachtl/repo.py`, `server/wachtl/web.py` · **Commit:** `f7b6944` · **Risiko:** niedrig · **Rückbau:** `git revert f7b6944`

## E-18 · 03:16 · Alarmregeln teilweise gespeichert, NaN akzeptiert — PRÜFEN
- **Anlass:** `rules_update` schrieb Regel für Regel; ungültiger Wert weiter unten → obere gespeichert, Regeldatei nicht neu geschrieben (DB ≠ vmalert), Meldung „ungültig“. `float("nan")` bestand die Prüfung `< 0` → `> nan` in der Regeldatei.
- **Gewählt:** erst alle prüfen, dann schreiben; `math.isfinite`. Meldung nennt „nichts gespeichert“.
- **Dateien:** `server/wachtl/web.py`, `server/tests/test_web.py` · **Commit:** `623bca9` · **Risiko:** niedrig · **Rückbau:** `git revert 623bca9`

## E-19 · 03:17 · NaN/Inf in Check-Zahlenfeldern — PRÜFEN
- **Anlass:** bestätigt: `checktypes._convert(udp_mbps, "nan")` → `nan`; Flask serialisiert das als `NaN` – ungültiges JSON in `/api/probe/v1/config`. Die .NET-Probe lehnt solches JSON standardmäßig ab → Probes mit diesem Check bekämen keine neue Konfiguration.
- **Gewählt:** Serverseitige Eingabeprüfung (`math.isfinite`) – Probe-Code unberührt.
- **Dateien:** `server/wachtl/checktypes.py`, `server/tests/test_v03.py` · **Commit:** `b489b77` · **Risiko:** niedrig · **Rückbau:** `git revert b489b77`

## E-20 · 03:19 · Meldung nach Speichern außer Sicht
- **Anlass:** Verwaltung leitet nach `/admin#benutzer` usw. weiter; die Meldung stand oben, die Seite sprang nach unten.
- **Optionen:** (a) Meldungen pro Abschnitt serverseitig rendern (viele Templates); (b) 6 Zeilen JS: Meldung an den Sprungabschnitt verschieben.
- **Gewählt:** (b); ohne JS bleibt alles wie vorher. Check-Schalten meldet „Check X ausgeschaltet/eingeschaltet“.
- **Hinweis:** In diesem Testlauf schlug einmalig ein (nicht identifizierter) Test fehl; 9 Wiederholungen grün. Vermutlich vorbestehender zeitabhängiger Test → Bericht, offene Punkte.
- **Dateien:** `server/wachtl/static/app.js`, `server/wachtl/web.py` · **Commit:** `54b1025` · **Risiko:** niedrig · **Rückbau:** `git revert 54b1025`

## E-21 · 03:24 · Leerzustände ohne nächsten Schritt
- **Gewählt:** „Alle Messungen ohne Auffälligkeiten“ erschien auch ohne eine einzige Probe → eigener Text + Link „Probes geführt einrichten“. Ping-Tabelle: „Keine Ping-Checks zugewiesen“ + Link. Standort ohne Probe: Link zum Setup. Leere Token-Liste: erklärender Satz.
- **Dateien:** `templates/overview.html`, `probe.html`, `site.html`, `admin.html` · **Commit:** `0877ad1` · **Risiko:** niedrig · **Rückbau:** `git revert 0877ad1`

## E-22 · 03:26 · Suche auf der Übersicht — PRÜFEN
- **Anlass:** Häufige Aufgabe „Ziel/Probe suchen, nach Kunde filtern“: bei > 400 Probes nur Scrollen oder Strg+F.
- **Optionen:** (a) serverseitige Suche (neue Route/Parameter = Funktionsänderung); (b) Suchfeld, das die schon geladenen Standort-Karten und Probe-Zeilen im Browser filtert (Name, Standort, Kundennummer).
- **Gewählt:** (b), ~20 Zeilen JS, keine Server-Änderung. Suchbegriff steht in `?q=` und übersteht das Auto-Neuladen; Tippen im Suchfeld pausiert das Neuladen nicht dauerhaft. „Kein Treffer“-Hinweis. Neuer Browser-Test in `e2e/tests/layout.spec.js`.
- **Shortcut:** Abteilung gibt es im Datenmodell nicht; gefiltert wird, was auf der Übersicht steht.
- **Dateien:** `templates/overview.html`, `static/app.js`, `static/app.css`, `e2e/tests/layout.spec.js` · **Commit:** `d695193` · **Risiko:** niedrig · **Rückbau:** `git revert d695193`
