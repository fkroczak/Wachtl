# Audit-Bericht Wachtl · 2026-10-21

Branch `audit/2026-10-21`, Basis `main` @ `9f379db` (0.9.2). `main` ist unberührt, nichts deployt, keine Produktivdaten und keine Zugangsdaten angefasst.
Details und Rückbau zu jeder Änderung: [ENTSCHEIDUNGEN.md](ENTSCHEIDUNGEN.md) (E-01 … E-28).

## 0. Kurzfassung

1. **Gemacht:** 8 Sicherheits- und Logikfehler behoben. Dazu gehören Login-CSRF, Sitzungen nach Passwortwechsel, Aussperren des Admins und das Reaktivieren gesperrter Probes. Ungültige Werte („NaN“) machten die Probe-Konfiguration kaputt. Deaktivierte Probes lösten 24 h kritischen Fehlalarm aus.
2. **Bedienung:** 14 UX- und Barrierefreiheits-Verbesserungen: Touch-Ziele ≥ 44 px, einheitliches Ein/Aus, Suche auf der Übersicht, Meldungen am richtigen Ort, kein Seitwärts-Scrollen auf Tablets, Eingaben bleiben nach Fehlern erhalten.
3. **Stand:** 197 Server-Tests und 164 Browser-Tests grün (vorher 182 + 121). Lighthouse: Performance, Barrierefreiheit und Best Practices auf allen 9 Seiten 100, SEO 63 nur wegen des gewollten noindex.
4. **Offen:** Übernahme einer *aktiven* Probe mit einem gültigen Registrierungs-Token (Design-Frage). Passwort-Mindestlänge fehlt (seit 0.8.4 bewusst frei). Abweichungen des Codes von der Auftragsbeschreibung (Grafana, Kundenzugang, PWA, Rollen-Namen) → Abschnitt 5.
5. **Zuerst prüfen:** E-26 (Login-Sperre je Gerät), E-05 (alle Sitzungen enden einmalig beim Einspielen), E-07 (Neuinstallation auf deaktiviertem PC wird abgelehnt), E-08 (Alarmregel), E-25 (Lighthouse-Budgets +1 KB / +10 KB).

## 1. Priorisierte Findings

| # | Schwere | Fundstelle | Auswirkung | Reproduktion | Status |
| --- | --- | --- | --- | --- | --- |
| F-01 | hoch | `security.py` `try_login` | Sperre galt je **Konto**: 5 falsche Passwörter von irgendwem → der Admin ist an seinem eigenen PC 15 min ausgesperrt, beliebig wiederholbar. Widerspricht der Vorgabe „Sperre je Sitzung/Gerät“. | Frischer Browser, 5× `admin` + falsches Passwort, dann richtiges Passwort am Admin-PC → „Konto gesperrt“ | behoben E-26 |
| F-02 | hoch | `checktypes._convert` | „nan“/„inf“ in einem Zahlenfeld eines Checks (z. B. UDP-Rate) wurde gespeichert. Die Probe-Konfiguration enthielt dann `NaN` (ungültiges JSON), und .NET-Probes lehnen solche Konfigurationen ab. | Check bearbeiten, UDP-Rate `nan` → `/api/probe/v1/config` liefert `NaN` | behoben E-19 |
| F-03 | mittel | `web.py` `login` | Login-CSRF: Ohne Sitzung war `None == None`, also konnte eine fremde Seite das Opfer in ein Angreiferkonto einloggen. | POST `/login` ohne Cookie und ohne Token → 302, angemeldet | behoben E-04 |
| F-04 | mittel | `security.py` `current_user` | Nach „Passwort zurücksetzen“ oder eigenem Wechsel blieben alte (auch gestohlene) Sitzungen bis 12 h gültig, gleitend. | Zwei Browser angemeldet, in einem Passwort ändern → der andere bleibt drin | behoben E-05 |
| F-05 | mittel | `api_probe.py` `enroll` | Wer einen gültigen Registrierungs-Token hat (steckt im verteilten Setup), konnte eine vom Admin **deaktivierte** Probe wieder aktivieren. | Probe deaktivieren, mit demselben Token und Hostnamen registrieren → 201, Status `active` | behoben E-07 |
| F-06 | mittel | `api_probe.py` `enroll` | Dasselbe für **aktive** Probes: Token-Inhaber übernimmt Hostname und Messreihe, die echte Probe verliert ihr Token. | wie F-05 ohne Deaktivieren | **offen**, Design-Frage (Abschnitt 5) |
| F-07 | mittel | `services/alertgen.py` | `WachtlProbeOffline` ignorierte den Status: Nach Deaktivieren oder Deinstallieren kam bis zu 24 h ein kritischer Alarm (E-Mail/Teams alle 4 h), plus ein Eintrag in „Ausfälle“. | Probe deaktivieren → Regel enthält keinen Statusfilter | behoben E-08 (gelöschte Probes: Shortcut) |
| F-08 | mittel | `web.py` `rules_update` | Ein Fehler in einer unteren Regel speicherte die oberen trotzdem, ohne die Regeldatei neu zu schreiben (DB ≠ vmalert). Außerdem wurde `nan` als Schwellwert akzeptiert. | Erste Regel 999, letzte `nan` → erste gespeichert | behoben E-18 |
| F-09 | mittel | Templates (Tabellen) | Tablets 720–960 px: Die ganze Seite scrollte seitlich (7 Seiten). | Fenster 768 px breit | behoben E-28 |
| F-10 | mittel | `app.css` | Touch-Ziele zu klein: Tabellen-Aktionen ≈ 22 px, Navigation ≈ 31 px, Buttons ≈ 36 px, Checkboxen 13 px. | Handy-Emulation, Höhe messen | behoben E-10 |
| F-11 | mittel | `app.css` | Fokusring im Benutzermenü unsichtbar (≈ 1,1:1 auf Weiß). | Tab ins Benutzermenü | behoben E-09 |
| F-12 | niedrig | `security.py`, `web.py`, `api_admin.py` | Mehrere Eingaben führten zu einem 500er statt einer Meldung, zwei davon ohne Anmeldung (`X-CSRF-Token: ä`, `Bearer ².x`). Betroffen: `hours`, `site_id`, `days`, `max_uses`, `since`. | siehe Tests `test_bad_numbers_no_500`, `test_csrf_non_ascii_is_400` | behoben E-04, E-06 |
| F-13 | niedrig | `__init__.py` | Keine Suchmaschinen-Sperre vorhanden (Vorgabe noindex). | Antwort-Header prüfen | behoben E-03 |
| F-14 | niedrig | `probe.html` | Bei einer deinstallierten Probe gab es einen „Aktivieren“-Knopf, der immer scheiterte. | Probe deinstallieren, Seite öffnen | behoben E-11 |
| F-15 | niedrig | `web.py` `token_create` | Ungültiger Proxy beim Setup-Download: Es entstand ein verwaister Token und eine Fehlerseite ohne Rückweg. | Proxy `proxy:3128` | behoben E-12 |
| F-16 | niedrig | Fehlerseiten | Bei 405/500 erschien eine englische Werkzeug-Seite, ohne Rückweg. | GET `/logout` | behoben E-13 |
| F-17 | niedrig | Verwaltung | Erfolgs- und Fehlermeldung außer Sicht (Sprung zu `#abschnitt`). Eingaben verloren nach Fehler (Benutzer, Benachrichtigungen). | Benutzer ohne Passwort anlegen | behoben E-20, E-27 |
| F-18 | niedrig | Zustände | Ein/Aus uneinheitlich („aktiv/pausiert“, „aktiv …/aus“, „Aktiv“). Probe „abgemeldet“ vs. „deinstalliert“. Die Standort-Matrix zeigte deaktivierte Probes als „offline“. | – | behoben E-14 |
| F-19 | niedrig | A11y | Standort-Matrix: Zustand nur über Farbe. 10× „Löschen“ ohne Bezug für Screenreader. Knopf-Ränder 1,3:1. | – | behoben E-15, E-16, E-23 |
| F-20 | niedrig | `web.py` `target` | Graph-Seite für Nicht-Ping-Checks erreichbar (kaputte Seite). | `/probes/1/checks/<Pfad-ID>` | behoben E-24 |
| F-21 | niedrig | `security.py` | Passwort: keine Mindestlänge (auch Admin „1“). Laut 0.8.4 bewusst „frei wählbar“. | – | offen, Entscheidung nötig |
| F-22 | niedrig | `api_probe.py` `heartbeat` | `int(buffer_items)` → 500 bei kaputtem Heartbeat. Echte Probes senden Zahlen. | – | offen, bewusst nicht angefasst (Probe-Ingest) |
| F-23 | niedrig | `web.py` `token_package` | ZIP-Download-Route wird nur noch von Tests aufgerufen. | – | offen (Entfernen wäre Funktionsänderung) |
| F-24 | niedrig | `app.css` (≤ 700 px) | `table { display: block }` kann in Safari/VoiceOver die Tabellen-Semantik verlieren. | – | offen |
| F-25 | info | Abhängigkeiten | `pip-audit`: requests 2.32.5, PYSEC-2026-2275 (`extract_zipped_paths`), **wird nicht genutzt** → nicht betroffen. `npm audit`: 17 Meldungen, nur in Dev-Werkzeugen (`@lhci/cli`), nicht im Produkt. | `pip-audit -r requirements.txt` | offen, Freigabe (Abschnitt 5) |

Geprüft und sauber (Sicherheits-Audit):
- Alle Routen prüfen die Rolle serverseitig (`login_required`), die Mindestrolle passt zu den Templates.
- SQL ist durchgängig parametrisiert, MetricsQL-Eingaben sind validiert.
- Probes können nur eigene Checks schreiben, Größenlimits sind gesetzt.
- Keine XSS-Stellen (Autoescape, CSP `script-src 'self'`), Download-Pfade sind sauber.
- Cookies sind Secure/HttpOnly/SameSite, kein offener Redirect.
- Der Graph-Dialog ist für alle Rollen identisch (keine Rollen-Abfrage in `target.html`).

## 2. Umgesetzte Änderungen

| E | Commit | Dateien | Grund | Tests |
| --- | --- | --- | --- | --- |
| E-03 | `9766c16` | `__init__.py` | noindex-Header | `test_noindex_everywhere` |
| E-04 | `2468168` | `security.py`, `web.py` | Login-CSRF, 500 bei Nicht-ASCII | `test_login_needs_csrf_from_session`, `test_csrf_non_ascii_is_400` |
| E-05 | `7325ae3` | `security.py`, `web.py` | Sitzung endet bei Passwortwechsel | `test_password_change_ends_other_sessions` |
| E-06 | `a0ad35a` | `web.py`, `api_admin.py`, `security.py` | 500 → 400/401 | `test_bad_numbers_no_500` |
| E-07 | `a65207c` | `api_probe.py` | Deaktivierte Probe bleibt gesperrt | `test_reenroll_refused_while_disabled_by_admin` |
| E-08 | `2b3dea5` | `alertgen.py`, `api_probe.py`, `web.py` | Kein Offline-Alarm für inaktive Probes | `test_probe_offline_skips_inactive_probes` |
| E-09 | `c13dbdd` | `app.css` | Fokusring Benutzermenü | Browser-Tests |
| E-10 | `d070b1e` | `app.css` | Touch-Ziele ≥ 44 px | Messung auf 21 Seiten (iPhone 13) |
| E-11 | `0235bbc` | `probe.html` | Kein Knopf, der nur scheitert | `test_v04` erweitert |
| E-12 | `d582d1c` | `web.py` | Proxy vor Token prüfen | `test_token_bad_proxy_creates_no_token` |
| E-13 | `2f2c1d6` | `__init__.py`, `error.html` | Fehlerseiten 405/500 | `test_error_pages_german_with_way_back` |
| E-14 | `cc283d9` | `_links.html` u. a. | Ein/Aus und Probe-Status einheitlich | Kontrast-Guardrail erweitert |
| E-15 | `0c4062e` | `admin.html`, `probe.html` | Eindeutige Aktionsnamen | axe |
| E-16 | `9816bea` | `site.html` | Zustand als Wort | Sichtprüfung |
| E-17 | `f7b6944` | diverse | Toter Code (ruff F) | `ruff check --select F` sauber |
| E-18 | `623bca9` | `web.py` | Alarmregeln atomar, NaN | `test_rules_update_all_or_nothing` |
| E-19 | `b489b77` | `checktypes.py` | NaN/Inf abweisen | `test_nan_and_inf_are_not_numbers` |
| E-20 | `54b1025` | `app.js`, `web.py` | Meldung am Sprungziel | Sichtprüfung |
| E-21 | `0877ad1` | Templates | Leerzustände mit nächstem Schritt | – |
| E-22 | `d695193` | `overview.html`, `app.js`, `app.css` | Suche | neuer Browser-Test |
| E-23 | `1872f16` | `app.css` | Knopf-Ränder ≥ 3:1 | – |
| E-24 | `86f0c3f` | `web.py` | Ziel-Seite nur für Pings | `test_target_page_only_for_ping` |
| E-25 | `6e252e1` | `app.css`, `lighthouserc.cjs`, `quality-guardrails.md` | Doppelte CSS-Regeln, Budgets | Lighthouse grün |
| E-26 | `b8714f1` | `security.py`, `web.py`, `BETRIEB.md` | Login-Sperre je Gerät | `test_lockout_is_per_device_not_per_account`, `test_account_backstop_spares_trusted_device` |
| E-27 | `e8ff475` | `web.py`, `admin.html` | Eingaben bleiben erhalten | `test_failed_forms_keep_input` |
| E-28 | `9d5098b` | 4 Templates, `layout.spec.js` | Tablet-Layout | Reflow 768/900 px (schlägt mit altem Stand fehl) |

Nach jedem Commit lief `pytest` (am Ende 197 grün, 2 übersprungen wie auf `main`). Nach den UI-Blöcken lief die komplette Playwright-Suite (axe, Tastatur, Reflow, Nähe, Auto-Refresh). Probe-Code (C#), Scheduler und Messpfad wurden **nicht** geändert.

## 3. UX-Verbesserungen mit Vorher/Nachher

Bilder: `docs/audit/screens/vorher/` (Stand `9f379db`) und `docs/audit/screens/nachher/`, jeweils Desktop 1280 px und Handy (iPhone 13 mit Touch). Die Demodaten sind zufällig, die Messwerte unterscheiden sich deshalb.

| Thema | Vorher | Nachher |
| --- | --- | --- |
| Probe oder Kunde finden | Scrollen oder Strg+F in langen Listen | Suchfeld „Standort oder Probe suchen“ auf der Übersicht. Filtert nach Name, Standort und Kundennummer, bleibt beim Auto-Neuladen erhalten (E-22) |
| Touch | Knöpfe 22–36 px | ≥ 44 px auf Touch-Geräten, mit Maus unverändert kompakt (E-10). Vergleich: `mobil-Probe.jpg` |
| Ein/Aus | „aktiv/pausiert“, „aus“, Checkbox „Aktiv“ | Überall Badge **Ein** (grün hinterlegt) / **Aus** (grau). Knöpfe „Einschalten/Ausschalten“ (E-14). Vergleich: `desktop-Verwaltung.jpg` |
| Probe-Status | „abgemeldet“ vs. „deinstalliert“; Matrix: deaktiviert = „offline“ | Überall online / offline / deaktiviert / deinstalliert mit gleichem Punkt (E-14) |
| Rückmeldung | Meldung oben, Seite springt nach unten | Meldung direkt über dem gespeicherten Abschnitt (E-20). Check schalten meldet „ausgeschaltet/eingeschaltet“ |
| Fehler | Englische 405/500-Seite, nur „Zur Übersicht“ | Deutsche Seite mit „Zurück zur vorigen Seite“ (E-13). Formulare behalten Eingaben (E-27) |
| Leerzustände | „Alle Messungen ohne Auffälligkeiten“ auch ohne Probe | Klarer Text und Link zum nächsten Schritt (E-21) |
| Tablet | Seite scrollt seitlich | Nur breite Tabellen scrollen in sich (E-28) |
| Tastatur/Screenreader | Fokus im Menü unsichtbar, 10× „Löschen“ | Sichtbarer Fokus, „Löschen: Gateway“ (E-09, E-15) |

## 4. Bewusste Shortcuts und ihre Grenzen

- **Offline-Alarm gelöschter Probes** (`alertgen.py`, `shortcut:`-Kommentar): Gelöschte Probes stehen nicht mehr in der DB und alarmieren weiter bis 24 h nach dem letzten Kontakt. Upgrade-Pfad: gelöschte IDs merken oder die Zeitreihe beim Löschen in VictoriaMetrics entfernen. Ebenfalls unverändert: Das Fenster ist fest `[24h]`, `window_s` der Regel wird nicht genutzt.
- **Login-Sperre je Gerät (E-26):** Wer Cookies löscht, bekommt je neuer Sitzung 5 Versuche. Gedeckelt wird das durch die Konto-Sperre (20 Versuche je 15 min, scrypt). Ein gestohlenes `wachtl_device`-Cookie hebt nur diesen Rückhalt auf, nicht die Passwortprüfung.
- **Suche (E-22)** filtert im Browser, was auf der Übersicht steht. „Abteilung“ gibt es im Datenmodell nicht.
- **Sitzungs-Kennung (E-05)** wird aus dem Passwort-Hash abgeleitet statt aus einer eigenen Spalte. Eine „alle Sitzungen abmelden“-Funktion ohne Passwortwechsel gibt es damit nicht.
- **Lighthouse-Budgets (E-25)** wurden um 1 KB CSS und 10 KB Seitengewicht angehoben. Mit Textkompression in Produktion lägen beide weit darunter.

## 5. Offene Risiken, blockierte Prüfungen, Freigabe nötig

**Freigabe nötig (nicht umkehrbar oder Außenwirkung, nur vorbereitet):**
1. **Merge nach `main` und Release:** Branch ist baubar und getestet; Merge, Versionsnummer (Vorschlag 0.9.3 bzw. 0.10.0 wegen Login-Verhalten) und Setup-Bau entscheidest du.
2. **Beim Einspielen (E-05):** Alle angemeldeten Benutzer müssen sich einmal neu anmelden.
3. **Beim Einspielen (E-07):** Wer einen im Web-UI **deaktivierten** PC neu installiert, bekommt „Probe ist im Web-UI deaktiviert – dort zuerst aktivieren“.
4. **requests 2.33** (pip-audit): Nicht betroffen, das Update ändert aber den Server-Build → nur auf deine Freigabe. npm-Meldungen: nur Dev-Werkzeuge, der Fix erfordert ein Downgrade von `@lhci/cli` → nicht angefasst.

**Design-Entscheidungen für dich:**
- **F-06:** Übernahme einer aktiven Probe mit gültigem Registrierungs-Token. Vorschlag: Neu-Registrierung eines Hostnamens nur, wenn die bisherige Probe seit > X min keinen Kontakt hatte oder ein Admin „Neu registrieren erlauben“ klickt. Das ändert den Ablauf „PC neu aufsetzen“, deshalb nicht umgesetzt.
- **F-21:** Passwort-Mindestlänge (z. B. 10 Zeichen, mindestens für Admins)?

**Abweichungen zwischen Auftrag und Code (E-01), nichts nachgebaut:**
- Rollen heißen „Nur lesen / Operator / Administrator“ (nicht Betrachter/Bearbeiter/Admin). „Nur lesen“ sieht Dashboards und Graphen; es gibt keinen Export und kein Grafana im Code.
- Es gibt keinen Kundenzugang und keinen Admin-Schalter dafür.
- Kein PWA-Manifest (nur `apple-touch-icon`).
- Das Farbschema ist neutrales Grau mit Blau-Akzent (System/Hell/Dunkel + Kontrast), kein „Zink“.
- noindex fehlte → ergänzt (E-03).

**Weitere offene Punkte (niedrig):**
- F-22 (Heartbeat-500), F-23 (`token_package`), F-24 (Tabellen-Semantik ≤ 700 px).
- Zahlenformat gemischt (Graph-Legende mit Komma, sonst Punkt).
- `theme-color` nur hell.
- Validierungsfehler bei Messeinstellungen ohne Markierung am Feld.
- Ein einzelner Testlauf bei E-20 meldete 1 Fehlschlag, der in 9 Wiederholungen nicht wieder auftrat. Vermutlich ein vorbestehender zeitabhängiger Test; nicht identifiziert.

**Blockiert/nicht geprüft:**
- Windows-Build und C#-Tests: kein Windows/.NET in dieser Umgebung. Probe-Code wurde nicht geändert; die CI auf GitHub prüft das beim nächsten Push nach `main`.
- PostgreSQL-Betrieb: Tests laufen mit SQLite; die Änderungen nutzen kein DB-spezifisches SQL und keine Migration.
- Echte Alertmanager/vmalert-Umgebung: Regel-Ausgabe ist per Unit-Test geprüft, nicht gegen ein laufendes vmalert.

## 6. Rückbau

Einzeln (neueste zuerst, jede Zeile unabhängig):

```bash
git revert 9d5098b   # E-28 Tablet-Layout
git revert e8ff475   # E-27 Eingaben behalten
git revert b8714f1   # E-26 Login-Sperre je Gerät (Cookie wachtl_device wird danach ignoriert)
git revert 6e252e1   # E-25 CSS-Duplikate, Budgets
git revert 86f0c3f   # E-24 Ziel-Seite nur Ping
git revert 1872f16   # E-23 Knopf-Ränder
git revert d695193   # E-22 Suche
git revert 0877ad1   # E-21 Leerzustände
git revert 54b1025   # E-20 Meldung am Sprungziel
git revert b489b77   # E-19 NaN in Checks
git revert 623bca9   # E-18 Alarmregeln atomar
git revert f7b6944   # E-17 toter Code
git revert 9816bea   # E-16 Matrix-Zustand als Wort
git revert 0c4062e   # E-15 Aktionsnamen
git revert cc283d9   # E-14 Ein/Aus einheitlich
git revert 2f2c1d6   # E-13 Fehlerseiten
git revert d582d1c   # E-12 Proxy-Prüfung
git revert 0235bbc   # E-11 Aktivieren-Knopf
git revert d070b1e   # E-10 Touch-Ziele
git revert c13dbdd   # E-09 Fokusring
git revert 2b3dea5   # E-08 Offline-Alarm (danach: flask --app wachtl regen-rules)
git revert a65207c   # E-07 deaktivierte Probe
git revert a0ad35a   # E-06 500er
git revert 7325ae3   # E-05 Sitzungen
git revert 2468168   # E-04 Login-CSRF
git revert 9766c16   # E-03 noindex
```

Hinweis: E-25 fasst CSS-Zeilen zusammen, die E-10/E-14 hinzugefügt haben. Wer E-10 oder E-14 einzeln zurücknimmt, nimmt vorher E-25 zurück oder löst den Konflikt in `app.css` von Hand.

Komplett: Branch nicht mergen und löschen. `main` ist unverändert.

```bash
git push origin --delete audit/2026-10-21   # Freigabe nötig – löscht den Branch auf GitHub
```
