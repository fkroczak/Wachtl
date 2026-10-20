# Qualitäts-Guardrails für das Web-UI

Regeln, Tests und Grenzwerte für Barrierefreiheit, Performance, Formulare und Texte im Wachtl-Web-UI
(`server/wachtl/templates`, `server/wachtl/static`). Ziel: WCAG 2.2 AA einhalten und die gemessene
Baseline nicht verschlechtern (Ratchet-Prinzip: Grenzwerte werden nur strenger, nie lockerer).

Verantwortlich: wer das UI ändert. Ausnahmen trägt der PR-Autor unten ein und lässt sie im Review bestätigen.

## Was automatisch geprüft wird

| Prüfung | Werkzeug | Wo | Blockiert den Merge |
| --- | --- | --- | --- |
| Semantik aller Seitentypen: `lang`, genau eine `h1`, keine Überschriftensprünge, beschriftete Felder (Platzhalter zählt nicht), gültige `aria-describedby`-Verweise, Namen von Links/Buttons, `alt`, keine leeren `<th>`, `fieldset` mit `legend` | `server/tests/test_ui_quality.py` (pytest, ohne Browser) | Job „Server-Tests“ | ja |
| Verweise sind Links: Standort- und Probe-Namen als eigener Wert (Zelle, Karte, Navigationspfad, Untertitel) stehen in einem `<a>` | `test_ui_quality.py::PageSemanticsTest::test_references_are_links` | „Server-Tests“ | ja |
| Formular-Fehlerzustand: Fehlerübersicht mit `role="alert"`, `aria-invalid` + verknüpfte Meldung, Reihenfolge wie im Formular | `test_ui_quality.py` | „Server-Tests“ | ja |
| Farbkontraste aller Design-Tokens in hell und dunkel (Text 4,5:1, Feldränder/Fokus/Grafik 3:1) | `test_ui_quality.py` | „Server-Tests“ | ja |
| axe-core, WCAG 2.2 A/AA + Best Practices, 15 Seiten + Anmeldung + Formular im Fehlerzustand, hell und dunkel | `server/e2e/tests/a11y.spec.js` | „UI-Qualität“ | ja, 0 Verstöße |
| Tastatur: Skip-Link, Anmeldung, Navigation, sichtbarer Fokus, Check-Formular mit Fehlern finden und beheben, Zeitraum-Buttons, Latenzgraph per Pfeiltasten mit Ansage | `server/e2e/tests/keyboard.spec.js` | „UI-Qualität“ | ja |
| Reflow bei 320 und 640 CSS-px (≙ 400 % / 200 % Zoom), Gesetz der Nähe bei 1280/768/320 px, Auto-Refresh verwirft keine Eingaben | `server/e2e/tests/layout.spec.js` | „UI-Qualität“ | ja |
| Lighthouse (mobil, 3 Läufe, Median) gegen Budgets | `server/e2e/lighthouserc.cjs` | „UI-Qualität“ | ja (Stufe `error`), Warnungen nur sichtbar |
| Lesbarkeit deutscher Hinweistexte | `server/devtools/readability.py --warn` | „UI-Qualität“ | nein, GitHub-Annotation |

Damit „blockiert“ wirklich blockiert, müssen in den Branch-Schutzregeln von GitHub die Checks
**Server-Tests (Python)** und **UI-Qualität (axe, Tastatur, Lighthouse)** als *required* eingetragen sein
(Repository-Einstellungen → Branches). Das lässt sich nicht aus dem Repository heraus setzen.

## Lokal ausführen

```bash
cd server
pip install -r requirements-dev.txt
python -m pytest -q                       # enthält die UI-Guardrails ohne Browser

# Browser-Tests: frische Instanz mit Demodaten (Fake-VictoriaMetrics, SQLite) auf Port 5000
cd e2e && npm ci && npx playwright install chromium && cd ..
e2e/start-server.sh
cd e2e
npx playwright test                        # axe, Tastatur, Reflow, Nähe
WACHTL_COOKIE=$(node login-cookie.js) npx lhci autorun --config=lighthouserc.cjs
cd .. && WACHTL_COOKIE=$(node e2e/login-cookie.js) python devtools/readability.py --warn http://127.0.0.1:5000/outages
```

`e2e/start-server.sh` legt jedes Mal eine neue Datenbank an. Prozesse danach mit `pkill -f fake_vm.py; pkill -f "flask --app wachtl run"` beenden.

## Grenzwerte (Lighthouse, mobil)

Festgelegt nach der Baseline vom 2026-10-16 (Median aus 3 Läufen je Seite, siehe unten), mit Puffer für die
Streuung auf GitHub-Runnern.

| Kennzahl | Baseline | Grenze | Stufe |
| --- | --- | --- | --- |
| Accessibility-Score | 91–100 → nach Korrektur 100 | 100 | error |
| Best-Practices-Score | 100 | 100 | error |
| Performance-Score | 98–100 | ≥ 90 | error |
| Largest Contentful Paint | 1,07–1,27 s | ≤ 2,0 s | error |
| Cumulative Layout Shift | 0–0,083 → nach Korrektur 0 | ≤ 0,05 | error |
| Total Blocking Time (Lab-Ersatz für INP) | 0–6 ms | ≤ 200 ms | error |
| Seitengewicht gesamt | 35–91 KB | ≤ 150 KB | error |
| JavaScript / CSS | 15 / 15 KB | ≤ 30 / 25 KB | error |
| Fremd-Ressourcen (Drittanbieter) | 0 | 0 | error |
| First Contentful Paint | 0,91 s | ≤ 1,5 s | warn |
| SEO-Score | 91 | ≥ 90 | warn |

### Begründete Ausnahmen

| Audit | Status | Begründung | Abbau |
| --- | --- | --- | --- |
| `uses-text-compression` | aus | Gemessen am Flask-Entwicklungsserver ohne Kompression. In Produktion entscheidet Traefik (Linux) bzw. cheroot (Windows). | **Offen:** Kompression in Traefik (`compress`-Middleware) und im Windows-Server prüfen und testen; dann Audit auf `error` stellen. |
| `unminified-css`, `unminified-javascript` | aus | Bewusst kein Build-Schritt (Offline-Appliance, CSP `'self'`); je ~15 KB, Ersparnis < 5 KB. | Wieder einschalten, falls ein Build-Schritt eingeführt wird. |
| `render-blocking-*`, `network-dependency-tree-insight`, `document-latency-insight` | aus | Eine kleine CSS-Datei, server-gerendertes HTML; LCP liegt trotzdem bei ~1,1 s mobil. | – |
| SEO | nur Warnung | Internes Werkzeug hinter Anmeldung, wird nicht indexiert. | – |

## Formulare

Neue Formularfelder **immer** mit dem Makro `field()` aus `server/wachtl/templates/_forms.html` bauen:

```jinja
{% from "_forms.html" import field, error_summary %}
{{ error_summary(errors) }}
{% call(attrs) field("timeout_ms", "Timeout", help="Wie lange auf eine Antwort gewartet wird.",
                     unit="ms", error=field_errors.timeout_ms) %}
  <input name="timeout_ms" type="number" min="100" max="5000" {{ attrs }}>
{% endcall %}
```

Das Makro sorgt für:

- **Label über dem Feld**, per `for`/`id` verknüpft; Kontrollkästchen mit Label rechts daneben (`check=True`).
- **Nähe**: Label, Feld, Einheit, Hilfe und Fehler stehen in einem `.field`-Container mit `--field-gap`
  (0,25 rem); zwischen Feldern liegt `--field-spacing` (1,1 rem). Abstände nur über diese Tokens ändern.
  Der Browser-Test prüft relativ: Jedes Label liegt näher an seinem Feld als an jedem anderen – keine Pixelvergleiche.
- **Beschreibungen**: Einheit, Hilfetext und Fehlermeldung hängen per `aria-describedby` am Feld.
- **Fehler**: `aria-invalid="true"`, Meldung direkt unter dem Feld (Symbol + Text, nicht nur Farbe) und in der
  Fehlerübersicht oben. Die Übersicht hat `role="alert"`, wird nach dem Absenden fokussiert und verlinkt die Felder.

Serverseitige Prüfungen liefern dafür `checktypes.FieldError(meldung, feldname)`. Meldungen nennen die Abhilfe
(„Wochentage: nur Ziffern 1 bis 7.“), nicht nur „ungültig“. Abhängige Felder (`show_if`) werden schon im HTML
ausgeblendet (`checktypes.visible_keys`), damit beim Laden nichts springt.

Tabellen mit Eingabefeldern (z. B. Alarmregeln) brauchen je Feld ein `aria-label` mit Zeilen- und Spaltenbezug
(„Paketverlust: Schwellwert“). Wiederholte Buttons je Zeile bekommen ein `aria-label`, das den sichtbaren Text
enthält („Bestätigen: Ziel nicht erreichbar“).

## Weitere UI-Konventionen

- **Farben** nur über die Tokens in `app.css`. Neue Kombinationen in `PAIRS` in `test_ui_quality.py` ergänzen.
  Status nie nur über Farbe: Punkte und Zellen bekommen Text („gestört“, „keine Daten“).
- **Verweise sind Links**: Wo ein Standort, eine Probe, ein Check/Ziel, eine Meldung oder ein Audit-Objekt genannt wird,
  führt der Name zur Detailseite – Standort → `web.site`, Probe → `web.probe`, Check einer Probe → `check_url(probe, check)`,
  Check ohne Probe → Bearbeiten-Formular, Meldung → gefilterte Meldungsliste. Alarme nutzen `alert_links()`,
  iperf3-Gegenstellen `check_target()` aus `templates/_links.html`. Linktext ist der Name, nie „hier“. Wiederholte Links
  mit verschiedenem Ziel bei gleichem Text bekommen ein `aria-label`, das den Text enthält („8.8.8.8 von PC-EMPFANG“).
  Ausnahmen: `<option>`, `<title>`, Bestätigungsdialoge, die h1 der eigenen Seite und Namen mitten in einem Satz.
  Test: `test_references_are_links`.
- **Links im Fließtext** sind unterstrichen; Navigation, Tabellen und Buttons dürfen ohne.
- **Fokus**: `:focus-visible` mit 3 px Ring in `--focus`. Nicht mit `outline: none` überschreiben.
- **Navigation**: mehrere `<nav>` brauchen ein `aria-label`; aktuelle Seite mit `aria-current="page"`.
- **Leere Tabellenköpfe**: `<th><span class="sr-only">Aktionen</span></th>`.
- **Auto-Refresh** (`data-autorefresh`) lädt nicht neu, solange ein Feld fokussiert oder ein Formular geändert ist.
- **Graphen** (SVG) haben ein `aria-label`, das auf die Tabelle mit denselben Werten verweist. Zahlen gehören
  zusätzlich in eine Tabelle.

## Lesbarkeit deutscher Texte

`devtools/readability.py` berechnet für Fließtext-Absätze (`p`, `small`, `li`, Hinweise):

- **Flesch-Index nach Amstad** (für Deutsch angepasst): 180 − Wörter/Satz − 58,5 × Silben/Wort. Höher = leichter; 50–60 ≈ mittelschwer.
- **1. Wiener Sachtextformel**: ≈ Schulstufe 4–15, niedriger = leichter. Warnung ab 12.

Flesch-Kincaid ist für Englisch kalibriert und wird nicht verwendet.

Grenzen: Silben werden heuristisch gezählt; Fachbegriffe (iperf3, Jitter, Gateway), lange Komposita und
IP-Adressen verfälschen die Werte; UI-Fragmente sind keine Fließtexte. Die Werte sind ein Hinweis auf lange
oder verschachtelte Sätze, kein Urteil. Ein Beispiel: „Kürzere Störungen tauchen nicht in der Ausfallübersicht
auf.“ löst eine Warnung aus, ist aber klar. Solche Fälle bleiben, wie sie sind.

Schreibregeln: Ein Gedanke pro Satz. Erst das Ergebnis, dann die Einschränkung. Abkürzungen wie „1-s-Rohdaten“
ausschreiben, wenn Platz ist. Fachbegriffe beim ersten Auftreten erklären. Button- und Linktexte sagen, was
passiert („Check anlegen“, „Jetzt messen“), nicht „OK“ oder „hier“.

## Review-Checkliste

Steht auch im PR-Template (`.github/pull_request_template.md`). Diese Punkte kann kein Test zuverlässig entscheiden:

1. **Hick'sches Gesetz** – Zählt die sichtbaren Entscheidungen auf der Seite. Sind seltene Optionen nachrangig
   (eigene Gruppe, weiter unten, ausklappbar)? Bleiben häufige Aufgaben ohne Umweg erreichbar? Kein Verstecken nur für eine Kennzahl.
2. **Gesetz der Nähe** – Gehört jede Beschriftung eindeutig zu einem Feld, auch bei 320 px und 200 % Zoom?
   Stehen Hilfe und Fehler am Feld?
3. **Verständlichkeit** – Versteht ein Administrator ohne Wachtl-Vorwissen, was das Feld bewirkt? Ist die Einheit klar?
4. **Scannbarkeit** – Lässt sich die Seite über Überschriften und erste Wörter erfassen? Stehen Zahlen in Tabellen,
   rechtsbündig mit Einheit?
5. **Mobil** – Mit dem Handy (320–400 px) bedienbar? Tabellen scrollen in ihrem Container?
6. **Verweise** – Ist jeder neu angezeigte Standort, jede Probe, jeder Check und jede Meldung ein Link auf die passende Seite?
7. **Screenreader** – Einmal mit NVDA (Windows) oder VoiceOver durch den geänderten Ablauf: Werden Fehler angesagt?
   Sind wiederholte Buttons unterscheidbar?

## Baseline und Abbauplan

Messumgebung: Lokaler Flask-Entwicklungsserver (`flask run`, kein HTTPS, keine Kompression) mit SQLite und
`devtools/fake_vm.py`, Demodaten aus `devtools/seed_demo.py` bzw. gleichwertig. Chromium 141 (Playwright 1.56),
Lighthouse 12.8.2, axe-core 4.11/4.14. Lighthouse „mobile“ = Moto G Power, simulierte 4G-Drosselung, 4× CPU-Bremse;
„desktop“ = `--preset=desktop`. Testzeitpunkt 2026-10-16. Keine Live-Installation und keine Felddaten (CrUX/RUM)
verfügbar – Core Web Vitals sind Labwerte; INP ist nur über TBT angenähert.

WAVE: Es gab keinen WAVE-API-Schlüssel und keine Möglichkeit, die WAVE-Browsererweiterung automatisiert zu
bedienen. **Ein WAVE-Test hat nicht stattgefunden.** Ersatzweise liefen axe-core, Lighthouse-Accessibility und
manuelle Prüfungen. Empfehlung: einmal je Release die Seiten aus `e2e/pages.js` mit der WAVE-Erweiterung prüfen.

Ausgangsbefunde, Korrekturen und Vorher/Nachher-Werte: siehe Abschnitt „Audit 2026-10-16“ unten.

## Audit 2026-10-16

### Vorher / nachher (Lighthouse, Median aus 3 Läufen, 11 Seiten × mobil/desktop)

| Kennzahl | Vorher | Nachher |
| --- | --- | --- |
| Accessibility | 91–100 (Verwaltung 91, Ausfälle 92, Übersicht/Standort 93, Alarme 95, Bandbreite 98) | 100 auf allen Seiten |
| Best Practices | 100 | 100 |
| SEO | 91 (fehlende Meta-Beschreibung) | 100 |
| Performance | 96–100 (Check-Formular desktop 96) | 100 auf allen Seiten |
| CLS Check-Formular | 0,083 mobil / 0,121 desktop | 0 / 0 |
| LCP mobil | 1,07–1,27 s | 1,06–1,26 s (keine Änderung jenseits der Streuung) |
| Seitengewicht | 35–91 KB | 39–79 KB (+4–7 KB CSS/JS/HTML; Graph-Daten schwanken mit der Uhrzeit) |

| axe-core (WCAG 2.2 AA + Best Practices, 15 Seiten × hell/dunkel) | Vorher | Nachher |
| --- | --- | --- |
| Betroffene Elemente | 95 | 0 |
| Regelverstöße (Regel × Seite) | 26 | 0 |

Die Standort- und Probe-Seite lieferten vor der Korrektur HTTP 500, sobald ein Ziel eine Minute lang nicht
antwortete; ihre Baseline-Werte stammen daher vom Stand mit diesem Fix.

### Befunde und Korrekturen

| # | Befund | WCAG / Kriterium | Wirkung | Korrektur |
| --- | --- | --- | --- | --- |
| 1 | Standort-/Probe-Seite HTTP 500, wenn alle Pings der letzten Minute verloren sind | Funktion | kritisch – Dashboard fällt genau bei Störungen aus | `vm.live_status` belegt alle Schlüssel vor (parallel auch auf `main` behoben) |
| 2 | 22 Eingabefelder und 9 Auswahllisten der Alarmregeln ohne Namen | 1.3.1, 4.1.2 | kritisch für Screenreader | `aria-label` mit Regel + Spalte, Regelname als Zeilenkopf |
| 3 | Kontrast: Warnung 2,8:1, ok 4,0:1, Badges 2,3/4,1:1, Feldränder 1,35:1 (hell) | 1.4.3, 1.4.11 | hoch | neue Farbwerte nahe der Markenpalette, Token-Test |
| 4 | Fehler im Check-Formular nur als Meldung oben, ohne Feldbezug; kein `aria-invalid` | 3.3.1, 3.3.3, 1.3.1 | hoch | Fehlerübersicht (fokussiert, verlinkt) + Meldung am Feld |
| 5 | Auto-Refresh alle 30 s lädt auch Seiten mit Formular neu – Eingaben gehen verloren | 2.2.1, 3.2.2 | hoch | kein Neuladen bei fokussiertem/geändertem Formular |
| 6 | Kein Skip-Link; 7 Tab-Schritte bis zum Inhalt | 2.4.1 | mittel | „Zum Inhalt springen“ |
| 7 | Leere Tabellenköpfe (Aktionen-Spalten) | 1.3.1 | mittel | `sr-only`-Text |
| 8 | Statuspunkte ohne Text (Dauerpings der Probe) | 1.4.1 | mittel | Text „ok/Verlust/gestört/keine Daten“ |
| 9 | Links im Navigationspfad nur über Farbe erkennbar (1,3:1 zum Text) | 1.4.1 | mittel | unterstrichen |
| 10 | Überschriften springen h1 → h3 (Bandbreite, Ausfälle) | 1.3.1 | niedrig | h2 |
| 11 | Zwei `<nav>` ohne Namen, aktuelle Seite nur per Klasse | 1.3.1, 4.1.2 | niedrig | `aria-label`, `aria-current` |
| 12 | Layout-Sprung im Check-Formular (Felder werden erst per JS ausgeblendet) | CLS | niedrig | Sichtbarkeit serverseitig |
| 13 | Hauptnavigation bei 320 px abgeschnitten | 1.4.10 | niedrig | Umbruch |
| 14 | Kommentarfeld beim Bestätigen nur mit Platzhalter beschriftet; „Bestätigen“ je Zeile nicht unterscheidbar | 3.3.2, 2.4.6 | niedrig | `aria-label` mit Alarmtext |
| 15 | Schweregrade englisch („critical“) in deutscher Oberfläche | Verständlichkeit | niedrig | „kritisch / Warnung / Info“ |
| 16 | Fokusring auf dem Uhrsymbol von Zeitfeldern kaum sichtbar | 2.4.7 | niedrig | `input:focus-within` |
| 17 | Hinweistexte Ziel/Ausfälle schwer lesbar (WSTF 16,4 / 12,7) | Lesbarkeit | niedrig | umformuliert (WSTF 10,9 / 7,6) |

Reproduzieren: `e2e/start-server.sh`, dann die genannte Seite öffnen; für 1 die Probe eine Minute nichts melden
lassen (oder `tests/test_web.py::LiveStatusGapsTest`); für 5 auf der Probe-Seite ein Feld ändern und 30 s warten;
für 2–4, 6–11 und 14 meldet `npx playwright test` bzw. axe die Stelle, wenn man den alten Stand auscheckt.

### Manuell geprüft (ohne Screenreader)

- Tastatur: Anmeldung, Navigation, Check-Formular inkl. Fehlerkorrektur, Zeitraum-Buttons – vollständig bedienbar, keine Fokusfalle.
- Reflow: alle Seiten bei 320 und 640 px ohne seitliches Scrollen der Seite; breite Tabellen scrollen in ihrem Container.
- Nähe: Label-zu-Feld-Abstand 0,25 rem, Feld-zu-Feld 1,1 rem; bei 1280/768/320 px liegt jedes Label näher am eigenen Feld.
- Hick: Hauptnavigation mit wenigen Punkten, Einstellungen als Startseite mit Kacheln und eigener Seite je Bereich, Check-Formulare in Feldgruppen.
  Das iperf3-Formular zeigt bis zu 16 Felder gleichzeitig – Vorschlag zum Einklappen siehe offene Punkte.
- Nicht geprüft: Screenreader-Ausgabe (NVDA/VoiceOver), echte Mobilgeräte, Windows-Hochkontrastmodus.

Offene Punkte mit Verantwortlichkeit (Projektverantwortliche/r, bis zum nächsten Minor-Release):

| Punkt | Art | Nächster Schritt |
| --- | --- | --- |
| Textkompression in Produktion | Performance | Traefik-`compress` und Windows-Server testen, Ausnahme entfernen |
| WAVE-Prüfung | Prozess | Manuell je Release, Ergebnis hier eintragen |
| Screenreader-Durchlauf (NVDA/VoiceOver) | manuell | Formular- und Alarm-Abläufe einmal prüfen |
| Wochentage als Ziffernfolge („12345“) | UX | Vorschlag: sieben Kontrollkästchen – Produktentscheidung offen |
| Erweiterte iperf3-Optionen | UX (Hick) | Vorschlag: Streams, TCP-Fenster, Anlaufzeit, Abbruch in „Erweitert“ einklappen – Produktentscheidung offen |
| Auto-Refresh abschaltbar | WCAG 2.2.1 | Vorschlag: Schalter „Automatisch aktualisieren“ – Produktentscheidung offen |
| Kurzformulare in Zeilen (Standort, Token, Benutzer, Benachrichtigungen, Anmeldung, Konto) | Konvention | Nutzen noch umschließende `<label>` (zugänglich, axe-konform), Fehler nur als Meldung oben. Bei der nächsten Änderung auf `field()` umstellen. |
