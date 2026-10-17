## Was ändert sich?

<!-- Kurz: Was und warum. Bei UI-Änderungen bitte Screenshots (hell/dunkel, schmal/breit). -->

## Prüfungen

- [ ] `python -m pytest -q` (inkl. `tests/test_ui_quality.py`) ist grün
- [ ] UI geändert: CI-Job „UI-Qualität“ ist grün (axe, Tastatur, Reflow, Lighthouse) – oder Ausnahme in `docs/quality-guardrails.md` begründet

## UX-Review (nur bei Änderungen am Web-UI)

Details und Beispiele: [`docs/quality-guardrails.md`](../docs/quality-guardrails.md#review-checkliste)

- [ ] **Auswahl (Hick):** Keine neue Seite/kein Formular verlangt mehr gleichzeitige Entscheidungen als nötig. Seltene Optionen sind gruppiert oder nachrangig, häufige bleiben sichtbar.
- [ ] **Nähe:** Neue Felder nutzen `field()` aus `templates/_forms.html`. Label, Hilfe und Fehler stehen am eigenen Feld, nicht zwischen zwei Feldern.
- [ ] **Fehler:** Ungültige Eingaben erscheinen in der Fehlerübersicht und am Feld, mit konkreter Abhilfe („Ziffern 1 bis 7“ statt „ungültig“). Eingaben bleiben erhalten.
- [ ] **Text:** Kurze Sätze, aktive Formulierungen, Fachbegriffe nur wo nötig und dann erklärt. Link- und Buttontexte sagen, was passiert.
- [ ] **Scannbarkeit:** Überschriften gliedern die Seite logisch (eine h1, keine Sprünge). Wichtiges steht zuerst.
- [ ] **Mobil:** Bei 320 px Breite bedienbar, kein seitliches Scrollen außerhalb von Tabellen.
- [ ] **Verweise sind Links:** Neu angezeigte Standorte, Probes, Checks/Ziele und Meldungen verlinken auf ihre Seite (Linktext = Name, `templates/_links.html`).
- [ ] **Screenreader:** Neue Bedienelemente haben eindeutige Namen (auch wenn sie sich je Tabellenzeile wiederholen). Status nicht nur über Farbe.
- [ ] **Tastatur:** Alles mit Tab/Enter/Leertaste erreichbar, Fokus sichtbar, keine Fokusfalle.
