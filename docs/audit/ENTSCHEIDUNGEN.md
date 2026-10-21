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
