# Störungsmeldungen und Tray-Symbol (0.6)

Auf jedem Windows-Client mit Probe und auf dem Windows-Server sitzt rechts unten neben der Uhr das
Wachtl-Symbol (`wachtl-tray.exe`). Rechtsklick (oder Linksklick) öffnet das Menü:

| Eintrag | Funktion |
| --- | --- |
| *Ping 1.1.1.1: 12 ms* (bis 3 Zeilen) | aktuelle Antwortzeit jeder Internet-Referenz (Ping-Check mit Rolle „Referenz“), dazu der Verlust der letzten Minute, wenn es welchen gab (ab 0.8.2) |
| *Jetzt: ↓ 3,2 Mbit/s ↑ 0,4 Mbit/s* | aktueller Datenverkehr des PCs über die Netzwerkkarte mit Gateway – was gerade läuft, keine Messung der Leitung |
| *Speedtest 14:05: ↓ 246 Mbit/s ↑ 38 Mbit/s* | Ergebnis des letzten WAN-Speedtests dieses PCs (nur wenn ein Speedtest-Check für ihn eingerichtet ist) |
| **Problem melden …** | kleines Fenster: Zeitpunkt (**Jetzt** vorausgewählt oder eine einstellbare Uhrzeit), Art der Störung, ungefähre Dauer, optional Beschreibung. **Senden** schickt die Meldung über den lokalen Wachtl-Dienst an den Server. |
| **Über Wachtl** | kurze Übersicht: was Wachtl ist, was es misst, mit welchem Server und Standort dieser PC verbunden ist, Version und Verbindungszustand. |
| **Beenden** | schließt nur das Symbol für diese Anmeldung. Der Messdienst läuft weiter; nach der nächsten Anmeldung erscheint das Symbol wieder. |

Auf dem Server gibt es zusätzlich **Dashboard öffnen**. Die Zeilen mit Ping und Datenrate stehen nur auf Clients;
solange das Menü offen ist, aktualisieren sie sich alle 2 s.

Im Web-UI erscheinen die Meldungen unter **Meldungen** (Navigation, mit Zahl der neuen), in der **Übersicht**, auf der
Seite der Probe und des Standorts – und als senkrechte Markierung in den Graphen, genau zum gemeldeten Zeitpunkt.
So sieht man direkt, ob Latenz, Verlust oder Bandbreite zu diesem Zeitpunkt auffällig waren.
Operatoren und Administratoren können eine Meldung als **erledigt** markieren (mit Notiz, im Audit-Log).

## Aufbau

```
wachtl-tray.exe (Benutzersitzung, .NET Framework 4.6.2 – in Windows enthalten, wenige KB)
      │  HTTP nur auf 127.0.0.1:47251, Kopfzeile X-Wachtl-Tray: 1
      ▼
Wachtl-Dienst (Client: wachtl-probe.exe als LocalSystem / Server: Server-Probe)
      │  HTTPS mit Probe-Token und Zertifikats-Pinning (wie alle Messdaten);
      │  ohne Verbindung bleibt die Meldung in reports-pending.json und wird nachgeliefert
      ▼
Wachtl-Server  POST /api/probe/v1/report  →  Tabelle incident_reports  →  Web-UI und Graphen
```

Das Tray-Programm kennt weder Token noch Server-Zugangsdaten. Es spricht nur mit dem lokalen Dienst.

## Lokale Schnittstelle (Tray → Dienst)

Adresse `http://127.0.0.1:47251` (Umgebungsvariable `WACHTL_TRAY_PORT` ändert den Port, für Dienst und Tray gleich).
Der Dienst lauscht ausschließlich auf der Loopback-Adresse.

Schutz gegen Webseiten im Browser (CSRF, DNS-Rebinding): jede Anfrage braucht die Kopfzeile `X-Wachtl-Tray: 1`,
`POST` zusätzlich `Content-Type: application/json` (beides erzwingt im Browser einen CORS-Preflight, den der Dienst nie
erlaubt), und der `Host` muss `127.0.0.1:<port>` oder `localhost:<port>` sein. Sonst `403`. Körper höchstens 16 KB,
höchstens 30 Meldungen je Stunde und Benutzer und 300 je Rechner (sonst `429`).

### `GET /tray/v1/status`

```json
{
  "role": "probe",                      // "probe" (Client) oder "server"
  "name": "PC-BUCHHALTUNG-03",          // Name der Probe im Dashboard
  "site": "Zentrale",                   // Standort (leer, wenn unbekannt)
  "server_url": "https://wachtl.kunde.local",
  "dashboard_url": "https://wachtl.kunde.local",   // nur role=server, sonst ""
  "version": "0.8.5",
  "enrolled": true,
  "connected": true,                    // letzte Verbindung zum Server < 2 min her
  "last_contact": 1792230000,           // Unix-Sekunden, 0 = noch nie
  "pending_reports": 0,                 // noch nicht zugestellte Meldungen
  "internet": {                         // ab 0.8.2, nur Clients: Werte fürs Menü
    "pings": [{"target": "1.1.1.1", "up": true, "rtt_ms": 12.3, "loss_pct": 0}],
    "rx_mbps": 3.21, "tx_mbps": 0.4,    // aktueller Datenverkehr, null beim ersten Abruf
    "speedtest": {"down_mbps": 245.6, "up_mbps": 38.2, "ts": 1792229000}   // null ohne Speedtest
  }
}
```

### `POST /tray/v1/report`

```json
{
  "occurred_at": 1792229400,            // Unix-Sekunden (UTC) – „Jetzt“ oder die gewählte Uhrzeit
  "category": "slow",                   // siehe Tabelle
  "duration": "minutes",                // siehe Tabelle
  "description": "Teams-Call ruckelt",  // optional, höchstens 1000 Zeichen
  "user": "KUNDE\\mmuster"              // angemeldeter Windows-Benutzer
}
```

Antwort `202 {"ok": true, "delivered": true}` (sofort zugestellt) oder `202 {"ok": true, "delivered": false}`
(gespeichert, wird nachgeliefert). Fehler: `400 {"error": "…"}` mit deutschem Text, `409` wenn die Probe nicht
registriert ist.

## Server-Schnittstelle (Dienst → Server)

`POST /api/probe/v1/report`, Authentifizierung wie alle Probe-Aufrufe (`Authorization: Bearer <Probe-Token>`).

```json
{
  "report_id": "6f1c…",                 // UUID der Probe – macht das Nachliefern idempotent
  "occurred_at": 1792229400,
  "category": "slow",
  "duration": "minutes",
  "description": "Teams-Call ruckelt",
  "user": "KUNDE\\mmuster",
  "hostname": "PC-BUCHHALTUNG-03"
}
```

Antwort `201 {"id": 17}` (neu) oder `200 {"id": 17}` (dieselbe `report_id` gab es schon). `400` bei ungültigen Werten:
`occurred_at` muss zwischen jetzt − 7 Tagen und jetzt + 5 Minuten liegen, `category`/`duration` aus den Listen,
Texte werden gekürzt (Beschreibung 1000, Benutzer 128, Hostname 255 Zeichen).

| `category` | Anzeige |
| --- | --- |
| `no_connection` | Keine Verbindung / Internet weg |
| `slow` | Langsam / lange Ladezeiten |
| `dropouts` | Aussetzer / Verbindungsabbrüche |
| `voice_video` | Telefonie oder Video gestört |
| `application` | Bestimmte Anwendung oder Website betroffen |
| `other` | Sonstiges |

| `duration` | Anzeige |
| --- | --- |
| `unknown` | Unbekannt |
| `short` | Kurz (unter 1 Minute) |
| `minutes` | Einige Minuten (1–15 Minuten) |
| `long` | Länger (über 15 Minuten) |
| `ongoing` | Dauert noch an |

## Web-UI-Daten

`GET /api/reports?from=<unix>&to=<unix>[&probe_id=<id>][&site_id=<id>]` (angemeldet, alle Rollen) liefert die Meldungen
für die Graph-Markierungen:

```json
{"reports": [{"id": 17, "ts": 1792229400, "probe_id": 4, "probe": "PC-BUCHHALTUNG-03", "site": "Zentrale",
              "category": "slow", "category_label": "Langsam / lange Ladezeiten", "duration_label": "Einige Minuten (1–15 Minuten)",
              "description": "Teams-Call ruckelt", "user": "KUNDE\\mmuster", "status": "open"}]}
```

## Installation

- **`WachtlSetup`, Rolle Probe** legt `wachtl-tray.exe` neben `wachtl-probe.exe`, trägt es unter
  `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (Wert `Wachtl Tray`) für alle Benutzer ein und startet es
  nach der Installation für den angemeldeten Benutzer. Abschalten für alle: Setup-Parameter `/NoTray` – das Setup merkt
  sich die Wahl auch für spätere Updates, `/Tray` schaltet das Symbol wieder ein.
- **Rolle Server** genauso (Wert `Wachtl Server Tray`, Symbol mit „Dashboard öffnen“).
- **Update** (auch unbeaufsichtigt) beendet laufende Symbole nicht: die alte `wachtl-tray.exe` wird umbenannt, die neue
  gilt ab der nächsten Anmeldung.
- **Deinstallation** beendet alle `wachtl-tray.exe`-Prozesse und entfernt den Autostart-Eintrag.
