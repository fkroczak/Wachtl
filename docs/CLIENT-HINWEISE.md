# Client-Hinweise: Wachtl erkennt Probleme am PC selbst

Ausfälle von Gateway, Internet und Zielen, jeder verlorene Ping und Netzwerkwechsel erscheinen ebenfalls als
Sprechblase – siehe [BENACHRICHTIGUNGEN.md](BENACHRICHTIGUNGEN.md). Diese Seite beschreibt die Hinweise zu
Netzwerkkarte, Kabel, Treiber und IP-Einstellungen.

Die Probe prüft auf jedem PC laufend Netzwerkkarte, Kabel, Treiber und IP-Einstellungen. Findet sie etwas,
das Störungen verursacht, erscheint neben der Uhr eine **Sprechblase** mit klarer Meldung und Lösungsvorschlag.
Derselbe Hinweis geht an den Wachtl-Server und steht dort auf der Übersicht, beim Standort und bei der Probe.

```
Netzwerkkarte, WMI, Ereignisprotokoll ──alle 5 s──▶ Wachtl-Dienst ──▶ Server (POST /api/probe/v1/findings)
                                                        │ lokal, 127.0.0.1
                                                        ▼
                                              Tray-Symbol: Abfrage alle 5 s, Sprechblase
```

## Was erkannt wird

Nur echte Netzwerkkarten zählen. Virtuelle Adapter (Hyper-V, VMware, VirtualBox, VPN, TAP, WireGuard,
WAN-Miniport, Bluetooth, Npcap) werden ignoriert.

| Hinweis | Stufe | Erkannt an |
|---|---|---|
| **Netzwerkkabel getrennt** | kritisch | Eine LAN-Karte, die verbunden war, hat keinen Link mehr. Läuft die Verbindung über eine andere Karte weiter (z. B. Notebook vom Dock genommen): nur Info, keine Sprechblase |
| **WLAN getrennt** | Warnung | WLAN-Adapter verliert die Verbindung, und kein Kabel übernimmt |
| **Netzwerk langsamer** (Link-Geschwindigkeit gesunken) | Warnung | z. B. 1 Gbit/s → 100 Mbit/s. Typisch: Kabel mit fehlenden Adern, Switch-Port, Energiesparen |
| **Langsame Netzwerkverbindung** | Info (100 Mbit/s, keine Sprechblase), unter 100 Mbit/s kritisch | LAN-Karte seit 30 s unter 1 Gbit/s verbunden. 100 Mbit/s ist an Telefonen und USB-Adaptern üblich, daher nur im Web-UI |
| **Netzwerkverbindung bricht wiederholt ab** | Warnung | mindestens 3 Abbrüche in 10 min |
| **Netzwerkkarte deaktiviert** | kritisch, Warnung wenn eine andere Verbindung übernimmt | Eine Karte, die verbunden war, wird in Windows oder im Geräte-Manager deaktiviert |
| **Netzwerkkarte entfernt** | wie „Kabel getrennt“ | Eine Karte, die verbunden war, ist verschwunden: USB-Adapter oder Dockingstation abgezogen, Treiber abgemeldet. Übernimmt eine andere Karte, nur Info |
| **Problem mit der Netzwerkkarte oder ihrem Treiber** | kritisch | Geräte-Manager meldet einen Fehlercode (z. B. 10, 28, 31, 43). „Deaktiviert“ ist ein eigener Hinweis, kein Treiberfehler |
| **Treiber setzt die Netzwerkkarte wiederholt zurück** | Warnung | mindestens 2 Ereignisse NDIS 10400 in 15 min |
| **Keine IP-Adresse vom DHCP-Server** | kritisch | Karte verbunden, aber nur 169.254.x.x |
| **Kein Standard-Gateway** | Warnung | IP-Adresse vorhanden, aber kein Gateway |
| **Viele fehlerhafte Datenpakete** | Warnung | mehr als 50 fehlerhafte oder verworfene Pakete pro Minute und über 0,5 % |

Damit kurze Zustände keinen Fehlalarm auslösen, muss ein Zustand etwa 10 s bestehen. „Kabel getrennt“ geht sofort als
Info an den Server und wird nach 15 s ohne andere Verbindung kritisch (Sprechblase). Nach Ruhezustand oder
Standby zählen 60 s lang keine Abbrüche, Geschwindigkeitswechsel und Rücksetzungen – die Karte handelt den Link neu aus.
Nach dem Beheben meldet Wachtl „wieder verbunden“ bzw. „wieder normal“ mit der Dauer der Störung. Kritische Hinweise
und Verbindungsverlust (Kabel, WLAN, Karte deaktiviert) erscheinen jedes Mal. Andere Warnungen und Info-Einträge für
dieselbe Karte erscheinen frühestens nach 30 min erneut, außer sie werden schlimmer. Ändert sich eine Karte, liest die
Probe den Geräte-Manager sofort neu.

## Sprechblase auf dem PC

- Wachtl zeigt den Hinweis in einem eigenen kleinen Fenster unten rechts über der Uhr, nicht als
  Windows-Benachrichtigung. So erscheint er auch unter Windows 11 bei „Nicht stören“, ausgeschalteten
  App-Benachrichtigungen und in der ersten Stunde nach der Anmeldung. Das Fenster nimmt keinen Fokus, bleibt
  stehen, solange die Maus darauf liegt, und schließt sich sonst nach 15 s. Bei Spielen im Vollbild und
  Präsentationen wartet der Hinweis, bis sie beendet sind.
- Rot für kritisch, Gelb für Warnung, Blau für Info und Entwarnung. Jeder neue Hinweis erscheint, auch „Info“
  (z. B. Kabel getrennt, während das WLAN übernimmt).
- Solange ein Hinweis aktiv ist, trägt das Wachtl-Symbol einen roten bzw. gelben Punkt.
- **Test-Hinweis anzeigen** im Menü prüft, ob Hinweise auf diesem PC sichtbar sind.
- Text: eine Kurzfassung mit Problem und Lösungsvorschlag (passt in die 255 Zeichen, die Windows erlaubt). Ein Klick zeigt die ausführliche Fassung.
- Im Menü des Symbols zeigt **Netzwerk-Hinweise …** alle aktiven Hinweise.
- Höchstens eine Sprechblase alle 15 s; mehrere gleichzeitig werden zusammengefasst.
- Auch ohne Verbindung zum Server: Die Sprechblase kommt vom Dienst auf dem PC selbst.
- Antwort des Dienstes je Eintrag zusätzlich `event` (einmaliges Ereignis, nicht in der Liste) und `quiet`
  (nur Liste, keine Sprechblase). Die Meldung an den Server
  wird gespeichert (`findings-pending.json`, bis 200 Einträge) und nachgeliefert, sobald das Netz wieder da ist.

## Einstellungen

**Verwaltung › Messung › Client-Hinweise**

| Einstellung | Standard |
|---|---|
| Netzwerkkarte und Kabel auf den PCs überwachen | an |
| Hinweis als Sprechblase auf dem PC anzeigen | an |

Mit „überwachen“ aus erkennt und meldet die Probe nichts. Mit „Sprechblase“ aus gehen die Hinweise nur an den
Server. Die Einstellung erreicht die Probes mit dem nächsten Abruf der Konfiguration. Die Sprechblase braucht das
Wachtl-Symbol (Setup ohne `/NoTray`).

## Schnittstelle (Probe → Server)

`POST /api/probe/v1/findings`, Token der Probe, höchstens 50 Hinweise je Aufruf:

```json
{"findings": [{
  "finding_id": "8f6c…", "kind": "link_speed_changed", "severity": "warning", "state": "active",
  "adapter": "Ethernet", "adapter_description": "Intel(R) Ethernet Connection I219-V",
  "title": "Netzwerk langsamer: 1 Gbit/s → 100 Mbit/s", "message": "…", "solution": "…",
  "details": {"old_mbps": "1000", "new_mbps": "100"}, "detected_at": 1792220000, "resolved_at": null
}]}
```

- `kind`: `cable_unplugged`, `wifi_disconnected`, `link_speed_changed`, `link_speed_low`, `link_flapping`,
  `driver_error`, `nic_reset`, `apipa`, `no_gateway`, `nic_errors`, `adapter_disabled`, `adapter_removed`. Unbekannte Arten nimmt der Server an.
- `finding_id` bleibt für ein Vorkommen gleich: aktiv senden, später behoben mit derselben ID. Der Server
  aktualisiert. Ein behobener Hinweis wird durch eine verspätete Nachlieferung nicht wieder aktiv.
- Beim Beheben schickt die Probe den Entwarnungstext als `title`/`message` und das ursprüngliche Problem in
  `details.problem`. Der Server behält Problem und Lösungsvorschlag und zeigt die Entwarnung zusätzlich an.
- Antwort 200 `{"stored", "new", "rejected", "errors"}`; ungültige Einträge werden einzeln übersprungen.
  400 nur bei unbrauchbarem Körper; die Probe verwirft die Sendung dann.

Lokal fragt das Tray-Symbol `GET http://127.0.0.1:47251/tray/v1/findings?since=<seq>` ab (Kopfzeile
`X-Wachtl-Tray: 1`, wie bei den Störungsmeldungen). Antwort: `{"notify", "latest_seq", "findings": [...]}`.

Liste für eigene Auswertungen: `GET /api/v1/client-findings?days=7[&probe=<id>]`.

## Grenzen

- Nur Windows-Probes. Die Server-Probe (Wachtl-Server) erkennt keine Client-Hinweise.
- Duplex (Halb-/Vollduplex) liest Windows nicht zuverlässig aus. Ein Duplex-Fehler zeigt sich als
  „Viele fehlerhafte Datenpakete“ oder niedrige Geschwindigkeit.
- Fehlercodes und Rücksetz-Ereignisse kommen aus WMI und dem Ereignisprotokoll. Ist eines davon gesperrt, fehlen
  nur diese Hinweise; die übrigen arbeiten weiter (Eintrag im Log der Probe).
