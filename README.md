# Wachtl

Netzwerk-Monitoring für Kunden mit mehreren Standorten: Windows-PCs und -Server messen als Dienst
Latenz, Paketverlust und Jitter (Ping im 1-s-Takt), den Pfad ins Internet Hop für Hop, die Bandbreite
(iperf3 intern, HTTP/iperf3 ins WAN) und die Sprachqualität (RTP-Sprachtest mit MOS). Ein zentraler Server beim Kunden speichert, wertet aus, zeigt Graphen,
erkennt Ausfälle mit Ursache und alarmiert per E-Mail oder Microsoft Teams. Alles ist im Web-UI einstellbar.

Der Server läuft wahlweise als **Linux-VM mit Docker** oder als **Windows-Dienst** (Setup-Assistent, kein Docker).

```
Windows-Probes (C#-Dienst) ──HTTPS, nur ausgehend──▶ Traefik ─▶ Flask-Collector + Web-UI ─▶ PostgreSQL
                                                                     │
                                                                     ▼
                                              VictoriaMetrics raw (1 s, 30 Tage)
                                                       │ vmalert: 1-min-Aggregate + Alarmregeln
                                                       ▼
                                              VictoriaMetrics agg (1 min, 13 Monate)
                                              Alertmanager ─▶ E-Mail / Teams, Historie zurück an Flask
```

## Stand: 0.9

| Bereich | Enthalten |
| --- | --- |
| Probe | Windows-Dienst (.NET 8, eine .exe), Ping 1–60 s, Gateway-Erkennung, Jitter, lokaler Puffer (SQLite, 7 Tage), Enrollment mit Token, Zertifikats-Pinning, Proxy |
| Server | Probe-API, Ingest nach VictoriaMetrics, zentrale Check-Verwaltung, Rollen (Admin, Operator, Nur lesen), Audit-Log |
| Dashboard | Übersicht, Standort-Matrix (alle Probes im Vergleich), Probe-Detail, Ziel-Detail mit Graph (1 h – 30 Tage) und Statistik (1 min – 24 h) |
| Alarme | Probe offline, Ziel nicht erreichbar (3 Fehler in Folge), WAN gestört, Paketverlust, Latenz; Bestätigen = Stummschalten; Historie |
| Betrieb | Linux: `setup.sh`, `backup.sh`/`restore.sh` · Windows: Setup-Assistent, `wachtl-server.cmd` |
| Installation | Ein Setup `WachtlSetup` für Probe (Standard) und Server. Im Web-UI „Setup herunterladen“: alle Server-Adressen (Name und IP), Pin und Token eingebaut – auf dem PC nur „Installieren“. Ausweichen auf die IP, wenn ein Name nicht auflösbar ist; Anmeldung wird nachgeholt, wenn der Server bei der Installation nicht erreichbar ist |
| Marke | Flaches Logo mit Wachtel-Umriss (Wachtelbraun/Ocker), Quelle `brand/render.py`; Oberfläche im UniFi-Stil: Seitenleiste, helles Grau, weiße Karten, kräftiges Blau als Akzent |
| Benachrichtigungen | E-Mail und Teams im Web-UI einstellbar, mit Testnachricht |
| Pfade (0.3) | Traceroute + Dauerpings auf jeden Hop, MTR-Tabelle mit Bewertung (echter Verlust vs. ICMP-Drosselung, Latenzsprung), Pfadverlauf, Alarm bei Pfadwechsel |
| Bandbreite (0.3) | iperf3 Probe ↔ Server und Probe ↔ Probe (TCP/UDP), WAN per HTTP oder iperf3; Zeitplan, Zeitfenster, Wochentage, „Jetzt messen“, Schwellwert-Alarm |
| Zustand (0.4) | Übersicht, Standort und Probe bewerten jede Check-Art (Ping, Pfad, iperf3, WAN); „Messungen mit Problemen“ zeigt jede fehlgeschlagene, auffällige oder ausbleibende Messung mit Grund |
| Server-Probe (0.4) | Der Server misst selbst – dieselben Checks wie die Probes, über das Probe-API, ohne offenen Port |
| Standardpaket (0.4) | Ping, Traceroute, iperf3 und Speedtest mit einem Klick; Rollout-Anleitung [docs/ROLLOUT.md](docs/ROLLOUT.md) |
| Deinstallation (0.4) | Probe meldet sich am Server ab, alle Firewall-Regeln und das Token werden entfernt; Server Windows/Linux (`deploy/uninstall.sh`) mit Prüfung auf offene Ports |
| Tray-Symbol (0.6) | Symbol neben der Uhr auf Clients und Windows-Server: Problem melden, Über, Beenden ([docs/STOERUNGSMELDUNGEN.md](docs/STOERUNGSMELDUNGEN.md)) |
| Geführte Einrichtung (0.7) | Verwaltung › Probes einrichten: Standort, Messungen, Alarmierung und Setup für die PCs in vier Schritten, mit Standards vorbelegt |
| Kurzausfälle (0.8) | Ziel und WAN gelten ab 5 s ohne Antwort als gestört, sekundengenaue Dauer in der Ausfallübersicht |
| Client-Hinweise (0.8) | Probe erkennt Kabel getrennt, Link-Geschwindigkeit, Treiberfehler, DHCP/Gateway, Paketfehler – Sprechblase mit Lösung auf dem PC, Anzeige im Web-UI ([docs/CLIENT-HINWEISE.md](docs/CLIENT-HINWEISE.md)) |
| Störungsmeldungen (0.6) | Benutzer melden Netzprobleme (Jetzt oder einstellbare Uhrzeit); Seite „Meldungen“, Übersicht und Markierung zum Zeitpunkt in allen Graphen der Probe |
| Sprache (0.9) | RTP-Sprachtest wie ein Telefonat (G.711/G.729) zum Wachtl-Server, zu einer anderen Probe oder einem eigenen Reflektor: MOS, Laufzeit, Jitter und Verlust je Richtung, Alarm bei schlechter Sprachqualität ([docs/MESSUNGEN.md](docs/MESSUNGEN.md#sprache-rtpvoip)) |
| PDF-Bericht (1.0) | Alle Störungen eines Zeitraums als PDF für den Provider: Einschätzung, wo das Problem liegt, Zeitstrahl mit Kurzausfällen, Leitungsschwankungen, Störungsliste, Pfadanalyse, Netzwerkscan |
| Netzwerkscan (1.0) | Geräte im Kundennetz, Anwesenheit, unregelmäßige Geräte, IP-Konflikte, Portscan mit Diensterkennung und Links zum Verbinden ([docs/NETZWERKSCAN.md](docs/NETZWERKSCAN.md)) |
| Switch-Topologie (1.0) | SNMPv1/v2c/v3 je Switch mit Assistent (Zugang testen, verschlüsselt speichern); Baum Internet → Gateway → Switches → Geräte mit Ports und Geschwindigkeit, Switch-Frontansicht mit Port-Details und Probe-Messwerten, Probleme (Port-Fehler, langsame Uplinks, Kabelkreise, nicht verwaltete Switches), Pfad eines Geräts bis ins Internet; Verlauf mit Zeitleiste am Baum, Chronik, Port-Verlauf und Störung im Kontext (Port-Status jede Minute) ([docs/TOPOLOGIE.md](docs/TOPOLOGIE.md)) |
| Benachrichtigungen (1.0) | Jede Störung sofort sehen: Server erkennt Ausfälle und **jeden verlorenen Ping** aus den Rohdaten, auch nachgelieferte; Hinweis im Browser, Tray auf PC und Server, E-Mail/Teams ([docs/BENACHRICHTIGUNGEN.md](docs/BENACHRICHTIGUNGEN.md)) |
| Ausfälle (0.3) | Übersicht mit Dauer und Ursache (Probe/Standort, Gateway/LAN, WAN, Ziel), Folgestörungen zusammengefasst |

Alle Mess-Einstellungen: [docs/MESSUNGEN.md](docs/MESSUNGEN.md).

Nächste Phasen: DNS-, HTTP/HTTPS- und TCP-Checks, MTU, Berichte als CSV, Heatmaps, mTLS und automatische Probe-Updates.
Konzept für die automatische Fehlerdiagnose mit Lösungsvorschlägen: [docs/DIAGNOSE-KONZEPT.md](docs/DIAGNOSE-KONZEPT.md).

## Download

Fertige, in der CI auf Windows Server getestete Setups liegen im Repository unter
[`releases/`](releases/) – je Version ein Ordner mit `WachtlSetup-<Version>.exe` (Probe und Server)
und `SHA256SUMS.txt`. Bis 0.4 waren es zwei Setups. Auf GitHub die Datei öffnen und **Download raw file** wählen.

## Ordner

| Pfad | Inhalt |
| --- | --- |
| `server/` | Flask-Collector und Dashboard (Python 3.12), Tests unter `server/tests` |
| `probe/` | Windows-Probe (C# / .NET 8) und xUnit-Tests, `build.ps1` |
| `server/wachtl/serverprobe/` | Server-Probe: der Server misst selbst (Ping, Pfad, iperf3, HTTP-Speedtest, Sprache) |
| `server/wachtl/rtp/` | RTP-Sprachtest: Protokoll, MOS-Berechnung, Reflektor (`python -m wachtl.rtp`); Gegenstück der Probe in `probe/Wachtl.Probe/Rtp/` |
| `deploy/` | Linux: Docker-Compose-Stack, `setup.sh`, `uninstall.sh`, Backup und Restore |
| `windows/` | Setup für Probe und Server (`WachtlSetup.iss`), `build-server.ps1`, `wachtl-server.cmd`, `assets/` (Symbole, Assistenten-Bilder) |
| `probe/Wachtl.Tray/` | Tray-Symbol `wachtl-tray.exe` (.NET Framework 4.6.2): Problem melden, Über, Beenden |
| `brand/` | Logo-Quelle und Generator für SVG, PNG, ICO und Assistenten-Bilder |
| `server/wachtl/win/` | Windows-Laufzeit: Dienst-Supervisor, HTTPS-Server, Einrichtung, Backup |
| `docs/` | Installationsanleitungen, Betrieb, Sicherheit, API, UI-Qualitäts-Guardrails |

## Schnellstart

1. Server, eine von zwei Varianten:
   - Linux-VM mit Docker: [docs/INSTALL-SERVER.md](docs/INSTALL-SERVER.md) – `sudo ./setup.sh wachtl.kunde.local`
   - Windows Server: [docs/INSTALL-SERVER-WINDOWS.md](docs/INSTALL-SERVER-WINDOWS.md) – `WachtlSetup-0.9.6.exe` starten, Rolle „Wachtl-Server“
2. Bauen: GitHub Actions erzeugt `wachtl-probe-win-x64` und `wachtl-server-setup` (testet das Setup dabei auf einem
   echten Windows-Server). Lokal: `probe\build.ps1` bzw. `windows\build-server.ps1` auf einem Windows-Rechner.
3. Probes installieren: [docs/INSTALL-PROBE.md](docs/INSTALL-PROBE.md) – kompakt für den Rollout beim Kunden: [docs/ROLLOUT.md](docs/ROLLOUT.md)
4. Betrieb, Backup, Updates, Sicherheit, Alarme: [docs/BETRIEB.md](docs/BETRIEB.md)

## Entwicklung

```bash
cd server
pip install -r requirements-dev.txt
python -m pytest -q                              # Server-Tests inkl. Windows-Logik und UI-Guardrails

# Lokal ohne Docker: Fake-VictoriaMetrics + SQLite
python devtools/fake_vm.py 18428 &
export WACHTL_SECRET_KEY=dev WACHTL_DATABASE_URL=sqlite:///dev.db WACHTL_RULES_DIR=./rules \
       WACHTL_VM_RAW_URL=http://127.0.0.1:18428 WACHTL_VM_AGG_URL=http://127.0.0.1:18428 \
       WACHTL_VMALERT_URL= WACHTL_ALERTMANAGER_URL= WACHTL_COOKIE_SECURE=0 \
       WACHTL_INITIAL_ADMIN_PASSWORD=admin-passwort-123
flask --app wachtl init && flask --app wachtl run
# Enrollment-Token im UI erzeugen, dann Demodaten einspielen:
python devtools/simulate_probes.py http://127.0.0.1:5000 <token> 2
```

Web-UI: Barrierefreiheit, Tastatur, Performance-Budgets und Formular-Konventionen stehen in
[docs/quality-guardrails.md](docs/quality-guardrails.md); Browser-Tests unter `server/e2e` (`e2e/start-server.sh`, dann `npx playwright test`).

```powershell
cd probe
dotnet test Wachtl.Probe.Tests
.\build.ps1        # erzeugt ..\dist\probe\wachtl-probe.exe + iperf3 (das Setup baut windows\build-server.ps1)
```
