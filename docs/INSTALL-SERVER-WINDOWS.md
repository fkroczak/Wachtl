# Installation: Wachtl Server auf Windows Server

Alternative zur Linux-VM mit Docker. Ein Setup-Assistent richtet alles ein; danach läuft Wachtl als
Windows-Dienst **Wachtl Server**. Funktionen und Web-UI sind identisch mit der Linux-Variante.

## Voraussetzungen

| Punkt | Wert |
| --- | --- |
| Betriebssystem | Windows Server 2016, 2019, 2022 oder 2025 (x64), auch Windows 10/11 für Tests |
| Hardware | bis 25 Probes: 2 vCPU, 4 GB RAM, 10 GB frei · bis 100 Probes: 4 vCPU, 8 GB RAM, 40 GB frei (Richtwerte bei je 10 Zielen, 30 Tage Rohdaten; Details: [BETRIEB.md](BETRIEB.md#größe-und-speicherplatz)) |
| Rechte | lokaler Administrator für die Installation |
| Ports | eingehend 443 (HTTPS) und optional 80 (Umleitung) – frei wählbar, falls IIS sie belegt |
| Sonstiges | nichts – Python, Datenbank und alle Dienste bringt das Setup mit, kein Docker, kein IIS |

## Installation mit dem Assistenten

`WachtlSetup-0.9.5.exe` als Administrator starten – dasselbe Setup wie für die Probes – und den Seiten folgen:

1. **Rolle** – „Wachtl-Server“ wählen (Standard ist Probe). Programmordner: `C:\Program Files\Wachtl Server`.
2. **Server-Adresse** – DNS-Namen, unter denen Probes und Browser den Server erreichen (mit Komma getrennt; der erste wird die Adresse im Browser). Die IP-Adressen des Servers ergänzt das Setup selbst – Probes weichen darauf aus, wenn ein Name am Standort nicht auflösbar ist. HTTPS-Port (Standard 443) und HTTP-Port für die Umleitung (Standard 80, 0 = aus). Der Assistent prüft, ob die Ports frei sind.
3. **Administrator** – Passwort für die Anmeldung als `admin`.
4. **Benachrichtigungen** (optional) – E-Mail über SMTP und/oder Microsoft-Teams-Webhook. Später im Web-UI änderbar.
5. **Daten und Aufbewahrung** – Datenordner (Standard `C:\ProgramData\Wachtl Server`, für größere Installationen gern eine eigene Platte), Aufbewahrung der Rohdaten (Tage) und des Verlaufs (Monate).
6. **Bereit** – Zusammenfassung, dann **Installieren**.

Das Setup erledigt anschließend:

- Dateien kopieren (Python 3.12, VictoriaMetrics, Alertmanager, WinSW, Wachtl)
- Wachtl-CA (10 Jahre, per Namensbeschränkung nur für diese Namen und IP-Adressen) und Server-Zertifikat
  (397 Tage, erneuert sich im laufenden Dienst selbst) erzeugen, SPKI-Pin berechnen
- Wachtl-CA unter **Vertrauenswürdige Stammzertifizierungsstellen** (Computer, Anzeigename „Wachtl Server“)
  ablegen – Browser auf dem Server öffnen Wachtl ohne Warnung. Die PCs mit Probe erledigt das Probe-Setup,
  alle übrigen Geräte: [Zertifikat auf anderen Geräten](BETRIEB.md#zertifikat-im-browser)
- Datenbank anlegen, Standard-Checks (Gateway, 8.8.8.8, 1.1.1.1) und Standard-Alarme einrichten, Admin anlegen
- Dienst „Wachtl Server“ unter dem virtuellen Konto `NT SERVICE\WachtlServer` (verzögerter Autostart, Neustart nach Absturz)
- Datenordner auf SYSTEM, Administratoren und das Dienstkonto beschränken
- Firewall-Regeln für HTTPS/HTTP (alle Netzwerkprofile, nur diese Ports), iperf3 (TCP+UDP 5201) und den
  RTP-Reflektor für Sprachtests (UDP 5004; unbeaufsichtigt `/RtpPort=…`, 0 = aus)
- Geplante Aufgabe „Wachtl Server Backup“ täglich 02:15 Uhr
- Dienst starten und warten, bis er antwortet

Die letzte Seite zeigt Adresse und **SPKI-Pin** (zum Kopieren). Beides steht auch in `setup-info.txt` im Datenordner.
Im Startmenü liegen „Wachtl Dashboard“, „Wachtl Status“, „Zugangsdaten“, „Logdateien“ und „Setups für die Probes“.
Das Setup legt eine Kopie von sich selbst auf dem Server ab: Im Web-UI erzeugt **Verwaltung › Probes registrieren**
daraus mit einem Klick ein vorbelegtes Setup für die PCs (alle Adressen, Pin und Token eingetragen).

## Unbeaufsichtigte Installation

```powershell
.\WachtlSetup-0.9.5.exe /VERYSILENT /SUPPRESSMSGBOXES /LOG=C:\Temp\wachtl-setup.log /Role=Server `
    /Hostnames="wachtl.kunde.local" /AdminPassword="…" `
    /HttpsPort=443 /HttpPort=80 /DataDir="D:\Wachtl" /RawDays=30 /AggMonths=13 `
    /EmailTo=it@kunde.de /EmailFrom=wachtl@kunde.de /SmtpHost=mail.kunde.de:587 /TeamsUrl=https://…
```

Exit-Code 0 = Server läuft; 10 = Dateien installiert, Einrichtung fehlgeschlagen (Grund in `<Daten>\logs\setup.log`).

## Update

Neue `WachtlSetup-x.y.z.exe` starten (auch über eine Installation mit dem alten `WachtlServerSetup`). Das Setup erkennt die Installation, überspringt die Eingabeseiten,
stoppt den Dienst, ersetzt die Programmdateien und startet wieder. Datenbank-Migrationen laufen beim Start automatisch.
Daten, Zertifikat (und damit der Pin der Probes) und Einstellungen bleiben erhalten. Vorher eine Sicherung zu ziehen schadet nie:
`wachtl-server.cmd backup`.

## Verwaltung

PowerShell **als Administrator**:

```powershell
$w = "C:\Program Files\Wachtl Server\wachtl-server.cmd"
& $w status                     # Dienst, Ports, Zertifikat, Speicherbedarf
& $w backup                     # Sicherung nach <Daten>\backups (14 Tage aufbewahrt)
& $w restore D:\wachtl-20261016-021500.zip    # stoppt den Dienst, spielt zurück, startet
& $w create-user admin          # Passwort zurücksetzen / Benutzer anlegen
                                # (dasselbe: Startmenü › Wachtl › Admin-Passwort zurücksetzen)
& $w create-token --site Zentrale --uses 20   # Enrollment-Token ohne Web-UI
& $w probes                     # registrierte Probes und ob sie online sind
& $w logs                       # Logordner öffnen
Restart-Service WachtlServer
```

Der Server misst selbst mit (Server-Probe, Teilprozess `serverprobe`): dieselben Checks wie die Probes, sichtbar als
Probe „Server“ am Standort „Wachtl-Server“. Abschalten: in `wachtl.env` `SERVER_PROBE=0` und den Dienst neu starten,
oder die Probe im Web-UI deaktivieren.

Konfiguration (Ports, Aufbewahrung) steht in `<Daten>\config\wachtl.env`. Nach Änderungen `Restart-Service WachtlServer`.
Neue Servernamen: Setup erneut ausführen ist der einfachste Weg; alternativ `WACHTL_HOSTNAMES` anpassen – das Zertifikat
wird beim nächsten Start mit demselben Schlüssel neu ausgestellt, der Pin bleibt gleich. Die Wachtl-CA im
Stammspeicher des Servers aktualisiert nur das Setup.

### Tray-Symbol

Neben der Uhr erscheint für jeden angemeldeten Benutzer das Wachtl-Symbol mit **Problem melden …**, **Über Wachtl**,
**Dashboard öffnen** und **Beenden**. Meldungen vom Server laufen über die Server-Probe (lokal auf `127.0.0.1:47251`) und
erscheinen wie die der Clients unter „Meldungen“. Ohne Symbol installieren: Setup-Parameter `/NoTray`.
Details: [STOERUNGSMELDUNGEN.md](STOERUNGSMELDUNGEN.md).

## Ordner und Logs

| Pfad | Inhalt |
| --- | --- |
| `C:\Program Files\Wachtl Server\` | Programm (python, app, bin, service), `wachtl-server.cmd` |
| `<Daten>\config\wachtl.env` | Ports, Aufbewahrung, Geheimnisse |
| `<Daten>\certs\` | `wachtl.key`, `wachtl.crt` (Server-Zertifikat mit Kette), `wachtl-ca.key`, `wachtl-ca.crt` (Wachtl-CA, auch unter `https://<Server>/zertifikat`) |
| `<Daten>\data\wachtl.db` | SQLite-Datenbank (Standorte, Probes, Checks, Benutzer, Alarme, Audit) |
| `<Daten>\vm-raw\`, `<Daten>\vm-agg\` | Messwerte: 1-s-Rohdaten und 1-min-Verlauf |
| `<Daten>\logs\` | `supervisor.log`, `web.log`, `serverprobe.log`, `vm-raw.log`, `vm-agg.log`, `vmalert.log`, `alertmanager.log`, `setup.log`, `backup.log` |
| `<Daten>\serverprobe\` | Registrierung der Server-Probe (Token) |
| `<Daten>\backups\` | tägliche Sicherungen |

## Unterschiede zur Linux-Variante

| | Linux (Docker) | Windows |
| --- | --- | --- |
| Datenbank | PostgreSQL | SQLite (bis etwa 100 Probes; darüber die Linux-Variante mit PostgreSQL) |
| TLS | Traefik | im Collector (cheroot), TLS ≥ 1.2, HSTS |
| Prozesse | ein Container je Dienst | ein Windows-Dienst, der alle Teilprozesse überwacht und neu startet |
| Einrichtung | `setup.sh` | Setup-Assistent |
| Sicherung | `backup.sh` per Cron | geplante Aufgabe, `wachtl-server.cmd backup` |

Intern lauschen die Teilprozesse nur auf 127.0.0.1 (8427 Collector-intern, 8428/8429 VictoriaMetrics, 8880 vmalert, 9093 Alertmanager).
Sind diese Ports belegt, meldet das Setup das; sie lassen sich in `wachtl.env` (`PORT_…`) ändern.

## Fehlersuche

| Symptom | Prüfen |
| --- | --- |
| Setup meldet „Port 443 belegt“ | IIS oder andere Software. Anderen HTTPS-Port wählen (z. B. 8443) oder die IIS-Bindung entfernen |
| Dienst startet, Web-UI nicht erreichbar | `wachtl-server.cmd status`, dann `logs\web.log` und `logs\supervisor.log` |
| Graphen leer | `logs\vm-raw.log`; Probes senden? (Übersicht › Letzter Kontakt) |
| Keine Alarme | `logs\vmalert.log`, `logs\alertmanager.log`; Verwaltung › Benachrichtigungen › Testnachricht |
| Dienst startet nicht, Fehler 1069 | Eine Domänen-GPO überschreibt „Anmelden als Dienst“. `NT SERVICE\ALL SERVICES` dort wieder aufnehmen |
| Deinstallation | Programme und Features › Wachtl Server, unbeaufsichtigt `unins000.exe /VERYSILENT /SUPPRESSMSGBOXES [/REMOVEDATA]`. Entfernt Dienst (samt Server-Probe), Firewall-Regeln – auch von Windows für `python.exe`/`iperf3.exe` angelegte –, die geplante Sicherung und den Registry-Eintrag und prüft danach, dass kein Port mehr lauscht. Am Ende fragt das Setup, ob der Datenordner (Datenbank, privater Schlüssel, Sicherungen) gelöscht werden soll; `/REMOVEDATA` tut das unbeaufsichtigt |
