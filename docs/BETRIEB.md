# Betrieb: Backup, Updates, Sicherheit, Alarme

Die Befehle in diesem Dokument gelten für die Linux-Variante. Windows: siehe [INSTALL-SERVER-WINDOWS.md](INSTALL-SERVER-WINDOWS.md)
(Abschnitte Verwaltung und Update); Sicherheitskonzept und Alarme gelten für beide.

## Größe und Speicherplatz

Richtwerte bei je 10 Zielen pro Probe (Pings im 1-s-Takt, Pfad-Checks mit Hop-Pings), 30 Tage Rohdaten und 13 Monate
Verlauf. Hochgerechnet aus dem Basiswert 25 Probes ≈ 10 GB; der Platz wächst linear mit Probes × Zielen × Aufbewahrung.

| Probes | CPU / RAM | Platz für Messwerte | Server |
| --- | --- | --- | --- |
| bis 25 | 2 vCPU, 4 GB | 10 GB | Windows oder Linux |
| bis 100 | 4 vCPU, 8 GB | 40 GB | Windows (SQLite) oder Linux |
| bis 300 | 8 vCPU, 16 GB | 120 GB | Linux mit PostgreSQL |

Läuft die Platte voll, nimmt VictoriaMetrics keine Werte mehr an; die Probes puffern 7 Tage, danach gehen Messwerte
verloren. Der Windows-Setup-Assistent warnt bei weniger als 20 GB freiem Platz. Vor einem großen Rollout den
tatsächlichen Verbrauch nach einigen Tagen im Datenordner (`vm-raw`, `vm-agg`) prüfen und hochrechnen.

## Backup

| Was | Wie | Wichtig weil |
| --- | --- | --- |
| PostgreSQL (Standorte, Probes, Checks, Benutzer, Benachrichtigungen, Alarm-Historie, Audit) | `pg_dump` | ohne sie müssen alle Probes neu registriert werden |
| vm-agg (1-min-Aggregate, 13 Monate) | `vmbackup` (konsistenter Snapshot) | Langzeitverlauf |
| `.env`, `certs/` | Kopie | Schlüssel = SPKI-Pin aller Probes |
| vm-raw (1-s-Rohdaten) | nur mit `--raw` | kurzlebig und groß, meist verzichtbar |

```bash
sudo /opt/wachtl/deploy/backup.sh            # legt backups/wachtl-JJJJMMTT-HHMM.tar.gz an, behält 14 Tage
sudo crontab -e
15 2 * * *  /opt/wachtl/deploy/backup.sh >> /var/log/wachtl-backup.log 2>&1
```

Die Archive enthalten Geheimnisse (`.env`, privater Schlüssel) – auf ein geschütztes Ziel kopieren (z. B. per `rsync` auf den Backup-Server), nicht auf eine offene Freigabe.

**Wiederherstellung** auf derselben oder einer neuen VM (gleicher DNS-Name/IP):

```bash
sudo ./restore.sh backups/wachtl-20261016-0215.tar.gz
```

Da Schlüssel und Zertifikat mit zurückkommen, verbinden sich alle Probes ohne Änderung wieder und senden ihren Puffer nach.

## Updates

**Server**

```bash
cd /opt/wachtl && sudo ./deploy/backup.sh && git pull     # oder neues ZIP entpacken, .env/certs behalten
sudo ./deploy/setup.sh                                    # baut neu, migriert die Datenbank automatisch
```

Versionen der Fremdkomponenten (VictoriaMetrics, Alertmanager, Traefik, PostgreSQL) stehen in `.env` und werden nur bewusst angehoben. PostgreSQL-Hauptversionen (16 → 17) brauchen Dump und Restore.

**Probes**

1. Server aktualisieren – er legt das neue `WachtlSetup` für die Probes ab.
2. Auf den PCs `WachtlSetup-x.y.z.exe /VERYSILENT /SUPPRESSMSGBOXES` (Softwareverteilung): aktualisiert nur das Programm, die Registrierung bleibt.
3. Dashboard zeigt die neue Version je Probe. Während des Updates puffert nichts verloren: der Puffer liegt in `C:\ProgramData\Wachtl\buffer.db`.

Automatische, signierte Updates sind für Phase 4 geplant (Ed25519-signiertes Manifest).

## Zertifikat im Browser

Wachtl hat eine eigene Zertifizierungsstelle, die **Wachtl-CA**:

| Datei (`certs/`) | Inhalt | Laufzeit |
| --- | --- | --- |
| `wachtl-ca.key`, `wachtl-ca.crt` | Wachtl-CA – kommt auf die Geräte als vertrauenswürdige Stammzertifizierungsstelle | 10 Jahre |
| `wachtl.key`, `wachtl.crt` | Server-Zertifikat, von der CA ausgestellt; `wachtl.crt` enthält die Kette (Server, CA) | 397 Tage |

- Das Server-Zertifikat erneuert sich **30 Tage vor Ablauf selbst** – Windows im laufenden Dienst (Prüfung alle
  6 Stunden, ohne Neustart), Linux täglich per `/etc/cron.d/wachtl-zertifikat` (`deploy/zertifikat.sh`, Log in
  `/var/log/wachtl-zertifikat.log`). Die Geräte merken davon nichts, sie vertrauen der CA. Mit 397 Tagen erfüllt
  es auch die Regeln von Apple (macOS, iOS) und den Browsern.
- Der Schlüssel des Server-Zertifikats bleibt immer gleich – der **Pin der Probes ändert sich nie**.
- Die CA hat eine **Namensbeschränkung**: Sie stellt nur für die Namen und IP-Adressen des Wachtl-Servers gültige
  Zertifikate aus. Selbst wer ihren Schlüssel stiehlt, kann damit keine fremden Seiten fälschen.
- Neue Servernamen (Windows: Setup erneut ausführen; Linux: `WACHTL_HOST` und `./setup.sh`) stellen die CA mit
  demselben Schlüssel neu aus. PCs mit Probe übernehmen sie innerhalb eines Tages (geplante Aufgabe), andere Geräte
  brauchen sie neu von `/zertifikat`.
- Bis 0.9.3 war das Zertifikat selbstsigniert (10 Jahre). Das Update stellt einmal auf die CA um, gleicher Pin.

| Gerät | Wie |
| --- | --- |
| Windows-PC mit Probe | automatisch beim Probe-Setup und täglich per geplanter Aufgabe „Wachtl Zertifikat“, Entfernen bei der Deinstallation (beide Server-Varianten) |
| Windows-Server (Wachtl-Server) | automatisch beim Setup und jedem Update |
| Windows ohne Probe | GPO (Computerkonfiguration › Richtlinien › Windows-Einstellungen › Sicherheitseinstellungen › Richtlinien für öffentliche Schlüssel › Vertrauenswürdige Stammzertifizierungsstellen) oder Datei von `/zertifikat` öffnen › Lokaler Computer |
| macOS | Datei von `/zertifikat` › Schlüsselbund „System“ › „Immer vertrauen“, oder per MDM-Profil |
| iPhone, iPad | in Safari `/zertifikat` › Profil installieren › Einstellungen › Allgemein › Info › Zertifikatsvertrauenseinstellungen einschalten (MDM: Profil mit Zertifikat-Payload) |
| Android | Datei von `/zertifikat` › Einstellungen › Sicherheit › Zertifikat installieren › CA-Zertifikat |
| Linux | `/usr/local/share/ca-certificates/wachtl.crt` + `update-ca-certificates`; Firefox/Chrome ggf. zusätzlich im eigenen Zertifikatspeicher |

Die Seite `https://<Server>/zertifikat` (ohne Anmeldung, verlinkt auf der Anmeldeseite) bietet die Wachtl-CA zum
Herunterladen an, zeigt den SHA-256-Fingerabdruck zum Vergleichen und die Schritte je Gerät.

## Sicherheitskonzept

| Ebene | Maßnahme |
| --- | --- |
| Transport | Nur HTTPS (TLS ≥ 1.2), Port 80 leitet um. Linux: Traefik, interne Dienste nur im Docker-Netz. Windows: TLS im Collector, interne Dienste nur auf 127.0.0.1 |
| Server-Identität | Selbstsigniertes EC-Zertifikat; Probes vertrauen ausschließlich dem SPKI-Pin (SHA-256 des öffentlichen Schlüssels). Erneuerung mit gleichem Schlüssel ändert den Pin nicht |
| Enrollment | Token pro Standort mit Ablaufdatum und Nutzungszahl, nur als SHA-256-Hash gespeichert, widerrufbar |
| Probe-Identität | Eigenes 256-Bit-Token je Probe, serverseitig nur als Hash; auf dem PC per DPAPI (LocalMachine) verschlüsselt; Probe sperren im UI wirkt sofort |
| Datenintegrität | Labels wie Probe, Standort und Ziel setzt der Server; eine Probe kann keine Daten für andere Probes oder fremde Checks einliefern |
| Windows-Server | Dienst unter `NT SERVICE\WachtlServer` statt SYSTEM; Datenordner nur für SYSTEM, Administratoren und Dienstkonto; Firewall-Regeln nur für die nötigen Ports |
| Probe auf dem PC | Virtuelles Dienstkonto statt SYSTEM, ICMP ohne Adminrechte, Datenordner nur für SYSTEM/Administratoren/Dienst, keine eingehenden Ports |
| Web-UI | Rollen Admin/Operator/Nur lesen, Passwörter mit scrypt (Länge frei wählbar), Sperre nach 5 Fehlversuchen für 15 min je Gerät (Browser-Sitzung, nie je IP); zusätzlich Konto-Sperre nach 20 Fehlversuchen, die Geräte mit früherer erfolgreicher Anmeldung nicht betrifft, CSRF-Schutz, Secure/HttpOnly-Cookies, Content-Security-Policy ohne externe Skripte |
| Nachvollziehbarkeit | Audit-Log für Anmeldungen, Enrollment und jede Änderung (24 Monate) |
| Geheimnisse | `.env`, `certs/wachtl.key` und `certs/wachtl-ca.key` nur root-lesbar; Backups enthalten sie und müssen geschützt abgelegt werden |

Firewall-, Proxy- und NAT-Szenarien: Probes bauen jede Verbindung selbst auf, NAT ist daher unkritisch. Proxys werden über `-Proxy` oder die Umgebungsvariable `HTTPS_PROXY` des Dienstes genutzt; eine TLS-Inspection muss den Wachtl-Server ausnehmen, sonst greift der Pin (gewollt).

## Standard-Alarme

| Alarm | Bedingung (Standard) | Stufe | Unterdrückt |
| --- | --- | --- | --- |
| WachtlProbeOffline | 120 s kein Heartbeat | kritisch | alle anderen Alarme dieser Probe |
| WachtlTargetDown | 5 s ohne Antwort (bei 1-s-Ping 5 Pings in Folge, bei längerem Intervall mindestens 2) | kritisch | bei Rolle Gateway: Internet- und Zielalarme dieser Probe |
| WachtlWanDown | alle Internet-Referenzen zugleich 5 s ohne Antwort | kritisch | Einzelalarme der Referenzen |
| WachtlPacketLossAny | **jeder** verlorene Ping, der kein Ausfall ist; endet nach 60 s ohne Verlust | Warnung | – |
| WachtlPacketLoss | > 2 % über 5 min, 1 min anhaltend | Warnung | – |
| WachtlPacketLossCritical | > 10 % über 5 min, 1 min anhaltend | kritisch | die Warnung |
| WachtlLatencyHigh | Durchschnitt > 100 ms über 5 min, 1 min anhaltend | Warnung | – |

Ausfälle (WachtlTargetDown, WachtlWanDown) und jeder Paketverlust (WachtlPacketLossAny) erkennt der Server selbst,
sobald die Messwerte ankommen – Sekunde für Sekunde aus den Rohdaten. Das gilt auch für **nachgelieferte** Werte:
Hat ein PC selbst kein Netz (Kabel gezogen, Switch aus, WLAN weg), puffert die Probe ihre Messwerte und schickt sie
später. Der Ausfall wird dann nachträglich erkannt, steht sekundengenau in der Übersicht und geht per E-Mail/Teams
raus (mit „nachträglich erkannt“). Bis 0.9.5 hat vmalert solche Ausfälle übersehen, weil die Werte zu spät kamen.
Details: [BENACHRICHTIGUNGEN.md](BENACHRICHTIGUNGEN.md).

Schwellwerte, Dauer und Stufe sind unter **Verwaltung › Alarmregeln** änderbar. Empfehlungen:

- Pro Standort mindestens zwei Probes, damit „nur dieser PC“ und „ganzer Standort“ unterscheidbar sind.
- Für Telefonie-Standorte die Latenz-Warnung auf 50 ms und den Paketverlust auf 1 % senken.
- Zu viele E-Mails wegen einzelner verlorener Pings: bei „Jeder Paketverlust“ den Schwellwert erhöhen (z. B. 3 = erst ab 3 verlorenen Pings in einer Störung) oder die Regel abschalten. Angezeigt wird jeder Verlust trotzdem.
- WLAN-Clients als Probe nur gezielt einsetzen – sie erzeugen naturgemäß mehr Jitter und Verlust.
- Bestätigen schaltet einen Alarm für 1 h bis 3 Tage stumm; danach meldet er sich erneut, falls er noch besteht.
- Empfänger (E-Mail, Teams) unter **Verwaltung › Benachrichtigungen**; die Testnachricht kommt nach etwa 30 Sekunden an.

## Beispielkonfiguration

Im MVP werden Checks im Web-UI angelegt (Verwaltung › Checks). Die Probe erhält daraus diese Konfiguration (`GET /api/probe/v1/config`):

```json
{
  "probe_id": 4,
  "etag": "9f3c1d2a7b6e5f40",
  "upload_interval_s": 10,
  "heartbeat_interval_s": 30,
  "config_poll_s": 300,
  "checks": [
    {"id": 1, "type": "ping", "target": "gateway",  "role": "gateway",   "interval_s": 1, "timeout_ms": 1000, "params": {}},
    {"id": 2, "type": "ping", "target": "8.8.8.8",  "role": "reference", "interval_s": 1, "timeout_ms": 1000, "params": {}},
    {"id": 3, "type": "ping", "target": "1.1.1.1",  "role": "reference", "interval_s": 1, "timeout_ms": 1000, "params": {}},
    {"id": 4, "type": "ping", "target": "10.10.0.20", "role": "target",  "interval_s": 5, "timeout_ms": 1000, "params": {}}
  ]
}
```

Vorgesehene Form der Checks aus Phase 2 und 3 (Datenmodell steht bereits, Probe und Server folgen):

```json
[
  {"type": "traceroute", "target": "10.10.0.20", "interval_s": 900, "params": {"max_hops": 30, "on_loss": true}},
  {"type": "traceroute", "target": "8.8.8.8",    "interval_s": 900, "params": {"max_hops": 30, "on_loss": true}},
  {"type": "iperf",      "target": "10.10.0.30", "interval_s": 3600, "params": {"port": 5201, "proto": "tcp", "duration_s": 10, "parallel": 4, "reverse": false, "min_mbps": 200}},
  {"type": "dns",        "target": "intranet.kunde.local", "interval_s": 60, "params": {"server": "10.10.0.10", "expect": ["10.10.0.50"]}},
  {"type": "http",       "target": "https://portal.kunde.de/health", "interval_s": 60, "params": {"expect_status": 200, "expect_text": "ok", "cert_warn_days": 21}}
]
```
