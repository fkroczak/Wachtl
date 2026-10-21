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
| Geheimnisse | `.env` und `certs/wachtl.key` nur root-lesbar; Backups enthalten sie und müssen geschützt abgelegt werden |

Firewall-, Proxy- und NAT-Szenarien: Probes bauen jede Verbindung selbst auf, NAT ist daher unkritisch. Proxys werden über `-Proxy` oder die Umgebungsvariable `HTTPS_PROXY` des Dienstes genutzt; eine TLS-Inspection muss den Wachtl-Server ausnehmen, sonst greift der Pin (gewollt).

## Standard-Alarme

| Alarm | Bedingung (Standard) | Stufe | Unterdrückt |
| --- | --- | --- | --- |
| WachtlProbeOffline | 120 s kein Heartbeat | kritisch | alle anderen Alarme dieser Probe |
| WachtlTargetDown | 5 s ohne Antwort (bei 1-s-Ping 5 Pings in Folge, bei längerem Intervall mindestens 2) | kritisch | bei Rolle Gateway: Internet- und Zielalarme dieser Probe |
| WachtlWanDown | alle Internet-Referenzen zugleich 5 s ohne Antwort | kritisch | Einzelalarme der Referenzen |
| WachtlPacketLoss | > 2 % über 5 min, 1 min anhaltend | Warnung | – |
| WachtlPacketLossCritical | > 10 % über 5 min, 1 min anhaltend | kritisch | die Warnung |
| WachtlLatencyHigh | Durchschnitt > 100 ms über 5 min, 1 min anhaltend | Warnung | – |

Ausfälle werden ab der eingestellten Dauer zuverlässig erkannt, auch wenn sie kürzer sind als der
15-s-Auswertetakt von vmalert: Die Regel prüft jede Sekunde der letzten 20 s. In der Ausfallübersicht stehen
Beginn und Dauer sekundengenau, nachgerechnet aus den 1-s-Messwerten. Der Alarm selbst kommt bis zu 45 s nach dem
Ausfall (Auswertetakt plus 30 s Wartezeit auf spät hochgeladene Messwerte).

Schwellwerte, Dauer und Stufe sind unter **Verwaltung › Alarmregeln** änderbar. Empfehlungen:

- Pro Standort mindestens zwei Probes, damit „nur dieser PC“ und „ganzer Standort“ unterscheidbar sind.
- Für Telefonie-Standorte die Latenz-Warnung auf 50 ms und den Paketverlust auf 1 % senken.
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
