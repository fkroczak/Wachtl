# Installation: zentraler Wachtl-Server (Linux)

Ein Server pro Kunde, als Linux-VM mit Docker. Für Windows Server gibt es einen Setup-Assistenten:
[INSTALL-SERVER-WINDOWS.md](INSTALL-SERVER-WINDOWS.md). Die Probes verbinden sich ausschließlich ausgehend per HTTPS (Port 443) zu diesem Server.

## Voraussetzungen

| Punkt | Empfehlung |
| --- | --- |
| VM | Debian 13 oder Ubuntu 24.04/26.04 LTS, 2 vCPU, 4 GB RAM, 40 GB SSD für bis zu 25 Probes × 10 Ziele; mehr Probes: [BETRIEB.md](BETRIEB.md#größe-und-speicherplatz) |
| Netz | Feste IP oder DNS-Name, erreichbar von allen Standorten (VPN/MPLS) |
| Firewall | Eingehend TCP 443 (Probes, Browser), optional TCP 80 (Weiterleitung auf 443). Ausgehend: SMTP-Server und/oder `*.logic.azure.com`/`*.powerplatform.com` für Teams |
| Zeit | NTP aktiv – Messwerte tragen Zeitstempel der Probes, große Abweichungen werden verworfen |

## 1. Docker installieren

```bash
sudo apt update && sudo apt install -y ca-certificates curl openssl git
curl -fsSL https://get.docker.com | sudo sh
sudo systemctl enable --now docker
docker compose version   # muss v2.x anzeigen
```

## 2. Wachtl ablegen

```bash
sudo mkdir -p /opt/wachtl && sudo chown "$USER" /opt/wachtl
git clone <euer-repo> /opt/wachtl      # oder das ZIP nach /opt/wachtl entpacken
cd /opt/wachtl/deploy
```

## 3. Einrichten und starten

```bash
sudo ./setup.sh wachtl.kunde.local     # DNS-Name oder IP, unter der die Probes den Server erreichen
```

`setup.sh` erledigt beim ersten Aufruf:

1. `.env` mit zufälligen Geheimnissen anlegen (Datei nur für root lesbar)
2. Wachtl-CA (10 Jahre) und Server-Zertifikat (397 Tage) in `certs/` erzeugen (`deploy/zertifikat.sh`) und die
   tägliche Erneuerung einrichten (`/etc/cron.d/wachtl-zertifikat`)
3. SPKI-Pin berechnen und in `.env` eintragen
4. Container bauen und starten, Datenbank anlegen, Standard-Checks und -Alarme anlegen, Alertmanager-Konfiguration erzeugen

Am Ende stehen URL, **Admin-Passwort** (nur einmal angezeigt) und **SPKI-Pin** auf dem Bildschirm. Beides sicher ablegen.

## 4. Alarm-Empfänger eintragen

Im Web-UI unter **Verwaltung › Benachrichtigungen**: E-Mail (SMTP) und/oder Microsoft-Teams-Webhook eintragen,
speichern, **Testnachricht senden**. Die Werte `ALERT_EMAIL_*`, `SMTP_*` und `TEAMS_WEBHOOK_URL` in `.env` werden
nur bei der Ersteinrichtung einmalig übernommen.

## 5. Erste Schritte im Web-UI

1. `https://wachtl.kunde.local` öffnen. Die Browserwarnung ist beim ersten Aufruf normal. Windows-PCs mit Probe
   legen die Wachtl-CA bei der Installation selbst unter „Vertrauenswürdige Stammzertifizierungsstellen“ ab;
   alle anderen Geräte: Seite `https://wachtl.kunde.local/zertifikat` (Link auf der Anmeldeseite), siehe
   [Zertifikat im Browser](BETRIEB.md#zertifikat-im-browser).
2. Mit `admin` und dem Passwort aus Schritt 3 anmelden, unter **admin › Konto** das Passwort ändern.
3. **Verwaltung › Standorte**: Standorte anlegen (Name, Kundennummer).
4. **Verwaltung › Standardpaket**: mit einem Klick Ping, Traceroute, iperf3 und Speedtest für alle Probes anlegen (Schritt-für-Schritt: [ROLLOUT.md](ROLLOUT.md)). Eigene Ziele (Server, Firewall, Cloud-Dienste) unter **Verwaltung › Checks** ergänzen, global, je Standort oder je Probe.
5. **Verwaltung › Probes registrieren**: Enrollment-Token erzeugen; die Seite zeigt den fertigen Installationsbefehl für die Probes.
6. **Verwaltung › Benutzer**: Operatoren (dürfen Alarme bestätigen) und Nur-lesen-Konten anlegen. Hat jemand sein
   Passwort vergessen, setzt ein Admin es dort mit **Passwort zurücksetzen** neu (hebt auch eine Sperre auf).

## Prüfen

```bash
cd /opt/wachtl/deploy
sudo docker compose ps                     # alle Dienste „running“, app „healthy“
sudo docker compose logs -f app            # Collector-Log
sudo docker compose exec app flask --app wachtl regen-rules   # Alarmregeln neu schreiben
```

## Admin-Passwort vergessen

Die Anmeldeseite verweist mit **Passwort vergessen?** hierher. Andere Benutzer setzt ein Admin im Web-UI zurück;
für das Admin-Konto selbst:

```bash
sudo /opt/wachtl/deploy/passwort.sh
```

## Ports und Dienste im Stack

| Dienst | Aufgabe | Von außen erreichbar |
| --- | --- | --- |
| traefik | TLS, Port 80/443 | ja |
| app | Flask-Collector, Web-UI (Gunicorn, 4 Worker) | nur über Traefik |
| postgres | Konfiguration, Alarme, Audit | nein |
| vm-raw | 1-s-Rohdaten (`RAW_RETENTION`, Standard 30 Tage) | nein |
| vm-agg | 1-min-Aggregate (`AGG_RETENTION`, Standard 13 Monate) | nein |
| vmalert | Aggregate berechnen, Alarmregeln auswerten | nein |
| alertmanager | Benachrichtigungen, Stummschaltungen | nein |
| iperf3 | Gegenstelle für Bandbreitenmessungen der Probes (`IPERF_PORT`, TCP+UDP) | ja |
| rtp | RTP-Reflektor für Sprachtests der Probes (`RTP_PORT`, UDP, Standard 5004) | ja |
| serverprobe | Server-Probe: der Server misst selbst (Ping, Pfad, iperf3, WAN), im Host-Netz, nur ausgehend; `SERVER_PROBE=0` schaltet sie ab | nein (kein Port) |

## Deinstallieren

```bash
cd /opt/wachtl/deploy
sudo ./uninstall.sh            # Container, Netzwerke, Images, Cron-Eintrag – Daten bleiben für eine Neuinstallation
sudo ./uninstall.sh --alles    # zusätzlich Datenbank, Messwerte, .env, Zertifikat (privater Schlüssel), Sicherungen
```

Mit den Containern verschwinden auch die Portfreigaben (80, 443, iperf3), die Docker als iptables-Regeln setzt.
Das Skript prüft am Ende, dass keine Container, Netzwerke oder von Docker freigegebenen Ports des Projekts übrig sind,
und endet sonst mit Code 2. Die Probes vorher mit ihrem Deinstaller entfernen – sie melden sich dabei am Server ab.
