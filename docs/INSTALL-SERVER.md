# Installation: zentraler Wachtl-Server (Linux)

Ein Server pro Kunde, als Linux-VM mit Docker. Für Windows Server gibt es einen Setup-Assistenten:
[INSTALL-SERVER-WINDOWS.md](INSTALL-SERVER-WINDOWS.md). Die Probes verbinden sich ausschließlich ausgehend per HTTPS (Port 443) zu diesem Server.

## Voraussetzungen

| Punkt | Empfehlung |
| --- | --- |
| VM | Debian 13 oder Ubuntu 24.04/26.04 LTS, 2 vCPU, 4 GB RAM, 40 GB SSD (reicht für 25 Probes × 10 Ziele) |
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
2. EC-Schlüssel und selbstsigniertes Zertifikat (10 Jahre) in `certs/` erzeugen
3. SPKI-Pin berechnen und in `.env` eintragen
4. Container bauen und starten, Datenbank anlegen, Standard-Checks und -Alarme anlegen, Alertmanager-Konfiguration erzeugen

Am Ende stehen URL, **Admin-Passwort** (nur einmal angezeigt) und **SPKI-Pin** auf dem Bildschirm. Beides sicher ablegen.

## 4. Alarm-Empfänger eintragen

Im Web-UI unter **Verwaltung › Benachrichtigungen**: E-Mail (SMTP) und/oder Microsoft-Teams-Webhook eintragen,
speichern, **Testnachricht senden**. Die Werte `ALERT_EMAIL_*`, `SMTP_*` und `TEAMS_WEBHOOK_URL` in `.env` werden
nur bei der Ersteinrichtung einmalig übernommen.

## 5. Erste Schritte im Web-UI

1. `https://wachtl.kunde.local` öffnen. Die Browserwarnung ist bei selbstsignierten Zertifikaten normal; dauerhaft beheben, indem `deploy/certs/wachtl.crt` per GPO als vertrauenswürdige Stammzertifizierungsstelle verteilt wird.
2. Mit `admin` und dem Passwort aus Schritt 3 anmelden, unter **admin › Konto** das Passwort ändern.
3. **Verwaltung › Standorte**: Standorte anlegen (Name, Kundennummer).
4. **Verwaltung › Checks**: Standard sind Gateway, 8.8.8.8 und 1.1.1.1 im 1-s-Takt für alle Probes. Eigene Ziele (Server, Firewall, Cloud-Dienste) ergänzen, global, je Standort oder je Probe.
5. **Verwaltung › Probes registrieren**: Enrollment-Token erzeugen; die Seite zeigt den fertigen Installationsbefehl für die Probes.
6. **Verwaltung › Benutzer**: Operatoren (dürfen Alarme bestätigen) und Nur-lesen-Konten anlegen.

## Prüfen

```bash
cd /opt/wachtl/deploy
sudo docker compose ps                     # alle Dienste „running“, app „healthy“
sudo docker compose logs -f app            # Collector-Log
sudo docker compose exec app flask --app wachtl regen-rules   # Alarmregeln neu schreiben
```

## Admin-Passwort vergessen

```bash
sudo docker compose exec app flask --app wachtl create-user admin --role admin
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
