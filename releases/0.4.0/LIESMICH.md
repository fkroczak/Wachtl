## Downloads

- **WachtlServerSetup-…exe**: Wachtl-Server für Windows Server 2019/2022/2025. Als Administrator starten, der Assistent richtet alles ein.
- **WachtlProbeSetup-…exe**: Probe für Windows-PCs. Das passende Paket mit Server, Pin und Token gibt es im Web-UI unter Verwaltung › Probes registrieren.
- **SHA256SUMS.txt**: Prüfsummen.

## Neu in 0.4

- **Alle Messungen im Blick**: Übersicht, Standort und Probe bewerten jetzt jede Check-Art – Ping, Pfad, iperf3 und WAN – statt nur der Dauerpings. Die Spalte „Checks ok / auffällig / gestört / keine Daten“ zählt alle Checks einer Probe.
- **Messungen mit Problemen**: neuer Abschnitt auf der Übersicht. Er listet jede Messung, die fehlschlägt (z. B. „HTTP 403 von speed.cloudflare.com“), auffällig ist (Verlust, Bandbreite unter Schwellwert, Ziel im Traceroute nicht erreicht) oder ausbleibt (keine aktuellen Werte, geplante Bandbreitenmessung überfällig). Jeder Eintrag führt direkt zur Detailseite.
- **Bandbreiten-Übersicht** auf der Startseite: letzte Download-/Upload-Werte aller Probes und Bandbreiten-Checks.
- **Server misst selbst** (Server-Probe): Der Wachtl-Server führt dieselben Checks aus wie die Probes – Ping, Traceroute, iperf3 und Speedtest – und erscheint als Probe „Server“. Er nutzt dasselbe Probe-API mit Zertifikats-Pinning und öffnet keinen Port. Abschaltbar mit `SERVER_PROBE=0` oder per „Deaktivieren“ im Web-UI.
- **Standardpaket**: Verwaltung › Standardpaket legt mit einem Klick Ping (Gateway, drei Internet-Referenzen, Wachtl-Server), Traceroute (Internet, Server), iperf3 zum Server und einen Speedtest an. Anleitung für den Rollout: `docs/ROLLOUT.md`.
- **Deinstallation ohne Rückstände**: Der Probe-Deinstaller meldet die Probe am Server ab (Token sofort ungültig) und entfernt Dienst, iperf3-Prozess, alle Firewall-Regeln für Wachtl-Programme (auch von Windows selbst angelegte) und das Token. Der Server-Deinstaller (Windows) entfernt zusätzlich von Windows angelegte Regeln, prüft offene Ports und kennt unbeaufsichtigt `/REMOVEDATA`. Für Linux gibt es `deploy/uninstall.sh`.
- **Admin-API**: `GET /api/v1/check-status` liefert den Zustand jeder Messung (z. B. für PRTG oder eigene Skripte).
- **Behoben**: Unter Linux/PostgreSQL brach die Einrichtung (`flask init`) mit „only '%s', '%b', '%t' are allowed as placeholders“ ab; `cryptography` fehlte im Docker-Image.

Bei einem Update von 0.3 einfach die neuen Setups über die alten installieren (Linux: `sudo ./setup.sh`). Die Server-Probe registriert sich beim ersten Start selbst.

## Neu in 0.3

- **Pfad-Check**: Traceroute bis ins Internet, danach Dauerpings auf jeden Hop (Standard 1 s). Die Hop-Tabelle zeigt wie MTR, ab welchem Hop Verluste oder Verzögerungen beginnen. Eine Bewertung unterscheidet echte Probleme von ICMP-Drosselung. Dazu kommen Pfadverlauf mit Wechselerkennung und der Alarm „Pfad geändert“.
- **Bandbreite intern (iperf3)**: Probe ↔ Wachtl-Server oder Probe ↔ Probe, TCP oder UDP, Richtung, Dauer und Streams einstellbar. Der Wachtl-Server und jede Probe können iperf3-Gegenstelle sein.
- **Bandbreite WAN**: HTTP-Speedtest (Standard: Cloudflare) oder iperf3-Server im Internet.
- **Zeitplan je Check**: Intervall, Zeitfenster und Wochentage, dazu „Jetzt messen“ per Knopfdruck. Alarm, wenn die Bandbreite unter einem Schwellwert liegt.
- **Jitter** im Graphen und als Alarmregel.
- **Ausfallübersicht**: Störungen mit Dauer und Ursache (Probe/Standort, Gateway/LAN, WAN, Ziel). Folgestörungen werden zusammengefasst.
- **Alles im Web-UI einstellbar**: Formulare je Check-Art, Messeinstellungen und Einstellungen je Probe.

Details: `docs/MESSUNGEN.md`. Bei einem Update von 0.2 einfach die neuen Setups über die alten installieren; Daten und Registrierungen bleiben erhalten.
