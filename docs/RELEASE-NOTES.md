## Downloads

- **WachtlSetup-…exe**: ein Setup für Probe (Standard) und Wachtl-Server (Windows Server 2019/2022/2025). Für die PCs gibt es im Web-UI unter Verwaltung › Probes registrieren ein vorbelegtes Setup – dort nur „Installieren“.
- **SHA256SUMS.txt**: Prüfsummen.

## Neu in 0.9.1

- **Benutzermenü**: Oben rechts steht nur noch der Benutzername. Ein Klick öffnet das Menü mit **Konto** und **Design**, darunter abgesetzt **Abmelden**. Bedienbar auch per Tastatur (Escape schließt).
- **Konto**: zeigt Benutzername, Rolle, Anlagedatum und letzte Anmeldung. Beim Passwortwechsel wird das neue Passwort zur Sicherheit zweimal eingegeben.
- **Design**: Farbschema **Wie das System**, **Hell** oder **Dunkel** und Kontrast **Standard** oder **Erhöht** (Schrift mind. 7:1, kräftigere Ränder, alle Links unterstrichen). Die Auswahl wirkt sofort als Vorschau und gilt nach dem Speichern für das Konto auf jedem Gerät.

## Neu in 0.9.0

- **Sprachtest (RTP/VoIP)**: Neue Messart „Sprache (RTP/VoIP)“. Die Probe simuliert ein Telefonat – ein echter RTP-Sprachstrom wie von einem SIP-Telefon (G.711 oder G.729, alle 20 ms ein Paket) – zum Wachtl-Server, zu einer anderen Probe oder einem eigenen Reflektor. Wachtl misst Laufzeit sowie Jitter und Paketverlust **getrennt je Richtung** und schätzt die Sprachqualität als **MOS** (E-Modell nach ITU-T G.107). Standard: 30 s alle 15 Minuten, „Jetzt testen“ auf Knopfdruck.
- **Sprachqualität im Web-UI**: eigene Seite je Test mit MOS-Verlauf und allen Werten, Abschnitt „Sprache (RTP)“ auf der Probe-Seite, „Sprachqualität“ auf der Übersicht; schlechte oder fehlgeschlagene Tests erscheinen unter „Messungen mit Problemen“.
- **Alarm „Sprachqualität“**: wenn der MOS mehrere Tests in Folge unter dem Schwellwert des Checks liegt (Standard 3.6).
- **RTP-Reflektor**: Der Wachtl-Server antwortet auf UDP-Port 5004 (Linux: Container `rtp`, `RTP_PORT` in `.env`; Windows: Teil des Dienstes, Firewall-Regel „Wachtl Server RTP“, unbeaufsichtigt `/RtpPort=`). Probes, die als **Gegenstelle für andere Probes** eingerichtet sind, antworten ebenfalls (Firewall-Regel „Wachtl Probe RTP“ legt das Probe-Setup an).
- Für Sprachtests braucht es auf den PCs die Probe 0.9; ältere Probes melden den Check als nicht unterstützt.

## Neu in 0.8.4

- **Passwort vergessen?**: Die Anmeldeseite verlinkt eine Hilfe. Normale Benutzer bitten einen Admin; der setzt das Passwort unter Verwaltung › Benutzer › **Passwort zurücksetzen** neu (hebt auch eine Sperre auf, steht im Audit-Log). Für das Admin-Konto zeigt die Seite den Weg passend zum Server.
- **Admin-Passwort zurücksetzen**: Windows-Server mit Startmenü-Eintrag **Wachtl › Admin-Passwort zurücksetzen**, Linux mit `sudo /opt/wachtl/deploy/passwort.sh`.
- **Passwort frei wählbar**: keine Mindestlänge mehr, nur nicht leer.

## Neu in 0.8.3

- **Messungen ab Werk**: Eine neue Installation legt für alle Probes Ping auf Gateway, Cloudflare, Google und Quad9 (1 s), Ping auf den Wachtl-Server (5 s), Traceroute ins Internet und zum Server und einen Speedtest alle 6 Stunden an. iperf3 bleibt im Standardpaket wählbar. Bestehende Installationen behalten ihre Checks.
- **Jede Messung einzeln entfernen**: Auf der Probe-Seite hat jede Messung den Knopf „Entfernen“. Gilt sie nur für diese Probe, wird sie gelöscht; gilt sie für mehrere, wird nur diese Probe ausgenommen („wieder aufnehmen“ macht es rückgängig, Verwaltung › Checks zeigt „außer PC-…“).

## Neu in 0.8.2

- **Internet auf einen Blick im Tray-Menü**: Oben im Menü des Wachtl-Symbols stehen jetzt die aktuelle Antwortzeit ins Internet (bis zu drei Referenzen, mit Verlust der letzten Minute), der aktuelle Datenverkehr des PCs (↓ Download / ↑ Upload) und das Ergebnis des letzten Speedtests mit Uhrzeit. Solange das Menü offen ist, aktualisieren sich die Werte alle 2 s.
- **„Über Wachtl“ erklärt die Netzwerk-Hinweise**: Das Fenster nennt jetzt auch, dass Wachtl Probleme am PC (z. B. getrenntes Kabel, Treiberfehler) erkennt und neben der Uhr mit Lösungsvorschlag meldet.

## Neu in 0.8.1

- **Sprechblase mit vollständigem Lösungsvorschlag**: Jeder Hinweis hat eine eigene Kurzfassung für die Sprechblase (z. B. „Das Netzwerkkabel von „Ethernet“ ist nicht verbunden. Lösung: Stecker am PC und an der Netzwerkdose fest einstecken …“). Bisher schnitt Windows den Text nach 255 Zeichen mitten im Lösungsvorschlag ab. Die ausführliche Fassung steht weiter im Detailfenster (Klick auf die Sprechblase) und im Web-UI.

## Neu in 0.8

- **Ausfälle ab 5 s**: Ziel und WAN gelten ab 5 s ohne Antwort als ausgefallen (vorher 3 Pings bzw. 30 s). Die Regel prüft jede Sekunde, kurze Ausfälle zwischen zwei Auswertungen gehen nicht mehr verloren. Beginn und Dauer in der Ausfallübersicht sind sekundengenau.
- **Client-Hinweise**: Die Probe erkennt am PC getrenntes Kabel, gesunkene oder niedrige Link-Geschwindigkeit, instabile Verbindung, Treiberfehler, Rücksetzen der Netzwerkkarte, fehlende DHCP-Adresse, fehlendes Gateway und Paketfehler. Der Benutzer sieht eine Sprechblase mit Lösungsvorschlag, der Server zeigt die Hinweise auf Übersicht, Standort und Probe. Details: `docs/CLIENT-HINWEISE.md`.

## Neu in 0.7

- **Probes geführt einrichten**: Verwaltung › „Probes einrichten (geführt)“ fragt in vier Schritten alles Wichtige ab – Standort, Messungen (Standardpaket, bereits angehakt), Alarmierung per E-Mail oder Teams und die Anzahl der PCs – und bietet danach direkt das fertige Setup an. Alle Werte sind mit Standards vorbelegt; bei einem Fehler wird nichts halb angelegt.
- **Graph wie Smokeping/HOP7**: Rauch-Bänder (80 % und mittlere 50 % der Pings), Median-Linie gefärbt nach Paketverlust, Latenzschwelle, Zeiten über der Alarmschwelle hinterlegt, Verluststreifen unter der Zeitachse, Störungsmeldungen als Markierung. Tooltip mit Median und Streuung, Bedienung per Tastatur, Zoom durch Aufziehen.
- **Standort als Dashboard**: Kennzahlen (Probes online, Probleme, Alarme, Meldungen, Internet, Bandbreite) und je Probe ein Widget mit Kurzwerten und Mini-Graph der letzten Stunde. Probes mit Fehlern stehen oben, rot umrandet, mit dem Problem im Klartext.
- **Alles verlinkt**: Standorte, Probes, Ziele, Alarme, Meldungen und Audit-Einträge führen überall zur passenden Seite; ein Test sorgt dafür, dass das so bleibt.
- **Ruhigere, neutrale Farben**: Grautöne mit einer zurückhaltenden Akzentfarbe statt Braun/Ocker, hell und dunkel.

## Neu in 0.6

- **Wachtl-Symbol neben der Uhr** auf jedem Client mit Probe und auf dem Windows-Server: **Problem melden …**, **Über Wachtl** (was Wachtl ist und macht, Verbindung, Standort, Version) und **Beenden** (schließt nur das Symbol, der Messdienst läuft weiter). Auf dem Server zusätzlich **Dashboard öffnen**. Das Programm nutzt das in Windows enthaltene .NET Framework und ist rund 100 KB groß.
- **Störungsmeldungen**: Benutzer erfassen erlebte Netzprobleme – Zeitpunkt **Jetzt** (vorausgewählt) oder eine einstellbare Uhrzeit der letzten 7 Tage, Art der Störung, ungefähre Dauer und optional eine Beschreibung. Die Meldung geht über den Wachtl-Dienst mit Zertifikats-Pinning an den Server; ohne Verbindung wird sie gespeichert und nachgeliefert.
- **Meldungen im Web-UI**: neue Seite „Meldungen“ (mit Zahl der offenen in der Navigation), Abschnitt in der Übersicht, auf Probe- und Standortseite. Operatoren markieren Meldungen als erledigt (Audit-Log).
- **Meldungen in den Graphen**: senkrechte Markierung genau zum gemeldeten Zeitpunkt in Latenz-, Verlust- und Bandbreitengraphen der Probe – mit Details im Tooltip. So sieht man sofort, ob die Messwerte zur Störung passen.
- Setup-Parameter `/NoTray` lässt das Symbol weg. Details: `docs/STOERUNGSMELDUNGEN.md`.

Bei einem Update einfach das neue `WachtlSetup` über die alte Installation laufen lassen. Das Symbol erscheint sofort für den angemeldeten Benutzer, auf allen anderen PCs ab der nächsten Anmeldung.

## Neu in 0.5

- **Ein Setup für alles**: `WachtlSetup` installiert eine Probe (Standard) oder den Server. Vorhandene Probes und Server (bis 0.4 zwei getrennte Setups) werden an Ort und Stelle aktualisiert.
- **Vorbelegtes Setup aus dem Web-UI**: „Setup herunterladen“ unter Verwaltung › Probes registrieren erzeugt `WachtlSetup-<Standort>.exe` mit allen Server-Adressen, Pin und Token. Auf dem PC nur noch „Installieren“, per Softwareverteilung ohne Parameter.
- **Robuste Verbindung**: Der Server kennt seine IP-Adressen und gibt sie den Probes mit. Ist der Name am Standort nicht auflösbar, weicht die Probe auf die nächste Adresse aus – bei der Installation und im Betrieb.
- **Installation ohne Server**: Ist der Server beim Installieren nicht erreichbar, läuft die Probe trotzdem an und meldet sich selbst an, sobald er erreichbar ist.
- Entfallen: das ZIP-Paket und `Install-Wachtl.ps1`.

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
