## Downloads

- **WachtlSetup-…exe**: ein Setup für Probe (Standard) und Wachtl-Server (Windows Server 2019/2022/2025). Für die PCs gibt es im Web-UI unter Verwaltung › Probes registrieren ein vorbelegtes Setup – dort nur „Installieren“.
- **SHA256SUMS.txt**: Prüfsummen.

## Neu in 1.0.0

- **Nur ein Standort**: Gibt es genau einen Standort, blendet Wachtl ihn aus. „Übersicht“ zeigt direkt die Standortseite mit Probes, Netzwerk, Topologie und dem Verlauf (24 h bis 90 Tage). Menüpunkt „Standorte“, Standortliste in der Seitenleiste sowie Standortauswahl in Filtern, Bericht, Messungen, Setup und Einrichtung entfallen; die Einrichtung nutzt den vorhandenen Standort oder legt „Hauptstandort“ an. Ab dem zweiten Standort erscheint alles wieder.
- **Jede Störung sichtbar und gemeldet**: Ausfälle und jeder einzelne verlorene Ping werden jetzt direkt aus den Messwerten erkannt, sobald sie beim Server ankommen – auch **nachträglich**, wenn ein PC selbst kein Netz hatte und seine Werte erst danach schickt. Bisher fielen genau diese Ausfälle (Kabel gezogen, Switch aus) unter den Tisch: Graph rot, Übersicht „0 Ausfälle“. Neue Alarmregel **Jeder Paketverlust** (Standard: jeder verlorene Ping, per E-Mail/Teams). Details: [BENACHRICHTIGUNGEN.md](BENACHRICHTIGUNGEN.md).
- **Nichts mehr grün, wenn etwas war**: Jeder Verlust in den letzten 5 Minuten macht Messung, Probe und Standort gelb (bisher erst ab 2 %). Der Standort-Verlauf zeigt jeden Paketverlust als gelben Balken; „ohne Störung“ zählt jede Störung mit und zeigt bei kurzen Störungen genug Nachkommastellen (99,998 % statt 100,0 %). „Ausfälle“ heißen jetzt **Störungen**. Sehr kleiner Verlust steht genau da („0.004 %“).
- **Hinweis im Browser**: Neue Störungen, Alarme und Hinweise der PCs erscheinen auf jeder Seite unten rechts, auf Wunsch auch als Desktop-Benachrichtigung. Bei „Alarme“ steht die Zahl der aktiven Alarme.
- **Tray auf dem Wachtl-Server**: Das Symbol auf dem Server zeigt Störungen aller Standorte als Hinweis.
- **Tray auf dem PC**: Die Probe meldet selbst, wenn das Gateway (Netzwerk), das Internet oder ein Ziel nicht antwortet, jeden verlorenen Ping und jeden Netzwerkwechsel (LAN ↔ WLAN, neue IP) – auch ohne Verbindung zum Server. Alle Netzwerk-Hinweise erscheinen jetzt als Sprechblase, auch „Kabel getrennt“, wenn das WLAN übernimmt. Bei aktiver Störung trägt das Symbol einen roten oder gelben Punkt. Neu im Menü: **Test-Hinweis anzeigen**.
- **Switches automatisch finden**: Wachtl erkennt Switches gängiger Hersteller (TP-Link, D-Link, Zyxel, Netgear, Aruba/HPE, Cisco, Ubiquiti, MikroTik, LANCOM …) selbst – ohne Anmeldung am Gerät: am Hersteller der MAC-Adresse und der Weboberfläche aus dem Netzwerkscan, an LLDP/CDP der eingetragenen Switches und an einem **Rundruf der Server-Probe**, auf den TP-Link Easy Smart und Netgear ProSAFE Plus mit Modell, Name, IP und Firmware antworten. Standort › Topologie › Switches zeigt sie unter **Gefundene Switches**; fehlen Zugangsdaten, fragt Wachtl danach. Der Assistent ist mit Adresse, Name und Zugangsart vorbelegt und übernimmt dieselben Zugangsdaten auf Wunsch für weitere angehakte Funde. Wachtl probiert keine Passwörter selbst aus. Funde ohne Abfragemöglichkeit erscheinen trotzdem im Baum.
- **TP-Link Easy Smart ohne SNMP** (TL-SG105E/108E/105PE/108PE/1016PE …): Wachtl liest Ports, Geschwindigkeit, Paketfehler und PoE über die Weboberfläche. Im Baum hängt der Switch an dem Port, an dem ihn der übergeordnete Switch sieht, mit den Geräten dahinter; „Pfad suchen“ führt durch ihn hindurch.
- **Wahrscheinliche Knotenpunkte**: Hängen an einem Port mehrere Geräte ohne LLDP-Nachbarn, zeigt der Baum einen nicht verwalteten Switch – ab 3 Geräten „wahrscheinlich“, bei 2 „möglich“. Virtuelle Maschinen eines Hosts zählen nicht mit.
- **Menüpunkt Topologie** in der Seitenleiste: bei einem Standort direkt der Baum, bei mehreren zuerst je Standort eine Kachel mit Zahl der Switches, Problemen und gefundenen Switches, die noch Zugangsdaten brauchen.
- Windows-Server: neue Firewall-Regel „Wachtl Server Switch-Suche“ (UDP 29809, 63321, 63323, nur aus dem eigenen Netz) für die Antworten auf den Rundruf.
- **Alarme, Meldungen und Hinweise unter einem Menüpunkt**: Die Seitenleiste ist kürzer. „Alarme“ führt zu Reitern für Alarme, Störungsmeldungen der Benutzer und Hinweise der PCs; die Zahl offener Meldungen steht am Menüpunkt.

## Neu in 0.9.6

- **Jede Störung sichtbar und gemeldet**: Ausfälle und jeder einzelne verlorene Ping werden jetzt direkt aus den Messwerten erkannt, sobald sie beim Server ankommen – auch **nachträglich**, wenn ein PC selbst kein Netz hatte und seine Werte erst danach schickt. Bisher fielen genau diese Ausfälle (Kabel gezogen, Switch aus) unter den Tisch: Graph rot, Übersicht „0 Ausfälle“. Neue Alarmregel **Jeder Paketverlust** (Standard: jeder verlorene Ping, per E-Mail/Teams). Details: [BENACHRICHTIGUNGEN.md](BENACHRICHTIGUNGEN.md).
- **Nichts mehr grün, wenn etwas war**: Jeder Verlust in den letzten 5 Minuten macht Messung, Probe und Standort gelb (bisher erst ab 2 %). Der Standort-Verlauf zeigt jeden Paketverlust als gelben Balken; „ohne Störung“ zählt jede Störung mit und zeigt bei kurzen Störungen genug Nachkommastellen (99,998 % statt 100,0 %). „Ausfälle“ heißen jetzt **Störungen**. Sehr kleiner Verlust steht genau da („0.004 %“).
- **Hinweis im Browser**: Neue Störungen, Alarme und Hinweise der PCs erscheinen auf jeder Seite unten rechts, auf Wunsch auch als Desktop-Benachrichtigung. Bei „Alarme“ steht die Zahl der aktiven Alarme.
- **Tray auf dem Wachtl-Server**: Das Symbol auf dem Server zeigt Störungen aller Standorte als Hinweis.
- **Tray auf dem PC**: Die Probe meldet selbst, wenn das Gateway (Netzwerk), das Internet oder ein Ziel nicht antwortet, jeden verlorenen Ping und jeden Netzwerkwechsel (LAN ↔ WLAN, neue IP) – auch ohne Verbindung zum Server. Alle Netzwerk-Hinweise erscheinen jetzt als Sprechblase, auch „Kabel getrennt“, wenn das WLAN übernimmt. Bei aktiver Störung trägt das Symbol einen roten oder gelben Punkt. Neu im Menü: **Test-Hinweis anzeigen**.
- **Switch-Topologie**: Neuer Reiter Standort › **Topologie**. Wachtl fragt die Switches per SNMP ab (**SNMPv1, v2c und v3** mit MD5/SHA-1/SHA-2 und DES/AES-128/192/256) und zeigt einen **Baum** vom Internet über das Gateway bis zu jedem Switch und Gerät – mit Port und Geschwindigkeit an jeder Verbindung. Klick auf einen Switch: Seitenbereich mit Uplink, Ports, Nachbarn und „Weboberfläche öffnen“. **Switch aufgeschaltet**: Frontansicht aller Ports; ein Klick zeigt Gerät, VLAN, PoE, Fehler und die Messwerte einer Wachtl-Probe am Port. Dazu **Switch-Karten**, **Probleme** (Port-Fehler, Verbindungen unter 1 Gbit/s, Halbduplex, Kabelkreise, nicht verwaltete Switches, Switches ohne Zugangsdaten) und **Pfad suchen** (jedes Kabel vom Gerät bis ins Internet). Ein **Assistent** fragt je Switch die Zugangsdaten ab, testet sie sofort und übernimmt sie auf Wunsch für den nächsten Switch. Zugangsdaten liegen verschlüsselt in der Datenbank. Details: [TOPOLOGIE.md](TOPOLOGIE.md).

- **Verlauf der Topologie**: Wachtl prüft den Port-Status der Switches jede Minute und fragt sie alle 5 Minuten vollständig ab (beides einstellbar). Kurze Aussetzer zwischen zwei Abfragen erkennt es über den Zeitpunkt der letzten Statusänderung am Port. Jede Änderung wird gespeichert: Link weg/da, kurz ohne Link, Geschwindigkeit, Port-Fehler, Neustart, Switch nicht erreichbar, Nachbar geändert, Gerät neu oder umgesteckt. **Zeitleiste am Baum** wie Time Machine: Klick auf eine Änderung zeigt den Baum von damals. Dazu **Chronik** mit Filtern, **Port-Verlauf** je Switch (jeder Port über 6 h, 24 h oder 7 Tage) und **Störung im Kontext**: Paketverlust einer Probe neben den Ports auf ihrem Weg und den Änderungen derselben Zeit, mit Einschätzung der Ursache (Link aus der Ausfallübersicht).

- **Standort bearbeiten**: Ein Stift neben dem Standortnamen öffnet das Bearbeiten direkt (statt eines aufklappbaren Menüs).

## Neu in 0.9.5

- **PDF-Bericht für den Provider**: Neuer Menüpunkt **Bericht** (auch auf der Seite Ausfälle). Für einen oder alle Standorte und einen Zeitraum (24 h, 7 Tage, 30 Tage oder frei, bis 400 Tage) entsteht ein PDF mit allen Störungen und Vorkommnissen. Vorne steht die **Einschätzung, wo das Problem liegt** (Internetanschluss/Provider, lokales Netz, einzelner PC, einzelnes Ziel), mit Sicherheit und Belegen. Es folgen ein Zeitstrahl, auf dem auch **5-Sekunden-Aussetzer** sichtbar sind, Störungen je Tag und Uhrzeit, **Leitungsschwankungen** (Latenz, Jitter, Paketverlust; Gateway und Internet im Vergleich), die sekundengenaue Störungsliste, die Pfadanalyse („Verlust beginnt ab Hop …“), Bandbreite und Sprachqualität, Hinweise der PCs und Meldungen der Benutzer, der Netzwerkscan und die Messmethode im Anhang. Kunde, Ersteller und eine Bemerkung an den Provider lassen sich eintragen.
- **Netzwerkscan**: Neue Messart „Netzwerkscan (Geräte und Dienste)“. Eine Probe oder der Server scannt alle 15 Minuten das eigene Netz (oder eingestellte private Netze), findet Geräte per Ping, TCP und ARP-Tabelle, prüft offene Ports und erkennt Dienste (SSH, HTTP/HTTPS mit Seitentitel, RDP, VNC, FTP, SMB, Drucker …). Standort › **Netzwerk** zeigt jedes Gerät mit Anwesenheitsleiste, Wiederkehrern und Diensten. Markiert werden **unregelmäßige Geräte** (≥ 3-mal neu aufgetaucht in 24 h), **IP-Konflikte**, IP-Wechsel und neue Geräte. Für erkannte Dienste gibt es Links zum Verbinden (ssh://, http(s)://, vnc://, RDP als .rdp-Datei). Details: [NETZWERKSCAN.md](NETZWERKSCAN.md).

## Neu in 0.9.4

- **Eigene Wachtl-CA**: Wachtl stellt sein Server-Zertifikat jetzt mit einer eigenen Zertifizierungsstelle aus. Auf die Geräte kommt nur die CA (10 Jahre, per Namensbeschränkung nur für die Adressen des Servers). Das Server-Zertifikat gilt 397 Tage und erneuert sich 30 Tage vor Ablauf selbst – Windows im laufenden Dienst ohne Neustart, Linux täglich per Cron. Damit akzeptieren auch Safari auf Mac, iPhone und iPad das Zertifikat. Der Pin der Probes bleibt gleich; bestehende Installationen stellt das Update einmal um.
- **Tägliche Prüfung auf den PCs**: Die geplante Aufgabe „Wachtl Zertifikat“ legt die CA nach, wenn der Server beim Setup nicht erreichbar war, und übernimmt eine neu ausgestellte CA.
- **Standort bearbeiten**: Admins ändern Name, Kundennummer und Beschreibung eines Standorts direkt auf der Standortseite (Link auch in der Verwaltung).
- **Probe umziehen**: Auf der Probe-Seite (Details) lässt sich eine Probe einem anderen Standort zuordnen.
- **Handy: Menü rechts**: Am Handy öffnet ein Hamburger-Symbol oben rechts die Navigation und das Benutzermenü.
- **Richtiges Setup zum Herunterladen**: Liegen auf dem Server mehrere Setups im Probe-Ordner, gibt das Web-UI jetzt immer das mit der höchsten Versionsnummer aus. Bisher entschied das Dateidatum – ein später kopiertes älteres Setup (z. B. 0.9.2) verdrängte das aktuelle.

## Neu in 0.9.3

- **Netzwerkkarte deaktiviert oder entfernt**: Wachtl meldet jetzt unten rechts, wenn eine verbundene Netzwerkkarte in Windows deaktiviert oder abgezogen wird (USB-Adapter, Dockingstation). Bisher fiel die Karte still aus der Überwachung, es kam kein Hinweis. Deaktiviert: sofort, kritisch ohne andere Verbindung, sonst Warnung. Entfernt: wie „Kabel getrennt“ (nur Info, solange z. B. das WLAN übernimmt).
- **Jede Trennung wird gemeldet**: „Kabel getrennt“ und andere kritische Hinweise kamen nach dem ersten Mal 30 Minuten lang nicht wieder – wer das Kabel zum Test zweimal zog, sah beim zweiten Mal nichts. Kritische Hinweise und Verbindungsverlust erscheinen jetzt jedes Mal.
- **Zuverlässigere Erkennung**: Ändert sich eine Karte, liest die Probe den Geräte-Manager sofort neu statt bis zu 30 s alte Werte zu nutzen. Das Wachtl-Symbol fragt alle 5 s statt 10 s und gibt nach einem Fehler beim Abfragen (z. B. während eines Updates) nicht mehr bis zur nächsten Anmeldung auf.
- **Zertifikat direkt vertrauenswürdig**: Das Setup legt das Server-Zertifikat unter **Vertrauenswürdige Stammzertifizierungsstellen** ab – auf dem Windows-Server (Server-Setup) und auf jedem PC mit Probe (Probe-Setup, nur wenn es zum Pin passt). Browser öffnen Wachtl dort ohne Warnung, eine GPO ist nicht mehr nötig. Die Deinstallation entfernt es wieder. Gilt für Windows- und Linux-Server gleichermaßen.
- **Namensbeschränkung**: Das Zertifikat gilt nur noch für die Namen und IP-Adressen des Wachtl-Servers. Bestehende Zertifikate werden beim Update einmal neu ausgestellt – gleicher Schlüssel, der Pin der Probes bleibt.
- **Andere Geräte**: Neue Seite `/zertifikat` (Link auf der Anmeldeseite) zum Herunterladen mit Fingerabdruck und Anleitung für Windows, macOS, iPhone/iPad, Android und Linux.
- **Neues Design im UniFi-Stil**: Seitenleiste links mit Symbolen, darunter alle Standorte mit Status-Punkt (gestörte zuerst). Helles Grau, weiße Karten, kräftiges Blau; Dunkelmodus passend. Am Handy wird die Seitenleiste zur Kopfzeile.
- **Alles auf einen Bildschirm**: Die Übersicht zeigt nur noch Kennzahlen, den Verlauf je Standort der letzten 24 h (Balken je 30 min, Anteil ohne Störung), Messungen mit Problemen, aktive Alarme und Ausfälle – je die wichtigsten. Neue Menüpunkte **Standorte** (Kacheln mit 24-h-Verlauf), **Probes** (Probleme, alle Probes, Bandbreite, Sprache) und **Hinweise**. Verwaltung, Standort- und Probe-Seite sind in Reiter aufgeteilt; lange Messlisten unter Graphen sind aufklappbar.
- **Kurze Ausfälle bleiben sichtbar**: Übersicht und Standort zeigen eine Kachel **Ausfälle (24 h)** und den Abschnitt **Ausfälle der letzten 24 Stunden**. Bisher stand dort nur der aktuelle Zustand – ein Ausfall von 20–30 s war nach wenigen Minuten wieder „ok“ und nirgends mehr auf der Startseite zu sehen. Ein Klick aufs Ziel öffnet den Graphen zum Zeitpunkt des Ausfalls.
- **Probe-Seite**: Unter „Alle Messungen“ steht bei jedem Check mit Ausfall in den letzten 24 h, wann und wie lange.

## Neu in 0.9.2

- **Benutzermenü**: Oben rechts steht nur noch der Benutzername. Ein Klick öffnet das Menü mit **Konto** und **Design**, darunter abgesetzt **Abmelden**. Bedienbar auch per Tastatur (Escape schließt).
- **Konto**: zeigt Benutzername, Rolle, Anlagedatum und letzte Anmeldung. Beim Passwortwechsel wird das neue Passwort zur Sicherheit zweimal eingegeben.
- **Design**: Farbschema **Wie das System**, **Hell** oder **Dunkel** und Kontrast **Standard** oder **Erhöht** (Schrift mind. 7:1, kräftigere Ränder, alle Links unterstrichen). Die Auswahl wirkt sofort als Vorschau und gilt nach dem Speichern für das Konto auf jedem Gerät.

## Neu in 0.9.1

- **Netzwerk-Hinweise auch unter Windows 11**: Das Wachtl-Symbol zeigt Hinweise (z. B. Kabel getrennt) jetzt in einem eigenen kleinen Fenster unten rechts statt als Windows-Benachrichtigung. Windows 11 hatte die Meldung bei „Nicht stören“, ausgeschalteten Benachrichtigungen oder kurz nach der Anmeldung still verworfen. Das Fenster nimmt keinen Fokus, bleibt unter der Maus stehen, schließt sich sonst nach 15 s; ein Klick zeigt Details und Lösung. Bei Spielen im Vollbild und Präsentationen wartet der Hinweis.

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
