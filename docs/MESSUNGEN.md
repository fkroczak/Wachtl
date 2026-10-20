# Messungen in Wachtl

Was gemessen wird, legst du zentral im Web-UI fest: **Einstellungen › Messungen anlegen und bearbeiten**. Jeder Check gilt für alle Probes, einen Standort oder eine einzelne Probe. Änderungen erreichen die Probes mit dem nächsten Heartbeat, ohne Neustart und ohne Zugriff auf die PCs.

**Ab Werk** legt eine neue Installation diese Messungen für alle Probes an: Ping auf Gateway, Cloudflare (1.1.1.1),
Google (8.8.8.8) und Quad9 (9.9.9.9) im 1-s-Takt, Ping auf den Wachtl-Server (5 s), Traceroute ins Internet und zum
Server sowie ein Speedtest alle 6 Stunden. Ping und Traceroute zum Server entfallen, wenn die Server-URL keinen
echten Hostnamen hat. Bestehende Installationen behalten ihre Checks.

**Einzeln entfernen:** Auf der Seite einer Probe hat jede Messung den Knopf **Entfernen** (Administratoren). Gilt die
Messung nur für diese Probe, wird sie gelöscht. Gilt sie für mehrere, wird sie nur bei dieser Probe ausgenommen, die
anderen messen weiter; „wieder aufnehmen“ macht das rückgängig. Unter Einstellungen › Messungen anlegen und bearbeiten steht dann z. B.
„Alle Probes, außer PC-01“. Ganz löschen geht weiter unter Einstellungen › Messungen anlegen und bearbeiten.

Für einen neuen Kunden gibt es das **Standardpaket** (Einstellungen › Messungen anlegen und bearbeiten › Standardmessungen): Ping auf Gateway, drei
Internet-Referenzen und den Wachtl-Server, Traceroute ins Internet und zum Server, iperf3 zum Server und ein
WAN-Speedtest – mit einem Klick, ohne doppelte Checks. Anleitung: [ROLLOUT.md](ROLLOUT.md).

Der **Wachtl-Server misst selbst mit** (Server-Probe). Er bekommt dieselben Checks wie die Probes, nur iperf3 gegen
den Server selbst entfällt.

| Art | Wofür | Ergebnis |
|---|---|---|
| **Ping (Dauerping)** | Erreichbarkeit, Latenz, Paketverlust, Jitter zu einem Ziel | Ziel-Detailseite mit Graph und Statistik |
| **Pfad (Traceroute + Hop-Pings)** | Wo auf dem Weg ins Internet entstehen Verluste oder Verzögerungen? | Hop-Tabelle mit Bewertung, Pfadverlauf |
| **Bandbreite intern (iperf3)** | Durchsatz zwischen Probe und Wachtl-Server oder zwischen zwei Probes | Messungen mit Download/Upload, Verlauf |
| **Bandbreite WAN** | Durchsatz ins Internet (HTTP oder iperf3-Server im Internet) | wie oben, plus Latenz |

## Ping

| Einstellung | Standard | Bedeutung |
|---|---|---|
| Ziel | – | IP-Adresse, Hostname oder `gateway` (das Default-Gateway ermittelt jede Probe selbst) |
| Rolle | Ziel | **Gateway** und **Referenz (Internet)** steuern die Ursachenerkennung: Gateway weg = LAN-Problem, alle Referenzen weg = WAN-Problem |
| Intervall | 1 s | 1, 2, 5, 10, 15, 30, 60, 120 oder 300 s |
| Timeout | 1000 ms | höchstens das Intervall |
| Paketgröße | 32 Byte | Nutzdaten je ICMP-Paket |
| TTL | 128 | |
| Jitter berechnen über | 60 s | Jitter = mittlere Differenz aufeinanderfolgender Antwortzeiten |

## Pfad

Die Probe ermittelt die Router bis zum Ziel (ICMP mit steigender TTL, wie `tracert`) und pingt danach **jeden Hop dauerhaft** im eingestellten Intervall. So siehst du auf der Pfad-Seite wie bei MTR, ab welchem Hop es hakt.

| Einstellung | Standard | Bedeutung |
|---|---|---|
| Ziel | 1.1.1.1 | IP-Adresse oder Hostname |
| Ping-Intervall je Hop | 1 s | |
| Maximale Hops | 20 | |
| Pfad neu ermitteln alle | 10 min | zusätzlich jederzeit per „Pfad jetzt neu ermitteln“ |
| Sofort neu ermitteln bei Verlust am Ziel | an | nach 3 fehlgeschlagenen Pings, höchstens einmal pro Minute |
| Timeout / Versuche je Traceroute-Hop | 1000 ms / 2 | |
| Hops | alle | alle Hops, nur die ersten N oder nur Traceroute |
| Private Hops überspringen | aus | z. B. wenn das LAN schon eigene Checks hat |

**So liest Wachtl die Hop-Tabelle** (Abschnitt „Bewertung“):

- **Verlust, der an einem Hop beginnt und bis zum Ziel bleibt**, ist echt. Das Problem liegt zwischen dem letzten sauberen Hop und diesem Hop. Wachtl nennt den Bereich: Gateway/LAN, Zugangsnetz des Providers oder Internet.
- **Verlust nur an einem Zwischen-Hop**, während spätere Hops sauber sind, ist ICMP-Drosselung des Routers. Der Router beantwortet Pings nur gedrosselt, der Datenverkehr ist nicht betroffen.
- Ein **Latenzsprung**, der bis zum Ziel bleibt, zeigt eine langsame Strecke.
- Hops mit `*` antworten nicht auf Pings. Das ist bei vielen Routern so eingestellt.

Ändert sich der Pfad (anderer Router an einem Hop), erscheint im Pfadverlauf „Wechsel“ und der Alarm „Pfad geändert“ (Stufe info, abschaltbar).

## Bandbreite intern (iperf3)

Gegenstelle ist wahlweise:

- **der Wachtl-Server**: Er bringt einen iperf3-Server mit (Port 5201, bei der Installation änderbar). Adresse und Port, die die Probes verwenden, stehen unter **Einstellungen › Erweitert**, etwa bei NAT oder Portweiterleitung.
- **eine andere Probe**: Auf deren Seite unter **Einstellungen dieser Probe** die Option **iperf3-Gegenstelle** einschalten. Das Probe-Setup hat dafür eine Firewall-Regel nur für `iperf3.exe` angelegt. Die Adresse ermittelt Wachtl aus den lokalen IP-Adressen der Probe und lässt sich überschreiben.
- **ein eigener iperf3-Server**: Host und Port eintragen.

| Einstellung | Standard | Bedeutung |
|---|---|---|
| Protokoll | TCP | UDP misst zusätzlich Jitter und Verlust bei der eingestellten Sendeleistung |
| Richtung | beide | Download = Gegenstelle sendet zur Probe, Upload = Probe sendet |
| Testdauer | 10 s | je Richtung |
| Anlaufzeit ignorieren | 1 s | TCP-Slow-Start zählt nicht mit |
| Parallele Streams | 1 | für schnelle Leitungen 4–8 |
| UDP-Sendeleistung | 100 Mbit/s | nur UDP |
| TCP-Fenster | 0 | 0 = Betriebssystem-Standard |
| Abbruch nach | 60 s | falls die Gegenstelle hängt |

## Bandbreite WAN

| Einstellung | Standard | Bedeutung |
|---|---|---|
| Verfahren | HTTP | HTTP-Download/-Upload oder iperf3-Server im Internet |
| Download-URL | `https://speed.cloudflare.com/__down?bytes=25000000` | wird wiederholt geladen, bis die Testdauer erreicht ist |
| Upload-URL | `https://speed.cloudflare.com/__up` | leer = kein Upload-Test |
| Latenz-URL | `https://speed.cloudflare.com/__down?bytes=0` | Median aus 5 Anfragen |
| Proxy der Probe verwenden | aus | sonst direkt ins Internet |
| Parallele Verbindungen | 4 | |
| Testdauer je Richtung | 10 s | |

Eigene Server (z. B. ein Webserver im Rechenzentrum) lassen sich genauso eintragen.

## Zeitplan und Schwellwerte (beide Bandbreiten-Arten)

| Einstellung | Standard | Bedeutung |
|---|---|---|
| Automatisch messen alle | 60 min | 0 = nur auf Knopfdruck „Jetzt messen“ |
| Versatz | automatisch | verteilt die Probes über die Stunde, damit nicht alle gleichzeitig messen |
| Nur zwischen … und | 00:00–23:59 | Ortszeit der Probe, auch über Mitternacht (z. B. 22:00–04:00) |
| An Wochentagen | 1234567 | 1 = Montag … 7 = Sonntag |
| Alarm, wenn Download/Upload unter | 0 = aus | Alarm „Bandbreite“, wenn so viele Messungen in Folge darunter liegen, wie unter Alarmregeln eingestellt (Standard 2) |

**Jetzt messen**: auf der Seite der Probe oder der Bandbreiten-Seite. Die Probe holt den Auftrag mit dem nächsten Heartbeat ab (Standard ≤ 30 s). Je Probe läuft immer nur eine Bandbreitenmessung gleichzeitig.

Bandbreitentests belasten die Leitung. Bei vielen PCs an einem Standort genügt meist ein Check für eine einzelne Probe je Standort.

## Zustand der Messungen

Übersicht, Standort und Probe bewerten jede Messung gleich:

| Zustand | Ping | Pfad | Bandbreite (iperf3, WAN) |
|---|---|---|---|
| **ok** | Ziel antwortet, Verlust ≤ 2 % | Ziel im Traceroute erreicht | letzte Messung ohne Fehler, über den Schwellwerten |
| **auffällig** | Verlust > 2 % (5 min) | Ziel im Traceroute nicht erreicht | unter dem Schwellwert des Checks |
| **gestört** | Ziel antwortet nicht | – | Fehler der letzten Messung (z. B. „Connection refused“, „HTTP 403“) |
| **keine Daten** | seit über 3 min kein Wert | kein Traceroute seit 3 × Intervall | geplante Messung überfällig (laut Zeitplan) |
| wartet | Check neu | erster Traceroute läuft | noch nicht fällig oder nur manuell |

Alles außer „ok“ und „wartet“ steht auf der Übersicht unter **Messungen mit Problemen** – mit Grund und Link zur
Detailseite. Ist eine Probe offline, steht sie dort einmal als „offline“ statt mit jeder einzelnen Messung.
Dieselbe Liste liefert `GET /api/v1/check-status`.

## Ausfälle

**Ausfälle** im Hauptmenü listet alle Störungen mit Beginn, Dauer und Ursache:

| Ursache | Erkannt an |
|---|---|
| Probe / Standort offline | Probe sendet keinen Heartbeat mehr (Strom, Netz, PC aus) |
| Gateway / LAN | Check mit Rolle Gateway antwortet nicht |
| WAN / Internet | Gateway erreichbar, aber alle Referenzen gestört |
| Starker Paketverlust | kritische Paketverlust-Schwelle überschritten |
| Ziel / einzelne Referenz | nur dieses Ziel gestört |

Eine Störung zählt ab **5 s ohne Antwort** (Einstellungen › Benachrichtigungen › Ab wann ein Alarm kommt). Beginn und Dauer rechnet Wachtl nach dem Ende
aus den 1-s-Messwerten sekundengenau nach; beim WAN zählt nur die Zeit, in der alle Referenzen zugleich weg waren.
Kurze Ausfälle erkennt nur ein Ping-Intervall von 1 s sicher – bei 5 s Intervall braucht es 2 verlorene Pings (≈ 10 s).

Gleichzeitige Folgestörungen derselben Probe werden zusammengefasst, zum Beispiel „Internet weg“ während „Gateway weg“. Mit „Folgestörungen zeigen“ werden sie eingeblendet. Unter **Einstellungen › Erweitert** lässt sich eine Mindestdauer einstellen, ab der eine Störung erscheint.

## Allgemeine Einstellungen (Einstellungen › Erweitert)

| Einstellung | Standard |
|---|---|
| iperf3-Gegenstelle auf dem Wachtl-Server an/aus, Adresse und Port für Probes | an, Server-URL, 5201 |
| Messwerte hochladen alle | 10 s |
| Heartbeat alle | 30 s |
| Konfiguration spätestens abrufen alle | 300 s |
| Standard-Port der iperf3-Gegenstelle auf Probes | 5201 |
| Pfad- und Bandbreitenverlauf aufbewahren | 400 Tage |
| Ausfälle anzeigen ab | 0 s |
| Netzwerkkarte und Kabel auf den PCs überwachen (Client-Hinweise, [CLIENT-HINWEISE.md](CLIENT-HINWEISE.md)) | an |
| Hinweis als Sprechblase auf dem PC anzeigen | an |

## Firewall

| Verbindung | Port |
|---|---|
| Probe → Wachtl-Server (Messwerte) | TCP 443 bzw. der gewählte HTTPS-Port |
| Server-Probe | nur ausgehend wie eine Probe, kein eigener Port |
| Probe → Wachtl-Server (iperf3) | TCP **und** UDP 5201 |
| Probe → Probe (iperf3) | TCP und UDP 5201 bzw. der Port der Gegenstelle |
| Probe → Internet (WAN-Messung) | TCP 443 zu den eingetragenen URLs |
| Pfad-Check | ICMP Echo ausgehend, „Time Exceeded“ zurück (unter Windows erlaubt) |
