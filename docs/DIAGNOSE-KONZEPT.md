# Automatische Fehlerdiagnose – Konzept

Ziel: Wachtl erkennt typische Netzprobleme beim Kunden **selbst**, nennt die wahrscheinliche Ursache und
schlägt eine Lösung vor. Grundlage ist der Stand 0.6. Dieses Dokument beschreibt, was Wachtl heute schon sieht,
was fehlt und wie die Lücken geschlossen werden.

## Kurzfassung

Heute misst Wachtl nur vier Arten: **Ping**, **Pfad**, **iperf3** und **WAN-Speedtest**. Ausgewertet wird über
Schwellwerte und Alarme. Eine Ursache nennt Wachtl nur bei Ausfällen (Probe, Gateway/LAN, WAN, Ziel) und in der
Hop-Bewertung. Lösungsvorschläge gibt es keine.

Von den acht Problemen unten erkennt Wachtl heute **keines vollständig**. Drei Hebel schließen die Lücken:

1. **Neue Messarten auf der Probe**: DNS, TCP-Port (z. B. SMB 445), HTTP/HTTPS, MTU, VoIP-Profil,
   Netzwerkkarte (Link, Geschwindigkeit, Fehler, Retransmits), Netzwerk-Ereignisse, öffentliche IP.
2. **SNMP vom Server** auf Router, Firewall und Switches: Auslastung des WAN-Ports, Port-Fehler,
   STP-Topologiewechsel. Damit sieht Wachtl auch die Infrastruktur, nicht nur die PCs.
3. **Diagnose-Regeln auf dem Server** (`services/diagnosis.py`): verknüpfen Messwerte, Ausfälle, mehrere
   Probes und Störungsmeldungen zu einem **Befund mit Ursache und Lösungsvorschlag**.

Einiges geht **sofort mit den vorhandenen Daten** (Abschnitt [Sofort umsetzbar](#sofort-umsetzbar)).

## Was Wachtl heute misst

| Messung | Werte | Lücke |
|---|---|---|
| Ping | erreichbar, RTT, TTL, Jitter (60 s) | kein DF-Bit, kein DSCP, DNS-Fehler nur als „nicht erreichbar“ |
| Pfad | Hops, Verlust und RTT je Hop, Pfadwechsel | nur Anzeige, keine Alarme je Hop |
| iperf3 | Mbit/s, Retransmits (nur in der DB), UDP-Jitter/-Verlust | höchstens 120 s, keine Werte je Sekunde, Retransmits und UDP ohne Alarm |
| WAN-Speedtest | Mbit/s, Latenz | Latenz nur im Leerlauf, nicht unter Last |
| Heartbeat | Version, lokale IPs | keine Ereignisse bei IP-, Gateway- oder Link-Wechsel |

Nicht gemessen: DNS, TCP-Verbindungsaufbau, SMB, MTU, Link-Geschwindigkeit/Duplex, Fehlerzähler der Netzwerkkarte,
WLAN, ARP/MAC von Gateway und Server, Windows-Ereignisse, öffentliche IP, Auslastung der Leitung.

Erledigt in 0.7: Ausfälle ab 5 s (sekundengenau) und Client-Hinweise zu Netzwerkkarte, Kabel und Treiber
([CLIENT-HINWEISE.md](CLIENT-HINWEISE.md)). Stand 0.6 war: Der Alarm **WAN gestört** braucht 30 s Ausfall aller Referenzen. Ein
20-s-Ausfall erscheint deshalb nur als mehrere „einzelne Internet-Referenz“-Störungen, nicht als WAN.
Beginn und Ende eines Ausfalls sind wegen des 15-s-Auswertetakts nur auf ±15 s genau.

---

## Die Probleme im Einzelnen

Jeder Abschnitt: mögliche Ursachen, was Wachtl dafür messen muss, die Diagnose-Regel und der Lösungsvorschlag,
den Wachtl anzeigt.

### 1. Große Dateien brechen ab

| Ursache | Erkennbar an |
|---|---|
| MTU-Problem (VPN, PPPoE, Tunnel), „PMTU-Blackhole“ | Ping mit DF-Bit: kleine Pakete gehen, große nicht |
| Duplex-Fehler, schlechtes Kabel, defekter Switch-Port | Link 100 Mbit/s oder Halbduplex, Fehlerzähler steigen, viele Retransmits |
| Link-Abbruch / Energiesparen der Netzwerkkarte | Ereignis „Link down“ auf der Probe, kurze Lücke in allen Pings |
| Firewall/IPS beendet lange Sitzungen | Dauertransfer bricht nach immer gleicher Zeit ab |
| WLAN-Roaming | BSSID-Wechsel genau zum Abbruch |

**Neu messen**

- **MTU-Check**: Ping mit gesetztem DF-Bit (`PingOptions.DontFragment`), Nutzdaten per Intervallhalbierung
  zwischen 548 und 1472 Byte (Pfad-MTU = Nutzdaten + 28). Ergebnis `wachtl_mtu_bytes` je Ziel (Server, Gateway,
  Internet) und ob der Router „Paket zu groß“ zurückmeldet oder große Pakete stumm verschwinden. Alle 6 h und bei Pfadwechsel.
- **Dauertransfer**: iperf3 mit `-i 1` und 300–600 s Dauer (nachts). Auswerten je Sekunde: Einbrüche auf 0,
  Abbruch, Retransmit-Rate.
- **Netzwerkkarte** (alle 60 s, kostet nichts): Link-Geschwindigkeit (`NetworkInterface.Speed`), Duplex
  (WMI `MSFT_NetAdapter.FullDuplex`), Fehler und verworfene Pakete (`GetIPStatistics()`), systemweite
  TCP-Retransmits (`GetTcpIPv4Statistics().SegmentsResent / SegmentsSent`), Medientyp LAN/WLAN. Die Zähler
  laufen seit dem Start hoch, gemeldet wird die Differenz je Minute.
- **Netzwerk-Ereignisse**: `OperationalStatus` jeder Netzwerkkarte prüfen (bzw. `NotifyIpInterfaceChange`) und
  `NetworkChange.NetworkAddressChanged` auswerten; Link weg/da, neue IP und neues Gateway (danach neu lesen) sofort
  an den Server melden. `NetworkAvailabilityChanged` allein reicht nicht: es meldet sich erst, wenn gar keine
  Karte mehr aktiv ist (VPN- und Hyper-V-Adapter bleiben „aktiv“).

**Diagnose und Vorschlag**

| Befund | Vorschlag |
|---|---|
| Große Pakete verschwinden ohne Rückmeldung „Paket zu groß“ (PMTU-Blackhole) oder Pfad-MTU kleiner als für die Leitung üblich (1500 Ethernet, 1492 PPPoE/DSL) | MSS-Clamping am Router/VPN aktivieren (z. B. MSS 1360) oder MTU des Tunnels senken; ICMP Typ 3 Code 4 „Fragmentation needed“ bzw. ICMPv6 „Packet Too Big“ in der Firewall erlauben |
| Link 100 Mbit/s oder Halbduplex, obwohl 1 Gbit/s möglich | Kabel (Cat 5e/6) und Switch-Port prüfen, beidseitig „Auto“ statt fester Werte |
| Fehlerzähler steigt, Retransmits > 1 % | Patchkabel und Port tauschen, Treiber der Netzwerkkarte aktualisieren |
| „Link down“ kurz vor dem Abbruch | Energiesparen der Netzwerkkarte abschalten („Computer kann Gerät ausschalten“, selektives Energiesparen); bei Verlust ohne Link-Abbruch auch Energy Efficient Ethernet testweise aus |
| Dauertransfer endet immer nach gleicher Zeit | Sitzungs-Timeout der Firewall bzw. IPS-Regel prüfen |

### 2. Knacken, Rauschen, Verzögerung bei VoIP

Sprache verträgt kaum Verlust (< 1 %), wenig Jitter (< 30 ms) und kurze Laufzeit (< 150 ms einfach).
Schuld sind fast immer **volle Leitung ohne Priorisierung** (vor allem Upload), **WLAN** oder **Verlust im LAN**.

**Neu messen**

- **MOS-Schätzung** aus den vorhandenen Ping-Werten zur Telefonanlage bzw. zum SIP-Provider (E-Modell nach
  ITU-T G.107, vereinfacht): L = RTT/2 + 2 × Jitter + 10 ms; R = 93,2 − L/40 (L < 160 ms), sonst
  93,2 − (L − 120)/10; R −= 2,5 × Verlust in %; MOS = 1 + 0,035·R + 7·10⁻⁶·R·(R − 60)·(100 − R), höchstens ca. 4,4.
  Geht **ohne neue Probe-Version**.
- **VoIP-Profil** für iperf3: UDP, 50 Pakete/s à 172 Byte wie G.711 mit 20-ms-Paketen (`-u -l 172 -b 69k`),
  30 s, beide Richtungen. Liefert Jitter und Verlust wie bei einem echten Gespräch. Mit DSCP EF (`--dscp 46`)
  nur, wenn eine QoS-Richtlinie (GPO) für `iperf3.exe` die Markierung setzt – Windows ignoriert sie sonst.
- **Latenz unter Last** (Bufferbloat): während jedes Speedtests läuft ein Ping zum Gateway und ins Internet mit.
  Ergebnis: Latenz Leerlauf vs. Download vs. Upload.
- **SIP-Ziel als Rolle** „Telefonie“ im Ping-Check, damit Regeln wissen, welches Ziel zählt.

**Diagnose und Vorschlag**

| Befund | Vorschlag |
|---|---|
| MOS < 3,6 nur während Speedtest oder bei hoher WAN-Auslastung (SNMP) | QoS am Router: Sprache priorisieren, Bandbreite auf ca. 90 % der Leitung begrenzen (SQM/Traffic-Shaping) |
| Latenz unter Upload-Last steigt um > 100 ms | Bufferbloat: Upload-Shaping am Router, ggf. Leitung mit mehr Upload |
| Jitter/Verlust schon zum Gateway | Problem im LAN/WLAN: Telefone per Kabel, Voice-VLAN, WLAN-Kanal prüfen |
| Gateway sauber, ab Provider-Hop Verlust | Provider-Störung: Ticket mit Hop-Tabelle als Nachweis |
| DSCP-Test (mit GPO-Markierung) nicht besser als ohne | Markierung wird verworfen/umgeschrieben oder nicht priorisiert: QoS-Richtlinie der Switches/Firewall prüfen |
| Einseitig keine Sprache, nach 30 s Abbruch (Meldung „Sprache/Video“) | SIP-ALG am Router abschalten, UDP-Timeouts ≥ 180 s |

### 3. Verbindungsabbruch ins WAN für ca. 20 s, einmal täglich (STP-Verdacht)

Zwei Ursachen liegen nahe, und sie sehen für den Benutzer gleich aus:

- **Spanning Tree**: Klassisches STP (802.1D) braucht nach einer Neuberechnung 30–50 s, bis Uplinks wieder
  weiterleiten. Für alle spürbar ist das nur, wenn sich der **Baum selbst** ändert: ein Uplink wackelt, ein Switch
  startet neu (z. B. nächtliches Firmware-Update) oder ein Switch mit zufällig niedrigerer Priorität wird
  **Root-Bridge**. Ein einzelnes Endgerät ohne PortFast blockiert nur seinen eigenen Port; für alle anderen löst es
  nur eine Topologie-Meldung aus (kurzes Fluten, kein Ausfall). RSTP braucht nur 1–3 s. 20 s passen also eher zu
  einem Gerät, das täglich neu startet, oder zu einem Mischbetrieb STP/RSTP.
- **Zwangstrennung des Providers** (vor allem DSL/VDSL, oft alle 24 h): typischerweise 5–30 s, danach neue
  öffentliche IP bzw. neues IPv6-Präfix. Kabel (DOCSIS), Glasfaser und viele Business-Anschlüsse trennen nicht
  zwangsweise. Bei DS-Lite/CGNAT ändert sich die öffentliche IPv4 nicht zuverlässig, dann zählt das IPv6-Präfix;
  bei fester IP entfällt dieses Merkmal.

STP abzuschalten beseitigt zwar die Unterbrechung, aber auch den Schutz vor Netzschleifen. Ein einziges falsch
gestecktes Kabel legt dann das ganze Netz lahm. Besser: **RSTP** statt STP, Root-Bridge fest auf dem
Core-Switch (niedrigste Priorität) mit **Root-Guard**, Endgeräte-Ports als **Edge/PortFast** mit **BPDU-Guard**.

**Wachtl unterscheidet beides so**

| Merkmal | STP / LAN | Zwangstrennung / WAN |
|---|---|---|
| Ping zum Gateway | fällt aus | bleibt ok |
| Betroffene Probes | alle hinter demselben Switch, gleichzeitig | alle am Standort, gleichzeitig |
| Link der Netzwerkkarte | bleibt oben | bleibt oben |
| Öffentliche IP / IPv6-Präfix danach | gleich | neu (bei DSL ohne feste IP) |
| SNMP am Switch | STP-Topologiewechsel-Zähler steigt | – |
| Uhrzeit | an Neustart eines Geräts gebunden | fast immer gleiche Uhrzeit (± Minuten) |

**Neu messen**

- **Öffentliche IP** der Probe alle 5 min (z. B. `https://speed.cloudflare.com/cdn-cgi/trace`, Feld `ip=`),
  getrennt für IPv4 und IPv6, ohne Proxy (sonst kommt die IP des Proxys) – nur auf einer Probe je Standort.
- **SNMP am Switch** (vom Server): `dot1dStpTopChanges` (Zähler) und `dot1dStpTimeSinceTopologyChange`
  (Zeit seit der letzten Änderung), Link-Status der Ports, `sysUpTime`. Den auslösenden Port nennt die
  BRIDGE-MIB nicht; dafür Syslog des Switches oder Hersteller-MIB. Bei Cisco PVST+ gelten die Werte je VLAN.
- **Gateway-MAC** aus der ARP-Tabelle (Win32 `GetIpNetTable2`): VRRP/HSRP behalten beim Umschalten ihre
  virtuelle MAC – ein Wechsel deutet auf einen IP-Konflikt.

**Auswertung verbessern (ohne neue Probe)**

- **WAN-Alarm wie den Ziel-Alarm bauen**: „alle Referenzen N Pings in Folge weg“ statt „30 s lang weg“. Dann
  erscheint der 20-s-Ausfall als WAN und nicht als drei einzelne Referenzen.
- **Exakte Dauer** aus den 1-s-Rohdaten nachrechnen statt aus dem 15-s-Alarmtakt.
- **Standortweite Zusammenfassung**: fallen mehrere Probes eines Standorts gleichzeitig aus, ist es ein
  Standort-Ereignis (Switch, Router, Leitung), keine Einzelstörung.
- **Wiederkehr erkennen**: Ausfälle derselben Ursache an ≥ 3 Tagen zur gleichen Uhrzeit (± 15 min) → Befund
  „täglich wiederkehrend um 04:12“.

**Diagnose und Vorschlag**

| Befund | Vorschlag |
|---|---|
| Täglich gleiche Uhrzeit, Gateway ok, neue öffentliche IP | Zwangstrennung: im Router auf eine Nachtzeit legen (z. B. 04:00) oder Business-Anschluss ohne Zwangstrennung |
| Gateway weg, mehrere Probes gleichzeitig, Topologie-Zähler (SNMP) steigt | STP-Neuberechnung: RSTP aktivieren, Root-Bridge fest auf dem Core-Switch mit Root-Guard, Endgeräte-Ports als Edge/PortFast mit BPDU-Guard; auslösenden Port und Switch im Syslog suchen, Switch-Uptimes vergleichen |
| Gateway weg, nur eine Probe, „Link down“ | Kabel/Port/Energiesparen dieser Probe |
| STP ausgeschaltet (Hinweis im Befund) | Schleifenschutz fehlt: RSTP mit Edge-Ports statt ganz aus, alternativ Loop-Protection des Switches |

### 4. Sporadischer Abbruch zum Fileserver, alles andere ok

**Neu messen**

- **TCP-Port-Check**: Verbindungsaufbau zu `fileserver:445` (SMB) im 5-s-Takt, Zeit bis zum Aufbau und Fehlerart
  (Timeout, abgelehnt, Reset). Zeigt, ob der **Dienst** weg ist, obwohl Ping geht.
- **Rolle „Server“** für Ziele, damit Regeln den Fileserver kennen.
- **MAC des Fileservers** aus der ARP-Tabelle (nur wenn er im selben Subnetz wie die Probe steht): wechselt sie,
  gibt es einen **IP-Konflikt** oder ein falsch eingerichtetes NIC-Teaming.
- **Probe auf dem Fileserver** (Windows Server wird unterstützt): misst in Gegenrichtung zu den Clients und ist
  gleichzeitig iperf3-Gegenstelle.

**Diagnose**

| Befund | Vorschlag |
|---|---|
| Alle Probes verlieren gleichzeitig den Fileserver | Problem am Server bzw. seinem Switch-Port: Energiesparen der Server-Netzwerkkarte, Teaming, Treiber, Port-Fehler (SNMP) |
| Nur Probes hinter einem Switch | Uplink dieses Switches prüfen |
| Nur eine Probe | Kabel/Port/WLAN dieses PCs |
| MAC des Fileservers wechselt | IP-Konflikt: doppelte IP suchen (DHCP-Bereich vs. feste IP), Teaming-Modus prüfen |
| Ping ok, Port 445 Timeout | Dienst/Firewall/Virenscanner auf dem Server, SMB-Ereignisse im Server-Log |
| Gleichzeitig „Link down“ auf dem Client | lokales Problem des Clients, nicht der Server |

### 5. Webradio stockt

Webradio ist ein dauernder HTTP-Download mit kleiner Rate (128–320 kbit/s). Stocken heißt: Verlust oder
Verzögerung über mehrere Sekunden, meist durch eine **volle Leitung**, **Bufferbloat**, **WLAN** oder einen
**Proxy/Inhaltsfilter**, der den Strom puffert oder trennt.

**Neu messen**

- **HTTP-Stream-Check**: eine Stream-URL 60 s lang laden, Durchsatz je Sekunde. Befund „Unterbrechung“, wenn
  der Puffer (z. B. 5 s bei der Stream-Rate) leerlaufen würde. Wahlweise über den Proxy der Probe.
- **WAN-Auslastung** per SNMP am Router/Firewall (Bytes je Sekunde am WAN-Port).

**Diagnose**

| Befund | Vorschlag |
|---|---|
| Stocken nur bei hoher WAN-Auslastung | Leitung voll: QoS/Shaping, Updates und Backups zeitlich verlegen, ggf. mehr Bandbreite |
| Stocken nur über den Proxy | Proxy/Inhaltsfilter: Stream-Domain vom Scannen ausnehmen |
| Verlust schon zum Gateway, Probe im WLAN | WLAN: Signal/Kanal prüfen, Kabel nutzen |
| Stocken trotz freier Leitung, Verlust ab Provider-Hop | Provider bzw. Peering: Hop-Tabelle als Nachweis an den Provider |

### 6. Bandbreite ins Internet gering

**Neu messen bzw. einstellen**

- **Gebuchte Bandbreite je Standort** (Download/Upload) im Web-UI. Alarm und Bewertung in **% des Solls**
  statt fester Mbit/s je Check.
- **Link-Geschwindigkeit** der Probe (s. Problem 1): Eine Probe mit 100-Mbit-Link kann keine 250 Mbit/s messen.
- **Vergleich mehrerer Probes und der Server-Probe** am selben Standort.
- **Direkt vs. Proxy**: derselbe Speedtest einmal mit und einmal ohne Proxy.
- **Tageszeit-Profil**: Mittelwert je Stunde über 14 Tage.

**Diagnose**

| Befund | Vorschlag |
|---|---|
| Alle Probes und Server < 70 % des Solls, auch nachts | Leitung/Provider: Störung melden, Messprotokoll als Nachweis |
| Nur abends/tagsüber zu Spitzenzeiten | Auslastung (eigene oder beim Provider): SNMP-Auslastung prüfen, QoS |
| Nur eine Probe langsam | PC: Link-Geschwindigkeit, WLAN, Virenscanner/VPN-Client |
| Mit Proxy deutlich langsamer als direkt | Proxy/Inhaltsfilter ist der Engpass: dimensionieren oder Ausnahmen |
| Gute Bandbreite, aber stark steigende Latenz unter Last | Bufferbloat (s. Problem 2) |
| WAN-Auslastung (SNMP) bereits nahe 100 % vor dem Test | Leitung durch andere Nutzer belegt, nicht zu langsam |

### 7. Bandbreite zum Fileserver gering

**Neu messen**

- **iperf3 gegen eine Probe auf dem Fileserver** (geht schon heute: Probe installieren, „iperf3-Gegenstelle“ an).
  Das trennt **Netz** von **Server/Anwendung**.
- **Link-Geschwindigkeit/Duplex** auf Client und Server, Fehlerzähler, Retransmits (s. Problem 1).
- Optional später: **SMB-Lesetest** (Testdatei von einer Freigabe lesen, braucht ein Konto).

**Diagnose**

| Befund | Vorschlag |
|---|---|
| iperf3 gut, Kopieren trotzdem langsam | Server: Datenträger, Virenscanner, SMB-Signierung/-Verschlüsselung, Energiesparprofil |
| iperf3 ≈ 94 Mbit/s | irgendwo nur 100 Mbit/s: Link-Geschwindigkeit von Client, Server und Uplinks prüfen |
| iperf3 schlecht, viele Retransmits | Kabel, Port, Duplex, Fehlerzähler (SNMP) |
| Nur Probes hinter einem Switch langsam | Uplink dieses Switches (1 Gbit/s geteilt?) bzw. Kaskade |
| Nur im WLAN langsam | WLAN ist der Engpass, für große Dateien Kabel nutzen |

### 8. Bestimmte Seiten lassen sich nicht öffnen (DNS)

**Neu messen**

- **DNS-Check**: eine Liste von Namen (z. B. die betroffenen Seiten, `microsoft.com`, interne Namen) gegen
  **jeden DNS-Server der Probe** (aus `GetIPProperties().DnsAddresses`) **und** einen öffentlichen Resolver
  (1.1.1.1) auflösen. Werte: Antwortzeit, Ergebnis (ok, NXDOMAIN, SERVFAIL, Timeout), Adressen.
  `System.Net.Dns` lässt den Server nicht wählen; die Probe nutzt Win32 `DnsQueryEx` mit Serverliste oder einen
  eigenen kleinen DNS-Client (UDP 53, TCP bei abgeschnittener Antwort). Veraltete Einträge wie `fec0:0:0:ffff::1`
  werden ignoriert. Blockt die Firewall DNS ins Internet, ist der Vergleich mit 1.1.1.1 nicht möglich – Wachtl
  meldet das als Hinweis, nicht als Fehler.
- **HTTP/HTTPS-Check**: Zeit für DNS, TCP-Aufbau, TLS-Handschlag und erste Antwort getrennt, Statuscode,
  Zertifikats-Ablauf. Zeigt, ob es **nach** DNS hakt.

**Diagnose**

| Befund | Vorschlag |
|---|---|
| Interner DNS: SERVFAIL/Timeout, öffentlicher DNS: ok | Weiterleitung des internen DNS (Forwarder) prüfen; Root-Hints/DNSSEC-Validierung; zweiten Forwarder eintragen |
| Interner DNS: NXDOMAIN, öffentlicher: Adresse | veraltete oder falsche interne Zone (Split-DNS), bedingte Weiterleitung prüfen |
| Antwort 0.0.0.0 oder Adresse der Sperrseite | DNS-Filter/Sicherheitsdienst blockt: Ausnahme eintragen |
| Nur einer von zwei DNS-Servern der Probe antwortet | ausgefallenen DNS-Server aus DHCP entfernen oder reparieren |
| DNS > 200 ms | DNS-Server überlastet oder Weiterleitung über langsame Strecke |
| DNS ok, TLS-Handschlag hängt | MTU-Problem (s. Problem 1) oder SSL-Inspektion der Firewall |
| DNS ok, TCP-Aufbau scheitert | Firewall/Geoblocking/Proxy-Regel |

---

## Übergreifende Bausteine

### Diagnose-Regeln auf dem Server

Neues Modul `server/wachtl/services/diagnosis.py`, nach dem Muster der vorhandenen Hop-Bewertung
(`pathanalysis.Finding`):

```
Befund(
  ebene      = info | warn | bad,
  problem    = "dns" | "voip" | "wan_kurzausfall" | …,
  aussage    = "Täglich um 04:12 fällt das Internet am Standort Nord 18 s aus (5 von 7 Tagen).",
  ursache    = "Zwangstrennung des Providers – das Gateway bleibt erreichbar, die öffentliche IP wechselt.",
  vorschlag  = "Zwangstrennung im Router auf 04:00 legen oder Anschluss ohne Zwangstrennung buchen.",
  sicherheit = hoch | mittel | gering,
  belege     = [Links zu Graph, Ausfällen, Hop-Tabelle],
)
```

- Eingaben: Zustände aus `checkstatus`, Ausfälle aus `outages`, Hop-Bewertung, `bandwidth_runs`,
  Störungsmeldungen und neue Messarten.
- Läuft alle 5 min und beim Öffnen einer Seite. Befunde erscheinen in der Übersicht („Diagnose“), auf Standort-
  und Probe-Seite und in der Alarm-Mail.
- Jede Regel hat einen Test mit gestellten Daten (wie `tests/test_v03.py` für die Hop-Bewertung).

### Störungsmeldungen automatisch zuordnen

Meldet ein Benutzer „Sprache/Video“ oder „Abbrüche“, sucht Wachtl ±10 min nach Ausfällen, Verlust, Jitter und
MOS dieser Probe und schreibt das Ergebnis an die Meldung: „Passt zu: Verlust 6 % zum Gateway 09:41–09:44“
oder „Keine Auffälligkeit im Netz – eher Anwendung oder Gegenstelle“.

### Mehrere Probes vergleichen

Die stärkste Aussage entsteht durch Vergleich: **eine** Probe betroffen → PC/Kabel/WLAN; **alle hinter einem
Switch** → Switch/Uplink; **alle am Standort** → Router/Leitung; **alle Standorte** → Rechenzentrum/Server.
Dafür braucht Wachtl optional eine Zuordnung Probe → Switch (Feld an der Probe oder per SNMP/LLDP).

### SNMP (Infrastruktur)

Neue Messart auf dem Server (bzw. einer Probe am Standort): SNMP v2c/v3 auf Router, Firewall und Switches.
Werte: Bytes, Fehler und Verwerfungen je Port, Link-Status, Port-Geschwindigkeit, `sysUpTime` (Neustarts),
STP-Topologiewechsel. Beantwortet „Ist die Leitung voll?“, „Welcher Port hat Fehler?“ und „Hat sich der
Spanning Tree neu berechnet?“ – drei Fragen, die die PCs allein nicht beantworten können.

### WLAN

Bei Probes im WLAN: Signalstärke, Kanal, Access Point (BSSID) und Wechsel über die Windows-WLAN-API.
Viele „Abbrüche“ und „Knacken“ sind schwaches Signal oder Roaming. Ab Windows 11 24H2 liefert die API SSID und
BSSID nur mit Standortfreigabe; ob das für einen Dienst gilt, ist vorab zu testen.

---

## Übersicht: Problem → Bausteine

| Problem | Heute erkennbar | Neu nötig | Sicherheit danach |
|---|---|---|---|
| Große Dateien brechen ab | kaum | MTU, Netzwerkkarte, Ereignisse, Dauertransfer | hoch |
| VoIP-Knacken/-Verzögerung | Jitter/Verlust zum Ziel | MOS, VoIP-Profil, Latenz unter Last, SNMP-Auslastung | hoch |
| 20-s-WAN-Ausfall täglich | teilweise (als Einzelziele) | WAN-Alarm, Wiederkehr, Standort-Korrelation, öffentliche IP, SNMP-STP | hoch |
| Fileserver sporadisch weg | Ping-Ausfall | TCP 445, ARP/MAC, Probe-Vergleich, Probe auf dem Server | hoch |
| Webradio stockt | indirekt | HTTP-Stream, SNMP-Auslastung | mittel |
| Internet langsam | Speedtest | Soll-Bandbreite, Link-Speed, Probe-Vergleich, Proxy-Vergleich | hoch |
| Fileserver langsam | iperf3 | Link-Speed/Duplex, Retransmits, Probe auf dem Server | hoch |
| Seiten öffnen nicht (DNS) | nein | DNS-Check je Server, HTTP-Check | hoch |

## Sofort umsetzbar

Nur Server, keine neue Probe-Version nötig:

1. **WAN-Alarm** auf „N Pings in Folge auf allen Referenzen“ umstellen (erkennt 20-s-Ausfälle als WAN).
2. **Exakte Ausfalldauer** aus den 1-s-Rohdaten.
3. **Standortweite Ausfälle** zusammenfassen und **tägliche Wiederkehr** erkennen.
4. **MOS-Schätzung** aus Ping-RTT, Jitter und Verlust, Rolle „Telefonie“.
5. **Retransmits** als Messwert und in der Bewertung; Alarm für UDP-Jitter/-Verlust aus iperf3.
6. **Soll-Bandbreite** je Standort, Bewertung in %.
7. **Störungsmeldungen automatisch zuordnen**.
8. Grundgerüst `diagnosis.py` mit den Regeln aus 1–7 und Anzeige „Diagnose“ in der Übersicht.

Empfehlung für den Kunden jetzt: eine **Probe auf dem Fileserver** installieren (iperf3-Gegenstelle an), einen
**Ping auf den Fileserver** im 1-s-Takt und einen **Ping auf die Telefonanlage/den SIP-Provider** anlegen.

## Reihenfolge

| Phase | Inhalt |
|---|---|
| 0.7 | Sofort umsetzbar (oben), Diagnose-Seite |
| 0.8 | Probe: DNS-, TCP-Port- und HTTP-Check, MTU-Check, Netzwerkkarte + Ereignisse, öffentliche IP |
| 0.9 | VoIP-Profil, Latenz unter Last, HTTP-Stream, Dauertransfer, ARP/MAC |
| 1.0 | SNMP (Auslastung, Port-Fehler, STP), WLAN, Probe → Switch-Zuordnung |

Jede neue Messart entsteht doppelt: in der Windows-Probe (C#) und in der Server-Probe (Python), mit Eintrag in
`checktypes.py`, Ingest-Freigabe, `checkstatus` und Alarmregeln (Ablauf siehe Code-Kommentare in `checktypes.py`).
