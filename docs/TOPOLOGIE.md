# Switch-Topologie (1.0)

Wachtl fragt die Switches eines Standorts per SNMP ab und zeigt daraus einen Baum vom Internet bis zum einzelnen
Gerät: welche Switches wie verbunden sind, welche Ports belegt sind, welches Gerät an welchem Port hängt – und was
dabei auffällt (Port-Fehler, langsame Verbindungen, nicht verwaltete Switches, Kabelkreise).

Im Web-UI: Standort › **Topologie** mit vier Ansichten:

| Ansicht | Inhalt |
| --- | --- |
| **Baum** | Internet → Gateway → Switches → Geräte. An jeder Linie Port und Geschwindigkeit („P1 ⇄ P25 · 10G“), Farbe nach Geschwindigkeit, gestrichelt = vermutet. Klick auf einen Switch zeigt rechts Adresse, Modell, Uplink, Ports und direkte Nachbarn mit „Weboberfläche öffnen“ und SSH. Auf dem Handy steht der Baum zusätzlich als Liste da. |
| **Switches** | Eine Karte je Switch: Uplink, Belegung, PoE, „Aufschalten“ und „Weboberfläche“. Nicht verwaltete und noch nicht eingetragene Switches erscheinen gestrichelt. |
| **Switch aufgeschaltet** | Frontansicht aller Ports (Farbe = Geschwindigkeit, rot = Fehler, ↑ Uplink, ⚡ PoE). Klick auf einen Port zeigt Verbindung, Nachbar, VLAN, PoE, Fehler der letzten 24 h, die Geräte am Port und – wenn auf einem davon eine Wachtl-Probe läuft – ihre Messwerte. Darunter alle Ports als Tabelle, Zugang und Verlauf. |
| **Probleme** | Baum mit nummerierten Markierungen und die Liste der Befunde, je mit „seit“, Abhilfe und „Als bekannt markieren“. |
| **Verlauf** | Chronik aller Änderungen nach Tagen, filterbar (Störungen, Links und Ports, Geräte, Switches) und je Switch; rechts das gewählte Ereignis mit dem Baum von damals. |
| **Pfad suchen** | Gerät nach Name, IP oder MAC suchen: jedes Kabel und jeder Port bis ins Internet, Engstelle, Fehler unterwegs, Messwerte der Probe auf dem Gerät und Änderungen auf dem Weg. |

## Switch eintragen (Assistent)

Standort › Topologie › **Switch hinzufügen** (nur Administratoren), je Switch:

1. **Switch und Zugang**: Adresse, Bezeichnung, Ort, UDP-Port; SNMP-Version und Zugangsdaten – oder „wie bei Switch X“
   übernehmen (viele Switches teilen sich dieselben Zugangsdaten).
2. **Verbindung testen**: Der Wachtl-Server fragt den Switch sofort ab und zeigt Name, Modell, Ports, Größe der
   MAC-Tabelle, Anzahl der LLDP/CDP-Nachbarn, PoE und VLANs – oder den Fehler mit Hinweisen (falsche Community,
   falscher v3-Benutzer, falsches Auth- oder Priv-Passwort, keine Antwort).
3. **Speichern**: ab dann regelmäßig (siehe Abfrage); „Speichern und nächsten Switch einrichten“ startet den Assistenten neu mit
   denselben Zugangsdaten. Per LLDP/CDP gefundene Switches ohne Zugangsdaten stehen dort als Vorschläge.

Unterstützt werden **SNMPv1**, **SNMPv2c** (Community) und **SNMPv3** mit allen Sicherheitsstufen
(noAuthNoPriv, authNoPriv, authPriv):

| | Verfahren |
| --- | --- |
| Anmeldung (Auth) | MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (RFC 3414, RFC 7860) |
| Verschlüsselung (Priv) | DES, AES-128 (RFC 3826), AES-192/AES-256 (Blumenthal, wie net-snmp „AES192/AES256“), AES-192/AES-256 Cisco („Reeder“, net-snmp „AES192C/AES256C“) |

Wachtl liest nur (GET/GETNEXT/GETBULK), schreibt nie auf den Switch. Ein Lesezugang genügt.

Die Zugangsdaten liegen verschlüsselt in der Datenbank (Fernet, Schlüssel aus `WACHTL_SECRET_KEY` abgeleitet), werden
im Web-UI nie wieder angezeigt und tauchen nicht im Audit-Log auf. Wer nur die Datenbank oder ein Backup hat, kann sie
nicht lesen. Ändert sich `WACHTL_SECRET_KEY`, müssen sie neu eingegeben werden (der Switch meldet dann „Zugangsdaten
nicht lesbar“).

## Abfrage

- Zwei Takte, einstellbar unter Verwaltung › Messung › Switch-Topologie:
  - **schnell, alle 60 s** (`topo_quick_s`, 0 = aus): nur Laufzeit und je Port Status, Geschwindigkeit, Fehler und
    letzte Statusänderung (`ifLastChange`) – wenige Pakete je Switch;
  - **vollständig, alle 5 min** (`topo_full_min`): zusätzlich MAC-Tabelle, Nachbarn, PoE, VLAN, ARP.
  Nicht erreichbare Switches werden nur im vollständigen Takt erneut versucht.
- Die **Server-Probe** fragt alle 15 s beim Server nach fälligen Abfragen (`GET /api/probe/v1/topology/jobs`, je Auftrag
  `kind` = `quick` oder `full`), fragt per SNMP ab (bis zu 4 parallel, Timeout 2 s, 1 Wiederholung) und meldet das
  Ergebnis (`POST /api/probe/v1/results/topology`). Nur die Server-Probe bekommt Aufträge und Zugangsdaten; Windows-Probes nicht.
- Der Wachtl-Server muss die Switches über **UDP 161** erreichen (bei mehreren Standorten über das VPN). Viele Switches
  erlauben SNMP nur von eingetragenen Adressen – dort die Adresse des Wachtl-Servers eintragen.
- „Jetzt abfragen“ auf der Switch-Seite: vollständige Abfrage, Ergebnis nach etwa 15–30 Sekunden.

Gelesene Standard-MIBs (herstellerunabhängig): SNMPv2-MIB (System), IF-MIB (Ports, Geschwindigkeit, Fehler),
EtherLike-MIB (Duplex), BRIDGE-MIB und Q-BRIDGE-MIB (MAC-Tabelle, VLAN), LLDP-MIB und CISCO-CDP-MIB (Nachbarn),
POWER-ETHERNET-MIB (PoE), IP-MIB (Adressen, ARP, Standard-Gateway). Fehlt eine Tabelle, bleibt der Teil leer.

## Auswertung

1. **Verbindungen zwischen Switches** aus LLDP/CDP (der Switch nennt Nachbar und dessen Port).
2. Fehlt LLDP, aus den **MAC-Tabellen**: Switch A sieht B an Port p, B sieht A an Port q, und kein dritter Switch liegt
   dazwischen → Kabel A.p ⇄ B.q.
3. **Geräte** hängen an dem Port, an dem ihre MAC gelernt wurde und der keine Verbindung zu einem Switch ist. Namen und
   IP-Adressen kommen aus dem [Netzwerkscan](NETZWERKSCAN.md) und den ARP-Tabellen der Switches.
4. **Wurzel**: der Switch, an dem das Standard-Gateway des Switches hängt (darüber Gateway und Internet); sonst der
   Switch mit den meisten Verbindungen. Switches ohne Verbindung stehen unter dem Baum.

Befunde:

| Befund | Wann | Stufe |
| --- | --- | --- |
| Switch antwortet nicht | letzte Abfrage fehlgeschlagen | Störung |
| Eingangsfehler an Port | ≥ 50 neue fehlerhafte Pakete in 24 h (ab 1000 Störung) | Warnung/Störung |
| Langsame Verbindung | Verbindung zu einem Switch oder Access Point unter 1 Gbit/s | Warnung |
| Halbduplex | Port mit Link im Halbduplex | Warnung |
| Möglicher Kabelkreis | dieselbe MAC wechselt in 24 h ≥ 3-mal zwischen Geräte-Ports | Warnung |
| Nicht verwalteter Switch | ≥ 3 Geräte an einem Port ohne LLDP-Nachbarn | Hinweis |
| Switch ohne Zugangsdaten | per LLDP/CDP gefunden, aber nicht eingetragen | Hinweis |
| Keine MAC-Tabelle | Switch liefert weder MAC-Tabelle noch Nachbarn | Hinweis |

Grenzen: Cisco-Switches mit mehreren VLANs liefern die MAC-Tabelle per SNMPv2c nur je VLAN („Community@VLAN“) bzw. per
SNMPv3 je Kontext – dann fehlen Geräte außerhalb von VLAN 1. Die Port-Nummer der PoE-MIB ist nicht genormt; Wachtl
nimmt die Bridge-Port-Nummer an. Access Points werden über LLDP erkannt.

## Verlauf

Bei jeder Abfrage vergleicht Wachtl mit der vorigen und speichert Änderungen als Ereignis:

| Ereignis | Erkannt über | Stufe |
| --- | --- | --- |
| Link weg / Link wieder da | Port-Status; Zeitpunkt aus `ifLastChange` | Störung an Ports zu Switches, Access Points und Routern, sonst Info (PC aus) |
| Kurz ohne Link | `ifLastChange` hat sich geändert, der Port ist aber wieder verbunden – ein Aussetzer zwischen zwei Abfragen | Warnung, an Uplinks Störung |
| Geschwindigkeit geändert | IF-MIB | Warnung, wenn langsamer (Uplink oder unter 1 Gbit/s), sonst Info |
| Port-Fehler | ≥ 10 neue Eingangsfehler seit der letzten Abfrage | Warnung, ab 1000 Störung |
| Switch neu gestartet | Laufzeit kleiner als zuvor | Warnung |
| Switch nicht erreichbar / wieder erreichbar | Abfrage schlägt fehl bzw. klappt wieder | Störung / Info |
| Nachbar geändert | LLDP/CDP je Port | Warnung |
| Gerät neu / umgesteckt | MAC-Tabelle an Geräte-Ports (nicht an Uplinks) | Info |

Dazu speichert Wachtl **Stände** je Switch: sobald sich der Aufbau ändert (Ports verbunden, Geschwindigkeit, Nachbarn),
sonst höchstens stündlich – komprimiert. Nach 7 Tagen bleiben nur Änderungen und ein Stand je Tag.

So lässt sich zurückblättern:

- **Zeitleiste am Baum** (Baum › Seitenbereich „Zeitleiste“): Ereignisse nach Tagen, Punkt rot = Störung, orange =
  Warnung, blau = Info; standardmäßig nur Störungen und Warnungen. Ein Klick zeigt den **Baum zu diesem Zeitpunkt** mit
  hervorgehobenem Switch und einem Banner „Stand … – Zurück zu Jetzt“; „Früher“ und „Später“ springen von Änderung zu Änderung.
- **Chronik** (Ansicht „Verlauf“): alle Änderungen mit Filtern und Switch-Auswahl, rechts Details und der Baum von damals.
- **Port-Verlauf** (Switch-Seite): je Port eine Zeile über 6 h, 24 h oder 7 Tage – verbunden mit Geschwindigkeit,
  Aussetzer, Fehler, kein Link. Wackelnde Ports fallen so sofort auf.
- **Störung im Kontext** (Ausfälle › „Switch-Netz zu dieser Zeit“ oder Chronik › „Was passierte gleichzeitig“):
  Paketverlust der Probe und darunter die Ports auf ihrem Weg ins Internet sowie die Erreichbarkeit der Switches im
  selben Zeitraum, dazu die Änderungen und eine Einschätzung („Wahrscheinliche Ursache: Anschluss der Probe …“ oder
  „Switch-Netz unauffällig“). Dafür muss der PC der Probe im Netzwerkscan gefunden und einem Switch-Port zugeordnet sein.

Aufbewahrung: Ereignisse, Port-Fehler und Stände 90 Tage, erledigte Befunde 90 Tage nach dem letzten Auftreten.
