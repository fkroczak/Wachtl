# Switch-Topologie (1.0)

Wachtl fragt die Switches eines Standorts per SNMP ab und zeigt daraus einen Baum vom Internet bis zum einzelnen
Gerät: welche Switches wie verbunden sind, welche Ports belegt sind, welches Gerät an welchem Port hängt – und was
dabei auffällt (Port-Fehler, langsame Verbindungen, nicht verwaltete Switches, Kabelkreise).

Im Web-UI: Menüpunkt **Topologie** links (bei einem Standort direkt dessen Baum, bei mehreren zuerst eine Kachel je
Standort mit Switches, Problemen und gefundenen Switches) oder Standort › **Topologie**, jeweils mit vier Ansichten:

| Ansicht | Inhalt |
| --- | --- |
| **Baum** | Internet → Gateway → Switches → Geräte. An jeder Linie Port und Geschwindigkeit („P1 ⇄ P25 · 10G“), Farbe nach Geschwindigkeit, gestrichelt = vermutet. Klick auf einen Switch zeigt rechts Adresse, Modell, Uplink, Ports und direkte Nachbarn mit „Weboberfläche öffnen“ und SSH. Auf dem Handy steht der Baum zusätzlich als Liste da. |
| **Switches** | Eine Karte je Switch: Uplink, Belegung, PoE, „Aufschalten“ und „Weboberfläche“. Nicht verwaltete und noch nicht eingetragene Switches erscheinen gestrichelt. |
| **Switch aufgeschaltet** | Frontansicht aller Ports (Farbe = Geschwindigkeit, rot = Fehler, ↑ Uplink, ⚡ PoE). Klick auf einen Port zeigt Verbindung, Nachbar, VLAN, PoE, Fehler der letzten 24 h, die Geräte am Port und – wenn auf einem davon eine Wachtl-Probe läuft – ihre Messwerte. Darunter alle Ports als Tabelle, Zugang und Verlauf. |
| **Probleme** | Baum mit nummerierten Markierungen und die Liste der Befunde, je mit „seit“, Abhilfe und „Als bekannt markieren“. |
| **Pfad suchen** | Gerät nach Name, IP oder MAC suchen: jedes Kabel und jeder Port bis ins Internet, Engstelle, Fehler unterwegs, Messwerte der Probe auf dem Gerät und Änderungen auf dem Weg. |

## Switch eintragen (Assistent)

Standort › Topologie › **Switch hinzufügen** (nur Administratoren), je Switch:

1. **Switch und Zugang**: Adresse, Bezeichnung, Ort, UDP-Port; SNMP-Version und Zugangsdaten – oder „wie bei Switch X“
   übernehmen (viele Switches teilen sich dieselben Zugangsdaten).
2. **Verbindung testen**: Der Wachtl-Server fragt den Switch sofort ab und zeigt Name, Modell, Ports, Größe der
   MAC-Tabelle, Anzahl der LLDP/CDP-Nachbarn, PoE und VLANs – oder den Fehler mit Hinweisen (falsche Community,
   falscher v3-Benutzer, falsches Auth- oder Priv-Passwort, keine Antwort).
3. **Speichern**: ab dann alle 15 Minuten; „Speichern und nächsten Switch einrichten“ startet den Assistenten neu mit
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

## Switches automatisch finden

Wachtl sucht Switches selbst und trägt alles ein, was ohne Zugangsdaten geht. Quellen, alle **ohne Anmeldung am Gerät**:

| Quelle | Was sie liefert |
| --- | --- |
| Netzwerkscan der Probes ([NETZWERKSCAN.md](NETZWERKSCAN.md)) | MAC-Adresse → Hersteller (TP-Link, D-Link, Zyxel, Netgear, Aruba/HPE, Cisco, Ubiquiti, MikroTik, LANCOM, Juniper, Extreme, Allied Telesis …); Titel und Server-Kennung der Weboberfläche → Modell (z. B. „TL-SG108E“, „GS1900-24E“, „DGS-1100-08“, „1930 24G“) |
| LLDP/CDP der eingetragenen Switches | Nachbarn, die sich als Bridge melden, mit Name, Adresse und Beschreibung |
| Rundruf der Server-Probe (alle 15 Minuten) | TP-Link Easy Smart (UDP 29808) und Netgear ProSAFE Plus (NSDP, UDP 63322/63324) antworten mit Modell, Name, MAC, IP und Firmware |
| MAC-Tabellen der eingetragenen Switches | ein Gerät eines Netzwerkherstellers an einem Port mit weiteren Geräten |

Je Fund bewertet Wachtl, wie sicher es ein Switch ist („sicher“, „wahrscheinlich“, „möglich“; Router, Access Points,
Kameras und Drucker mit eindeutigem Titel fallen heraus) und wie er sich abfragen lässt:

| Zugangsart | Für | Zugangsdaten |
| --- | --- | --- |
| SNMP | fast alle verwalteten Switches | Community bzw. SNMPv3-Benutzer |
| Weboberfläche | TP-Link Easy Smart (TL-SG105E, TL-SG108E, TL-SG105PE, TL-SG108PE, TL-SG1016PE …) – können kein SNMP | Benutzer und Passwort der Weboberfläche |
| keine | Netgear ProSAFE Plus (GS105E, GS108E, GS305E …) | – |

Standort › Topologie › **Switches** zeigt die Funde unter **Gefundene Switches**. Der Baum hängt jeden Fund an den Port,
an dem ein verwalteter Switch seine MAC sieht, mit den Geräten dahinter (gestrichelt, „Zugangsdaten fehlen“ bzw. „ohne
Abfrage“). **Wachtl probiert keine Passwörter aus.** Fehlen Zugangsdaten, fragt Wachtl danach: Hinweis über dem Baum,
Befund „ohne Zugangsdaten“ und **Zugangsdaten eingeben** am Fund. Der Assistent ist dann mit Adresse, Name und
Zugangsart vorbelegt. Darunter stehen die übrigen Funde zum Anhaken („gelten dieselben Zugangsdaten auch hier?“):
Beim Speichern testet Wachtl sie und trägt die ein, bei denen die Anmeldung klappt. Ein Fund, der kein Switch ist oder
nicht überwacht werden soll, lässt sich ausblenden.

Der Rundruf bleibt im eigenen Netzsegment der Server-Probe. Switches anderer Standorte findet der Netzwerkscan der
dortigen Probes. Auf einem Windows-Server legt das Setup dafür die Firewall-Regel „Wachtl Server Switch-Suche“ an
(UDP 29809, 63321 und 63323, nur aus dem eigenen Netz). Unter Linux läuft die Server-Probe mit `network_mode: host`.

### TP-Link Easy Smart über die Weboberfläche

Die Server-Probe meldet sich alle 15 Minuten an der Weboberfläche an (HTTP, TCP 80), liest Systeminformationen,
Port-Einstellungen, Port-Statistik und – bei PoE-Modellen – die PoE-Werte und meldet sich wieder ab. Daraus entstehen
Ports mit Link und Geschwindigkeit, Eingangsfehler (fehlerhaft empfangene Pakete, Befund „Port-Fehler“) und PoE je Port.
Eine MAC-Tabelle und LLDP haben diese Switches nicht. Wachtl hängt sie deshalb an den Port des übergeordneten Switches,
der als einziger sie sieht. Die Geräte dahinter gehören zum Easy-Smart-Switch, an welchem seiner Ports sie hängen,
bleibt aber unbekannt. Ohne einen verwalteten Switch darüber steht er unter dem Baum. Die Weboberfläche lässt nur
wenige gleichzeitige Anmeldungen zu – Wachtl meldet sich deshalb nach jeder Abfrage ab.

### Wahrscheinliche Knotenpunkte

Switches ganz ohne Verwaltung (Tisch-Switches, ohne Weboberfläche und SNMP) melden sich nirgends. Wachtl erkennt sie
an den MAC-Tabellen: Hängen an einem Port eines verwalteten Switches mehrere Geräte und kein LLDP-Nachbar, steht dort
ein **nicht verwalteter Switch** – ab 3 Geräten „wahrscheinlich“, bei 2 „möglich“ (z. B. auch PC hinter einem
Telefon ohne LLDP). MACs virtueller Maschinen (VMware, Hyper-V, KVM, Xen, VirtualBox, Parallels) zählen nicht mit,
ein Virtualisierungs-Host wird also nicht zum Switch. Ohne mindestens einen verwalteten Switch lässt sich so ein
Knotenpunkt nicht erkennen.

## Abfrage

- Die **Server-Probe** fragt alle 30 s beim Server nach fälligen Switches (`GET /api/probe/v1/topology/jobs`),
  fragt sie per SNMP ab (bis zu 4 parallel, Timeout 2 s, 1 Wiederholung) und meldet das Ergebnis
  (`POST /api/probe/v1/results/topology`). Nur die Server-Probe bekommt Aufträge und Zugangsdaten; Windows-Probes nicht.
- Der Wachtl-Server muss die Switches über **UDP 161** erreichen (bei mehreren Standorten über das VPN). Viele Switches
  erlauben SNMP nur von eingetragenen Adressen – dort die Adresse des Wachtl-Servers eintragen.
- „Jetzt abfragen“ auf der Switch-Seite: Ergebnis nach etwa 30 Sekunden.

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
| Nicht verwalteter Switch | ≥ 2 Geräte (ohne virtuelle Maschinen) an einem Port ohne LLDP-Nachbarn | Hinweis |
| Switch ohne Zugangsdaten | per LLDP/CDP, Netzwerkscan oder Rundruf gefunden, aber nicht eingetragen | Hinweis |
| Keine MAC-Tabelle | Switch liefert weder MAC-Tabelle noch Nachbarn | Hinweis |

Grenzen: Cisco-Switches mit mehreren VLANs liefern die MAC-Tabelle per SNMPv2c nur je VLAN („Community@VLAN“) bzw. per
SNMPv3 je Kontext – dann fehlen Geräte außerhalb von VLAN 1. Die Port-Nummer der PoE-MIB ist nicht genormt; Wachtl
nimmt die Bridge-Port-Nummer an. Access Points werden über LLDP erkannt.

Aufbewahrung: Port-Fehler und Verlauf 90 Tage, erledigte Befunde 90 Tage nach dem letzten Auftreten. Gespeichert wird je
Switch nur die letzte Abfrage.
