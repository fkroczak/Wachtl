# Werkzeuge

Menüpunkt **Werkzeuge**: Einzeltests wie in Hop7 – **Ping, MTU, Traceroute, DNS, Port, HTTP(S), Zertifikat und IP-Info** –
direkt von einer Probe aus. So prüft man genau den Weg, den die Probe im Alltag nimmt: vom Wachtl-Server oder von
einem PC beim Kunden.

## Ablauf

1. Werkzeug wählen, Ziel eintragen, unter **Ausführen auf** die Probe wählen (der Wachtl-Server steht oben).
2. **Test starten**: Ein Fortschrittsbalken zeigt den aktuellen Schritt („Paket 3 von 10: 12,4 ms“, „Hop 5: …“,
   „Port 443: offen“), die vergangene Zeit und die geschätzte Restzeit. Die Zeilen der Ausgabe erscheinen schon
   während des Tests.
3. Ergebnis: eine Zeile mit der Einschätzung (grün, gelb, rot), bei Ping Verlust, min/Mittel/max und Streuung, eine
   Zusammenfassung (Ziel, Status, Zeiten, Zertifikat …), bei Traceroute, DNS und Port eine Tabelle und darunter die
   komplette Ausgabe.
4. **Letzte Tests** listet die Tests der letzten 30 Tage; ein Klick auf das Ziel zeigt das Ergebnis erneut.

Der Wachtl-Server holt einen Test sofort ab. Ein PC meldet sich spätestens nach 30 s (Heartbeat) und fragt danach
zwei Minuten lang alle 3 s nach weiteren Tests. Je Probe läuft immer nur ein Test, weitere warten in der Reihe. Holt
eine Probe einen Test nicht innerhalb von 5 Minuten ab (offline), wird er als Fehler beendet.

Tests starten dürfen **Operatoren** und **Administratoren**; jeder Test steht im Audit-Log. „Nur lesen“ sieht die
Ergebnisse.

## Werkzeuge

| Werkzeug | Einstellungen | Ergebnis |
| --- | --- | --- |
| **Ping** | Anzahl (1–100), Nutzdaten (0–8972 Byte), Intervall (0,2–5 s), nicht fragmentieren | Verlust, min/Mittel/max, Streuung; Hinweis, wenn ein Paket zu groß für den Weg ist |
| **MTU** | MTU von/bis (Standard 576–1500), Pings je Größe | Pfad-MTU (Suche mit „nicht fragmentieren“), Einordnung (Ethernet, PPPoE, WireGuard, IPsec …), TCP-MSS, Hinweis auf PMTU-Blackhole |
| **Traceroute** | Pakete je Hop, höchstens Hops, Namen auflösen | je Hop Router, Verlust, min/Mittel/max |
| **DNS** | Typ (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR, CAA), DNS-Server | Antwort je Server (bis zu drei Resolver der Probe oder ein eigener), Einträge mit TTL; eine IP-Adresse fragt automatisch PTR |
| **Port** | bis zu 10 TCP-Ports, Wartezeit | offen, geschlossen (abgewiesen) oder gefiltert (keine Antwort) mit Antwortzeit |
| **HTTP(S)** | Methode HEAD oder GET, Zertifikatsfehler ignorieren | Statuscode, Zeiten (DNS, Verbindung, TLS, erstes Byte, gesamt), Weiterleitung, Server, Zertifikat |
| **Zertifikat** | Port, Servername (SNI) | Namen, Aussteller, Ablauf (gelb unter 21 Tagen), Vertrauen, Protokoll |
| **IP-Info** | IP oder Host | je Adresse Rückwärtsname, Netz, Netzname, Anbieter (laut AS-Objekt), Netz-Inhaber, Land, Herkunfts-AS, Kontakte (Inhaber, Verwaltung, Technik, Missbrauch), Quelle |

### IP-Info

Übernommen aus Hop7: Wachtl fragt **direkt die zuständige Registry** (RIPE NCC, ARIN, APNIC, LACNIC, AFRINIC) per
RDAP, ersatzweise per WHOIS über TCP 43 – ohne Dienst eines Dritten, kein Anbieter sieht, welche Adressen geprüft
werden. Welche Registry zuständig ist, steht in der Liste der IANA (14 Tage zwischengespeichert). Umleitungen folgt
Wachtl nur zu Registries und nur über HTTPS. Den Anbieter nimmt Wachtl aus dem AS-Objekt (wer das Netz ankündigt);
der Kontakt im Netz-Objekt erscheint als „Netz-Inhaber“. Antworten werden je Netz 30 Tage im Datenverzeichnis der
Server-Probe gespeichert (`registry/`), zwischen zwei Abfragen liegt mindestens eine Sekunde.

IP-Info läuft immer auf dem **Wachtl-Server** (die Auswahl „Ausführen auf“ ist dann gesperrt). Er braucht dafür
ausgehend HTTPS zu `data.iana.org` und den RDAP-Servern der Registries sowie TCP 43 zu deren WHOIS-Servern.
Private Adressen haben keinen Eintrag bei einer Registry.

Die ICMP-Werkzeuge (Ping, MTU, Traceroute) arbeiten mit IPv4. Wachtl nimmt nur diese Werkzeuge mit geprüften Werten an,
nie Befehle oder freie Parameter.

## Technik

- Web-UI legt einen Auftrag an (`tool_jobs`), die Probe holt ihn über `GET /api/probe/v1/tools/next`, meldet
  Fortschritt und Ergebnis über `POST /api/probe/v1/tools/<id>` ([API.md](API.md)). Der Heartbeat meldet wartende
  Tests (`tools_pending`).
- Server-Probe: `server/wachtl/serverprobe/tools.py`, ohne Fremdprogramme außer `ping` unter Linux.
- Windows-Probe: `probe/Wachtl.Probe/Tools/` mit demselben Ergebnisformat und denselben Texten.
