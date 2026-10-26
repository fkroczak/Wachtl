# Netzwerkscan (1.0)

Eine Probe (Windows-PC beim Kunden) oder die Server-Probe scannt regelmäßig das lokale Netz:
welche Geräte sind da, wann kommen und gehen sie, welche Ports sind offen und welche Dienste laufen dort.
So fallen Geräte auf, die sich unregelmäßig anmelden (WLAN-Repeater, defekte Netzteile, Geräte mit
doppelter IP-Adresse) und Störungen verursachen können.

Im Web-UI: Standort › **Netzwerk**. Für erkannte Dienste (SSH, HTTP, HTTPS, RDP, VNC, FTP, Telnet, SMB)
erscheint ein Link, der die Verbindung **vom eigenen Browser-PC** aus startet – er funktioniert also nur,
wenn dieser PC das Gerät erreicht (z. B. im selben Netz oder per VPN).

## Check-Typ `netscan`

Wie die übrigen Checks zentral im Web-UI angelegt (Verwaltung › Check anlegen › Netzwerkscan).

| Feld | Standard | Bedeutung |
| --- | --- | --- |
| Ziel (`target`) | `auto` | `auto` = alle eigenen IPv4-Netze der Probe (je Netzwerkkarte, höchstens /22). Sonst ein oder mehrere Netze in CIDR-Schreibweise, durch Komma getrennt, z. B. `192.168.10.0/24, 10.0.5.0/24` |
| `schedule_min` | 15 | Scan alle N Minuten (0 = nur „Jetzt messen“) |
| `offset_min`, `window_start`, `window_end`, `weekdays` | wie bei Bandbreite | Zeitplan |
| `ports` | siehe unten | TCP-Ports für den Portscan, Komma-getrennt, Bereiche erlaubt (`8000-8010`), höchstens 1024 Ports |
| `port_scan` | true | false = nur Geräteerkennung |
| `timeout_ms` (Param) | 500 | Timeout je Ping bzw. TCP-Verbindungsversuch |
| `parallel` | 64 | gleichzeitige Verbindungsversuche |
| `max_hosts` | 1024 | Schutz gegen versehentlich große Netze; mehr Adressen = Abbruch mit Fehler |

Standard-Ports: `21,22,23,25,53,80,110,135,139,143,443,445,515,554,631,993,995,1883,3306,3389,5060,5432,5900,8006,8080,8443,9100`

## Ablauf auf der Probe

1. Netze bestimmen (`auto`: Adressen und Präfix der aktiven Netzwerkkarten, nur IPv4, ohne Loopback/APIPA;
   größere Netze als /22 werden auf das /22 um die eigene Adresse gekürzt).
2. **Geräteerkennung**: ICMP-Ping an jede Adresse (parallel), zusätzlich TCP-Verbindungsversuch auf 80, 443, 445, 22
   (für Geräte, die Ping blockieren). Danach ARP-Tabelle lesen (Windows: `GetIpNetTable2`, Linux: `/proc/net/arp`)
   → MAC-Adressen; Geräte, die nur in der ARP-Tabelle stehen, zählen auch als gefunden.
3. Namen: Reverse-DNS (PTR), Timeout 1 s je Gerät.
4. **Portscan** (wenn `port_scan`): TCP-Connect auf alle `ports` jedes gefundenen Geräts.
5. **Diensterkennung** je offenem Port, höchstens 2 s:
   - zuerst bis 1 s lesen, ob der Dienst sich selbst meldet (Banner: SSH, FTP, SMTP, Telnet …);
   - sonst auf typischen HTTP-Ports (80, 8080, 8000, 8006, 8443, 443, 631, 9100 nicht) `HEAD / HTTP/1.0` senden;
     auf 443/8443/8006 und wenn die Antwort wie TLS aussieht: TLS-Handshake (Zertifikat nicht prüfen),
     dann HTTP über TLS. `Server`-Header, Statuscode und `<title>` (per `GET /`, höchstens 16 KB) mitnehmen.
6. Ergebnis per `POST /api/probe/v1/results/netscan` senden (bei Fehler wie andere Ergebnisse puffern/wiederholen).

Die Probe scannt nur die eingestellten Netze, nie das Internet. Nur TCP-Connect (kein SYN-Scan, keine Exploits).

## API: `POST /api/probe/v1/results/netscan`

```json
{
  "check_id": 42,
  "ts": 1793000000,
  "trigger": "schedule",            // oder "manual"
  "duration_s": 37.4,
  "subnets": ["192.168.10.0/24"],
  "error": null,                    // Text, wenn der Scan nicht laufen konnte
  "hosts": [
    {
      "ip": "192.168.10.1",
      "mac": "AA:BB:CC:DD:EE:FF",   // null, wenn unbekannt (anderes Netz, keine ARP-Antwort)
      "hostname": "fritz.box",      // null, wenn kein PTR
      "rtt_ms": 0.6,                // null, wenn kein Ping-Echo
      "via": ["icmp", "arp", "tcp"],
      "self": false,                // true = die scannende Probe selbst
      "ports": [
        {"port": 22, "banner": "SSH-2.0-OpenSSH_9.6", "tls": false,
         "http_status": null, "http_server": null, "http_title": null, "tls_subject": null},
        {"port": 443, "banner": null, "tls": true, "http_status": 200,
         "http_server": "nginx", "http_title": "FRITZ!Box", "tls_subject": "CN=fritz.box"}
      ]
    }
  ]
}
```

Grenzen (Server prüft und kürzt): höchstens 4096 Hosts, 256 Ports je Host, Texte auf 200 Zeichen.
Antwort: `201 {"stored": <Zahl Hosts>}`; `422`, wenn `check_id` nicht zur Probe gehört oder kein `netscan` ist.

## Auswertung auf dem Server

- **Gerät** = je Standort eindeutig über die MAC-Adresse, ohne MAC über die IP-Adresse.
- **Anwesenheit**: Zeiträume, in denen ein Gerät bei aufeinanderfolgenden Scans gesehen wurde. Fehlt es in einem
  Scan und taucht später wieder auf, beginnt ein neuer Zeitraum.
- **Unregelmäßig**: ≥ 3 Wiederkehrer (neue Zeiträume) in 24 h.
- **IP-Konflikt**: dieselbe IP mit verschiedenen MAC-Adressen im selben Scan, oder eine IP wechselt zwischen
  zwei Scans die MAC.
- **Neu**: zum ersten Mal in den letzten 24 h gesehen.
- **Dienst**: aus Port, Banner, TLS und HTTP-Antwort, z. B. `ssh` (Banner `SSH-`), `https`, `http`, `rdp` (3389),
  `smb` (445), `vnc` (5900, Banner `RFB`), `ftp`, `telnet`, `smtp`, `dns`, `mqtt`, `mysql`, `postgres`, `printer`
  (9100/515/631), `sip` (5060), `proxmox` (8006).
- **Links**: `ssh://ip`, `http://ip[:port]/`, `https://ip[:port]/`, `vnc://ip[:port]`, `ftp://ip`, `telnet://ip`,
  RDP als herunterladbare `.rdp`-Datei, SMB als `\\ip` zum Kopieren.

Aufbewahrung: Scan-Läufe 90 Tage, Geräte bis 90 Tage nach dem letzten Sehen.
