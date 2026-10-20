# Rollout beim Kunden – Schritt für Schritt

Diese Anleitung ist für Kolleginnen und Kollegen gedacht, die Wachtl zum ersten Mal beim Kunden ausrollen.
Netzwerkkenntnisse braucht es dafür kaum: Die Messungen bringt das **Standardpaket** mit, die Probes werden
mit einem fertigen Paket installiert. Rechne mit etwa 30 Minuten für den Server und 2 Minuten je PC.

> Vorher klären: Wer beim Kunden darf Software installieren (Adminrechte)? Welcher Rechner wird der
> Wachtl-Server (immer eingeschaltet, feste IP oder DNS-Name)? An welchen Standorten stehen PCs, die messen sollen?

## 1. Server installieren

| Variante | Was tun |
|---|---|
| Windows Server | `WachtlSetup-0.9.1.exe` als Administrator starten, Rolle **Wachtl-Server** wählen, den Seiten folgen. Die IP-Adressen des Servers ergänzt das Setup selbst. Details: [INSTALL-SERVER-WINDOWS.md](INSTALL-SERVER-WINDOWS.md) |
| Linux-VM mit Docker | `sudo ./setup.sh wachtl.kunde.local` im Ordner `deploy`. Details: [INSTALL-SERVER.md](INSTALL-SERVER.md) |

Am Ende zeigt das Setup die Adresse, den Admin-Zugang und den **SPKI-Pin**. Zugangsdaten sofort im
Passwort-Tresor des Kunden ablegen, dann mit dem Browser anmelden und das Admin-Passwort ändern.

Der Server **misst selbst mit** (Server-Probe): Er erscheint nach etwa einer Minute in der Übersicht als Probe
mit dem Zusatz „Server“ am Standort „Wachtl-Server“. So sieht man auch ohne PCs sofort, ob Internet und Gateway
vom Server aus funktionieren.

## 2. Standorte und Standardpaket

**Am schnellsten:** Verwaltung › **Probes einrichten (geführt)**. Vier Schritte – Standort, Messungen (Standardpaket),
Alarmierung (E-Mail/Teams) und Anzahl PCs – sind mit Standards vorbelegt. **Einrichten** legt alles an und bietet
direkt das fertige Setup für die PCs an; weiter mit Schritt 3, Punkt 2. Von Hand geht es so:

1. **Verwaltung › Standorte**: für jeden Standort einen Eintrag anlegen (z. B. „Zentrale“, „Lager Coesfeld“).
2. **Verwaltung › Standardpaket**: alles angehakt lassen, „Gilt für: alle Probes“, **Standardpaket anlegen**.

Damit misst jede Probe:

| Check | Art | Wofür |
|---|---|---|
| Gateway | Ping, 1 s | Router des Standorts – fällt er aus, liegt das Problem im LAN |
| Cloudflare DNS, Google DNS, Quad9 DNS | Ping, 1 s | Internet-Referenzen – sind alle weg, meldet Wachtl „WAN gestört“ |
| Wachtl-Server | Ping, 5 s | Erreichbarkeit des Servers (VPN, Standortkopplung) |
| Traceroute Internet | Pfad, Hops alle 5 s | Ab welchem Router es hakt (wie MTR) |
| Traceroute Wachtl-Server | Pfad, Hops alle 5 s | Weg vom Standort zum Server |
| iperf3 zum Wachtl-Server | Bandbreite, alle 6 h | Durchsatz LAN/VPN, beide Richtungen |
| Speedtest Internet | Bandbreite, alle 6 h | Download/Upload ins Internet |

Bei sehr vielen PCs an einem Standort reicht es, die Bandbreiten-Checks nur einer Probe je Standort zuzuweisen
(Verwaltung › Checks › Bearbeiten › Zuweisung). Bandbreitentests belasten die Leitung.

## 3. Probes installieren

1. **Verwaltung › Probes registrieren**: Standort wählen, „Für wie viele PCs“ eintragen, **Setup herunterladen**.
2. Auf jedem PC `WachtlSetup-<Standort>.exe` als Administrator starten und **Installieren** klicken. Server, Pin und
   Token sind eingebaut; ist der Server gerade nicht erreichbar, meldet sich die Probe später selbst an.
3. Nach 30 Sekunden steht der PC in der Übersicht unter **Probes** mit „online“.
4. Neben der Uhr erscheint das Wachtl-Symbol. Test: Rechtsklick › **Problem melden …** › Senden – die Meldung steht
   kurz darauf unter **Meldungen** und als Markierung im Graphen dieser Probe.

Für viele PCs per Softwareverteilung: siehe [INSTALL-PROBE.md](INSTALL-PROBE.md), Abschnitt „Unbeaufsichtigt“.

## 4. Abnahme: funktioniert jede Messung?

Auf der **Übersicht**:

- **Messungen mit Problemen** muss nach 10 Minuten leer sein – oder jeder Eintrag ist erklärbar.
  Dort steht jede Messung, die gerade fehlschlägt (rot), auffällig ist (gelb) oder keine Daten liefert
  (rot umrandet), egal ob Ping, Pfad, iperf3 oder Speedtest – mit Grund, z. B. „HTTP 403 von speed.cloudflare.com“.
- In der Tabelle **Probes** zählt die Spalte „Checks ok / auffällig / gestört / keine Daten“ **alle** Checks der Probe.
- Im Abschnitt **Bandbreite** stehen alle Bandbreiten-Checks mit der letzten Messung. Für die Abnahme auf der
  Probe-Seite bei jedem Bandbreiten-Check **Jetzt messen** klicken – nach spätestens einer Minute steht ein Wert da.

Typische Gründe, wenn etwas nicht grün wird:

| Anzeige | Ursache | Lösung |
|---|---|---|
| Ping „Ziel antwortet nicht“ für alle Internet-Ziele | Firewall blockiert ICMP ausgehend | ICMP Echo ausgehend erlauben |
| Pfad „Ziel im Traceroute nicht erreicht“ | Ein Router filtert ICMP mit TTL | meist harmlos, die Hop-Pings laufen trotzdem |
| iperf3 „Connection refused“ / „Zeitlimit“ | Port 5201 TCP+UDP zum Server zu | Firewall-Regel Standort → Server, Port 5201 |
| Sprache „keine Antwort von der Gegenstelle“ | UDP 5004 zum Server bzw. zur Gegenstellen-Probe zu | Firewall-Regel Standort → Gegenstelle, UDP 5004 |
| Speedtest „HTTP 403“ oder Proxy-Fehler | Proxy oder Webfilter | im Check „Proxy der Probe verwenden“ anhaken oder eigene URL eintragen |
| „keine Daten“ | Probe offline oder Check neu | Probe-Seite prüfen, Dienst „Wachtl“ auf dem PC |

## 5. Übergabe

- Benachrichtigungen einrichten: **Verwaltung › Benachrichtigungen** (E-Mail und/oder Teams), **Testnachricht** senden.
- Für den Kunden einen Benutzer mit Rolle **Nur lesen** anlegen.
- Sicherung prüfen: Windows legt sie täglich an, unter Linux den Cron-Eintrag aus [BETRIEB.md](BETRIEB.md) setzen.

## Wieder entfernen – ohne Sicherheitslücke

Alles lässt sich vollständig zurückbauen; die Deinstaller prüfen am Ende selbst, dass nichts offen bleibt.

| Was | Wie | Was passiert |
|---|---|---|
| Probe (PC) | Apps › Wachtl Probe › Deinstallieren, oder `"C:\Program Files\Wachtl\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES` | Probe meldet sich **am Server ab** (Token sofort ungültig), Dienst, iperf3-Prozess und **alle Firewall-Regeln** für Wachtl-Programme (auch von Windows selbst angelegte) werden entfernt, das Token auf dem PC gelöscht. Unbeaufsichtigt werden auch Puffer und Logs gelöscht. |
| Server Windows | Programme und Features › Wachtl Server, oder `unins000.exe /VERYSILENT /SUPPRESSMSGBOXES /REMOVEDATA` | Dienst samt Server-Probe, Firewall-Regeln (HTTPS, HTTP, iperf3 und von Windows angelegte), geplante Sicherung, Registry-Eintrag; prüft danach, dass kein Port mehr lauscht. Mit `/REMOVEDATA` bzw. „Ja“ auch Datenbank, Schlüssel, Sicherungen. |
| Server Linux | `sudo ./uninstall.sh --alles` im Ordner `deploy` | Container, Netzwerke (damit die Docker-Portfreigaben 80/443/5201), Images, Cron-Eintrag; mit `--alles` auch Volumes, `.env`, Zertifikat, Sicherungen. Prüft danach Container, Netzwerke und Ports. |

Reihenfolge beim Rückbau: **erst die Probes, dann den Server** – dann melden sich die Probes sauber ab.
Ist der Server schon weg, löscht der Probe-Deinstaller das Token trotzdem; es ist dann ohnehin wertlos.
