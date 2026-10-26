# Benachrichtigungen: jede Störung sofort sehen

Wachtl meldet jede Störung dort, wo man gerade hinschaut – auf dem PC, auf dem Wachtl-Server, im Browser und per
E-Mail/Teams. Auch ein einzelner verlorener Ping zählt; nichts wird als „grün“ gezeigt, wenn etwas war.

| Wo | Was erscheint | Wie schnell |
|---|---|---|
| **PC mit Probe** (Wachtl-Symbol neben der Uhr) | Gateway/Netzwerk weg, Internet weg, Ziel nicht erreichbar, jeder verlorene Ping, Netzwerkwechsel (LAN ↔ WLAN, neue IP), Kabel/WLAN/Netzwerkkarte | ca. 7 s nach Beginn eines Ausfalls, Paketverlust nach dem Aussetzer |
| **Wachtl-Server** (Wachtl-Symbol neben der Uhr, Windows) | Störungen **aller Standorte**: Ausfälle, Paketverlust, Probe offline, Alarme, Hinweise der PCs | ≤ 10 s nach Eingang der Messwerte |
| **Web-UI** (jede Seite) | wie auf dem Server, als Hinweis unten rechts; mit Erlaubnis auch als Desktop-Benachrichtigung des Browsers; rote Zahl aktiver Alarme bei „Alarme“ | ≤ 15 s |
| **E-Mail / Teams** | jede Störung inkl. jedem Paketverlust (abschaltbar je Regel) | ca. 30 s (Wartezeit von Alertmanager) |

## Was als Störung zählt

Der Server wertet jeden Ping aus, sobald er ankommt (`server/wachtl/services/disturbances.py`):

| Art | Bedingung | Ursache in der Übersicht |
|---|---|---|
| Ausfall | Ziel antwortet mindestens 5 s nicht (Regel „Ziel nicht erreichbar ab“) | Gateway / LAN, Einzelne Internet-Referenz, Ziel |
| Internet | alle Internet-Referenzen einer Probe zugleich ohne Antwort | WAN / Internet |
| Paketverlust | jeder Ping ohne Antwort, der kein Ausfall ist; mehrere Aussetzer kurz hintereinander bilden eine Störung, sie endet nach 60 s ohne Verlust | Paketverlust |

**Nachgelieferte Werte**: Hat der PC selbst kein Netz, puffert die Probe die Messwerte und schickt sie, sobald das
Netz wieder da ist. Die Störung wird dann nachträglich erkannt, mit echtem Beginn und Ende, und als „nachträglich
erkannt“ gemeldet. Vorher fielen genau diese Ausfälle unter den Tisch.

**Anzeige**: Probe, Standort und Übersicht werden gelb, sobald in den letzten 5 Minuten ein Ping verloren ging
(vorher erst ab 2 %). Der Verlauf je Standort zeigt jeden Verlust als gelben Balken, „ohne Störung“ zählt jede
Störung mit (bei sehr kurzen Störungen mit drei Nachkommastellen, z. B. 99,998 %). Sehr kleiner Verlust steht
genau da, z. B. „0.004 %“ statt „0.0 %“.

## Auf dem PC

Die Probe erkennt an ihren eigenen Pings, was los ist – unabhängig vom Server, auch wenn der PC gerade kein Netz hat:

- **Netzwerk unterbrochen – Gateway antwortet nicht** (rot): Internet und Ziele sind dann Folgen und erscheinen nicht extra.
- **Internet ausgefallen** (rot): Gateway erreichbar, aber keine Internet-Referenz antwortet.
- **„Ziel“ nicht erreichbar** (gelb): einzelnes Ziel oder einzelne Referenz.
- **Paketverlust zu …** (gelb, einmalig): der erste verlorene Ping sofort, weitere derselben Minute als ein Hinweis
  („Weitere 3 Pings … in der letzten Minute“).
- **Netzwerkverbindung gewechselt** (blau): andere Verbindung oder IP-Adresse, z. B. Notebook vom Dock genommen.
- Dazu wie bisher die Hinweise zu Kabel, WLAN, Netzwerkkarte und DHCP ([CLIENT-HINWEISE.md](CLIENT-HINWEISE.md)) –
  jetzt **alle** als Sprechblase, auch „Kabel getrennt“, wenn das WLAN übernimmt.

Ist ein Ausfall vorbei, kommt „wieder da“ mit der Dauer. Solange etwas gestört ist, trägt das Wachtl-Symbol einen
**roten** (Störung) oder **gelben** (Warnung) Punkt; der Tooltip sagt es auch. Das Menü zeigt unter
**Netzwerk-Hinweise …** alle aktiven Hinweise.

**Test-Hinweis anzeigen** (Menü des Symbols) zeigt einen Beispiel-Hinweis. Erscheint er nicht, läuft das Symbol
nicht in dieser Sitzung (Setup mit `/NoTray`?) oder ein anderes Programm verdeckt die Ecke unten rechts.

Kritische Hinweise bleiben 60 s stehen, andere 20 s; unter der Maus bleiben sie, bis man wegfährt. Bei Spielen im
Vollbild und Präsentationen warten sie.

## Auf dem Wachtl-Server (Windows)

Das Wachtl-Symbol auf dem Server zeigt Störungen **aller Standorte**. Die Server-Probe fragt dafür alle 10 s
`GET /api/probe/v1/notices` (nur für die Server-Probe erlaubt) und stellt sie dem Symbol bereit. Laufende Alarme
bleiben in der Liste, bis sie enden („Beendet: …“); nachträglich erkannte Ausfälle, Paketverlust und Hinweise der
PCs erscheinen einmal als Sprechblase.

## Im Browser

Jede Seite fragt alle 15 s `GET /api/v1/notifications?a=<Alarm-ID>&f=<Hinweis-ID>` und zeigt Neues unten rechts
(höchstens 5, Klick öffnet den Graphen zum Zeitpunkt). Mit **Desktop-Benachrichtigungen einschalten** (Knopf unten
rechts, nur über HTTPS) erscheinen sie auch, wenn der Tab im Hintergrund ist. Mehrere offene Tabs zeigen jedes
Ereignis nur einmal.

## Einstellungen

| Wo | Einstellung | Standard |
|---|---|---|
| Verwaltung › Alarmregeln | **Jeder Paketverlust**: Schwellwert = verlorene Pings bis zur Meldung (1 = jeder), Fenster = Sekunden ohne Verlust bis zum Ende, Stufe; abschaltbar | 1, 60 s, Warnung, an |
| Verwaltung › Alarmregeln | Ziel nicht erreichbar ab / Alle Internet-Referenzen gestört ab (Sekunden) | 5 s |
| Verwaltung › Messung › Client-Hinweise | **Ausfälle, Paketverlust und Netzwerkwechsel auf dem PC melden** | an |
| Verwaltung › Messung › Client-Hinweise | Hinweis als Sprechblase auf dem PC anzeigen (Kabel, WLAN, Karte) | an |
| Verwaltung › Benachrichtigungen | E-Mail und Teams | – |

Eine abgeschaltete Regel verhindert nur E-Mail/Teams. Angezeigt wird die Störung im Web-UI trotzdem.
