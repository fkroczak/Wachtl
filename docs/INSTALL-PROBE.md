# Installation: Windows-Probe

Die Probe ist eine einzelne Datei `wachtl-probe.exe`, installiert vom gemeinsamen Setup `WachtlSetup` (self-contained, kein .NET auf dem Ziel-PC nötig).
Sie läuft als Dienst **Wachtl** unter dem virtuellen Konto `NT SERVICE\Wachtl`, startet nach jedem Neustart
automatisch (verzögert) und braucht keinen angemeldeten Benutzer.

## Voraussetzungen

| Punkt | Wert |
| --- | --- |
| Betriebssystem | Windows 10/11 oder Windows Server 2016+ (x64) |
| Rechte | lokaler Administrator für die Installation |
| Netz | ausgehend TCP 443 zum Wachtl-Server; ICMP zu den Zielen |
| Ressourcen | typisch unter 100 MB RAM und kaum CPU; bis ca. 200 MB Platte für den Puffer bei längerem Serverausfall |

## Installation: vorbelegtes Setup (empfohlen)

Im Web-UI unter **Verwaltung › Probes registrieren** Standort wählen und **Setup herunterladen**.
Die Datei `WachtlSetup-<Standort>.exe` enthält alle Adressen des Servers (Namen und IP-Adressen), den SPKI-Pin
und einen Token für die eingestellte Zahl PCs. Auf dem PC als Administrator starten, **Installieren** klicken – fertig.

- Die Probe erscheint nach etwa 30 Sekunden im Dashboard, Name ist der Computername.
- Ist ein Servername am Standort nicht auflösbar, nimmt die Probe die nächste Adresse (z. B. die IP) – bei der
  Installation und später im Betrieb. Neue Adressen des Servers übernimmt sie automatisch.
- Ist der Server bei der Installation gar nicht erreichbar (Standort offline, VPN aus), wird die Probe trotzdem
  installiert und meldet sich selbst an, sobald der Server erreichbar ist.
- Welche Ziele gemessen werden, legt immer der Server fest (Verwaltung › Checks).

Dasselbe Setup ohne Vorbelegung (`WachtlSetup-<Version>.exe`, Link ebenfalls unter „Probes registrieren“) fragt nach
der Rolle (Probe ist Standard) und dann auf einer Seite nach Server, Pin, Token und optional Proxy.
Mehrere Server-Adressen mit Komma trennen. Ist die Probe schon installiert, fragt es: **Nur aktualisieren**,
**Proxy ändern** oder **Neu registrieren**.

### Unbeaufsichtigt (Softwareverteilung, GPO, Intune)

```powershell
WachtlSetup-Standort.exe /VERYSILENT /SUPPRESSMSGBOXES
# ohne Vorbelegung:
WachtlSetup-0.9.0.exe /VERYSILENT /SUPPRESSMSGBOXES /Server=https://wachtl.kunde.local,https://10.0.0.5 /Pin="kpbQ…=" /Token=wachtl-… [/Proxy=http://proxy:3128] [/Hostname=PC-01]
```

Exit-Code 0 = Probe läuft (angemeldet oder Anmeldung folgt automatisch), 10 = nicht betriebsbereit (Grund im `/LOG`,
z. B. Token abgelaufen). `/SUPPRESSMSGBOXES` ist unbeaufsichtigt Pflicht. Parameter überschreiben die Vorbelegung.
Auf einem bereits registrierten PC aktualisiert ein unbeaufsichtigter Lauf nur das Programm.

`/NoTray` lässt das Tray-Symbol weg (kein Autostart-Eintrag); spätere Updates behalten das bei, `/Tray` schaltet es wieder ein. Unbeaufsichtigt per Softwareverteilung läuft das Setup
meist als SYSTEM – das Symbol erscheint dann bei der nächsten Anmeldung der Benutzer.

### Tray-Symbol: Problem melden

Neben der Uhr zeigt das Wachtl-Symbol (`wachtl-tray.exe`, startet bei jeder Anmeldung) die Einträge **Problem melden …**,
**Über Wachtl** und **Beenden**. Benutzer melden damit erlebte Netzprobleme mit Zeitpunkt (Jetzt oder eine einstellbare
Uhrzeit), Art und Dauer; die Meldung erscheint im Web-UI unter „Meldungen“ und als Markierung in den Graphen dieser Probe.
Verknüpfung im Startmenü: *Wachtl – Problem melden*. Details: [STOERUNGSMELDUNGEN.md](STOERUNGSMELDUNGEN.md).

## Deinstallation

Apps › Wachtl Probe, oder `"C:\Program Files\Wachtl\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES`.
Der Deinstaller lässt nichts zurück, was von außen erreichbar wäre:

1. Er meldet die Probe **am Server ab** – ihr Token ist dort sofort ungültig. Ist der Server nicht erreichbar,
   wird das Token trotzdem gelöscht und der Deinstaller weist darauf hin.
2. Er stoppt den Dienst „Wachtl“ und eine noch laufende iperf3-Gegenstelle der Probe.
3. Er entfernt die Firewall-Regel „Wachtl Probe iperf3“ und alle weiteren Regeln für `wachtl-probe.exe` und `iperf3.exe`
   der Probe – auch solche, die Windows selbst angelegt hat.
4. Er löscht Token, Konfiguration und eine noch nicht nachgeholte Registrierung immer; Puffer und Logs auf Nachfrage,
   unbeaufsichtigt immer.

## Status und Logs

Startmenü › *Wachtl Probe › Wachtl Status* oder `"C:\Program Files\Wachtl\wachtl-probe.exe" status` (als Administrator).
Logs: `C:\ProgramData\Wachtl\logs\probe-JJJJMMTT.log` (14 Tage).

## Fehlersuche

| Meldung | Ursache und Lösung |
| --- | --- |
| „Das Server-Zertifikat passt nicht zum angegebenen Pin“ | Falscher Pin oder TLS-Inspection eines Proxys. Pin vom Server prüfen: `wachtl-probe.exe show-pin --server https://…`; Proxy-Ausnahme für den Server |
| „Server lehnt die Registrierung ab“ | Token abgelaufen, widerrufen oder Nutzungen aufgebraucht – im Web-UI ein neues Setup herunterladen |
| Log: „Server noch nicht erreichbar, Registrierung wird weiter versucht“ | Registrierung wartet auf den Server (Firewall, VPN, Proxy prüfen); sie läuft von selbst durch |
| Probe im Dashboard „offline“, Puffer steigt | Server nicht erreichbar; Werte bleiben bis 7 Tage im Puffer und werden nachgesendet |
| „Token ungültig oder Probe deaktiviert“ | Probe im UI wieder aktivieren oder mit neuem Token neu installieren |
| Gateway „kein Default-Gateway gefunden“ | PC ohne IPv4-Gateway (z. B. nur VPN). Check für diese Probe pausieren |

Die Probe kann zum Test auch im Vordergrund laufen (Dienst vorher stoppen): `wachtl-probe.exe` in einer Admin-Konsole.
