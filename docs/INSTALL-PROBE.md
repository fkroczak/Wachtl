# Installation: Windows-Probe

Die Probe ist eine einzelne Datei `wachtl-probe.exe` (self-contained, kein .NET auf dem Ziel-PC nötig).
Sie läuft als Dienst **Wachtl** unter dem virtuellen Konto `NT SERVICE\Wachtl`, startet nach jedem Neustart
automatisch (verzögert) und braucht keinen angemeldeten Benutzer.

## Voraussetzungen

| Punkt | Wert |
| --- | --- |
| Betriebssystem | Windows 10/11 oder Windows Server 2016+ (x64) |
| Rechte | lokaler Administrator für die Installation |
| Netz | ausgehend TCP 443 zum Wachtl-Server; ICMP zu den Zielen |
| Ressourcen | typisch unter 100 MB RAM und kaum CPU; bis ca. 200 MB Platte für den Puffer bei längerem Serverausfall |

## 1. Setup-Assistent (empfohlen)

Im Web-UI unter **Verwaltung › Probes registrieren** einen Token erzeugen und **Paket herunterladen** wählen.
Das ZIP enthält `WachtlProbeSetup-0.2.0.exe` und eine `wachtl-probe.ini` mit Server, Pin und Token.
Auf dem PC entpacken und das Setup als Administrator starten:

| Seite | Inhalt |
| --- | --- |
| Wachtl-Server | Server-Adresse und SPKI-Pin (aus dem Paket vorbelegt). Ohne Pin fragt der Assistent den Server und zeigt den Pin zur Kontrolle an |
| Verbindung | Proxy (optional). Beim Weiter prüft der Assistent Erreichbarkeit und Pin – ohne den Token zu verbrauchen |
| Registrierung | Enrollment-Token und Name der Probe (Standard: Computername). Die Registrierung läuft sofort; ein abgelaufener Token lässt sich direkt korrigieren |
| Fertig | Dienst „Wachtl Netzwerk-Probe“ läuft, die Probe erscheint nach etwa 30 Sekunden im Dashboard |

Ist die Probe schon installiert, fragt der Assistent zuerst: **Nur aktualisieren**, **Proxy ändern** oder **Neu registrieren**.
Dasselbe erreicht man später über Startmenü › *Wachtl Probe – Einstellungen ändern*. Welche Ziele gemessen werden,
legt immer der Server fest (Verwaltung › Checks) – am PC selbst gibt es dafür nichts einzustellen.

### Unbeaufsichtigt (Softwareverteilung, GPO, Intune)

```powershell
WachtlProbeSetup-0.2.0.exe /VERYSILENT /SUPPRESSMSGBOXES /Server=https://wachtl.kunde.local /Pin="kpbQ…=" /Token=wachtl-… [/Proxy=http://proxy:3128] [/Hostname=PC-01]
```

Exit-Code 0 = Probe läuft, 10 = installiert, aber Registrierung oder Dienststart fehlgeschlagen. Ohne `/Pin` wird
unbeaufsichtigt nicht installiert (kein ungeprüftes Vertrauen). Liegt eine `wachtl-probe.ini` neben dem Setup, genügt
`WachtlProbeSetup-0.2.0.exe /VERYSILENT /SUPPRESSMSGBOXES`.

Deinstallation: Apps › Wachtl Probe, oder `"C:\Program Files\Wachtl\unins000.exe" /VERYSILENT`.

## 2. Alternative: PowerShell-Skript

Der Ordner aus `build.ps1` enthält zusätzlich `wachtl-probe.exe` und `Install-Wachtl.ps1`:

```powershell
.\Install-Wachtl.ps1 -Action Install `
    -ServerUrl "https://wachtl.kunde.local" `
    -EnrollToken "wachtl-…" `
    -SpkiPin "kpbQsJ0j+ClD+hdvTU0UJJrhH2d+ZtprZ/w/Ahf9g8A="
```

Mit Proxy zusätzlich `-Proxy "http://proxy.kunde.local:3128"`. Falls die Ausführungsrichtlinie blockiert:
`powershell -ExecutionPolicy Bypass -File .\Install-Wachtl.ps1 …`

## 3. Status, Logs, Update, Entfernen

```powershell
.\Install-Wachtl.ps1 -Action Status       # Dienst, Speicher, Server, Checks, Puffer, letzte Logzeilen
.\Install-Wachtl.ps1 -Action Logs         # Log live verfolgen
.\Install-Wachtl.ps1 -Action Restart
.\Install-Wachtl.ps1 -Action Update -SourceExe \\fileserver\it$\wachtl\wachtl-probe.exe
.\Install-Wachtl.ps1 -Action Uninstall [-RemoveData]
```

Logs: `C:\ProgramData\Wachtl\logs\probe-JJJJMMTT.log` (14 Tage).

## Fehlersuche

| Meldung | Ursache und Lösung |
| --- | --- |
| „Das Server-Zertifikat passt nicht zum angegebenen Pin“ | Falscher Pin oder TLS-Inspection eines Proxys. Pin vom Server prüfen: `wachtl-probe.exe show-pin --server https://…`; Proxy-Ausnahme für den Server |
| „Server lehnt die Registrierung ab“ | Token abgelaufen, widerrufen oder Nutzungen aufgebraucht – neuen Token erzeugen |
| Probe im Dashboard „offline“, Puffer steigt | Server nicht erreichbar; Werte bleiben bis 7 Tage im Puffer und werden nachgesendet |
| „Token ungültig oder Probe deaktiviert“ | Probe im UI wieder aktivieren oder mit neuem Token neu installieren |
| Gateway „kein Default-Gateway gefunden“ | PC ohne IPv4-Gateway (z. B. nur VPN). Check für diese Probe pausieren |

Die Probe kann zum Test auch im Vordergrund laufen (Dienst vorher stoppen): `wachtl-probe.exe` in einer Admin-Konsole.
