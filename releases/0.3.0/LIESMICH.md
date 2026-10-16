## Downloads

- **WachtlServerSetup-…exe**: Wachtl-Server für Windows Server 2019/2022/2025. Als Administrator starten, der Assistent richtet alles ein.
- **WachtlProbeSetup-…exe**: Probe für Windows-PCs. Das passende Paket mit Server, Pin und Token gibt es im Web-UI unter Verwaltung › Probes registrieren.
- **SHA256SUMS.txt**: Prüfsummen.

## Neu in 0.3

- **Pfad-Check**: Traceroute bis ins Internet, danach Dauerpings auf jeden Hop (Standard 1 s). Die Hop-Tabelle zeigt wie MTR, ab welchem Hop Verluste oder Verzögerungen beginnen. Eine Bewertung unterscheidet echte Probleme von ICMP-Drosselung. Dazu kommen Pfadverlauf mit Wechselerkennung und der Alarm „Pfad geändert“.
- **Bandbreite intern (iperf3)**: Probe ↔ Wachtl-Server oder Probe ↔ Probe, TCP oder UDP, Richtung, Dauer und Streams einstellbar. Der Wachtl-Server und jede Probe können iperf3-Gegenstelle sein.
- **Bandbreite WAN**: HTTP-Speedtest (Standard: Cloudflare) oder iperf3-Server im Internet.
- **Zeitplan je Check**: Intervall, Zeitfenster und Wochentage, dazu „Jetzt messen“ per Knopfdruck. Alarm, wenn die Bandbreite unter einem Schwellwert liegt.
- **Jitter** im Graphen und als Alarmregel.
- **Ausfallübersicht**: Störungen mit Dauer und Ursache (Probe/Standort, Gateway/LAN, WAN, Ziel). Folgestörungen werden zusammengefasst.
- **Alles im Web-UI einstellbar**: Formulare je Check-Art, Messeinstellungen und Einstellungen je Probe.

Details: `docs/MESSUNGEN.md`. Bei einem Update von 0.2 einfach die neuen Setups über die alten installieren; Daten und Registrierungen bleiben erhalten.
