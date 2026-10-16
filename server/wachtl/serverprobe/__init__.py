"""Server-Probe: der Wachtl-Server misst selbst – dieselben Checks wie die Windows-Probes.

Läuft als eigener Prozess (Docker: Dienst ``serverprobe`` im Host-Netz, Windows: Teilprozess des
Dienstes) und spricht den Server über dasselbe Probe-API an wie jede Probe. Damit gelten Checks,
Auswertung, Alarme und Statusübersicht ohne Sonderfälle auch für den Server.

Registrierung: Beim Start legt der Server ``enroll.json`` mit einem einmaligen Enrollment-Token in
den Ordner der Server-Probe (``WACHTL_SERVER_PROBE_DIR``). Die Probe registriert sich damit und
speichert ihr eigenes Token in ``probe.json``. Abschalten: Probe im Web-UI deaktivieren oder
``WACHTL_SERVER_PROBE=0`` setzen.
"""
