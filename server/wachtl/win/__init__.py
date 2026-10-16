"""Windows-Variante des Wachtl-Servers: ohne Docker, als ein Windows-Dienst.

Aufbau
  {Programmordner}\\python\\        eingebettetes Python 3.12 mit Flask, cheroot, cryptography
  {Programmordner}\\app\\wachtl\\    diese Anwendung
  {Programmordner}\\bin\\           victoria-metrics.exe, vmalert.exe, vmbackup.exe, vmrestore.exe, alertmanager.exe
  {Programmordner}\\service\\       WachtlServer.exe (WinSW) + WachtlServer.xml
  {Datenordner}\\                   config, certs, data (SQLite), vm-raw, vm-agg, rules, alertmanager, logs, backups

Der Dienst startet ``python -m wachtl.win.host run``; der Supervisor startet und überwacht alle
Teilprozesse. Die Einrichtung übernimmt ``python -m wachtl.win.installer`` (vom Setup-Assistenten aufgerufen).
"""
