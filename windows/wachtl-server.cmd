@echo off
rem Wachtl Server – Verwaltung. Als Administrator ausführen.
rem   wachtl-server status | backup | restore <datei.zip> | create-user <name> | logs
setlocal
"%~dp0python\python.exe" -m wachtl.win.host %*
exit /b %ERRORLEVEL%
