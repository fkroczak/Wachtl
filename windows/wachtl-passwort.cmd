@echo off
rem Wachtl Server - Passwort von admin zuruecksetzen (fordert bei Bedarf Administratorrechte an)
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'" & exit /b)
echo Neues Passwort fuer den Benutzer admin festlegen. Das Konto wird dabei auch entsperrt.
echo.
call "%~dp0wachtl-server.cmd" create-user admin
echo.
pause
