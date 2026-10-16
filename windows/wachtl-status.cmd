@echo off
rem Wachtl Server - Status (fordert bei Bedarf Administratorrechte an)
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'" & exit /b)
call "%~dp0wachtl-server.cmd" status
echo.
call "%~dp0wachtl-server.cmd" probes
echo.
pause
