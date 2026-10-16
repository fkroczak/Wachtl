@echo off
rem Wachtl Probe - Status (fordert bei Bedarf Administratorrechte an)
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'" & exit /b)
"%~dp0wachtl-probe.exe" status
echo.
pause
