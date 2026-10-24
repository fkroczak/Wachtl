<#
  Prüft die Deinstallation auf dem Windows-Runner: nichts darf zurückbleiben, was von außen erreichbar wäre.
    -Part Probe   Probe-Deinstaller: Abmeldung am Server, Dienst, Firewall-Regeln, Token
    -Part Server  Server-Deinstaller: Dienst (samt Server-Probe), Firewall-Regeln, geplante Aufgabe, Ports
#>
param([Parameter(Mandatory)] [ValidateSet('Probe', 'Server')] [string]$Part)
$ErrorActionPreference = 'Stop'
$base = 'https://localhost:8443'
$problems = [System.Collections.Generic.List[string]]::new()
# absolute Pfade: der Inno-Deinstaller kopiert sich nach %TEMP% und startet von dort neu
$logDir = (New-Item -ItemType Directory -Force -Path (Join-Path $PWD 'dist')).FullName

function Invoke-Uninstaller([string]$Exe, [string[]]$Extra, [string]$Log) {
    $p = Start-Process $Exe -Wait -PassThru -ArgumentList (@('/VERYSILENT', '/SUPPRESSMSGBOXES', "/LOG=`"$Log`"") + $Extra)
    if ($p.ExitCode -ne 0) {
        $tail = (Get-Content $Log -Tail 60 -ErrorAction SilentlyContinue) -join "`n"
        & (Join-Path $PSScriptRoot 'annotate.ps1') -Title ([IO.Path]::GetFileName($Log)) -Text $tail
        throw "Deinstallation fehlgeschlagen ($($p.ExitCode)), Log: $Log`n$tail"
    }
    # Inno wartet nicht immer auf die aus %TEMP% neu gestartete Kopie
    foreach ($i in 1..30) {
        if (-not (Get-Process -Name '_iu*', 'unins*' -ErrorAction SilentlyContinue)) { break }
        Start-Sleep 1
    }
}

function Csrf([string]$Html) { [regex]::Match($Html, 'name="csrf_token" value="([^"]+)"').Groups[1].Value }

if ($Part -eq 'Probe') {
    Invoke-Uninstaller "${env:ProgramFiles}\Wachtl\unins000.exe" @() (Join-Path $logDir 'probe-uninstall.log')
    Start-Sleep 3
    if (Get-Service Wachtl -ErrorAction SilentlyContinue) { $problems.Add('Dienst Wachtl') }
    if (Get-NetFirewallRule -DisplayName 'Wachtl Probe iperf3' -ErrorAction SilentlyContinue) { $problems.Add('Firewall-Regel Wachtl Probe iperf3') }
    if (Get-NetFirewallRule -DisplayName 'Wachtl Probe RTP' -ErrorAction SilentlyContinue) { $problems.Add('Firewall-Regel Wachtl Probe RTP') }
    $byProgram = Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | Where-Object Program -like "${env:ProgramFiles}\Wachtl\*"
    if ($byProgram) { $problems.Add("Firewall-Regeln für $(($byProgram.Program | Sort-Object -Unique) -join ', ')") }
    if (Test-Path C:\ProgramData\Wachtl\state.json) { $problems.Add('Token C:\ProgramData\Wachtl\state.json') }
    if (Test-Path C:\ProgramData\Wachtl) { $problems.Add('Datenordner C:\ProgramData\Wachtl (unbeaufsichtigt wird er gelöscht)') }
    if (Get-Process iperf3 -ErrorAction SilentlyContinue | Where-Object Path -like "${env:ProgramFiles}\Wachtl\*") { $problems.Add('iperf3.exe der Probe läuft noch') }
    if (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Wachtl Tray' -ErrorAction SilentlyContinue) { $problems.Add('Autostart-Eintrag Wachtl Tray') }
    if (Get-Process wachtl-tray -ErrorAction SilentlyContinue | Where-Object Path -like "${env:ProgramFiles}\Wachtl\*") { $problems.Add('wachtl-tray.exe der Probe läuft noch') }
    if (Get-NetTCPConnection -LocalPort 47252 -State Listen -ErrorAction SilentlyContinue) { $problems.Add('Tray-Endpunkt 127.0.0.1:47252 lauscht noch') }
    if (Get-ChildItem Cert:\LocalMachine\Root | Where-Object FriendlyName -eq 'Wachtl Server (Probe)') { $problems.Add('Stammzertifikat „Wachtl Server (Probe)“') }
    # das des Server-Setups auf demselben Rechner bleibt
    if (-not (Get-ChildItem Cert:\LocalMachine\Root | Where-Object FriendlyName -eq 'Wachtl Server')) { $problems.Add('Probe-Deinstallation hat das Stammzertifikat des Servers entfernt') }

    # Server: CI-PROBE ist abgemeldet, ihr Token ungültig
    $login = Invoke-WebRequest "$base/login" -SkipCertificateCheck -SessionVariable s
    Invoke-WebRequest "$base/login" -Method Post -WebSession $s -SkipCertificateCheck `
        -Body @{ username = 'admin'; password = 'ci-test-passwort-123'; csrf_token = (Csrf $login.Content) } | Out-Null
    $probe = (Invoke-RestMethod "$base/api/v1/probes" -WebSession $s -SkipCertificateCheck) | Where-Object hostname -eq 'CI-PROBE'
    if (-not $probe.deregistered_at -or $probe.status -ne 'disabled') { $problems.Add("CI-PROBE am Server nicht abgemeldet (Status $($probe.status))") }
    else { Write-Host "CI-PROBE am Server abgemeldet, Status $($probe.status)" }
}
else {
    Invoke-Uninstaller "${env:ProgramFiles}\Wachtl Server\unins000.exe" @('/REMOVEDATA') (Join-Path $logDir 'server-uninstall.log')
    Start-Sleep 3
    if (Get-Service WachtlServer -ErrorAction SilentlyContinue) { $problems.Add('Dienst WachtlServer') }
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object DisplayName -like 'Wachtl Server*'
    if ($rules) { $problems.Add("Firewall-Regeln: $(($rules.DisplayName | Sort-Object -Unique) -join ', ')") }
    $byProgram = Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | Where-Object Program -like "${env:ProgramFiles}\Wachtl Server\*"
    if ($byProgram) { $problems.Add("Firewall-Regeln für $(($byProgram.Program | Sort-Object -Unique) -join ', ')") }
    if (Get-ScheduledTask -TaskName 'Wachtl Server Backup' -ErrorAction SilentlyContinue) { $problems.Add('Geplante Aufgabe Wachtl Server Backup') }
    foreach ($port in 8443, 8080, 5201, 47251) {
        if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) { $problems.Add("Port $port lauscht noch") }
    }
    if (Get-Process python, iperf3, victoria-metrics, vmalert, alertmanager, wachtl-tray -ErrorAction SilentlyContinue |
            Where-Object Path -like "${env:ProgramFiles}\Wachtl Server\*") { $problems.Add('Prozesse aus dem Programmordner laufen noch') }
    if (Get-ChildItem Cert:\LocalMachine\Root | Where-Object FriendlyName -eq 'Wachtl Server') { $problems.Add('Stammzertifikat „Wachtl Server“') }
    if (Test-Path C:\WachtlData) { $problems.Add('Datenordner C:\WachtlData trotz /REMOVEDATA') }
    if (Test-Path 'HKLM:\Software\Wachtl Server') { $problems.Add('Registry-Schlüssel HKLM\Software\Wachtl Server') }
    if (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Wachtl Server Tray' -ErrorAction SilentlyContinue) { $problems.Add('Autostart-Eintrag Wachtl Server Tray') }
}

if ($problems.Count) {
    $text = "Nach der Deinstallation ($Part) noch vorhanden:`n - " + ($problems -join "`n - ")
    & (Join-Path $PSScriptRoot 'annotate.ps1') -Title "Deinstallation $Part" -Text $text
    throw $text
}
Write-Host "Deinstallation ($Part): nichts zurückgeblieben."
