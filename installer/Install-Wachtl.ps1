<#
.SYNOPSIS
    Installiert, aktualisiert, prüft oder entfernt die Wachtl-Probe als Windows-Dienst.

.DESCRIPTION
    Die Probe läuft als Dienst "Wachtl" unter dem virtuellen Konto "NT SERVICE\Wachtl",
    startet automatisch (verzögert) nach jedem Neustart und benötigt keinen angemeldeten Benutzer.
    Programm:  C:\Program Files\Wachtl\wachtl-probe.exe
    Daten:     C:\ProgramData\Wachtl  (state.json, config.json, buffer.db, logs\)

.EXAMPLE
    .\Install-Wachtl.ps1 -Action Install -ServerUrl https://wachtl.kunde.local -EnrollToken wachtl-xxxx -SpkiPin "kpbQ...g8A="

.EXAMPLE
    .\Install-Wachtl.ps1 -Action Status

.EXAMPLE
    .\Install-Wachtl.ps1 -Action Update -SourceExe \\fileserver\it\wachtl\wachtl-probe.exe

.EXAMPLE
    .\Install-Wachtl.ps1 -Action Uninstall -RemoveData
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall', 'Status', 'Update', 'Restart', 'Logs')]
    [string]$Action = 'Status',

    [string]$ServerUrl,
    [string]$EnrollToken,
    [string]$SpkiPin,
    [string]$Proxy,
    [string]$SourceExe = (Join-Path $PSScriptRoot 'wachtl-probe.exe'),
    [switch]$RemoveData,
    [int]$LogLines = 40
)

$ErrorActionPreference = 'Stop'
$ServiceName  = 'Wachtl'
$DisplayName  = 'Wachtl Netzwerk-Probe'
$Description  = 'Misst Latenz und Paketverlust und meldet sie an den zentralen Wachtl-Server.'
$InstallDir   = Join-Path $env:ProgramFiles 'Wachtl'
$ExePath      = Join-Path $InstallDir 'wachtl-probe.exe'
$DataDir      = Join-Path $env:ProgramData 'Wachtl'
$ServiceAcct  = "NT SERVICE\$ServiceName"

function Write-Step([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "    $Text" -ForegroundColor Green }

function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Bitte PowerShell als Administrator starten.'
    }
}

function Get-WachtlService { Get-Service -Name $ServiceName -ErrorAction SilentlyContinue }

function Stop-WachtlService {
    $svc = Get-WachtlService
    if ($svc -and $svc.Status -ne 'Stopped') {
        Write-Step 'Stoppe Dienst'
        Stop-Service -Name $ServiceName -Force
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
}

function Set-DataDirAcl {
    # Nur SYSTEM, Administratoren und das Dienstkonto dürfen auf Token und Puffer zugreifen.
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.PropagationFlags]::None
    # SIDs statt Namen: "BUILTIN\Administrators" heißt auf deutschem Windows "VORDEFINIERT\Administratoren"
    $identities = @(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')),       # SYSTEM
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')),   # Administratoren
        (New-Object System.Security.Principal.NTAccount($ServiceAcct))
    )
    foreach ($identity in $identities) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'Modify', $inherit, $none, 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $DataDir -AclObject $acl
}

function Copy-Exe {
    if (-not (Test-Path $SourceExe)) { throw "wachtl-probe.exe nicht gefunden: $SourceExe" }
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    if ((Resolve-Path $SourceExe).Path -ne $ExePath) {
        Copy-Item -Path $SourceExe -Destination $ExePath -Force
    }
    Unblock-File -Path $ExePath -ErrorAction SilentlyContinue
    Write-Ok "Programm: $ExePath ($(& $ExePath --version))"
}

function Install-Probe {
    Assert-Admin
    if (-not $ServerUrl -or -not $EnrollToken -or -not $SpkiPin) {
        throw 'Für -Action Install werden -ServerUrl, -EnrollToken und -SpkiPin benötigt (siehe Wachtl-Verwaltung > Probes registrieren).'
    }
    if ($ServerUrl -notmatch '^https://') { throw '-ServerUrl muss mit https:// beginnen.' }

    Stop-WachtlService
    Write-Step 'Kopiere Programm'
    Copy-Exe

    Write-Step "Registriere Probe bei $ServerUrl"
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    $enrollArgs = @('enroll', '--server', $ServerUrl, '--token', $EnrollToken, '--pin', $SpkiPin)
    if ($Proxy) { $enrollArgs += @('--proxy', $Proxy) }
    & $ExePath @enrollArgs
    if ($LASTEXITCODE -ne 0) { throw "Registrierung fehlgeschlagen (Exit-Code $LASTEXITCODE)." }

    if (-not (Get-WachtlService)) {
        Write-Step 'Lege Dienst an'
        New-Service -Name $ServiceName -BinaryPathName "`"$ExePath`"" -DisplayName $DisplayName `
            -Description $Description -StartupType Automatic | Out-Null
    }
    & sc.exe config $ServiceName start= delayed-auto obj= $ServiceAcct | Out-Null
    # Bei Absturz nach 10 s, 30 s, 60 s neu starten; Zähler nach einem Tag zurücksetzen
    & sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null
    & sc.exe failureflag $ServiceName 1 | Out-Null

    Write-Step 'Setze Berechtigungen'
    Set-DataDirAcl

    Write-Step 'Starte Dienst'
    Start-Service -Name $ServiceName
    (Get-WachtlService).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Write-Ok 'Dienst läuft. Die Probe erscheint in Kürze im Wachtl-Dashboard.'
}

function Update-Probe {
    Assert-Admin
    if (-not (Get-WachtlService)) { throw 'Dienst ist nicht installiert. Bitte -Action Install verwenden.' }
    Stop-WachtlService
    Write-Step 'Ersetze Programm'
    Copy-Exe
    Start-Service -Name $ServiceName
    Write-Ok 'Aktualisiert und gestartet. Gepufferte Messwerte werden nachgesendet.'
}

function Uninstall-Probe {
    Assert-Admin
    Stop-WachtlService
    if (Get-WachtlService) {
        Write-Step 'Entferne Dienst'
        & sc.exe delete $ServiceName | Out-Null
    }
    if (Test-Path $InstallDir) { Remove-Item -Path $InstallDir -Recurse -Force }
    if ($RemoveData -and (Test-Path $DataDir)) {
        Write-Step 'Entferne Daten (Token, Puffer, Logs)'
        Remove-Item -Path $DataDir -Recurse -Force
    }
    Write-Ok 'Wachtl-Probe entfernt. Im Dashboard die Probe ggf. noch löschen.'
}

function Show-Status {
    $svc = Get-WachtlService
    if (-not $svc) { Write-Host 'Dienst: nicht installiert' -ForegroundColor Yellow; return }
    $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
    $color = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
    Write-Host ("Dienst:        {0} ({1}, Konto {2})" -f $svc.Status, $cim.StartMode, $cim.StartName) -ForegroundColor $color
    if ($cim.ProcessId -gt 0) {
        $proc = Get-Process -Id $cim.ProcessId -ErrorAction SilentlyContinue
        if ($proc) { Write-Host ("Speicher:      {0:N0} MB, läuft seit {1}" -f ($proc.WorkingSet64 / 1MB), $proc.StartTime) }
    }
    if (Test-Path $ExePath) { & $ExePath status }
    $log = Get-ChildItem -Path (Join-Path $DataDir 'logs') -Filter 'probe-*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($log) {
        Write-Host "`nLetzte Meldungen ($($log.Name)):"
        Get-Content -Path $log.FullName -Tail 8
    }
}

function Show-Logs {
    $log = Get-ChildItem -Path (Join-Path $DataDir 'logs') -Filter 'probe-*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $log) { Write-Host 'Keine Logdatei gefunden.'; return }
    Get-Content -Path $log.FullName -Tail $LogLines -Wait
}

switch ($Action) {
    'Install'   { Install-Probe }
    'Update'    { Update-Probe }
    'Uninstall' { Uninstall-Probe }
    'Restart'   { Assert-Admin; Restart-Service -Name $ServiceName; Write-Ok 'Neu gestartet.' }
    'Logs'      { Show-Logs }
    default     { Show-Status }
}
