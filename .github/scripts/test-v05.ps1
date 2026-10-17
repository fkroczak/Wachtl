<#
  End-to-End-Test der 0.5-Funktionen auf dem Windows-Runner (nach test-v04.ps1):
  - Tray-Symbol: wachtl-tray.exe ist installiert, im Autostart eingetragen und startet
  - Tray-Endpunkt der Server-Probe (127.0.0.1:47251) und des Probe-Dienstes (hier auf 47252 umgestellt,
    weil Server und Probe auf demselben Runner laufen): Status, Schutz gegen Browser-Anfragen, Störungsmeldung
  - Meldungen kommen am Server an: /api/reports (Graph-Markierungen) und Seite „Meldungen“
#>
$ErrorActionPreference = 'Stop'
$base = 'https://localhost:8443'
$summary = [System.Collections.Generic.List[string]]::new()
$runKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'

function Csrf([string]$Html) {
    $m = [regex]::Match($Html, 'name="csrf_token" value="([^"]+)"')
    if (-not $m.Success) { throw 'Kein CSRF-Token in der Seite' }
    $m.Groups[1].Value
}
function Get-Json([string]$Path) { Invoke-RestMethod "$base$Path" -WebSession $script:s -SkipCertificateCheck }

function Invoke-Tray([int]$Port, [string]$Method, [string]$Path, $Body = $null, [hashtable]$Headers = @{ 'X-Wachtl-Tray' = '1' }) {
    $req = @{ Uri = "http://127.0.0.1:$Port$Path"; Method = $Method; Headers = $Headers; SkipHttpErrorCheck = $true
               TimeoutSec = 30; StatusCodeVariable = 'code' }
    if ($null -ne $Body) { $req.Body = ($Body | ConvertTo-Json -Compress); $req.ContentType = 'application/json' }
    $data = Invoke-RestMethod @req -SkipHeaderValidation
    [pscustomobject]@{ Code = [int]$code; Data = $data }
}

function Wait-TrayStatus([int]$Port, [string]$Role) {
    foreach ($i in 1..30) {
        try {
            $r = Invoke-Tray $Port GET '/tray/v1/status'
            if ($r.Code -eq 200 -and $r.Data.role -eq $Role -and $r.Data.enrolled -and $r.Data.connected) { return $r.Data }
        } catch { }
        Start-Sleep 2
    }
    throw "Tray-Endpunkt 127.0.0.1:$Port ($Role) antwortet nicht oder ist nicht verbunden"
}

function Test-Report([int]$Port, [string]$Role, [string]$Text) {
    $status = Wait-TrayStatus $Port $Role
    $summary.Add("Tray-Endpunkt :$Port – Rolle $($status.role), $($status.name), Standort $($status.site), Version $($status.version)")

    # Schutz: ohne Kopfzeile, fremder Host, falscher Content-Type
    if ((Invoke-Tray $Port GET '/tray/v1/status' -Headers @{}).Code -ne 403) { throw "Port ${Port}: Anfrage ohne X-Wachtl-Tray nicht abgewiesen" }
    if ((Invoke-Tray $Port GET '/tray/v1/status' -Headers @{ 'X-Wachtl-Tray' = '1'; Host = "evil.example:$Port" }).Code -ne 403) {
        throw "Port ${Port}: fremder Host nicht abgewiesen (DNS-Rebinding)"
    }
    $plain = Invoke-WebRequest "http://127.0.0.1:$Port/tray/v1/report" -Method Post -Body '{}' -ContentType 'text/plain' `
        -Headers @{ 'X-Wachtl-Tray' = '1' } -SkipHttpErrorCheck
    if ($plain.StatusCode -ne 403) { throw "Port ${Port}: text/plain nicht abgewiesen ($($plain.StatusCode))" }

    # ungültig: Zeitpunkt älter als 7 Tage
    $old = Invoke-Tray $Port POST '/tray/v1/report' @{ occurred_at = [DateTimeOffset]::UtcNow.AddDays(-8).ToUnixTimeSeconds(); category = 'slow' }
    if ($old.Code -ne 400 -or -not $old.Data.error) { throw "Port ${Port}: alte Meldung nicht mit 400 abgewiesen ($($old.Code))" }

    $ts = [DateTimeOffset]::UtcNow.AddMinutes(-3).ToUnixTimeSeconds()
    $r = Invoke-Tray $Port POST '/tray/v1/report' @{ occurred_at = $ts; category = 'dropouts'; duration = 'minutes'
                                                     description = $Text; user = "CI\$Role" }
    if ($r.Code -ne 202 -or -not $r.Data.ok) { throw "Port ${Port}: Meldung abgelehnt ($($r.Code)): $($r.Data | ConvertTo-Json -Compress)" }
    if (-not $r.Data.delivered) { throw "Port ${Port}: Meldung nur gepuffert, obwohl der Server erreichbar ist" }
    $summary.Add("Störungsmeldung über :$Port zugestellt ($Text)")
    return $ts
}

try {
    $login = Invoke-WebRequest "$base/login" -SkipCertificateCheck -SessionVariable s
    $script:s = $s
    Invoke-WebRequest "$base/login" -Method Post -WebSession $s -SkipCertificateCheck `
        -Body @{ username = 'admin'; password = 'ci-test-passwort-123'; csrf_token = (Csrf $login.Content) } | Out-Null

    # --- Tray-Programm installiert und im Autostart -------------------------------------------------
    foreach ($t in @(@{ Exe = "${env:ProgramFiles}\Wachtl\wachtl-tray.exe"; Value = 'Wachtl Tray' },
                     @{ Exe = "${env:ProgramFiles}\Wachtl Server\wachtl-tray.exe"; Value = 'Wachtl Server Tray' })) {
        if (-not (Test-Path $t.Exe)) { throw "$($t.Exe) fehlt" }
        $run = (Get-ItemProperty $runKey -Name $t.Value -ErrorAction SilentlyContinue).($t.Value)
        if ($run -ne "`"$($t.Exe)`"") { throw "Autostart $($t.Value) fehlt oder falsch: '$run'" }
        $size = (Get-Item $t.Exe).Length
        $summary.Add("$($t.Exe): $([math]::Round($size / 1KB)) KB, Autostart '$($t.Value)'")
    }
    if ((Get-Item "${env:ProgramFiles}\Wachtl\wachtl-tray.exe").Length -gt 2MB) { throw 'wachtl-tray.exe ist größer als 2 MB – Laufzeit mitgepackt?' }

    # startet (.NET Framework 4.6.2 aus Windows) und bleibt laufen; eine zweite Instanz beendet sich
    $tray = Start-Process "${env:ProgramFiles}\Wachtl\wachtl-tray.exe" -PassThru
    Start-Sleep 5
    if ($tray.HasExited) { throw "wachtl-tray.exe hat sich sofort beendet (Code $($tray.ExitCode))" }
    $second = Start-Process "${env:ProgramFiles}\Wachtl\wachtl-tray.exe" -PassThru
    if (-not $second.WaitForExit(15000)) { $second | Stop-Process -Force; throw 'Zweite Instanz von wachtl-tray.exe beendet sich nicht' }
    $tray | Stop-Process -Force
    $summary.Add('wachtl-tray.exe startet, zweite Instanz beendet sich (eine je Sitzung)')

    # --- Server-Probe: Tray-Endpunkt auf 47251 ------------------------------------------------------
    $tsServer = Test-Report 47251 'server' 'CI Meldung Server'

    # --- Probe-Dienst: Port umstellen (47251 belegt die Server-Probe), neu starten ------------------
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Wachtl'
    New-ItemProperty $svcKey -Name Environment -PropertyType MultiString -Value @('WACHTL_TRAY_PORT=47252') -Force | Out-Null
    Restart-Service Wachtl
    $tsProbe = Test-Report 47252 'probe' 'CI Meldung Probe'

    # --- Am Server angekommen -----------------------------------------------------------------------
    $from = $tsServer - 3600; $to = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 60
    $reports = $null
    foreach ($i in 1..10) {
        $reports = (Get-Json "/api/reports?from=$from&to=$to").reports
        if (@($reports | Where-Object description -like 'CI Meldung*').Count -ge 2) { break }
        Start-Sleep 2
    }
    $srv = $reports | Where-Object description -eq 'CI Meldung Server' | Select-Object -First 1
    $prb = $reports | Where-Object description -eq 'CI Meldung Probe' | Select-Object -First 1
    if (-not $srv -or -not $prb) { throw "Meldungen fehlen in /api/reports: $($reports | ConvertTo-Json -Compress -Depth 4)" }
    if ($srv.ts -ne $tsServer -or $prb.ts -ne $tsProbe) { throw 'Zeitpunkt der Meldung stimmt nicht' }
    if ($prb.probe -ne 'CI-PROBE') { throw "Probe-Meldung gehört zu '$($prb.probe)' statt CI-PROBE" }
    if ($prb.category -ne 'dropouts' -or $prb.user -ne 'CI\probe') { throw 'Kategorie oder Benutzer falsch übertragen' }
    $byProbe = (Get-Json "/api/reports?from=$from&to=$to&probe_id=$($prb.probe_id)").reports
    if (@($byProbe | Where-Object description -eq 'CI Meldung Server').Count) { throw 'Filter probe_id liefert fremde Meldungen' }
    $summary.Add("Server: beide Meldungen in /api/reports, Probe $($prb.probe) und $($srv.probe), Zeitpunkt exakt")

    $page = Invoke-WebRequest "$base/meldungen" -WebSession $s -SkipCertificateCheck
    if ($page.Content -notmatch 'CI Meldung Probe') { throw 'Seite „Meldungen“ zeigt die Meldung nicht' }
    $summary.Add('Seite „Meldungen“ zeigt die Meldungen')

    # Probe bleibt bis zur Deinstallation auf 47252 – test-uninstall.ps1 prüft, dass der Port danach zu ist
}
catch {
    foreach ($f in 'C:\WachtlData\logs\serverprobe.log', 'C:\WachtlData\logs\web.log') {
        if (Test-Path $f) { Write-Host "==== $f"; Get-Content $f -Tail 40 }
    }
    Get-ChildItem C:\ProgramData\Wachtl\logs -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1 |
        ForEach-Object { Write-Host "==== $($_.FullName)"; Get-Content $_.FullName -Tail 40 }
    throw
}
finally {
    Write-Host ''
    Write-Host '0.5 Ende-zu-Ende:' -ForegroundColor Green
    $summary | ForEach-Object { Write-Host "  $_" }
}
