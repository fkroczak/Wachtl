<#
  End-to-End-Test der 0.3-Funktionen auf dem Windows-Runner:
  Pfad-Check (Traceroute + Hop-Pings) und iperf3-Messung gegen den Wachtl-Server, ausgelöst per „Jetzt messen“.
  Alles über das Web-UI, so wie ein Administrator es bedient.
#>
$ErrorActionPreference = 'Stop'
$base = 'https://localhost:8443'
$summary = [System.Collections.Generic.List[string]]::new()

function Csrf([string]$Html) {
    $m = [regex]::Match($Html, 'name="csrf_token" value="([^"]+)"')
    if (-not $m.Success) { throw 'Kein CSRF-Token in der Seite' }
    $m.Groups[1].Value
}
function Get-Page([string]$Path) { Invoke-WebRequest "$base$Path" -WebSession $script:s -SkipCertificateCheck }
function Get-Json([string]$Path) { Invoke-RestMethod "$base$Path" -WebSession $script:s -SkipCertificateCheck }
function Post-Form([string]$Path, [hashtable]$Body) {
    $Body['csrf_token'] = Csrf (Get-Page '/admin').Content
    Invoke-WebRequest "$base$Path" -Method Post -Body $Body -WebSession $script:s -SkipCertificateCheck
}

function Show-Diagnostics {
    $a = Join-Path $PSScriptRoot 'annotate.ps1'
    & $a -Title 'E2E-Zusammenfassung' -Text ($summary -join "`n")
    & $a -Title 'web.log' -Text ((Get-Content C:\WachtlData\logs\web.log -Tail 120 -ErrorAction SilentlyContinue) -join "`n")
    & $a -Title 'Probe-Log' -Text ((Get-Content C:\ProgramData\Wachtl\logs\*.log -Tail 100 -ErrorAction SilentlyContinue) -join "`n")
}

try {
    # Anmelden
    $login = Invoke-WebRequest "$base/login" -SkipCertificateCheck -SessionVariable s
    $script:s = $s
    Invoke-WebRequest "$base/login" -Method Post -WebSession $s -SkipCertificateCheck `
        -Body @{ username = 'admin'; password = 'ci-test-passwort-123'; csrf_token = (Csrf $login.Content) } | Out-Null

    $probe = (Get-Json '/api/v1/probes') | Where-Object hostname -eq 'CI-PROBE' | Select-Object -First 1
    if (-not $probe) { throw 'CI-PROBE nicht gefunden' }
    $pid_ = $probe.id

    # iperf3-Gegenstelle des Servers läuft?
    $sup = Get-Content C:\WachtlData\logs\supervisor.log -Raw
    if ($sup -notmatch 'iperf3 gestartet') { throw 'iperf3-Gegenstelle auf dem Server wurde nicht gestartet' }
    $summary.Add('Server: iperf3-Gegenstelle läuft')

    # Checks anlegen
    Post-Form '/admin/checks' @{
        type = 'path'; name = 'CI Pfad'; target = '127.0.0.1'; interval_s = '1'; timeout_ms = '1000'; max_hops = '5'
        hop_size_bytes = '32'; trace_interval_min = '10'; retrace_on_loss = 'on'; trace_timeout_ms = '1000'
        probes_per_hop = '1'; ping_hops = 'all'; first_n = '5'; scope = 'all'
    } | Out-Null
    Post-Form '/admin/checks' @{
        type = 'iperf'; name = 'CI iperf'; peer = 'server'; protocol = 'tcp'; direction = 'both'; duration_s = '3'
        omit_s = '0'; streams = '2'; window_kb = '0'; timeout_s = '40'; schedule_min = '0'; offset_min = '-1'
        window_start = '00:00'; window_end = '23:59'; weekdays = '1234567'; min_down_mbps = '0'; min_up_mbps = '0'
        scope = 'all'
    } | Out-Null
    $checks = Get-Json '/api/v1/checks'
    $pathCheck = ($checks | Where-Object name -eq 'CI Pfad').id
    $iperfCheck = ($checks | Where-Object name -eq 'CI iperf').id
    if (-not $pathCheck -or -not $iperfCheck) { throw 'Checks wurden nicht angelegt' }
    $cfg = $checks | Where-Object id -eq $iperfCheck
    $summary.Add("Checks angelegt: Pfad $pathCheck, iperf $iperfCheck (Streams $($cfg.params.streams))")

    # Probe übernimmt die Konfiguration mit dem nächsten Heartbeat und meldet den ersten Pfad
    $path = $null
    foreach ($i in 1..24) {
        Start-Sleep 5
        $path = (Get-Json "/api/v1/probes/$pid_/paths") | Where-Object check_id -eq $pathCheck | Select-Object -First 1
        if ($path) { break }
    }
    if (-not $path) { throw 'Kein Pfad-Ergebnis von der Probe' }
    $summary.Add("Pfad: $($path.hops.Count) Hop(s), Ziel erreicht: $($path.reached), Hops: $(($path.hops | ForEach-Object { $_.ip }) -join ' > ')")
    if (-not $path.reached) { throw 'Pfad zu 127.0.0.1 nicht erreicht' }

    # Hop-Pings kommen an (Seite zeigt Verlust für 127.0.0.1). VictoriaMetrics liefert die letzten 30 s
    # erst verzögert (search.latencyOffset), daher bis zu 2 Minuten warten.
    $loss = ''
    foreach ($i in 1..12) {
        Start-Sleep 10
        $page = (Get-Page "/probes/$pid_/path/$pathCheck").Content
        $loss = [regex]::Match($page, '<td class="num ?">(\d+[.,]\d) %</td>').Groups[1].Value
        if ($loss -ne '') { break }
    }
    if ($page -notmatch '127\.0\.0\.1') { throw 'Pfad-Seite zeigt den Hop nicht' }
    $summary.Add("Pfad-Seite: Verlust Hop 1 = $loss %")
    if ($loss -eq '') {
        $row = [regex]::Match($page, '(?s)<table class="hops">.*?</table>').Value
        & (Join-Path $PSScriptRoot 'annotate.ps1') -Title 'Pfad-Seite' -Text (($summary -join "`n") + "`n" + $row)
        & (Join-Path $PSScriptRoot 'annotate.ps1') -Title 'Probe-Log' -Text ((Get-Content C:\ProgramData\Wachtl\logs\*.log -Tail 80) -join "`n")
        & (Join-Path $PSScriptRoot 'annotate.ps1') -Title 'web.log' -Text ((Get-Content C:\WachtlData\logs\web.log -Tail 60) -join "`n")
        throw 'Keine Hop-Messwerte auf der Pfad-Seite'
    }

    # „Jetzt messen“
    Post-Form "/probes/$pid_/checks/$iperfCheck/run" @{} | Out-Null
    $runs = @()
    foreach ($i in 1..30) {
        Start-Sleep 5
        $runs = @((Get-Json "/api/v1/probes/$pid_/bandwidth") | Where-Object check_id -eq $iperfCheck)
        if ($runs.Count -ge 2) { break }
    }
    foreach ($r in $runs) { $summary.Add("iperf3 $($r.direction): $($r.mbps) Mbit/s, Retransmits $($r.retransmits), Auslöser $($r.trigger), Fehler: $($r.error)") }
    $text = $summary -join "`n"
    Write-Host $text
    & (Join-Path $PSScriptRoot 'annotate.ps1') -Title 'Wachtl 0.3 E2E' -Text $text
    if ($runs.Count -lt 2) {
        & (Join-Path $PSScriptRoot 'annotate.ps1') -Title 'Probe-Log' -Text ((Get-Content C:\ProgramData\Wachtl\logs\*.log -Tail 80) -join "`n")
        throw 'Keine iperf3-Ergebnisse'
    }
    if (@($runs | Where-Object { $_.error -or -not ($_.mbps -gt 0) }).Count) { throw 'iperf3-Messung fehlerhaft' }
    if (@($runs | Where-Object trigger -ne 'manual').Count) { throw 'Auslöser nicht „manual“' }
    (Get-Page "/probes/$pid_/bandwidth/$iperfCheck").Content | Out-Null
    Get-Page '/outages' | Out-Null
}
catch {
    Show-Diagnostics
    throw
}
