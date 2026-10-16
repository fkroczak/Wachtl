<#
  End-to-End-Test der 0.4-Funktionen auf dem Windows-Runner (nach test-v03.ps1):
  - Server-Probe: registriert sich selbst, pingt (Windows-ICMP) und ermittelt Pfade wie eine Probe
  - Standardpaket: legt Ping, Traceroute, iperf3 und Speedtest mit einem Klick an
  - Zustand aller Messungen (/api/v1/check-status) und Übersicht „Messungen mit Problemen“
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
function Post-Form([string]$Path, $Body) {
    $Body['csrf_token'] = Csrf (Get-Page '/admin').Content
    Invoke-WebRequest "$base$Path" -Method Post -Body $Body -WebSession $script:s -SkipCertificateCheck
}

try {
    $login = Invoke-WebRequest "$base/login" -SkipCertificateCheck -SessionVariable s
    $script:s = $s
    Invoke-WebRequest "$base/login" -Method Post -WebSession $s -SkipCertificateCheck `
        -Body @{ username = 'admin'; password = 'ci-test-passwort-123'; csrf_token = (Csrf $login.Content) } | Out-Null

    # Server-Probe ist registriert und online
    $server = $null
    foreach ($i in 1..12) {
        $server = (Get-Json '/api/v1/probes') | Where-Object kind -eq 'server' | Select-Object -First 1
        if ($server -and $server.online) { break }
        Start-Sleep 5
    }
    if (-not $server) {
        Get-Content C:\WachtlData\logs\serverprobe.log -Tail 60 -ErrorAction SilentlyContinue
        throw 'Server-Probe hat sich nicht registriert'
    }
    if (-not $server.online) { throw "Server-Probe $($server.hostname) ist nicht online" }
    $summary.Add("Server-Probe: $($server.hostname) (Probe $($server.id)) am Standort $($server.site_name), online")

    # Ping auf 127.0.0.1 für alle (auch die Server-Probe) – Windows-ICMP über IcmpSendEcho
    Post-Form '/admin/checks' @{
        type = 'ping'; name = 'CI Loopback'; target = '127.0.0.1'; role = 'target'; interval_s = '1'; timeout_ms = '1000'
        size_bytes = '32'; ttl = '128'; jitter_window_s = '60'; scope = 'all'
    } | Out-Null
    $loop = ((Get-Json '/api/v1/checks') | Where-Object name -eq 'CI Loopback').id
    $up = $null
    foreach ($i in 1..18) {
        Start-Sleep 10
        $up = (Get-Json '/api/v1/status') | Where-Object { $_.probe -eq "$($server.id)" -and $_.check_id -eq "$loop" }
        if ($up -and $up.up -eq 1) { break }
    }
    if (-not $up -or $up.up -ne 1) {
        & (Join-Path $PSScriptRoot 'annotate.ps1') -Title 'serverprobe.log' -Text ((Get-Content C:\WachtlData\logs\serverprobe.log -Tail 80) -join "`n")
        throw 'Server-Probe liefert keine Ping-Werte'
    }
    $summary.Add("Server-Probe Ping 127.0.0.1: up=$($up.up), RTT $($up.rtt) ms")

    # Pfad-Check aus test-v03 (127.0.0.1) ermittelt auch die Server-Probe (TTL-Traceroute)
    $path = $null
    foreach ($i in 1..12) {
        $path = (Get-Json "/api/v1/probes/$($server.id)/paths") | Select-Object -First 1
        if ($path) { break }
        Start-Sleep 5
    }
    if (-not $path -or -not $path.reached) { throw 'Server-Probe: kein Pfad zu 127.0.0.1' }
    $summary.Add("Server-Probe Pfad: $($path.hops.Count) Hop(s), erreicht")

    # iperf3 gegen den Server misst die Server-Probe nicht (wäre gegen sich selbst)
    $cfgTypes = (Get-Json "/api/v1/check-status") | Where-Object probe_id -eq $server.id | ForEach-Object type
    if ($cfgTypes -contains 'iperf') { throw 'Server-Probe misst iperf3 gegen sich selbst' }

    # Standardpaket
    $body = 'scope=all&items=ping_quad9&items=path_internet&items=speedtest_wan&csrf_token=' + [uri]::EscapeDataString((Csrf (Get-Page '/admin').Content))
    Invoke-WebRequest "$base/admin/standard-package" -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' `
        -WebSession $s -SkipCertificateCheck | Out-Null
    $names = (Get-Json '/api/v1/checks') | ForEach-Object name
    foreach ($n in 'Quad9 DNS', 'Traceroute Internet', 'Speedtest Internet') {
        if ($names -notcontains $n) { throw "Standardpaket: $n fehlt" }
    }
    $summary.Add('Standardpaket: Quad9 DNS, Traceroute Internet, Speedtest Internet angelegt')

    # Zustand aller Messungen
    $states = Get-Json '/api/v1/check-status'
    $byType = $states | Group-Object type | ForEach-Object { "$($_.Name): $($_.Count)" }
    $summary.Add("Check-Status: $($states.Count) Messungen ($($byType -join ', '))")
    $loopState = $states | Where-Object { $_.probe_id -eq $server.id -and $_.check_id -eq $loop }
    if ($loopState.state -ne 'ok') { throw "Loopback-Ping der Server-Probe nicht ok: $($loopState.state) $($loopState.detail)" }
    $page = (Get-Page '/').Content
    if ($page -notmatch 'Messungen mit Problemen') { throw 'Übersicht ohne Abschnitt „Messungen mit Problemen“' }
    if ($page -notmatch 'Checks ok / auffällig / gestört / keine Daten') { throw 'Übersicht zählt nicht alle Check-Arten' }

    $text = $summary -join "`n"
    Write-Host $text
    & (Join-Path $PSScriptRoot 'annotate.ps1') -Title 'Wachtl 0.4 E2E' -Text $text
}
catch {
    & (Join-Path $PSScriptRoot 'annotate.ps1') -Title 'E2E 0.4' -Text (($summary -join "`n") + "`n" + $_)
    throw
}
