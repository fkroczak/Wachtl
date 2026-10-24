<#
  End-to-End-Test der 0.9-Funktion auf dem Windows-Runner: Sprachtest (RTP).
  1. Windows-Probe (CI-PROBE) gegen den RTP-Reflektor des Wachtl-Servers (Prozess „rtp“ im Dienst).
  2. Server-Probe gegen den RTP-Reflektor der Windows-Probe (Probe als Gegenstelle, eigener UDP-Port).
  Beide Male „Jetzt testen“ über das Web-UI; geprüft werden Ergebnis, MOS und die Seiten.
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

function New-RtpCheck([string]$Name, [hashtable]$Peer, [string]$ProbeId) {
    $body = @{
        type = 'rtp'; name = $Name; codec = 'g711'; ptime_ms = '20'; duration_s = '5'; dscp = '46'
        schedule_min = '0'; offset_min = '-1'; window_start = '00:00'; window_end = '23:59'; weekdays = '1234567'
        min_mos = '3.6'; scope = 'probe'; probe_id = $ProbeId
    }
    foreach ($k in $Peer.Keys) { $body[$k] = $Peer[$k] }
    Post-Form '/admin/checks' $body | Out-Null
    $id = ((Get-Json '/api/v1/checks') | Where-Object name -eq $Name).id
    if (-not $id) { throw "Check $Name wurde nicht angelegt" }
    $id
}

# „Jetzt testen“ so lange wiederholen, bis ein Ergebnis da ist: die Probe übernimmt neue Checks erst mit dem
# nächsten Heartbeat, ein früher zugestellter Auftrag läuft sonst ins Leere.
function Wait-RtpRun([string]$ProbeId, [string]$CheckId, [string]$Label) {
    $run = $null
    foreach ($i in 1..40) {
        if ($i % 7 -eq 1) { Post-Form "/probes/$ProbeId/checks/$CheckId/run" @{} | Out-Null }
        Start-Sleep 5
        $run = (Get-Json "/api/v1/probes/$ProbeId/rtp") | Where-Object check_id -eq $CheckId | Select-Object -First 1
        if ($run) { break }
    }
    if (-not $run) { throw "$($Label): kein Ergebnis des Sprachtests" }
    $summary.Add("$($Label): MOS $($run.mos), Laufzeit $($run.rtt_ms) ms, Verlust ↑ $($run.up_loss_pct) % ↓ $($run.down_loss_pct) %, " +
                 "Jitter ↑ $($run.up_jitter_ms) ms ↓ $($run.down_jitter_ms) ms, Pakete $($run.received)/$($run.sent), " +
                 "Modus $($run.mode), Auslöser $($run.trigger), Fehler: $($run.error)")
    if ($run.error) { throw "$($Label): $($run.error)" }
    if ($run.mode -ne 'wachtl') { throw "$($Label): Reflektor antwortet nicht als Wachtl-Reflektor ($($run.mode))" }
    if (-not ($run.mos -gt 4.0)) { throw "$($Label): MOS $($run.mos) zu niedrig für Loopback/LAN" }
    if ($run.received -lt 200) { throw "$($Label): nur $($run.received) von $($run.sent) Paketen zurück" }
    if ($run.trigger -ne 'manual') { throw "$($Label): Auslöser nicht manual, sondern $($run.trigger)" }
    $run
}

function Show-Diagnostics {
    $a = Join-Path $PSScriptRoot 'annotate.ps1'
    & $a -Title 'E2E 0.9' -Text ($summary -join "`n")
    & $a -Title 'supervisor.log' -Text ((Get-Content C:\WachtlData\logs\supervisor.log -Tail 40 -ErrorAction SilentlyContinue) -join "`n")
    & $a -Title 'serverprobe.log' -Text ((Get-Content C:\WachtlData\logs\serverprobe.log -Tail 60 -ErrorAction SilentlyContinue) -join "`n")
    & $a -Title 'Probe-Log' -Text ((Get-Content C:\ProgramData\Wachtl\logs\*.log -Tail 100 -ErrorAction SilentlyContinue) -join "`n")
}

try {
    $login = Invoke-WebRequest "$base/login" -SkipCertificateCheck -SessionVariable s
    $script:s = $s
    Invoke-WebRequest "$base/login" -Method Post -WebSession $s -SkipCertificateCheck `
        -Body @{ username = 'admin'; password = 'ci-test-passwort-123'; csrf_token = (Csrf $login.Content) } | Out-Null

    $probes = Get-Json '/api/v1/probes'
    $probe = $probes | Where-Object hostname -eq 'CI-PROBE' | Select-Object -First 1
    $server = $probes | Where-Object kind -eq 'server' | Select-Object -First 1
    if (-not $probe) { throw 'CI-PROBE nicht gefunden' }
    if (-not $server) { throw 'Server-Probe nicht gefunden' }

    # RTP-Reflektor des Servers läuft (Prozess im Dienst) und die Firewall-Regel ist da
    $sup = Get-Content C:\WachtlData\logs\supervisor.log -Raw
    if ($sup -notmatch 'rtp gestartet') { throw 'RTP-Reflektor auf dem Server wurde nicht gestartet' }
    if (-not (Get-NetFirewallRule -DisplayName 'Wachtl Server RTP' -ErrorAction SilentlyContinue)) { throw 'Firewall-Regel Wachtl Server RTP fehlt' }
    if (-not (Get-NetFirewallRule -DisplayName 'Wachtl Probe RTP' -ErrorAction SilentlyContinue)) { throw 'Firewall-Regel Wachtl Probe RTP fehlt' }
    $summary.Add('Server: RTP-Reflektor läuft, Firewall-Regeln für Server und Probe vorhanden')

    # 1. Windows-Probe -> Wachtl-Server
    $toServer = New-RtpCheck 'CI Sprache Server' @{ peer = 'server' } "$($probe.id)"
    Wait-RtpRun "$($probe.id)" "$toServer" 'Probe → Server' | Out-Null
    $page = (Get-Page "/probes/$($probe.id)/rtp/$toServer").Content
    if ($page -notmatch 'id="mos-data"') { throw 'Sprachtest-Seite ohne MOS-Graph' }

    # 2. Server-Probe -> Windows-Probe als Gegenstelle. Der Server belegt UDP 5004 und TCP/UDP 5201 selbst,
    #    die Probe bekommt deshalb andere Ports (Verwaltung › Messung bzw. Einstellungen der Probe).
    Post-Form '/admin/measure' @{
        iperf_enabled = 'on'; iperf_host = ''; iperf_port = '5201'; rtp_enabled = 'on'; rtp_host = ''; rtp_port = '5004'
        upload_interval_s = '10'; heartbeat_interval_s = '30'; config_poll_s = '300'; probe_iperf_port = '5201'
        probe_rtp_port = '5005'; client_findings_enabled = 'on'; client_findings_notify = 'on'; history_days = '400'
        outage_min_s = '0'
    } | Out-Null
    Post-Form "/probes/$($probe.id)/settings" @{ iperf_server = 'on'; iperf_port = '5202'; iperf_address = '127.0.0.1' } | Out-Null
    $toProbe = New-RtpCheck 'CI Sprache Probe' @{ peer = 'probe'; peer_probe_id = "$($probe.id)" } "$($server.id)"
    Wait-RtpRun "$($server.id)" "$toProbe" 'Server-Probe → Probe' | Out-Null
    $log = (Get-Content C:\ProgramData\Wachtl\logs\*.log -ErrorAction SilentlyContinue) -join "`n"
    if ($log -notmatch 'RTP-Reflektor lauscht auf UDP-Port 5005') { throw 'Probe-Log: RTP-Reflektor nicht gestartet' }

    # Zustand und Übersicht
    $states = Get-Json '/api/v1/check-status'
    foreach ($pair in @(@($probe.id, $toServer), @($server.id, $toProbe))) {
        $st = $states | Where-Object { $_.probe_id -eq $pair[0] -and $_.check_id -eq $pair[1] }
        if ($st.state -ne 'ok') { throw "Sprachtest $($pair[1]) auf Probe $($pair[0]) nicht ok: $($st.state) $($st.detail)" }
    }
    if ((Get-Page '/probes?tab=sprache').Content -notmatch 'Sprachqualität') { throw 'Seite „Probes“ ohne Reiter „Sprachqualität“' }
    $summary.Add('Check-Status beider Sprachtests: ok; Übersicht zeigt „Sprachqualität“')

    # Gegenstelle wieder aus: der Reflektor der Probe muss den Port freigeben
    Post-Form "/probes/$($probe.id)/settings" @{ iperf_port = '5202'; iperf_address = '' } | Out-Null

    $text = $summary -join "`n"
    Write-Host $text
    & (Join-Path $PSScriptRoot 'annotate.ps1') -Title 'Wachtl 0.9 E2E' -Text $text
}
catch {
    Show-Diagnostics
    throw
}
