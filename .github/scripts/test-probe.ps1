<#
  Probe wie im echten Rollout: vorbelegtes Setup im Web-UI herunterladen und ohne Eingaben installieren.
  /Server= stellt eine nicht auflösbare Adresse vor die richtige – die Probe muss auf die nächste ausweichen.
  Pin und Token kommen nur aus der Datei selbst.
#>
$ErrorActionPreference = 'Stop'
$base = 'https://localhost:8443'
$w = "${env:ProgramFiles}\Wachtl Server\wachtl-server.cmd"
function Csrf([string]$Html) { [regex]::Match($Html, 'name="csrf_token" value="([^"]+)"').Groups[1].Value }

$login = Invoke-WebRequest "$base/login" -SkipCertificateCheck -SessionVariable s
Invoke-WebRequest "$base/login" -Method Post -WebSession $s -SkipCertificateCheck `
    -Body @{ username = 'admin'; password = 'ci-test-passwort-123'; csrf_token = (Csrf $login.Content) } | Out-Null
$csrf = Csrf (Invoke-WebRequest "$base/admin" -WebSession $s -SkipCertificateCheck).Content
Invoke-WebRequest "$base/admin/sites" -Method Post -WebSession $s -SkipCertificateCheck -Body @{ name = 'CI'; csrf_token = $csrf } | Out-Null
$site = (Invoke-RestMethod "$base/api/v1/sites" -WebSession $s -SkipCertificateCheck) | Where-Object name -eq 'CI'

$setup = Join-Path (Resolve-Path dist) 'WachtlSetup-CI.exe'
Invoke-WebRequest "$base/admin/tokens" -Method Post -WebSession $s -SkipCertificateCheck -OutFile $setup -Body @{
    site_id = $site.id; max_uses = '3'; days = '1'; action = 'setup'; csrf_token = $csrf }
$tail = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($setup)[-2000..-1])
if ($tail -notmatch '@@WACHTL-SETUP-CONFIG@@') { throw 'Heruntergeladenes Setup enthält keine Vorbelegung' }
Write-Host "Vorbelegtes Setup: $([math]::Round((Get-Item $setup).Length / 1MB, 1)) MB, Server: $([regex]::Match($tail, 'servers=(.*)').Groups[1].Value.Trim())"

$p = Start-Process $setup -Wait -PassThru -ArgumentList @(
  '/VERYSILENT', '/SUPPRESSMSGBOXES', '/LOG=dist\probe-install.log',
  '/Server=https://wachtl-gibt-es-nicht.invalid:8443,https://localhost:8443', '/Hostname=CI-PROBE')
Write-Host "Probe-Setup beendet mit $($p.ExitCode)"
if ($p.ExitCode -ne 0) { Get-Content dist\probe-install.log -Tail 60; throw 'Probe-Setup fehlgeschlagen' }
Get-Service Wachtl | Format-List Name, Status, StartType
& "${env:ProgramFiles}\Wachtl\wachtl-probe.exe" status
$online = $false
foreach ($i in 1..12) {
  Start-Sleep 10
  $list = & $w probes
  $list
  if ($list -match 'CI-PROBE.*online') { $online = $true; break }
}
if (-not $online) { Get-Content C:\ProgramData\Wachtl\logs\*.log -Tail 40; throw 'Probe meldet sich nicht' }
