$ErrorActionPreference = 'Stop'
$w = "${env:ProgramFiles}\Wachtl Server\wachtl-server.cmd"
$pin = (Get-Content C:\WachtlData\config\wachtl.env | Where-Object { $_ -like 'WACHTL_SPKI_PIN=*' }) -replace '^WACHTL_SPKI_PIN=', ''
$token = (& $w create-token --site CI --uses 2 | Select-Object -Last 1).Trim()
if ($token -notlike 'wachtl-*') { throw "Kein Token: $token" }
$setup = Get-ChildItem dist/probe/WachtlProbeSetup-*.exe | Select-Object -First 1
$p = Start-Process $setup.FullName -Wait -PassThru -ArgumentList @(
  '/VERYSILENT', '/SUPPRESSMSGBOXES', '/LOG=dist\probe-install.log',
  '/Server=https://localhost:8443', "/Pin=$pin", "/Token=$token", '/Hostname=CI-PROBE')
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
