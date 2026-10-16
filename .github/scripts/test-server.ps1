$ErrorActionPreference = 'Stop'
Get-Service WachtlServer | Format-List Name, Status, StartType
(Get-CimInstance Win32_Service -Filter "Name='WachtlServer'").StartName
# HTTPS mit selbstsigniertem Zertifikat, Healthcheck und Login-Seite
$ok = $false
foreach ($i in 1..30) {
  try { $r = Invoke-WebRequest https://localhost:8443/healthz -SkipCertificateCheck -UseBasicParsing; $ok = $true; break }
  catch { Start-Sleep 5 }
}
if (-not $ok) { Get-ChildItem C:\WachtlData\logs; Get-Content C:\WachtlData\logs\*.log -Tail 30; throw 'Server antwortet nicht' }
Write-Host $r.Content
$login = Invoke-WebRequest https://localhost:8443/login -SkipCertificateCheck -UseBasicParsing
if ($login.StatusCode -ne 200) { throw 'Login-Seite fehlt' }
# Umleitung HTTP -> HTTPS (ohne ihr zu folgen; Invoke-WebRequest wirft hier in PowerShell 7)
$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [System.Net.Http.HttpClient]::new($handler)
$redir = $client.GetAsync('http://localhost:8080/').GetAwaiter().GetResult()
Write-Host "HTTP: $([int]$redir.StatusCode) -> $($redir.Headers.Location)"
if ([int]$redir.StatusCode -ne 301) { throw 'HTTP-Umleitung fehlt' }
& "${env:ProgramFiles}\Wachtl Server\wachtl-server.cmd" status
if ($LASTEXITCODE -ne 0) { throw 'Status meldet Fehler' }
& "${env:ProgramFiles}\Wachtl Server\wachtl-server.cmd" backup
if ($LASTEXITCODE -ne 0) { throw "Sicherung fehlgeschlagen" }
Get-ChildItem C:\WachtlData\backups
