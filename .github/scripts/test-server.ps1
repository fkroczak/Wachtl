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
# Wachtl-CA liegt unter „Vertrauenswürdige Stammzertifizierungsstellen“: HTTPS klappt ohne -SkipCertificateCheck
$X509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]
$file = $X509::new('C:\WachtlData\certs\wachtl-ca.crt')
$leaf = $X509::new('C:\WachtlData\certs\wachtl.crt')   # erstes Zertifikat der Kette
$root = Get-ChildItem Cert:\LocalMachine\Root | Where-Object FriendlyName -eq 'Wachtl Server'
if ($root.Thumbprint -ne $file.Thumbprint) { throw "Wachtl-CA fehlt oder veraltet im Stammspeicher: '$($root.Thumbprint)' statt $($file.Thumbprint)" }
if ($leaf.Issuer -ne $file.Subject) { throw "Server-Zertifikat nicht von der Wachtl-CA: $($leaf.Issuer)" }
$days = ($leaf.NotAfter - $leaf.NotBefore).TotalDays
if ($days -gt 398) { throw "Server-Zertifikat gilt $days Tage (höchstens 398)" }
Invoke-WebRequest https://localhost:8443/healthz -UseBasicParsing | Out-Null
Invoke-WebRequest https://127.0.0.1:8443/healthz -UseBasicParsing | Out-Null
$der = Invoke-WebRequest https://localhost:8443/zertifikat/wachtl.crt -UseBasicParsing
if ($X509::new($der.Content).Thumbprint -ne $file.Thumbprint) { throw 'Download unter /zertifikat liefert nicht die Wachtl-CA' }
Write-Host "Wachtl-CA $($file.Thumbprint) im Stammspeicher, Server-Zertifikat $([int]$days) Tage, Browser-Zugriff ohne Warnung"
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
