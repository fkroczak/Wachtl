<#
.SYNOPSIS
    Baut den Setup-Assistenten WachtlServerSetup-<Version>.exe für Windows Server.

.DESCRIPTION
    Lädt die Fremdkomponenten (eingebettetes Python, VictoriaMetrics, Alertmanager, WinSW),
    prüft deren SHA-256-Prüfsummen, installiert die Python-Pakete, kopiert die Anwendung und
    kompiliert das Inno-Setup-Skript. Läuft auf Windows (lokal oder GitHub Actions).

    Voraussetzungen: Windows, Python 3.12 (für pip), Inno Setup 6 (wird sonst per choco installiert).

.EXAMPLE
    .\windows\build-server.ps1 -Version 0.9.1
#>
param(
    [string]$Version = '0.9.1',
    [string]$PythonVersion = '3.12.10',
    [string]$VmVersion = 'v1.149.0',
    [string]$AlertmanagerVersion = '0.28.1',
    [string]$WinSWVersion = 'v2.12.0',
    [string]$ProbeDir = (Join-Path $PSScriptRoot '..\dist\probe'),   # wachtl-probe.exe + iperf3 aus probe\build.ps1
    [string]$IperfUrl = 'https://github.com/ar51an/iperf3-win-builds/releases/download/3.21/iperf-3.21-win64.zip',
    [string]$Output = (Join-Path $PSScriptRoot '..\dist')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
$Build = Join-Path $Root 'build\server'
$Cache = Join-Path $Root 'build\downloads'

function Step([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }

function Get-Download([string]$Url) {
    New-Item -ItemType Directory -Force -Path $Cache | Out-Null
    $file = Join-Path $Cache ([IO.Path]::GetFileName(([Uri]$Url).AbsolutePath))
    if (-not (Test-Path $file)) {
        Write-Host "    lade $Url"
        Invoke-WebRequest -Uri $Url -OutFile $file -UseBasicParsing
    }
    return $file
}

function Assert-Checksum([string]$File, [string]$ChecksumFile) {
    $name = [IO.Path]::GetFileName($File)
    $line = Get-Content $ChecksumFile | Where-Object { $_ -match [Regex]::Escape($name) } | Select-Object -First 1
    if (-not $line) { throw "Keine Prüfsumme für $name in $ChecksumFile" }
    $expected = ($line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 $File).Hash.ToLower()
    if ($expected -ne $actual) { throw "Prüfsumme falsch für $name (erwartet $expected, ist $actual)" }
    Write-Host "    Prüfsumme ok: $name"
}

function Expand-To([string]$Zip, [string]$Dest) {
    if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
    Expand-Archive -Path $Zip -DestinationPath $Dest
}

function Copy-Exe([string]$SearchDir, [string]$Pattern, [string]$Target) {
    $exe = Get-ChildItem -Path $SearchDir -Recurse -Filter $Pattern | Select-Object -First 1
    if (-not $exe) { throw "$Pattern nicht gefunden in $SearchDir" }
    Copy-Item $exe.FullName $Target -Force
    Write-Host "    $($exe.Name) -> $([IO.Path]::GetFileName($Target))"
}

# ---------------------------------------------------------------------------------------------
Step "Arbeitsordner $Build"
if (Test-Path $Build) { Remove-Item -Recurse -Force $Build }
foreach ($d in 'python', 'app', 'bin', 'service', 'docs') { New-Item -ItemType Directory -Force -Path (Join-Path $Build $d) | Out-Null }
$tmp = Join-Path $Root 'build\extract'

Step "Eingebettetes Python $PythonVersion"
$pyZip = Get-Download "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
Expand-Archive -Path $pyZip -DestinationPath (Join-Path $Build 'python') -Force
$short = ($PythonVersion -split '\.')[0..1] -join ''
# Suchpfade: Standardbibliothek, Pakete, Anwendung (..\app); "import site" aktiviert site-packages
Set-Content -Path (Join-Path $Build "python\python$short._pth") -Encoding ascii -Value @(
    "python$short.zip", '.', 'Lib\site-packages', '..\app', 'import site')

Step 'Python-Pakete'
$site = Join-Path $Build 'python\Lib\site-packages'
$pyMinor = ($PythonVersion -split '\.')[0..1] -join '.'
python -m pip install --disable-pip-version-check --no-compile --target $site `
    --only-binary=:all: --platform win_amd64 --python-version $pyMinor --implementation cp `
    -r (Join-Path $Root 'server\requirements-win.txt')
if ($LASTEXITCODE -ne 0) { throw 'pip install fehlgeschlagen' }

Step 'Anwendung'
Copy-Item -Recurse (Join-Path $Root 'server\wachtl') (Join-Path $Build 'app\wachtl')
Get-ChildItem -Path (Join-Path $Build 'app') -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force

Step "VictoriaMetrics $VmVersion"
$base = "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/$VmVersion"
$vmZip = Get-Download "$base/victoria-metrics-windows-amd64-$VmVersion.zip"
Assert-Checksum $vmZip (Get-Download "$base/victoria-metrics-windows-amd64-${VmVersion}_checksums.txt")
$utilZip = Get-Download "$base/vmutils-windows-amd64-$VmVersion.zip"
Assert-Checksum $utilZip (Get-Download "$base/vmutils-windows-amd64-${VmVersion}_checksums.txt")
Expand-To $vmZip "$tmp\vm"
Expand-To $utilZip "$tmp\vmutils"
Copy-Exe "$tmp\vm" 'victoria-metrics-windows-amd64-prod.exe' (Join-Path $Build 'bin\victoria-metrics.exe')
foreach ($tool in 'vmalert', 'vmbackup', 'vmrestore') {
    # exakte Namen: das Archiv enthält auch vmalert-tool-…exe
    Copy-Exe "$tmp\vmutils" "$tool-windows-amd64-prod.exe" (Join-Path $Build "bin\$tool.exe")
}

Step "Alertmanager $AlertmanagerVersion"
$amBase = "https://github.com/prometheus/alertmanager/releases/download/v$AlertmanagerVersion"
$amZip = Get-Download "$amBase/alertmanager-$AlertmanagerVersion.windows-amd64.zip"
Assert-Checksum $amZip (Get-Download "$amBase/sha256sums.txt")
Expand-To $amZip "$tmp\am"
Copy-Exe "$tmp\am" 'alertmanager.exe' (Join-Path $Build 'bin\alertmanager.exe')

Step "WinSW $WinSWVersion"
# .NET-Framework-Variante: kein Selbstentpacken nach %TEMP% unter dem virtuellen Dienstkonto
$winsw = Get-Download "https://github.com/winsw/winsw/releases/download/$WinSWVersion/WinSW.NET461.exe"
Copy-Item $winsw (Join-Path $Build 'service\WachtlServer.exe') -Force
Write-Host "    SHA-256 WinSW: $((Get-FileHash -Algorithm SHA256 $winsw).Hash)"

Step 'iperf3 (Gegenstelle für Bandbreitenmessungen der Probes)'
$iperfTarget = Join-Path $Build 'bin\iperf3'
if (Test-Path $iperfTarget) { Remove-Item -Recurse -Force $iperfTarget }
New-Item -ItemType Directory -Force -Path $iperfTarget | Out-Null
if ($ProbeDir -and (Test-Path (Join-Path $ProbeDir 'iperf3\iperf3.exe'))) {
    Copy-Item (Join-Path $ProbeDir 'iperf3\*') $iperfTarget -Recurse
    Write-Host '    aus dem Probe-Paket übernommen'
} else {
    $iperfZip = Get-Download $IperfUrl
    Write-Host "    SHA-256 iperf3: $((Get-FileHash -Algorithm SHA256 $iperfZip).Hash)"
    Expand-To $iperfZip "$tmp\iperf3"
    $iperfExe = Get-ChildItem "$tmp\iperf3" -Recurse -Filter iperf3.exe | Select-Object -First 1
    if (-not $iperfExe) { throw 'iperf3.exe nicht im Archiv gefunden' }
    Copy-Item (Join-Path $iperfExe.DirectoryName '*') $iperfTarget -Recurse
}
& (Join-Path $iperfTarget 'iperf3.exe') --version
if ($LASTEXITCODE -ne 0) { throw 'iperf3.exe startet nicht' }

Step 'Begleitdateien'
Copy-Item (Join-Path $PSScriptRoot 'wachtl-server.cmd') $Build
Copy-Item (Join-Path $PSScriptRoot 'THIRD-PARTY.txt') $Build
Copy-Item (Join-Path $Root 'docs\*') (Join-Path $Build 'docs') -Recurse

Step 'Selbsttest mit dem eingebetteten Python'
$py = Join-Path $Build 'python\python.exe'
& $py -c "import wachtl, wachtl.win.host, wachtl.win.serve, wachtl.serverprobe.probe, cheroot, cryptography, flask, yaml, requests; print('Module ok')"
if ($LASTEXITCODE -ne 0) { throw 'Eingebettetes Python findet die Module nicht' }
# unchecked-hash: gültig unabhängig von Dateizeiten; Dienstkonto darf __pycache__ nicht schreiben
& $py -m compileall -q --invalidation-mode unchecked-hash (Join-Path $Build 'app') $site | Out-Null
$testDir = Join-Path $Root 'build\selftest'
if (Test-Path $testDir) { Remove-Item -Recurse -Force $testDir }
New-Item -ItemType Directory -Force -Path "$testDir\inst" | Out-Null
@{ hostnames = 'localhost'; https_port = 18443; http_port = 0; data_dir = "$testDir\data"; install_dir = "$testDir\inst";
   admin_password = 'selbsttest-passwort'; notify = @{} } | ConvertTo-Json | Set-Content "$testDir\in.json" -Encoding utf8
& $py -m wachtl.win.installer install --input "$testDir\in.json" --result "$testDir\out.json" --no-start --dry-run
if ($LASTEXITCODE -ne 0) { Get-Content "$testDir\out.json"; throw 'Selbsttest der Einrichtung fehlgeschlagen' }
Remove-Item -Recurse -Force $testDir

Step 'Inno Setup'
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    choco install innosetup --no-progress -y | Out-Null
    $iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
}
New-Item -ItemType Directory -Force -Path $Output | Out-Null
# ein Setup für beide Rollen: Server-Dateien aus $Build, Probe aus $ProbeDir
if (-not (Test-Path (Join-Path $ProbeDir 'wachtl-probe.exe'))) { throw "wachtl-probe.exe fehlt in $ProbeDir (zuerst probe\build.ps1)" }
& $iscc "/DAppVersion=$Version" "/DBuildDir=$Build" "/DProbeDir=$((Resolve-Path $ProbeDir).Path)" "/O$((Resolve-Path $Output).Path)" (Join-Path $PSScriptRoot 'WachtlSetup.iss') 2>&1 | ForEach-Object { "$_" }
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup fehlgeschlagen' }
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
$setup = Get-Item (Join-Path $Output "WachtlSetup-$Version.exe")
Write-Host "Fertig: $($setup.FullName) ($([math]::Round($setup.Length / 1MB, 1)) MB)" -ForegroundColor Green
