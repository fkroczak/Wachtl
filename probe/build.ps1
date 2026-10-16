<#
.SYNOPSIS
  Baut die Wachtl-Probe: wachtl-probe.exe (selbstständig, kein .NET auf den Ziel-PCs nötig)
  und den Setup-Assistenten WachtlProbeSetup-<Version>.exe.
  Voraussetzungen auf dem Build-Rechner: .NET 8 SDK, Inno Setup 6 (sonst per choco).
#>
param(
    [string]$Version = '0.3.0',
    [string]$Output = "$PSScriptRoot\..\dist\probe",
    # Windows-Build von iperf3 (BSD-Lizenz), https://github.com/ar51an/iperf3-win-builds
    [string]$IperfVersion = '3.21',
    [string]$IperfUrl = "https://github.com/ar51an/iperf3-win-builds/releases/download/3.21/iperf-3.21-win64.zip"
)
$ErrorActionPreference = 'Stop'

dotnet test "$PSScriptRoot\Wachtl.Probe.Tests\Wachtl.Probe.Tests.csproj" -c Release
if ($LASTEXITCODE -ne 0) { throw 'Tests fehlgeschlagen' }

dotnet publish "$PSScriptRoot\Wachtl.Probe\Wachtl.Probe.csproj" -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none `
  -p:Version=$Version -o $Output
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish fehlgeschlagen' }
Copy-Item "$PSScriptRoot\..\installer\Install-Wachtl.ps1" $Output -Force

& "$Output\wachtl-probe.exe" --version
if ($LASTEXITCODE -ne 0) { throw 'wachtl-probe.exe startet nicht' }

# iperf3 beilegen: alle Dateien des Archivs (exe und ggf. DLLs) nach <Output>\iperf3
$iperfDir = Join-Path $Output 'iperf3'
if (-not (Test-Path "$iperfDir\iperf3.exe")) {
    $zip = Join-Path ([IO.Path]::GetTempPath()) "iperf3-$IperfVersion.zip"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "iperf3-$IperfVersion"
    Invoke-WebRequest $IperfUrl -OutFile $zip -UseBasicParsing
    Write-Host "iperf3-Archiv SHA256: $((Get-FileHash $zip -Algorithm SHA256).Hash)"
    if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
    Expand-Archive $zip -DestinationPath $tmp -Force
    $exe = Get-ChildItem $tmp -Recurse -Filter iperf3.exe | Select-Object -First 1
    if (-not $exe) { throw 'iperf3.exe nicht im Archiv gefunden' }
    New-Item -ItemType Directory -Force $iperfDir | Out-Null
    Copy-Item (Join-Path $exe.DirectoryName '*') $iperfDir -Recurse -Force
}
Get-ChildItem $iperfDir | ForEach-Object { Write-Host "  iperf3: $($_.Name) $($_.Length)" }
& "$iperfDir\iperf3.exe" --version
if ($LASTEXITCODE -ne 0) { throw 'iperf3.exe startet nicht' }

$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    choco install innosetup --no-progress -y | Out-Null
    $iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
}
$out = (Resolve-Path $Output).Path
& $iscc "/DAppVersion=$Version" "/DPublishDir=$out" "/O$out" "$PSScriptRoot\setup\WachtlProbe.iss" 2>&1 | ForEach-Object { "$_" }
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup fehlgeschlagen' }
Write-Host "Fertig: $out\wachtl-probe.exe, $out\WachtlProbeSetup-$Version.exe" -ForegroundColor Green
