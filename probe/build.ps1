<#
.SYNOPSIS
  Baut die Wachtl-Probe: wachtl-probe.exe (selbstständig, kein .NET auf den Ziel-PCs nötig)
  und den Setup-Assistenten WachtlProbeSetup-<Version>.exe.
  Voraussetzungen auf dem Build-Rechner: .NET 8 SDK, Inno Setup 6 (sonst per choco).
#>
param(
    [string]$Version = '0.2.0',
    [string]$Output = "$PSScriptRoot\..\dist\probe"
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

$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    choco install innosetup --no-progress -y | Out-Null
    $iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
}
$out = (Resolve-Path $Output).Path
& $iscc "/DAppVersion=$Version" "/DPublishDir=$out" "/O$out" "$PSScriptRoot\setup\WachtlProbe.iss"
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup fehlgeschlagen' }
Write-Host "Fertig: $out\wachtl-probe.exe, $out\WachtlProbeSetup-$Version.exe" -ForegroundColor Green
