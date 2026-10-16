<#
  Führt einen Befehl aus, schreibt die Ausgabe mit und meldet bei einem Fehler die letzten
  Zeilen als GitHub-Annotation (so sind sie auch ohne Zugriff auf die Log-Dateien lesbar).
#>
param(
    [Parameter(Mandatory)] [string]$Title,
    [Parameter(Mandatory)] [string]$Command,
    [int]$Tail = 150
)
$log = Join-Path ([IO.Path]::GetTempPath()) ("run-" + [guid]::NewGuid().ToString('N') + ".log")
$code = 0
try {
    Invoke-Expression $Command *>&1 | Tee-Object -FilePath $log
    if ($LASTEXITCODE) { $code = $LASTEXITCODE }
}
catch {
    $_ | Out-String | Tee-Object -FilePath $log -Append
    $code = 1
}
if ($code -ne 0) {
    $text = (Get-Content $log -Tail $Tail -ErrorAction SilentlyContinue) -join "`n"
    & (Join-Path $PSScriptRoot 'annotate.ps1') -Title $Title -Text $text
    exit $code
}
