<#
  Gibt einen langen Text als mehrere GitHub-Annotationen aus (je max. 4096 Zeichen, bis zu 30 Stück),
  damit Logs auch über die API lesbar sind.
#>
param([Parameter(Mandatory)] [string]$Title, [string]$Text = '')
$chunk = 3800
$max = 30
if ($Text.Length -gt $chunk * $max) { $Text = $Text.Substring($Text.Length - $chunk * $max) }
$parts = [Math]::Ceiling($Text.Length / $chunk)
for ($i = 0; $i -lt $parts; $i++) {
    $len = [Math]::Min($chunk, $Text.Length - $i * $chunk)
    $part = $Text.Substring($i * $chunk, $len).Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
    $level = @('notice', 'warning', 'error')[[Math]::Floor($i / 10)]
    Write-Host "::$level title=$Title $($i + 1)/$parts::$part"
}
