<#
  Nur CI: Heartbeat der Probes auf 10 s (Minimum) statt 30 s. Die Ende-zu-Ende-Tests warten oft auf den
  nächsten Heartbeat (neue Checks, „Jetzt testen“) und laufen so deutlich schneller.
  Schickt das Formular Verwaltung › Messung so zurück, wie es ein Browser täte: nur der Heartbeat ändert sich.
  Die Probes übernehmen den Wert mit ihrem nächsten Heartbeat (geänderte Konfiguration).
#>
param([int]$Seconds = 10)
$ErrorActionPreference = 'Stop'
$base = 'https://localhost:8443'

$login = Invoke-WebRequest "$base/login" -SkipCertificateCheck -SessionVariable s
$csrf = [regex]::Match($login.Content, 'name="csrf_token" value="([^"]+)"').Groups[1].Value
Invoke-WebRequest "$base/login" -Method Post -WebSession $s -SkipCertificateCheck `
    -Body @{ username = 'admin'; password = 'ci-test-passwort-123'; csrf_token = $csrf } | Out-Null

function Read-MeasureForm {
    $html = (Invoke-WebRequest "$base/admin?tab=messung" -WebSession $s -SkipCertificateCheck).Content
    $form = [regex]::Match($html, '(?s)<form[^>]*action="/admin/measure"[^>]*>(.*?)</form>')
    if (-not $form.Success) { throw 'Formular Verwaltung › Messung nicht gefunden' }
    $body = @{}
    foreach ($m in [regex]::Matches($form.Groups[1].Value, '<input\b[^>]*>')) {
        $tag = $m.Value
        $name = [regex]::Match($tag, '\bname="([^"]+)"').Groups[1].Value
        if (-not $name) { continue }
        if ($tag -match '\btype="checkbox"') {
            if ($tag -match '\schecked[\s>]') { $body[$name] = 'on' }   # nicht angehakt = Feld fehlt, wie im Browser
            continue
        }
        $body[$name] = [System.Net.WebUtility]::HtmlDecode([regex]::Match($tag, '\bvalue="([^"]*)"').Groups[1].Value)
    }
    if (-not $body.ContainsKey('heartbeat_interval_s')) { throw 'Feld heartbeat_interval_s fehlt im Formular' }
    $body
}

$body = Read-MeasureForm
$before = $body.Clone()
$body['heartbeat_interval_s'] = "$Seconds"
Invoke-WebRequest "$base/admin/measure" -Method Post -Body $body -WebSession $s -SkipCertificateCheck | Out-Null

# Gegenprobe: Heartbeat geändert, alles andere wie vorher
$after = Read-MeasureForm
if ($after['heartbeat_interval_s'] -ne "$Seconds") { throw "Heartbeat nicht gespeichert: $($after['heartbeat_interval_s'])" }
foreach ($k in $before.Keys) {
    if ($k -in 'csrf_token', 'heartbeat_interval_s') { continue }
    if ($after[$k] -ne $before[$k]) { throw "Einstellung $k hat sich ungewollt geändert: '$($before[$k])' -> '$($after[$k])'" }
}
Write-Host "Heartbeat der Probes: $Seconds s (nur CI), übrige Messeinstellungen unverändert ($($before.Count - 1) Felder)"
