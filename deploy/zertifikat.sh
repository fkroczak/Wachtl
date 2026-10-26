#!/usr/bin/env bash
# Wachtl – Wachtl-CA und Server-Zertifikat prüfen und bei Bedarf erneuern.
# Läuft bei jedem ./setup.sh und täglich per Cron (/etc/cron.d/wachtl-zertifikat).
# Das Server-Zertifikat gilt 397 Tage und wird 30 Tage vor Ablauf erneuert; sein Schlüssel – und damit der
# Pin der Probes – bleibt immer gleich. Die PCs vertrauen der Wachtl-CA und merken von der Erneuerung nichts.
set -euo pipefail
cd "$(dirname "$0")"
set -a; source .env; set +a

mkdir -p certs
# dieselbe Logik wie beim Windows-Server: Python-Modul im App-Image, als root für die Dateien in ./certs
out="$(docker compose run --rm --no-deps -T --user 0:0 --entrypoint python -v "$PWD/certs:/certs" \
        app -m wachtl.win.certs ensure --dir /certs --names "$WACHTL_HOST")"
pin="$(sed -n 's/^pin=//p' <<<"$out")"
renewed="$(sed -n 's/^renewed=//p' <<<"$out")"
reason="$(sed -n 's/^reason=//p' <<<"$out")"
[[ -n "$pin" ]] || { echo "Zertifikat: keine Antwort vom Container" >&2; exit 1; }

chmod 600 certs/wachtl.key certs/wachtl-ca.key
# öffentlicher Teil (Kette mit Wachtl-CA, ohne Schlüssel) für die Download-Seite /zertifikat
mkdir -p certs/public
cp certs/wachtl.crt certs/public/wachtl.crt
chmod 644 certs/public/wachtl.crt

if [[ "$renewed" == 1 ]]; then
  echo "$(date '+%F %T') Zertifikat neu ausgestellt: $reason"
  # Traefik liest das Zertifikat nur beim Start
  if [[ -n "$(docker compose ps -q traefik 2>/dev/null)" ]]; then
    docker compose restart traefik >/dev/null
  fi
fi
echo "pin=$pin"
