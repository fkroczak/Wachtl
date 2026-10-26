#!/usr/bin/env bash
# Wachtl – Einrichtung und Aktualisierung des Servers.
# Erstaufruf:   sudo ./setup.sh wachtl.kunde.local      (DNS-Name oder IP des Servers)
# Danach:       sudo ./setup.sh                         (übernimmt .env, baut neu, startet)
set -euo pipefail
cd "$(dirname "$0")"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mFehler:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || fail "Docker ist nicht installiert (siehe docs/INSTALL-SERVER.md)."
docker compose version >/dev/null 2>&1 || fail "Docker Compose Plugin fehlt."
command -v openssl >/dev/null || fail "openssl fehlt (apt install openssl)."

rand() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c "${1:-40}"; }
setvar() {  # setvar KEY VALUE – Wert in .env setzen
  local key=$1 value=$2
  if grep -q "^${key}=" .env; then
    sed -i "s|^${key}=.*|${key}=${value}|" .env
  else
    echo "${key}=${value}" >> .env
  fi
}

# --- .env ---------------------------------------------------------------
FIRST_RUN=0
if [[ ! -f .env ]]; then
  [[ $# -ge 1 ]] || fail "Beim ersten Aufruf bitte den Servernamen angeben: ./setup.sh wachtl.kunde.local"
  cp .env.example .env
  chmod 600 .env
  setvar WACHTL_HOST "$1"
  setvar WACHTL_PUBLIC_URL "https://$1"
  setvar WACHTL_SECRET_KEY "$(rand 64)"
  setvar WACHTL_WEBHOOK_SECRET "$(rand 40)"
  setvar POSTGRES_PASSWORD "$(rand 32)"
  ADMIN_PW="$(rand 20)"
  setvar WACHTL_INITIAL_ADMIN_PASSWORD "$ADMIN_PW"
  FIRST_RUN=1
  say ".env angelegt"
fi
set -a; source .env; set +a

# --- Zertifikat: eigene Wachtl-CA + Server-Zertifikat (397 Tage, erneuert sich selbst) ---
say "Baue die Container (dauert beim ersten Mal einige Minuten)"
docker compose build
say "Prüfe Wachtl-CA und Server-Zertifikat"
PIN="$(./zertifikat.sh | sed -n 's/^pin=//p')"
[[ -n "$PIN" ]] || fail "Zertifikat konnte nicht erstellt werden."
setvar WACHTL_SPKI_PIN "$PIN"
# täglich prüfen und rechtzeitig erneuern
cat > /etc/cron.d/wachtl-zertifikat <<CRON
# Wachtl: Server-Zertifikat rechtzeitig erneuern (angelegt von setup.sh, entfernt von uninstall.sh)
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
23 4 * * * root $(pwd)/zertifikat.sh >> /var/log/wachtl-zertifikat.log 2>&1
CRON
chmod 644 /etc/cron.d/wachtl-zertifikat

# --- Start ----------------------------------------------------------------
say "Starte Container"
docker compose up -d --remove-orphans

say "Warte auf den Collector"
for _ in $(seq 1 60); do
  if docker compose exec -T app python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo
say "Wachtl läuft: ${WACHTL_PUBLIC_URL}"
echo "    SPKI-Pin für die Probes: ${PIN}"
if [[ $FIRST_RUN -eq 1 ]]; then
  setvar WACHTL_INITIAL_ADMIN_PASSWORD ""
  echo "    Anmeldung:  admin / ${ADMIN_PW}"
  echo "    Bitte das Passwort nach der ersten Anmeldung ändern und sicher ablegen."
fi
echo "    Passwort vergessen: sudo $(pwd)/passwort.sh"
echo "    Zertifikat für Browser: ${WACHTL_PUBLIC_URL}/zertifikat (Windows-PCs mit Probe: automatisch)"
