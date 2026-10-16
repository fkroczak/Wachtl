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

# --- Zertifikat (selbstsigniert, 10 Jahre, Schlüssel bleibt bei Erneuerung) ---
mkdir -p certs
if [[ ! -f certs/wachtl.key ]]; then
  say "Erzeuge Schlüssel und selbstsigniertes Zertifikat für ${WACHTL_HOST}"
  openssl ecparam -name prime256v1 -genkey -noout -out certs/wachtl.key
fi
if [[ ! -f certs/wachtl.crt ]] || ! openssl x509 -checkend $((30*86400)) -noout -in certs/wachtl.crt >/dev/null; then
  if [[ "$WACHTL_HOST" =~ ^[0-9.]+$ ]]; then SAN="IP:${WACHTL_HOST}"; else SAN="DNS:${WACHTL_HOST}"; fi
  openssl req -new -x509 -key certs/wachtl.key -out certs/wachtl.crt -days 3650 \
    -subj "/CN=${WACHTL_HOST}/O=Wachtl" -addext "subjectAltName=${SAN}" \
    -addext "keyUsage=digitalSignature" -addext "extendedKeyUsage=serverAuth"
  say "Zertifikat erstellt"
fi
chmod 600 certs/wachtl.key
PIN="$(openssl x509 -in certs/wachtl.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
setvar WACHTL_SPKI_PIN "$PIN"

# --- Start ----------------------------------------------------------------
say "Baue und starte Container (dauert beim ersten Mal einige Minuten)"
docker compose up -d --build --remove-orphans

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
echo "    Zertifikat für Browser: $(pwd)/certs/wachtl.crt"
