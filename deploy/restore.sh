#!/usr/bin/env bash
# Wachtl – Wiederherstellung aus einer Sicherung von backup.sh.
# Aufruf: sudo ./restore.sh backups/wachtl-20261016-0215.tar.gz
# ACHTUNG: überschreibt Datenbank, Aggregate, .env und Zertifikat des laufenden Systems.
set -euo pipefail
cd "$(dirname "$0")"
ARCHIVE="${1:?Bitte Sicherungsdatei angeben}"
read -r -p "Aktuelle Daten werden überschrieben. Fortfahren? (ja/nein) " answer
[[ "$answer" == "ja" ]] || exit 1

WORK="$(mktemp -d)"
tar -xzf "$ARCHIVE" -C "$WORK"
cp "$WORK/env" .env && chmod 600 .env
rm -rf certs && cp -r "$WORK/certs" .

docker compose up -d postgres
sleep 5
docker compose exec -T postgres pg_restore -U wachtl -d wachtl --clean --if-exists < "$WORK/postgres.dump"

set -a; source .env; set +a
for svc in vm-agg vm-raw; do
  [[ -d "$WORK/$svc" ]] || continue
  vol="$( [[ $svc == vm-agg ]] && echo vmagg || echo vmraw )"
  docker compose stop "$svc"
  docker run --rm -v "wachtl_${vol}:/storage" -v "$WORK/$svc:/backup:ro" \
    "victoriametrics/vmrestore:${VM_VERSION}" -src=fs:///backup -storageDataPath=/storage
done

./setup.sh
rm -rf "$WORK"
echo "Wiederherstellung abgeschlossen."
