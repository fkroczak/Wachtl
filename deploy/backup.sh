#!/usr/bin/env bash
# Wachtl – Sicherung. Legt backups/wachtl-JJJJMMTT-HHMM.tar.gz an mit:
#   PostgreSQL-Dump (inkl. Benachrichtigungen), Snapshot der 1-min-Aggregate (vm-agg), .env, Zertifikat.
# Rohdaten (vm-raw) werden bewusst nicht gesichert (kurzlebig, groß). Mit --raw zusätzlich sichern.
# Täglich per Cron:  15 2 * * *  /opt/wachtl/deploy/backup.sh >> /var/log/wachtl-backup.log 2>&1
set -euo pipefail
cd "$(dirname "$0")"
KEEP_DAYS="${KEEP_DAYS:-14}"
STAMP="$(date +%Y%m%d-%H%M)"
WORK="backups/tmp-${STAMP}"
mkdir -p "$WORK"

set -a; source .env; set +a

snapshot() {  # snapshot <service> <volume> <zielordner> – konsistent über vmbackup
  local svc=$1 vol=$2 dest=$3
  mkdir -p "$dest"
  docker run --rm --network wachtl_internal \
    -v "wachtl_${vol}:/storage" -v "$(realpath "$dest"):/backup" \
    "victoriametrics/vmbackup:${VM_VERSION}" \
    -storageDataPath=/storage -snapshot.createURL="http://${svc}:8428/snapshot/create" -dst=fs:///backup \
    -loggerLevel=ERROR
}

echo "$(date -Is) Sicherung startet"
docker compose exec -T postgres pg_dump -U wachtl -d wachtl --format=custom > "${WORK}/postgres.dump"
snapshot vm-agg vmagg "${WORK}/vm-agg"
[[ "${1:-}" == "--raw" ]] && snapshot vm-raw vmraw "${WORK}/vm-raw"
cp .env "${WORK}/env"
cp -r certs "${WORK}/"

tar -czf "backups/wachtl-${STAMP}.tar.gz" -C "$WORK" .
rm -rf "$WORK"
chmod 600 "backups/wachtl-${STAMP}.tar.gz"
find backups -name 'wachtl-*.tar.gz' -mtime +"${KEEP_DAYS}" -delete
echo "$(date -Is) Fertig: backups/wachtl-${STAMP}.tar.gz ($(du -h "backups/wachtl-${STAMP}.tar.gz" | cut -f1))"
