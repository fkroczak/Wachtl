#!/usr/bin/env bash
# Wachtl – Passwort zurücksetzen (z. B. wenn das Admin-Passwort vergessen ist). Entsperrt das Konto auch.
#   sudo /opt/wachtl/deploy/passwort.sh            # Benutzer admin
#   sudo /opt/wachtl/deploy/passwort.sh <name>     # anderer Benutzer (erhält die Rolle Admin)
set -euo pipefail
cd "$(dirname "$0")"
exec docker compose exec app flask --app wachtl create-user "${1:-admin}" --role admin
