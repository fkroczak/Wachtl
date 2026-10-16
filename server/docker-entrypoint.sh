#!/bin/sh
# Datenbank migrieren, Standards anlegen, Regeldatei schreiben – dann Webserver starten.
set -e
flask --app wachtl init --no-reload
exec gunicorn \
  --bind 0.0.0.0:8000 \
  --workers "${WACHTL_WORKERS:-4}" \
  --timeout 60 \
  --access-logfile - \
  --forwarded-allow-ips "*" \
  wsgi:app
