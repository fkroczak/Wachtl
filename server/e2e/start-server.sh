#!/usr/bin/env bash
# Startet Collector + Fake-VictoriaMetrics mit frischer SQLite-DB und Demodaten für UI-Tests.
# Aufruf aus server/:  e2e/start-server.sh   (Python-Abhängigkeiten aus requirements-dev.txt nötig)
set -euo pipefail
cd "$(dirname "$0")/.."
RUN=${WACHTL_E2E_DIR:-$(mktemp -d)}
PORT=${WACHTL_E2E_PORT:-5000}
export WACHTL_SECRET_KEY=e2e WACHTL_DATABASE_URL="sqlite:///$RUN/e2e.db" WACHTL_RULES_DIR="$RUN/rules" \
  WACHTL_VM_RAW_URL=http://127.0.0.1:18428 WACHTL_VM_AGG_URL=http://127.0.0.1:18428 \
  WACHTL_VMALERT_URL= WACHTL_ALERTMANAGER_URL= WACHTL_COOKIE_SECURE=0 \
  WACHTL_INITIAL_ADMIN_PASSWORD=${WACHTL_E2E_PASSWORD:-e2e-admin-passwort} WACHTL_INTERNAL_URL="http://127.0.0.1:$PORT"
python devtools/fake_vm.py 18428 > "$RUN/vm.log" 2>&1 &
flask --app wachtl init > "$RUN/init.log"
flask --app wachtl run --port "$PORT" > "$RUN/flask.log" 2>&1 &
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$PORT/healthz" > /dev/null && break; sleep 1; done
python devtools/seed_demo.py "http://127.0.0.1:$PORT" e2e/.seed.json
echo "Wachtl läuft auf http://127.0.0.1:$PORT (Logs: $RUN)"
