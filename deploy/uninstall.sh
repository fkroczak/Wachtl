#!/usr/bin/env bash
# Wachtl – Server (Linux/Docker) vollständig entfernen und prüfen, dass nichts offen bleibt.
#
#   sudo ./uninstall.sh                 Container, Netzwerke, Images, Cron-Eintrag entfernen; Daten bleiben
#   sudo ./uninstall.sh --alles         zusätzlich Volumes (Datenbank, Messwerte), .env, Zertifikat, Sicherungen
#   sudo ./uninstall.sh --alles --ja    ohne Rückfrage (z. B. per Skript)
#
# Entfernt wird nur, was setup.sh angelegt hat. Die Port-Freigaben (80, 443, iperf3, RTP) setzt Docker selbst als
# iptables-Regeln – sie verschwinden mit den Containern; das Skript prüft das am Ende.
set -euo pipefail
cd "$(dirname "$0")"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mAchtung:\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mFehler:\033[0m %s\n' "$*" >&2; exit 1; }

ALL=0; YES=0
for arg in "$@"; do
  case "$arg" in
    --alles) ALL=1 ;;
    --ja) YES=1 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) fail "Unbekannte Option: $arg (siehe --help)" ;;
  esac
done
[[ $EUID -eq 0 ]] || fail "Bitte mit sudo ausführen."
command -v docker >/dev/null || fail "Docker fehlt – nichts zu entfernen?"

IPERF_PORT=5201
RTP_PORT=5004
if [[ -f .env ]]; then
  IPERF_PORT="$(grep -E '^IPERF_PORT=' .env | cut -d= -f2 || true)"
  IPERF_PORT="${IPERF_PORT:-5201}"
  RTP_PORT="$(grep -E '^RTP_PORT=' .env | cut -d= -f2 || true)"
  RTP_PORT="${RTP_PORT:-5004}"
fi

if [[ $YES -eq 0 ]]; then
  echo "Wachtl wird von diesem Server entfernt: Container, Netzwerke, Images und der tägliche Cron-Eintrag."
  if [[ $ALL -eq 1 ]]; then
    echo "Mit --alles außerdem ENDGÜLTIG: Datenbank, Messwerte, .env, Zertifikat (privater Schlüssel), Sicherungen."
  else
    echo "Datenbank, Messwerte, .env, Zertifikat und Sicherungen bleiben erhalten (für eine Neuinstallation)."
  fi
  read -r -p "Fortfahren? [j/N] " answer
  [[ "$answer" =~ ^[jJyY]$ ]] || { echo "Abgebrochen."; exit 1; }
fi

# --- Container, Netzwerke, Volumes ------------------------------------------------
say "Stoppe und entferne Container und Netzwerke"
if [[ -f docker-compose.yml ]]; then
  if [[ $ALL -eq 1 ]]; then
    docker compose down --remove-orphans --volumes --timeout 30 || true
  else
    docker compose down --remove-orphans --timeout 30 || true
  fi
fi
# Reste unter dem Projektnamen (z. B. wenn docker-compose.yml schon fehlt)
mapfile -t containers < <(docker ps -aq --filter "label=com.docker.compose.project=wachtl")
[[ ${#containers[@]} -gt 0 ]] && docker rm -f "${containers[@]}" >/dev/null
mapfile -t networks < <(docker network ls -q --filter "label=com.docker.compose.project=wachtl")
[[ ${#networks[@]} -gt 0 ]] && docker network rm "${networks[@]}" >/dev/null
if [[ $ALL -eq 1 ]]; then
  mapfile -t volumes < <(docker volume ls -q --filter "label=com.docker.compose.project=wachtl")
  [[ ${#volumes[@]} -gt 0 ]] && docker volume rm "${volumes[@]}" >/dev/null
fi

say "Entferne lokal gebaute Images"
docker image rm wachtl-app:local wachtl-iperf3:local >/dev/null 2>&1 || true

# --- Cron (tägliche Sicherung aus docs/BETRIEB.md) ------------------------------------
if crontab -l >/dev/null 2>&1 && crontab -l | grep -q "deploy/backup.sh"; then
  say "Entferne Cron-Eintrag für backup.sh"
  crontab -l | grep -v "deploy/backup.sh" | crontab -
fi

# --- Geheimnisse und Daten im Ordner -------------------------------------------------
if [[ $ALL -eq 1 ]]; then
  say "Lösche .env, Zertifikat und Sicherungen"
  rm -f .env
  rm -rf certs backups
  rm -f /var/log/wachtl-backup.log
fi

# --- Prüfung: bleibt etwas offen? ---------------------------------------------------
say "Prüfe, ob etwas zurückgeblieben ist"
problems=()
[[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=wachtl")" ]] && problems+=("Container des Projekts wachtl")
[[ -n "$(docker network ls -q --filter "label=com.docker.compose.project=wachtl")" ]] && problems+=("Docker-Netzwerke des Projekts wachtl")
if command -v ss >/dev/null; then
  for spec in "tcp:80" "tcp:443" "tcp:${IPERF_PORT}" "udp:${IPERF_PORT}" "udp:${RTP_PORT}"; do
    proto=${spec%%:*}; port=${spec##*:}
    flag=$([[ $proto == tcp ]] && echo "-ltnp" || echo "-lunp")
    if ss -H $flag "sport = :$port" 2>/dev/null | grep -q "docker-proxy"; then
      problems+=("Port $port/$proto ist noch von Docker freigegeben")
    fi
  done
fi
if command -v iptables >/dev/null && iptables -t nat -S DOCKER 2>/dev/null | grep -Eq -- "--dport (443|80|${IPERF_PORT}|${RTP_PORT}) "; then
  problems+=("iptables-Weiterleitung für Port 80/443/${IPERF_PORT}/${RTP_PORT} (Docker) – 'systemctl restart docker' räumt sie auf")
fi
if [[ $ALL -eq 1 ]]; then
  [[ -e .env || -e certs/wachtl.key ]] && problems+=(".env oder privater Schlüssel liegt noch im Ordner")
  [[ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=wachtl")" ]] && problems+=("Docker-Volumes mit Daten")
fi

if [[ ${#problems[@]} -gt 0 ]]; then
  warn "Nicht vollständig entfernt:"
  printf '  - %s\n' "${problems[@]}"
  exit 2
fi

echo
say "Wachtl ist entfernt. Keine Container, Netzwerke oder offenen Ports des Projekts mehr."
if [[ $ALL -eq 0 ]]; then
  echo "    Erhalten: Volumes (Datenbank, Messwerte), .env, certs/, backups/ in $(pwd)"
  echo "    Endgültig löschen: sudo ./uninstall.sh --alles"
else
  echo "    Den Ordner $(cd .. && pwd) kann man jetzt löschen."
fi
echo "    Docker selbst bleibt installiert. Probes beim Kunden mit ihrem Deinstaller entfernen (meldet sie ab)."
