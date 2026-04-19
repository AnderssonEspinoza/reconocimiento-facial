#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_FILE="docker-compose.micro.yml"

echo "[1/4] Levantando gateway (si no está arriba)..."
sudo docker compose -f "$COMPOSE_FILE" up -d gateway-service

echo "[2/4] Levantando túnel cloudflared (perfil tunnel)..."
sudo docker compose -f "$COMPOSE_FILE" --profile tunnel up -d cloudflared-tunnel

echo "[3/4] Esperando URL pública..."
for _ in {1..30}; do
  URL_LINE="$(sudo docker compose -f "$COMPOSE_FILE" logs --no-color --tail=120 cloudflared-tunnel 2>/dev/null | rg -o "https://[a-zA-Z0-9.-]+trycloudflare.com" | tail -n 1 || true)"
  if [[ -n "${URL_LINE}" ]]; then
    echo
    echo "[4/4] Túnel listo"
    echo "URL pública: ${URL_LINE}"
    echo "UI: ${URL_LINE}/"
    echo "Admin: ${URL_LINE}/admin"
    exit 0
  fi
  sleep 1
done

echo "No se pudo detectar la URL aún. Revisa logs con:"
echo "  sudo docker compose -f ${COMPOSE_FILE} logs -f cloudflared-tunnel"
exit 1

