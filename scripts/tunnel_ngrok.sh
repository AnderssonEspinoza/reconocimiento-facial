#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_FILE="docker-compose.micro.yml"

if ! command -v ngrok >/dev/null 2>&1; then
  echo "ngrok no está instalado en el host."
  echo "Instálalo y configura auth token: ngrok config add-authtoken <TU_TOKEN>"
  exit 1
fi

echo "[1/3] Levantando stack base..."
sudo docker compose -f "$COMPOSE_FILE" up -d gateway-service

echo "[2/3] Abriendo túnel ngrok hacia http://localhost:8002 ..."
echo "Tip: la URL pública aparecerá en esta misma consola."
echo "UI local ngrok: http://127.0.0.1:4040"
echo
echo "[3/3] Ejecutando ngrok (Ctrl+C para cerrar túnel)"
exec ngrok http 8002

